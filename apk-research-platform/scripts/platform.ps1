<#
.SYNOPSIS
    One control surface for the APK research platform: init, start, stop, status,
    check, test, gates, cleanup.

.DESCRIPTION
    Everything runs from the project's own virtual environment and its portable
    toolchain; no system-wide install is touched. Process ids and logs live under
    storage\run so that stop/status work across shells.

.EXAMPLE
    .\scripts\platform.ps1 init
    .\scripts\platform.ps1 start
    .\scripts\platform.ps1 check
    .\scripts\platform.ps1 stop

.NOTES
    DSH NEXT and the model API are provided by the operator. This script never
    installs, upgrades or reconfigures them.
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('init', 'start', 'stop', 'restart', 'status', 'check', 'test', 'gates', 'logs', 'cleanup')]
    [string]$Action = 'status',

    [int]$Port = 8765,
    [int]$StaticWorkers = 2,
    [switch]$WithModel,
    [switch]$WithDynamic
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Python = Join-Path $Root '.venv\Scripts\python.exe'
$Cli = Join-Path $Root 'scripts\apkplat_cli.py'
$RunDir = Join-Path $Root 'storage\run'
$ApiPid = Join-Path $RunDir 'api.pid'
$ApiLog = Join-Path $RunDir 'api.log'

if (-not (Test-Path $Python)) {
    throw "virtual environment missing: $Python (create it first, see docs/operations.md)"
}
if (-not (Test-Path $RunDir)) { New-Item -ItemType Directory -Path $RunDir -Force | Out-Null }

function Get-ApiHealth {
    param([int]$TimeoutSec = 3)
    try {
        return Invoke-RestMethod -Uri ("http://127.0.0.1:{0}/api/health" -f $Port) -TimeoutSec $TimeoutSec
    } catch {
        return $null
    }
}

function Test-PidFile {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return $null }
    $raw = (Get-Content $Path -Raw).Trim()
    if (-not $raw) { return $null }
    $process = Get-Process -Id ([int]$raw) -ErrorAction SilentlyContinue
    if ($process) { return $process }
    return $null
}

function Invoke-Logged {
    # Runs "$Python <parts...>" and captures *both* streams into $LogPath.
    # Why cmd.exe: with $ErrorActionPreference='Stop' PowerShell converts any stderr
    # byte from a native command into a terminating NativeCommandError, and these
    # scripts legitimately emit deprecation warnings on stderr. Redirecting inside
    # cmd.exe keeps PowerShell's error stream out of it; the exit code is still ours.
    param([string[]]$Parts, [string]$LogPath)
    $quoted = @('"' + $Python + '"')
    foreach ($part in $Parts) { $quoted += '"' + $part + '"' }
    $line = ('{0} > "{1}" 2>&1' -f ($quoted -join ' '), $LogPath)
    & cmd.exe /s /c $line | Out-Null
    return $LASTEXITCODE
}

function Start-Child {
    # Start-Process rebuilds the environment in a case-insensitive dictionary and
    # dies when the parent exports both NO_PROXY and no_proxy (which this host
    # does). Wrapping the command in cmd.exe keeps the inherited environment block
    # intact and gives us file redirection without async plumbing that behaves
    # differently between PowerShell 5.1 and 7.
    param([string]$Name, [string[]]$Arguments, [string]$LogName)
    $log = Join-Path $RunDir $LogName
    $err = $log + '.err'
    $quoted = @($Python) + $Arguments | ForEach-Object { '"' + $_ + '"' }
    $commandLine = ($quoted -join ' ') + ' > "' + $log + '" 2> "' + $err + '"'
    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = "$env:ComSpec"
    $info.Arguments = '/s /c "' + $commandLine + '"'
    $info.WorkingDirectory = $Root
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $process = [System.Diagnostics.Process]::Start($info)
    Set-Content -Path (Join-Path $RunDir ($Name + '.pid')) -Value $process.Id -Encoding ascii
    Write-Host ("  {0}: pid {1}, log {2}" -f $Name, $process.Id, $log)
}

function Stop-Children {
    foreach ($name in @('worker-static-1', 'worker-static-2', 'worker-dynamic', 'worker-report', 'api')) {
        $pidFile = Join-Path $RunDir ($name + '.pid')
        $process = Test-PidFile -Path $pidFile
        if ($process) {
            Write-Host ("  stopping {0} (pid {1})" -f $name, $process.Id)
            # /T also kills the python child that cmd.exe wrapped
            & taskkill /PID $process.Id /T /F 2>&1 | Out-Null
        }
        if (Test-Path $pidFile) { Remove-Item $pidFile -Force }
    }
}

switch ($Action) {
    'init' {
        Write-Host 'applying migrations'
        & $Python $Cli init
        Write-Host 'checking portable toolchain'
        & $Python $Cli versions
    }

    'start' {
        Write-Host ("starting API on 127.0.0.1:{0}" -f $Port)
        Start-Child -Name 'api' -Arguments @($Cli, 'serve', '--host', '127.0.0.1', '--port', "$Port") -LogName 'api.log'

        $deadline = (Get-Date).AddSeconds(30)
        $health = $null
        while ((Get-Date) -lt $deadline -and -not $health) {
            Start-Sleep -Milliseconds 400
            $health = Get-ApiHealth
        }
        if (-not $health) { throw "API did not answer /api/health within 30s; see $ApiLog" }
        Write-Host ("  health: auth_mode={0} db_ok={1}" -f $health.auth_mode, $health.db.ok)

        for ($i = 1; $i -le $StaticWorkers; $i++) {
            Start-Child -Name ("worker-static-{0}" -f $i) `
                -Arguments @($Cli, 'worker', '--id', ("static-{0}" -f $i), '--kinds', 'static_pipeline', '--idle', '0') `
                -LogName ("worker-static-{0}.log" -f $i)
        }
        if ($WithDynamic) {
            Start-Child -Name 'worker-dynamic' -Arguments @($Cli, 'worker', '--id', 'dynamic-1', '--kinds', 'dynamic_analysis', '--idle', '0') -LogName 'worker-dynamic.log'
        }
        if ($WithModel) {
            Start-Child -Name 'worker-report' -Arguments @($Cli, 'worker', '--id', 'report-1', '--kinds', 'agent_orchestrate,report_generate', '--idle', '0') -LogName 'worker-report.log'
        }
        Write-Host 'started. `scripts\platform.ps1 status` to verify.'
    }

    'stop' {
        Write-Host 'stopping platform processes'
        Stop-Children
    }

    'restart' {
        Stop-Children
        Start-Sleep -Seconds 1
        & $MyInvocation.MyCommand.Path start -Port $Port -StaticWorkers $StaticWorkers
    }

    'status' {
        $health = Get-ApiHealth
        if ($health) {
            Write-Host ("API: up on {0} (uptime {1}s, auth_mode {2})" -f $Port, $health.uptime_seconds, $health.auth_mode)
        } else {
            Write-Host ("API: down on {0}" -f $Port)
        }
        foreach ($name in @('worker-static-1', 'worker-static-2', 'worker-dynamic', 'worker-report')) {
            $process = Test-PidFile -Path (Join-Path $RunDir ($name + '.pid'))
            if ($process) { Write-Host ("  {0}: pid {1}" -f $name, $process.Id) }
        }
        if ($health) {
            $queue = $health.queue | ConvertTo-Json -Compress
            Write-Host ("queue: {0}" -f $queue)
            Write-Host ("audit_seq: {0}" -f $health.audit_seq)
        }
    }

    'check' {
        $health = Get-ApiHealth
        if ($health) {
            Write-Host 'health endpoint: OK'
            Write-Host ("  db: {0}" -f $health.db.url)
            foreach ($name in $health.tools.PSObject.Properties.Name) {
                $tool = $health.tools.$name
                $mark = 'missing'
                if ($tool.ok) { $mark = 'ok' }
                Write-Host ("  tool {0}: {1} {2}" -f $name, $mark, $tool.version)
            }
        } else {
            Write-Host 'health endpoint: DOWN'
        }
        Write-Host 'queue:'
        & $Python $Cli queue
        Write-Host 'projects:'
        & $Python $Cli list
    }

    'test' {
        $log = Join-Path $RunDir 'pytest.log'
        $code = Invoke-Logged -Parts @('-m', 'pytest', (Join-Path $Root 'tests'), '-q') -LogPath $log
        Get-Content $log -Tail 3
        if ($code -ne 0) { throw "pytest failed (exit $code): $log" }
    }

    'gates' {
        # Each acceptance script writes its own report and prints PASS/FAIL lines.
        # Their stderr (deprecation warnings from fastapi/starlette) must not abort the
        # run: with $ErrorActionPreference='Stop' PowerShell turns any stderr output into
        # a NativeCommandError, so Invoke-Logged redirects inside cmd.exe and the exit
        # code is checked explicitly.
        $failed = @()
        foreach ($gate in @('p0_check.py', 'gate1_accept.py', 'gate2_accept.py', 'gate4_accept.py', 'gate5_accept.py')) {
            $script = Join-Path $Root ('scripts\' + $gate)
            $log = Join-Path $RunDir (([IO.Path]::GetFileNameWithoutExtension($gate)) + '.gates.log')
            $code = Invoke-Logged -Parts @($script) -LogPath $log
            $tail = (Get-Content $log -Tail 1) -join ' '
            if ($code -eq 0) {
                Write-Host ("{0}: OK  {1}" -f $gate, $tail)
            } else {
                Write-Host ("{0}: FAILED (exit {1})  see {2}" -f $gate, $code, $log)
                $failed += $gate
            }
        }
        Write-Host 'gate3 needs the live model; run it separately:'
        Write-Host ('  ' + $Python + ' ' + (Join-Path $Root 'scripts\gate3_accept.py'))
        if ($failed.Count -gt 0) {
            throw ('acceptance failures: ' + ($failed -join ', '))
        }
    }

    'logs' {
        Get-ChildItem $RunDir -Filter '*.log' | ForEach-Object {
            Write-Host ("--- {0} (last 20 lines)" -f $_.Name)
            Get-Content $_.FullName -Tail 20
        }
    }

    'cleanup' {
        Write-Host 'this removes quarantine/tmp scratch only, never project data'
        foreach ($dir in @('tmp', 'inbox')) {
            $path = Join-Path $Root ('storage\' + $dir)
            if (Test-Path $path) {
                Get-ChildItem $path -Force | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                Write-Host ("  cleared {0}" -f $path)
            }
        }
    }
}

