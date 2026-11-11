# MCP server and DSH NEXT integration

The platform exposes its tool surface through a stdio MCP server, so DSH NEXT can
drive the whole APK workflow (ingest, index, query, evidence, report) without a
shell tool and without a second HTTP client.

- Server: `mcp-server/mcp_server/server.py` (single file, stdlib only, no extra wheels)
- Transport: newline-delimited JSON-RPC 2.0 on stdin/stdout, protocol version `2024-11-05`
- Diagnostics: stderr only, so the transport stays clean
- Downstream state: the same SQLite database and `storage/projects/<id>` tree the
  HTTP API uses; nothing is duplicated

## Tool whitelist

Sixteen tools; the names below are what the client reports, and DSH prefixes them
as `mcp__<serverName>__<tool>` (for example `mcp__apkplat__apk_search_code`).

| Tool | Required arguments | Purpose |
| --- | --- | --- |
| `project_create` | `name`, `apk_path` | Ingest and validate an APK, create the project row and quarantine layout |
| `project_get` | `project_id` | Project row plus ingest manifest |
| `apk_get_metadata` | `project_id` | Package, versions, SDK levels, permissions, signing facts |
| `apk_list_packages` | `project_id` | Package/namespace list from the index |
| `apk_search_code` | `project_id`, `query` | Full-text search over classes, methods, fields, strings |
| `apk_read_method` | `project_id`, `class_name`, `method` | Source slice for one method from the indexed file |
| `apk_read_manifest` | `project_id` | Decoded `AndroidManifest.xml` as text |
| `apk_search_resources` | `project_id`, `query` | Resource table search |
| `artifact_list` | `project_id` | Artifacts with kind, path, size and sha256 |
| `evidence_read` | `project_id` | Evidence rows with locator, excerpt and claim |
| `evidence_record` | `project_id`, `kind`, `locator`, `excerpt` | Append an evidence row tied to an artifact |
| `task_create` | `project_id`, `title` | Create a Kanban task |
| `task_get` | `task_id` | Task row with status and counters |
| `task_update` | `task_id` | Status/fields update under the same transition guards as the API |
| `task_list` | `project_id` | Tasks for one project |
| `report_generate` | `project_id` | Render the Markdown report and return its path and self-check |

There is deliberately no `shell_exec`, no "read arbitrary file" and no
"run jadx with my flags" tool. Decompilation only happens inside the static
pipeline, with the fixed restricted toolchain in `backend/apkplat/toolchain.py`.

## Response envelope

Every `tools/call` returns the same fields:

```json
{
  "ok": true,
  "project_id": "prj_...",
  "task_id": null,
  "tool": "apk_get_metadata",
  "tool_version": "1.0.0",
  "started_at": "2026-11-10T19:44:12.031Z",
  "duration_ms": 41,
  "stdout_artifact_id": null,
  "stderr_artifact_id": null,
  "produced_artifact_ids": [],
  "error_code": null,
  "retryable": false,
  "request_id": "mcp_..."
}
```

`ok=false` always carries an `error_code`; the codes currently emitted are
`apk_missing`, `artifact_missing`, `evidence_not_found`, `evidence_rejected`,
`ingest_failed`, `not_found`, `path_rejected`, `project_denied`,
`project_not_found`, `schema_invalid`, `task_not_found`, `unknown_tool`.

**Big results land in files.** A payload larger than 24 KB is written to
`storage/projects/<id>/artifacts/mcp/<tool>-<ts>.json`, registered as an artifact,
and the response returns `artifact_id` plus a truncated preview instead of the
full body. This is how the taskbook's "large results to file" rule is implemented;
nothing is silently truncated away.

**Project scoping.** The server reads `APKPLAT_MCP_PROJECTS` (comma separated ids,
`*` only for a trusted single-operator workstation) and refuses a call that names
any other project with `project_denied` before it opens the database.

**Tool-surface scoping.** `APKPLAT_MCP_ALLOW_TOOLS` (comma separated names, default
`*`) narrows what this server instance advertises: `tools/list` returns only the
allowed subset and a call to a whitelisted-but-not-exposed tool fails with the
distinct error code `tool_disabled` (a name that does not exist at all stays
`unknown_tool`). The startup banner reports `tools=<exposed>/<total>`. Use it when a
hosted agent only needs a few read-only tools — 16 schemas is context the model has
to carry on every turn. `READ_ONLY_TOOLS` in `server.py` lists the read-only subset.

## Registering with DSH NEXT

DSH NEXT 0.2.1-rc.4 ships `@deepseek-ai/dsh-mcp-client`. Registration is a Cordis
patch entry, not an edit to the app bundle. Generate machine-specific absolute
paths first:

```powershell
cd D:\ADeespseekSH\REA\apk-research-platform
.\.venv\Scripts\python.exe scripts\render_mcp_registration.py
```

That writes `config/dsh-mcp.registration.yml` and refreshes the installable bundle
in `dsh-plugin/`. Then either

1. paste the snippet into `%USERPROFILE%\.dsh\profiles\desktop\cordis.patch.yml`
   (top-level list) and reload the profile, or
2. install `dsh-plugin/` through the DSH plugin manager as a config-only bundle
   (`dsh.bundle.patch` points at `cordis.patch.yml`).

The generated entry looks like this:

```yaml
- insert:
    - id: apkplat-mcp
      name: '@deepseek-ai/dsh-mcp-client'
      config:
        serverName: apkplat
        transport: stdio
        command: 'D:\ADeespseekSH\REA\apk-research-platform\.venv\Scripts\python.exe'
        args:
          - 'D:\ADeespseekSH\REA\apk-research-platform\mcp-server\mcp_server\server.py'
        cwd: 'D:\ADeespseekSH\REA\apk-research-platform'
        env:
          APKPLAT_STORAGE: 'D:\ADeespseekSH\REA\apk-research-platform\storage'
          APKPLAT_MCP_PROJECTS: '*'
          APKPLAT_MCP_ACTOR: 'dsh-agent'
          PYTHONUTF8: '1'
          PYTHONIOENCODING: 'utf-8'
        toolCallTimeoutMs: 120000
        failOnStartupError: true
```

Two client behaviours matter when editing this by hand:

- `serverName` must match `[A-Za-z0-9_-]{1,32}` and is part of the tool name, so
  renaming it renames every `mcp__…__…` tool and invalidates prior tool
  permissions in the conversation.
- The client scrubs the inherited environment before spawning: every variable
  whose name matches `/KEY|PASSWORD|SECRET|TOKEN/i` and every `DSH_*` name is
  removed. `APKPLAT_STORAGE` and `APKPLAT_MCP_PROJECTS` survive; if you ever need
  to pass a secret, reference it with a Loader `!!js` expression instead of
  pasting the value, for example `SOME_TOKEN: !!js process.env.SOME_TOKEN`.

`failOnStartupError: true` makes a broken registration fail loudly at boot rather
than silently exposing zero tools.

## Verifying the registration

Without DSH, drive the server directly (this is what
`tests/integration/test_p1_closed_loop.py` does):

```powershell
$root = 'D:\ADeespseekSH\REA\apk-research-platform'
$env:PYTHONPATH = "$root\backend"
@'
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"probe","version":"0"}}}
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"project_get","arguments":{"project_id":"prj_REPLACE"}}}
'@ | .\.venv\Scripts\python.exe mcp-server\mcp_server\server.py
```

Expect: an `initialize` result with `serverInfo.name`, a `tools/list` result with
exactly sixteen tools, and one JSON-RPC response per request id. Note `PYTHONPATH`
is required — the server imports the backend package from `backend/`.

PowerShell may print the server's startup banner (`[apkplat-mcp] ready v1.0.0
tools=16 …`) as a `NativeCommandError`: it is written to stderr on purpose and is
not a failure. Append `2>$null` if the noise bothers you — DSH itself reads stdout
only, so the banner never reaches the model.

Inside DSH, call `mcp__apkplat__apk_get_metadata` (or any whitelisted tool) on a
project id you created; a successful envelope proves the stdio pipe, the schema
validation and the database path all line up.

## Compatibility notes

- Protocol `2024-11-05`; `initialize`, `ping`, `tools/list`, `tools/call`,
  `resources/list` and `prompts/list` are implemented. `resources/list` and
  `prompts/list` return empty lists — the platform has no MCP resources or prompts
  of its own, only tools.
- Notifications are accepted and ignored (no response is written for a message
  without `id`), which is what the client expects for `notifications/initialized`.
- Tool schemas are enforced server-side (`schema_invalid` on violation) and every
  call appends an `mcp_tool_call` audit event carrying `schema_ok`, which feeds the
  `tool_call_schema_valid_rate` metric.
- The server holds one SQLite connection; concurrent MCP and HTTP processes are
  fine because SQLite runs in WAL mode with a 30 s busy timeout.
