# APK Research Platform

A self-hosted Android APK analysis platform built to the taskbook
`DSH_NEXT_Android_APK_Analysis_Platform_Taskbook_V1.2.md`: ingest an APK, decompile
it with a restricted toolchain, index it, query it through MCP, attach evidence to
every claim, and produce a Markdown report -with a Kanban board, a persistent job
queue, multi-agent review, and a device pool for dynamic runs.

Everything here runs on one Windows workstation, inside this directory. Two things
are **provided by the operator and were not installed, upgraded or reconfigured by
this project**:

- DSH NEXT (`0.2.1-rc.4`, at `C:\Users\YHY\AppData\Local\Programs\DSH NEXT`)
- the remote model API (`http://192.168.43.1:8788/v1`, model `deepseek-v4.1-flash`)

The only modifications this project makes outside its own folder are:
a generated MCP registration snippet for DSH (`config/dsh-mcp.registration.yml`,
opt-in) and read-only access to the operator's credentials file to obtain the model
API key at call time (never printed, never copied into the repo).

## Quickstart

```powershell
cd D:\ADeespseekSH\REA\apk-research-platform

# 1. environment (already provisioned here; recreate if the venv is missing)
C:\Users\YHY\AppData\Local\Programs\Python\Python313\python.exe -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt

# 2. portable toolchain (java, node, jadx, apktool, android sdk) under .\tools
.\.venv\Scripts\python.exe scripts\fetch_toolchain.py --verify

# 3. configuration + schema
Copy-Item .env.example .env       # then edit if needed
.\.venv\Scripts\python.exe scripts\apkplat_cli.py init

# 4. run it
.\scripts\platform.ps1 start      # API on 127.0.0.1:8765 + two static workers
.\scripts\platform.ps1 status
.\scripts\platform.ps1 stop
```

Open `http://127.0.0.1:8765/` for the console (Chinese UI: board, project overview, evidence,
search, report, task drawer, settings), or drive it headless:

```powershell
.\.venv\Scripts\python.exe scripts\apkplat_cli.py create --name reef --apk samples\sample-app.apk
.\.venv\Scripts\python.exe scripts\apkplat_cli.py worker --once
.\.venv\Scripts\python.exe scripts\apkplat_cli.py verify <project_id>
.\.venv\Scripts\python.exe scripts\apkplat_cli.py report <project_id>
```

## What is implemented

| Gate | Property | Evidence |
| --- | --- | --- |
| P0 | Environment and model-API report, no installs, no config changes | `reports/p0/environment_report.md`, `reports/p0/model_api_check.json` |
| P1 | Single-APK static closed loop: upload ->validate ->restricted jadx/apktool ->index ->MCP ->evidence ->report | `reports/gate1/acceptance.md` (24/24) |
| P2 | Multi-project isolation, persistent queue, restart recovery, board, event stream | `reports/gate2/acceptance.md` (20/20) |
| P3 | Four agent roles with a deterministic evidence gate that rejects unsupported claims | `reports/gate3/acceptance.md` (19/19, live model) |
| P4 | Device pool: leases, single-device serialisation, unplug-safe failure, verified cleanup | `reports/gate4/acceptance.md` (30/30) |
| P5 | Stability and security: hostile APKs, oversize uploads, path tricks, immutable audit, recovery | `reports/gate5/acceptance.md` (36/36) |

## V3 taskbook phases (the incremental programme)

The V3 taskbook (`DSH_NEXT_APK_Analysis_Final_Taskbook_V3.0.md`) replaces the fixed
three-stage agent chain with a real autonomous loop, a dependency DAG, typed evidence and a
device layer. Each phase ships with its own acceptance script that prints every observed value.

| Phase | Property | Evidence |
| --- | --- | --- |
| P0 | Baseline: 13 tables snapshotted, `ctx.agents` proven present, one real MCP tool call from the model | `audit/g0_acceptance.md` (14/14), `audit/mcp_registration_proof.md` |
| P1 | Bridge plugin + opaque run capability + a genuinely autonomous loop (the model picks its own tools and is audited) | `audit/g1_acceptance.md` (17/17) |
| P2 | `task_edges`, PASS-gated unlocks, bounded review dispatch, roles registry, platform event stream | `audit/g2_acceptance.md` (18/18) |
| P3 | Typed evidence with integrity/provenance/assertion levels, cooperative sandbox, independent replay, extended report | `audit/g3_acceptance.md` (24/24) |
| P4 | Analysis cache, HAR/ProxyPin capture correlation, tool surface discipline | `reports/gate4/acceptance.md` (23/23) |
| P5 | Device health gate, whitelisted device actions, four cleanup policies, single-device serialisation | `reports/gate5/acceptance.md` (26/26) |
| P6 | Periodic scheduling with one owner, test identities by reference, injectable clock and resource probe | `reports/gate6/acceptance.md` (24/24) |
| P7 | Cross-project isolation, DAG-correct 21-card board, replayable evidence trail, restart survival | `reports/gate7/acceptance.md` (30/30) |

The P5 report is honest about its own boundary: destructive device paths ran on the
simulator, and the attached handset was only probed read-only (state, uiautomator dump, one
screenshot). Installing an APK on someone's phone is a real-world action, not something an
acceptance script performs by itself.

Test suites: `tests/unit` (state machine, validation, queue, evidence, auth,
toolchain policy), `tests/integration` (P1, P2, P3, P4, P5, API error shapes),
`tests/isolation` (cross-project isolation, concurrent claim) and `tests/e2e` (the
served API plus a separate worker process, over real HTTP). `pytest` currently
reports **113 passed** (~97 s). The six acceptance scripts together assert
**133 checks** (4 + 24 + 20 + 19 + 30 + 36), all passing on the run recorded in
`reports/`.

## Layout

```
backend/apkplat/        FastAPI app, services, static pipeline, agents, dynamic pool
mcp-server/mcp_server/  stdio MCP server (16 whitelisted tools)
dsh-plugin/             config-only DSH bundle that registers the MCP server
frontend/dist/          Kanban UI (static files, no build step, no CDN)
workers/                worker entry points
scripts/                CLI, toolchain fetcher, gate acceptance scripts, UI smoke
migrations/             SQLite schema (001 base, 002 append-only triggers)
config/                 MCP registration snippet, worker policy
tests/                  unit, integration, isolation, e2e
storage/projects/<id>/  inputs, manifests, artifacts, indexes, evidence, logs, reports
tools/                  portable java/node/jadx/apktool/android-sdk (deletable)
reports/                P0 and per-gate acceptance evidence, UI screenshots
samples/                ground-truth sample APK + six hostile variants
```

## Documentation

- [Architecture](docs/architecture.md) -topology, data model, state machine, pipeline stages
- [API](docs/api.md) -HTTP endpoints and MCP tool schemas
- [MCP and DSH integration](docs/mcp.md) -registration, envelope, verification
- [Operations](docs/operations.md) -install, run, backup, rerun acceptance
- [Troubleshooting](docs/troubleshooting.md) -the failures actually hit on this host
- [Evaluation](docs/evaluation.md) -metric definitions and measured values
- [Bridge protocol](docs/bridge.md) -run capabilities, the 13 tools, role matrix, error layers
- [Deployment](docs/deployment.md) -processes, supervision, DSH/MCP wiring, health checks
- [Rollback](docs/rollback.md) -what is backed up, how to restore code, database and capabilities
- [Capability matrix](docs/capability_matrix.md) -verified vs simulated vs absent, with numbers
- [Demo](docs/demo.md) -the 21-card walkthrough, step by step, with observed output
- [Delivery note](audit/DELIVERY.md) -what was built per phase, where the proof lives, honest limits
- [Final regression](reports/final_regression.md) -pytest plus fourteen acceptance scripts, one row each

## Honest limits

- No container, seccomp or AppArmor on this host: jadx/apktool isolation is
  approximated with a scrubbed child environment, a working directory forced
  inside `storage/`, hard timeouts and process-tree kills
  (`backend/apkplat/toolchain.py`). Deviations are listed in the P0 report.
- PostgreSQL and Redis are absent, so SQLite (WAL) is the single source of truth
  and the queue is a database outbox. The DDL is plain SQL and portable, but a
  PostgreSQL deployment is untested here.
- No Android device was attached during the build: dynamic analysis is exercised
  end to end through `SimTransport`, and `AdbTransport` is wired but unverified
  against real hardware (see `docs/evaluation.md`).
- jadx output of obfuscated applications is best-effort; the index reflects what
  jadx produced, and evidence always points at the artifact text.
