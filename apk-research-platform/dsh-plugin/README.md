# dsh-plugin — config-only bundle for the APK platform MCP server

This directory is a DSH NEXT bundle that contains no runtime code: it only
registers the platform's MCP server with the client that ships in DSH
(`@deepseek-ai/dsh-mcp-client`). The server itself lives in
`../mcp-server/mcp_server/server.py`.

Files:

| File | Role |
| --- | --- |
| `package.json` | bundle manifest; `dsh.bundle.patch` points at the patch below |
| `cordis.patch.yml` | one `insert` entry with `serverName`, `transport: stdio`, `command`, `args`, `cwd`, `env` |

`cordis.patch.yml` is generated — absolute paths belong to this machine:

```powershell
..\.venv\Scripts\python.exe ..\scripts\render_mcp_registration.py
```

Re-run it after moving the checkout or renaming the virtual environment.

## Install

1. DSH NEXT → plugin manager → install bundle from this directory, or paste
   `../config/dsh-mcp.registration.yml` into
   `%USERPROFILE%\.dsh\profiles\desktop\cordis.patch.yml`.
2. Reload the profile (or restart DSH NEXT).
3. The tools appear as `mcp__apkplat__<tool>` — sixteen of them, matching
   `docs/mcp.md`.

## Why a separate bundle instead of editing the app

The DSH installation is operator-provided and is never modified by this project.
A config-only bundle keeps the registration additive and reversible: uninstall the
bundle (or delete the patch entry) and DSH returns to exactly its previous state.

## Environment scrubbing caveat

The MCP client removes inherited variables matching `/KEY|PASSWORD|SECRET|TOKEN/i`
and every `DSH_*` name before spawning. `APKPLAT_STORAGE`, `APKPLAT_MCP_PROJECTS`
and `APKPLAT_MCP_ACTOR` survive, which is all the server needs — it reads the
signing key from `storage/secret.key` on disk rather than from the environment.
