"""P0 step 2b: render audit/baseline.md from the captured schema snapshot + real routes.

Nothing here is hand-typed twice: table/column/row data comes from
``audit/schema_snapshot.json`` (produced by ``p0_snapshot.py`` from the live DB), and the
route column is verified against ``backend/apkplat/api/app.py`` — a route named in the
mapping that the code does not define is printed as ``MISSING`` rather than silently
believed.

Usage:
  python scripts/p0_baseline_doc.py
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "backend" / "apkplat" / "api" / "app.py"

# table -> (surface description, [routes that read or write it])
TABLE_SURFACES: dict[str, tuple[str, list[str]]] = {
    "projects": ("project registry; one row per ingested APK", [
        "POST /api/projects", "GET /api/projects", "GET /api/projects/{project_id}",
        "GET /api/projects/{project_id}/board",
    ]),
    "tasks": ("kanban cards, 12-status machine", [
        "POST /api/projects/{project_id}/tasks", "GET /api/projects/{project_id}/tasks",
        "GET /api/tasks/{task_id}", "PATCH /api/tasks/{task_id}",
    ]),
    "artifacts": ("every produced file, content-addressed", [
        "GET /api/projects/{project_id}/artifacts", "GET /api/artifacts/{artifact_id}",
        "GET /api/artifacts/{artifact_id}/text", "GET /api/artifacts/{artifact_id}/download",
    ]),
    "evidence": ("verifiable claims: artifact + locator + verbatim excerpt", [
        "GET /api/projects/{project_id}/evidence", "POST /api/projects/{project_id}/evidence",
        "GET /api/evidence/{evidence_id}",
    ]),
    "audit_events": ("append-only event log (UPDATE/DELETE blocked by triggers)", [
        "GET /api/projects/{project_id}/events", "GET /api/events/stream",
    ]),
    "jobs": ("DB outbox queue: lease, retry, idempotency", [
        "GET /api/queue", "POST /api/jobs/{job_id}/cancel",
    ]),
    "devices": ("dynamic-analysis device pool", [
        "POST /api/devices/register", "GET /api/devices",
    ]),
    "device_leases": ("one live lease per device", [
        "POST /api/projects/{project_id}/devices/lease", "POST /api/leases/{lease_id}/heartbeat",
        "POST /api/leases/{lease_id}/release",
    ]),
    "agent_runs": ("one row per agent role execution", [
        "GET /api/tasks/{task_id}/runs", "GET /api/projects/{project_id}/agent-runs",
    ]),
    "approvals": ("human gate before DONE", [
        "POST /api/approvals/{approval_id}/decide",
    ]),
    "model_requests": ("per-call model telemetry (latency, tokens, status)", []),
    "counters": ("monotonic sequence allocator for audit", []),
    "schema_migrations": ("applied migration files", []),
}


def real_routes() -> set[str]:
    text = APP.read_text(encoding="utf-8")
    routes = set()
    for match in re.finditer(r'@app\.(get|post|patch|put|delete)\("([^"]+)"', text):
        method, path = match.group(1).upper(), match.group(2)
        # FastAPI path params use {name}; normalise to {project_id}-style placeholders.
        path = re.sub(r"\{[^}]+\}", lambda m: "{" + m.group(0)[1:-1] + "}", path)
        routes.add(f"{method} {path}")
    return routes


def normalise(route: str) -> str:
    return re.sub(r"\{[^}]+\}", "{x}", route)


def main() -> int:
    snap_path = ROOT / "audit" / "schema_snapshot.json"
    if not snap_path.exists():
        raise SystemExit(f"missing {snap_path}; run scripts/p0_snapshot.py first")
    snap = json.loads(snap_path.read_text(encoding="utf-8"))
    routes = real_routes()
    known = {normalise(r) for r in routes}

    tables = {t["name"]: t for t in snap["tables"]}
    lines = [
        "# Baseline: what exists today (P0)",
        "",
        f"- captured_at: `{snap['generated_at']}`",
        f"- database: `{snap['db_path']}` (snapshot sha256 `{snap['backup']['sha256'][:16]}...`)",
        f"- migrations applied: {', '.join(snap['migrations'])}",
        f"- tables: {len(snap['tables'])}, triggers: {len(snap['triggers'])}",
        "",
        "This file records the starting point. Nothing in this stage changes the schema: the",
        "taskbook forbids renaming `tasks.status` or collapsing the 12 states before the M1",
        "migration step, and P0 is a read-only inventory.",
        "",
        "## Tables, columns and the API surface that touches them",
        "",
        "| table | rows | columns | API surface |",
        "|---|---|---|---|",
    ]

    for name, table in tables.items():
        cols = ", ".join(c["name"] for c in table["columns"])
        surface, route_list = TABLE_SURFACES.get(name, ("(not mapped)", []))
        verified, missing = [], []
        for route in route_list:
            (verified if normalise(route) in known else missing).append(route)
        route_cell = "<br>".join(f"`{r}`" for r in verified) if verified else "—"
        if missing:
            route_cell += "<br>**MISSING**: " + ", ".join(f"`{r}`" for r in missing)
        lines.append(f"| `{name}` | {table['row_count']} | {len(table['columns'])} | {route_cell} |")

    lines += ["", "### Columns", ""]
    for name, table in tables.items():
        lines.append(f"- `{name}`: " + ", ".join(
            f"`{c['name']}`" + (" (PK)" if c["pk"] else "") for c in table["columns"]))

    lines += ["", "## 12-state task machine (unchanged this stage)", "",
              "| status | kanban column | terminal |", "|---|---|---|"]
    sm = snap["state_machine"]
    for status in sm["statuses"]:
        lines.append(f"| `{status}` | {sm['column_of'][status]} | "
                     f"{'yes' if status in sm['terminal'] else 'no'} |")

    lines += ["", "## Append-only guarantees (database-enforced)", ""]
    for trg in snap["triggers"]:
        lines.append(f"- `{trg['name']}` on `{trg['table']}`")

    lines += ["", "## The single existing project and card", ""]
    lines.append("Row counts at capture: " + ", ".join(
        f"`{t['name']}`={t['row_count']}" for t in snap["tables"] if t["row_count"]))

    lines += ["", "## Row fingerprints (the data-unchanged proof for G0)", "",
              "| table | rows | id_hash |", "|---|---|---|"]
    for name, fp in snap["fingerprints"].items():
        lines.append(f"| `{name}` | {fp['rows']} | `{fp['id_hash']}` |")

    lines += ["", "## Tool chain actually present (project-local, no system install)", "",
              "```", snap["tools_versions"].strip(), "```", "",
              "## ADB", "", "```", snap["adb_devices"].strip() or "(no output)", "```", ""]

    out = ROOT / "audit" / "baseline.md"
    out.write_text("\n".join(lines), encoding="utf-8")

    missing_total = sum(1 for _, (_, rs) in TABLE_SURFACES.items()
                        for r in rs if normalise(r) not in known)
    print(json.dumps({"out": str(out), "tables": len(tables),
                      "routes_in_code": len(routes), "route_mismatches": missing_total}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
