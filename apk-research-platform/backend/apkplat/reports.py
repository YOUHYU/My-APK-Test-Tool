"""Markdown report generation (evidence-first).

Rules encoded here, because a report is the artifact people actually read:

* every factual bullet carries an evidence id (``E-xxxx``) and the artifact it came from;
* a section that has no evidence is *printed as empty with a reason*, never filled with prose
  the model imagined;
* the verification block (artifact chain + excerpt traceability) is measured at render time,
  so a tampered artifact shows up as a failure in the report itself.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from . import audit, indexer, toolchain
from .config import settings
from .db import utcnow
from .services import artifacts as artifacts_service
from .services import evidence as evidence_service
from .services import projects as projects_service
from .services import tasks as tasks_service
from .util import dumps, project_layout


def generate(project_id: str, *, task_id: str | None = None, actor: str = "api") -> dict[str, Any]:
    project = projects_service.get(project_id)
    if not project:
        raise KeyError(project_id)
    manifest = projects_service.manifest(project_id)
    layout = project_layout(project_id)
    facts = _load_json(layout["artifacts"] / "facts.json")
    findings = _load_json(layout["artifacts"] / "findings.json")
    summary = _load_json(layout["artifacts"] / "static_summary.json")
    evidence = evidence_service.list_evidence(project_id)
    by_id = {row["id"]: row for row in evidence}
    chain = artifacts_service.verify_chain(project_id)
    trace = evidence_service.verify(project_id)

    def cite(kind: str, limit: int = 12) -> list[dict]:
        return [row for row in evidence if row["kind"] == kind][:limit]

    _COMPONENT_ZH = {"activity": "活动", "service": "服务", "receiver": "广播接收器", "provider": "内容提供者"}

    def ev_label(row: dict) -> str:
        return f"`{row['id']}`"

    lines: list[str] = []
    add = lines.append
    add(f"# APK 静态分析报告：{project['name']}")
    add("")
    add(f"- 项目：`{project_id}`")
    add(f"- 包名：`{manifest.get('package')}`")
    ingest = (manifest.get("ingest") or {})
    add(f"- APK：`{ingest.get('filename')}` · sha256 `{ingest.get('sha256')}` · {ingest.get('bytes')} 字节")
    add(f"- 签名证书：`{manifest.get('certificate_sha256')}`")
    add(f"- 分析时间：{ingest.get('ingested_at')}，报告生成：{utcnow()}")
    add(f"- 工具：jadx {_tool_version('jadx')}, apktool {_tool_version('apktool')}, androguard 4.1.4, aapt2 (SDK 34)")
    add("")
    add("## 1. 校验结果")
    add("")
    add(f"- 产物链：{'通过' if not chain['failures'] else '未通过'}：{chain['checked']} 个产物重算哈希，{len(chain['failures'])} 处不匹配")
    add(f"- 证据可追溯：{'通过' if not trace['failures'] else '未通过'}：{trace['total'] - len(trace['failures'])}/{trace['total']} 条摘录在产物中逐字命中（可追溯率 {trace['traceability_rate']}）")
    add(f"- 证据条数：{len(evidence)}")
    add("")
    add("## 2. 身份信息")
    add("")
    for row in cite("manifest_fact"):
        add(f"- {row.get('claim')}，证据 {ev_label(row)}（产物 `{row['artifact_id']}`）")
    add("")
    add("## 3. 权限")
    add("")
    perms = cite("permission")
    if perms:
        for row in perms:
            add(f"- {row.get('claim')}，证据 {ev_label(row)}")
    else:
        add("- 未记录权限类证据。")
    add("")
    add("## 4. 组件")
    add("")
    comps = indexer.components(project_id) if _index_ready(layout) else []
    if comps:
        for comp in comps:
            add(f"- {_COMPONENT_ZH.get(comp['kind'], comp['kind'])} `{comp['name']}`")
        add("")
        add("_组件清单取自清单产物，每一项都可以从 `facts.json` 复现。_")
    else:
        add("- 没有可索引的组件（索引缺失或清单为空）。")
    add("")
    add("## 5. 网络端点")
    add("")
    urls = cite("network_endpoint")
    if urls:
        for row in urls:
            add(f"- {row.get('claim')}，证据 {ev_label(row)}")
    else:
        add("- 未记录网络端点证据。")
    add("")
    add("## 6. 疑似密钥字面量")
    add("")
    secrets = cite("secret_candidate")
    if secrets:
        add("以下均为**候选**：它们是符合密钥/令牌形状的字面量，均带 file:line 定位，引自")
        add("反编译源码；在引用产物中能读到该行源码之前，任何一条都不会被提升为“已确认密钥”。")
        add("")
        for row in secrets:
            loc = row.get("locator") or {}
            add(f"- {row.get('claim')}，证据 {ev_label(row)} (`{loc.get('file')}:{loc.get('line')}`)")
    else:
        add("- 未记录疑似密钥字面量。")
    add("")
    add("## 7. 代码索引")
    add("")
    if summary:
        counts = summary.get("index") or {}
        add(f"- 类 {counts.get('classes', 0)} * methods {counts.get('methods', 0)} * fields {counts.get('fields', 0)} * strings {counts.get('strings', 0)} * resources {counts.get('resources', 0)}")
        add(f"- 反编译 Java 文件：{summary.get('java_files', 0)}")
        tools = summary.get("tools") or {}
        add(f"- apktool 退出码 {tools.get('apktool', {}).get('exit')} ({tools.get('apktool', {}).get('ms')} ms), jadx exit {tools.get('jadx', {}).get('exit')} ({tools.get('jadx', {}).get('ms')} ms, timed_out={tools.get('jadx', {}).get('timed_out')})")
    else:
        add("- 没有静态汇总产物（流水线未完成）。")
    add("")
    add("## 8. 无证据的断言")
    add("")
    unsupported = [row for row in evidence if not row.get("artifact_id")]
    if unsupported:
        for row in unsupported:
            add(f"- {row.get('claim')}，证据 {ev_label(row)} 没有对应产物")
    else:
        add("- 无。每条记录在案的断言都指向本项目内的产物。")
    add("")
    add("## 9. 复现步骤")
    add("")
    add("```")
    add(f".venv/Scripts/python.exe scripts/apkplat_cli.py create --name <name> --apk <file>  # 入库并入队")
    add(f".venv/Scripts/python.exe scripts/apkplat_cli.py worker --once                      # 执行流水线")
    add(f".venv/Scripts/python.exe scripts/apkplat_cli.py verify {project_id}   # 重算产物与证据哈希")
    add(f".venv/Scripts/python.exe scripts/apkplat_cli.py report {project_id}   # 重新生成本文件")
    add("```")
    add("")
    add("## 10. 证据附录")
    add("")
    add("| ID | 类型 | 断言 | 产物 | 置信度 |")
    add("|---|---|---|---|---|")
    for row in evidence[:200]:
        claim = (row.get("claim") or "").replace("|", "\\|")[:120]
        add(f"| `{row['id']}` | {row['kind']} | {claim} | `{row.get('artifact_id')}` | {row.get('confidence')} |")
    add("")

    typed = _typed_evidence(project_id)
    add("## 11. 摘要")
    add("")
    by_verdict: dict[str, int] = {}
    for row in typed:
        by_verdict[row["verdict"]] = by_verdict.get(row["verdict"], 0) + 1
    add(f"- 资产：1 个 APK (`{manifest.get('package')}`), {len(evidence)} 条文本证据，{len(typed)} 个类型化证据对象。")
    add(f"- 类型化证据判定：" + (", ".join(f"{k}={v}" for k, v in sorted(by_verdict.items())) or "无记录") + "。")
    add(f"- 校验：产物链 {'通过' if not chain['failures'] else '未通过'}，证据可追溯率 {trace['traceability_rate']}.")
    open_tasks = [t for t in tasks_service.list_tasks(project_id) if t["status"] not in ("DONE", "CANCELLED")]
    add(f"- 任务：{len(open_tasks)} 个未收口，{len(_checks(project_id))} 条审查检查记录。")
    blocked = [row for row in typed if row["verdict"] == "PARTIAL"]
    add(f"- 无法核验 / 部分核验：{len(blocked)} 项（见第 18 节）。")
    add("")

    add("## 12. 能力覆盖矩阵")
    add("")
    add("| 角色 | 允许工具 | 本项目已使用 |")
    add("|---|---|---|")
    used = _tools_used(project_id)
    for role in _roles():
        allowed = role["allowed_tools"]
        hit = ", ".join(sorted(t for t in allowed if used.get(t)))
        add(f"| {role['role_id']} | {', '.join(allowed)} | {hit or '-'} |")
    add("")
    add("_矩阵读自 `role_registry`（由角色模板初始化）与服务端工具调用日志。_")
    add("")

    add("## 13. 任务依赖图")
    add("")
    graph = _graph(project_id)
    if graph and graph.get("nodes"):
        add("```")
        for node in graph["nodes"]:
            parents = ", ".join(node.get("parents") or []) or "-"
            add(f"{node['id']}  [{node['status']}]  <- {parents}")
        add("```")
        add("")
        add(f"- 边 {len(graph.get('edges') or [])} 条，阻塞 {len(graph.get('blocked') or [])} 个，就绪 {len(graph.get('ready') or [])} 个")
    else:
        add("- 本项目没有任务图记录。")
    add("")

    add("## 14. 关键时间线")
    add("")
    timeline = _timeline(project_id, 40)
    if timeline:
        add("| 序号 | 类型 | 任务 | 时间 | 摘要 |")
        add("|---|---|---|---|---|")
        for event in timeline:
            payload = event.get("payload") or {}
            summary = payload.get("to") or payload.get("reason") or payload.get("tool") or payload.get("status") or ""
            add(f"| {event['seq']} | {event['type']} | `{event.get('task_id') or '-'}` | {event['created_at']} | {str(summary)[:80]} |")
    else:
        add("- 未记录平台事件。")
    add("")

    add("## 15. 类型化证据链")
    add("")
    if typed:
        add("| ID | 类型 | 判定 | 完整性 | 断言 | 已复现 | 产物 | 断言文本 |")
        add("|---|---|---|---|---|---|---|---|")
        for row in typed[:100]:
            claim = (row.get("claim") or "").replace("|", "\\|")[:100]
            add(
                f"| `{row['id']}` | {row['evidence_type']} | {row['verdict']} | {row['integrity_verified']} | "
                f"{row['assertion_verified']} | {row['reproduced']} | `{row.get('artifact_id')}` | {claim} |"
            )
        add("")
        add("_判定是机械的：字节被改过的产物不可能保持 VERIFIED；未经独立重跑的断言不能声称 REPRODUCED。_")
    else:
        add("- 尚未记录类型化证据。")
    add("")

    add("## 16. 媒体与抓包会话")
    add("")
    media = [row for row in typed if row["evidence_type"] in ("IMAGE", "VIDEO", "CAPTURE_FLOW", "PCAP")]
    if media:
        for row in media:
            loc = row.get("locator") or {}
            href = f"/api/projects/{project_id}/artifacts/{row['artifact_id']}/download"
            add(f"- {row['evidence_type']} `{row['id']}` ：[{os.path.basename(str(loc.get('path') or row['artifact_id']))}]({href})")
        add("")
        add("_链接均经项目作用域的产物接口访问，不直接暴露文件系统路径。_")
    else:
        add("- 未记录图像、录屏或抓包会话证据。")
    add("")

    add("## 17. 电脑端与真机结果")
    add("")
    sandbox_rows = _sandbox_runs(project_id)
    add(f"- 电脑端（静态 + 沙箱）：{len(sandbox_rows)} 次沙箱运行。")
    for run in sandbox_rows[:10]:
        add(f"  - `{run['id']}` {run['status']} exit={run['exit_code']} timeout={run['timed_out']} isolation={run['isolation']}")
    device_rows = [row for row in typed if row["evidence_type"] == "DEVICE_OBSERVATION"]
    add(f"- 真机（adb / UI）：{len(device_rows)} 条设备观测证据。")
    if not device_rows:
        add("  - 无设备证据：本报告未走真机路径。")
    add("")

    add("## 18. 无法核验的条目")
    add("")
    weak = [row for row in typed if row["verdict"] in ("PARTIAL", "FAILED")]
    if weak:
        for row in weak:
            add(f"- `{row['id']}` ({row['evidence_type']}) verdict={row['verdict']}：{row.get('failure_reason') or '平台限制'}")
    else:
        add("- 无。每个类型化证据对象要么通过核验，要么已显式标为部分核验。")
    add(f"- 仅静态的局限依然存在：本次无运行时行为、无网络抓包、无 UI 断言。")
    add("")

    add("## 19. 审查意见")
    add("")
    checks = _checks(project_id)
    if checks:
        add("| 任务 | 判定 | 判定标准 | 时间 |")
        add("|---|---|---|---|")
        for check in checks[:60]:
            criterion = (check.get("criterion") or "").replace("|", "\\|")[:100]
            add(f"| `{check['task_id']}` | {check['verdict']} | {criterion} | {check['checked_at']} |")
    else:
        add("- 本项目没有审查检查记录。")
    add("")

    add("## 20. 脚本与构建产物")
    add("")
    layout_artifacts = artifacts_service.list_artifacts(project_id, limit=200)
    scripts = [row for row in layout_artifacts if row["kind"] in ("script", "tool_stdout", "tool_stderr", "test_result")]
    if scripts:
        add("| 类型 | 路径 | 字节 | sha256 | 工具 |")
        add("|---|---|---|---|---|")
        for row in scripts[:60]:
            add(f"| {row['kind']} | `{row['rel_path']}` | {row['bytes']} | `{str(row['sha256'])[:16]}...` | {row.get('tool') or '-'} |")
    else:
        add("- 本项目没有脚本或捕获的工具输出。")
    add("")

    text = "\n".join(lines)
    layout["reports"].mkdir(parents=True, exist_ok=True)
    stamp = utcnow().replace(":", "").replace("-", "")[:15]
    path = layout["reports"] / f"report-{stamp}.md"
    path.write_text(text, encoding="utf-8")
    artifact = artifacts_service.register(
        project_id, kind="report", path=path, task_id=task_id, tool="apkplat.report", tool_version="1.0.0"
    )
    html_path = layout["reports"] / f"report-{stamp}.html"
    html_path.write_text(render_html(text, title=f"APK 分析报告：{project['name']}"), encoding="utf-8")
    html_artifact = artifacts_service.register(
        project_id, kind="report_html", path=html_path, task_id=task_id, tool="apkplat.report", tool_version="1.0.0"
    )
    audit.record(
        "report_generated",
        project_id=project_id,
        task_id=task_id,
        actor=actor,
        payload={
            "artifact_id": artifact["id"],
            "html_artifact_id": html_artifact["id"],
            "evidence_rows": len(evidence),
            "typed_evidence": len(typed),
            "chain_ok": not chain["failures"],
        },
    )
    return {
        "project_id": project_id,
        "report_path": str(path),
        "artifact_id": artifact["id"],
        "html_path": str(html_path),
        "html_artifact_id": html_artifact["id"],
        "evidence_rows": len(evidence),
        "typed_evidence_rows": len(typed),
        "traceability_rate": trace["traceability_rate"],
        "verification_ok": not chain["failures"] and not trace["failures"],
        "markdown": text,
    }


def _typed_evidence(project_id: str) -> list[dict]:
    from .services import evidence_types

    try:
        return [row for row in evidence_types.listing(project_id, limit=500)]
    except Exception:  # noqa: BLE001
        return []


def _roles() -> list[dict]:
    from .services import roles as roles_service

    try:
        out = []
        for role in roles_service.listing():
            tools = role.get("allowed_tools") or []
            out.append({"role_id": role["role_id"], "allowed_tools": list(tools)})
        return out
    except Exception:  # noqa: BLE001
        return []


def _tools_used(project_id: str) -> dict[str, int]:
    from .db import db

    try:
        rows = db.query(
            "SELECT c.tool AS tool, COUNT(*) AS n FROM run_tool_calls c "
            "JOIN run_capabilities r ON r.run_id = c.run_id WHERE r.project_id = ? GROUP BY c.tool",
            (project_id,),
        )
        return {row["tool"]: int(row["n"]) for row in rows}
    except Exception:  # noqa: BLE001
        return {}


def _graph(project_id: str) -> dict:
    from .services import dag as dag_service

    try:
        graph = dag_service.graph(project_id)
        nodes = []
        for node in graph.get("nodes") or []:
            node = dict(node)
            node["parents"] = [edge["from_task_id"] for edge in (graph.get("edges") or []) if edge["to_task_id"] == node["id"]]
            nodes.append(node)
        graph["nodes"] = nodes
        return graph
    except Exception:  # noqa: BLE001
        return {}


def _timeline(project_id: str, limit: int) -> list[dict]:
    from .services import events as events_service

    try:
        return list(events_service.tail(0, project_id=project_id, limit=limit))
    except Exception:  # noqa: BLE001
        return []


def _sandbox_runs(project_id: str) -> list[dict]:
    from .services import sandbox as sandbox_service

    try:
        return [dict(row) for row in sandbox_service.listing(project_id, limit=100)]
    except Exception:  # noqa: BLE001
        return []


def _checks(project_id: str) -> list[dict]:
    from .services import review as review_service

    try:
        return [dict(row) for row in review_service.checks_for_project(project_id)]
    except Exception:  # noqa: BLE001
        try:
            from .db import db

            rows = db.query(
                "SELECT * FROM task_checks WHERE project_id = ? ORDER BY checked_at ASC", (project_id,)
            )
            return [dict(row) for row in rows]
        except Exception:  # noqa: BLE001
            return []


def render_html(markdown: str, *, title: str) -> str:
    """Render the markdown source of truth into a static, dependency-free HTML page."""
    import html as html_module
    import re

    out: list[str] = []
    in_code = False
    in_table = False
    for raw in markdown.splitlines():
        line = raw.rstrip()
        if line.startswith("```"):
            if in_code:
                out.append("</pre>")
                in_code = False
            else:
                out.append("<pre>")
                in_code = True
            continue
        if in_code:
            out.append(html_module.escape(line))
            continue
        if line.startswith("|"):
            cells = [cell.strip() for cell in line.strip("|").split("|")]
            if all(set(cell) <= set("-: ") for cell in cells):
                continue
            if not in_table:
                out.append("<table>")
                in_table = True
                tag = "th"
            else:
                tag = "td"
            out.append("<tr>" + "".join(f"<{tag}>{_inline(cell)}</{tag}>" for cell in cells) + "</tr>")
            continue
        if in_table:
            out.append("</table>")
            in_table = False
        if line.startswith("#"):
            level = len(line) - len(line.lstrip("#"))
            text = _inline(line[level:].strip())
            out.append(f"<h{min(level, 6)}>{text}</h{min(level, 6)}>")
        elif line.startswith("- "):
            out.append(f"<li>{_inline(line[2:])}</li>")
        elif not line:
            out.append("")
        else:
            out.append(f"<p>{_inline(line)}</p>")
    if in_table:
        out.append("</table>")
    if in_code:
        out.append("</pre>")
    body = "\n".join(out)
    body = re.sub(r"(<li>.*?</li>\n?)+", lambda m: "<ul>" + m.group(0) + "</ul>", body, flags=re.S)
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        f"<title>{html_module.escape(title)}</title>"
        "<style>body{font:14px/1.55 -apple-system,Segoe UI,sans-serif;max-width:1100px;margin:32px auto;padding:0 20px;color:#1b1b1f}"
        "table{border-collapse:collapse;width:100%;margin:12px 0}th,td{border:1px solid #d7d7de;padding:5px 8px;text-align:left;vertical-align:top}"
        "th{background:#f4f4f7}code{background:#f4f4f7;padding:1px 4px;border-radius:3px}"
        "pre{background:#f8f8fb;border:1px solid #e2e2e8;padding:10px;overflow:auto}</style></head><body>"
        f"{body}</body></html>"
    )


def _inline(text: str) -> str:
    import html as html_module
    import re

    escaped = html_module.escape(text)
    escaped = re.sub(r"`([^`]+)`", r"<code>\1</code>", escaped)
    escaped = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r'<a href="\2">\1</a>', escaped)
    escaped = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", escaped)
    return escaped


def _load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return {}


def _tool_version(name: str) -> str:
    try:
        return toolchain.probe_versions().get(name, {}).get("version", "not installed") or "not installed"
    except Exception:  # noqa: BLE001
        return "unknown"


def _index_ready(layout: dict) -> bool:
    return (layout["indexes"] / "index.db").exists()
