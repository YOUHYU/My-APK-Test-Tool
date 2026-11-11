"""Seed an isolated demo project with 21 cards that mirror the reference screenshot's taxonomy.

The cards are *synthetic* - they exist as UI regression data in their own project, and the
taskbook is explicit that they are not production history. Every state change here goes through
the real services (transitions, DAG edges, review checks, approvals, events), so the board, the
audit trail and the report all read the same facts a real run would write.

Usage:
    .venv/Scripts/python.exe scripts/p7_seed.py --name "截图复刻演示（合成数据）"
    .venv/Scripts/python.exe scripts/p7_seed.py --clean   # remove the demo project(s) first
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

DEMO_MARKER = "synthetic-demo"

#: (key, title, role, goal, parents, outcome) - outcome: done | review | running | todo
CARDS: list[tuple[str, str, str, str, list[str], str]] = [
    ("scope", "S0 界定本次评估范围", "plan", "确定这个样本能回答什么、不能回答什么。", [], "done"),
    ("inventory", "S0 APK 静态清点", "exec", "枚举类、方法、资源与原生库。", ["scope"], "done"),
    ("signature", "S1 签名与证书", "exec", "记录全部签名方案与证书摘要。", ["inventory"], "done"),
    ("dex", "S1 DEX 清点", "exec", "按 DEX 统计类、方法、字符串数量。", ["inventory"], "done"),
    ("native", "S1 原生库甄别", "exec", "列出 SO 文件及其大小与架构。", ["dex"], "done"),
    ("protection", "S1 加固特征指纹", "exec", "查找壳、反调试与字符串混淆痕迹。", ["dex"], "done"),
    ("resources", "S0 资源映射", "exec", "索引字符串、布局与资产。", ["inventory"], "done"),
    ("secrets", "S2 密钥扫描", "exec", "定位形似凭据的字面量及其 文件:行号。", ["resources"], "done"),
    ("endpoints", "S2 端点梳理", "exec", "汇总代码中出现的全部网络端点。", ["resources"], "done"),
    ("protocol", "S2 登录协议形态", "exec", "描述授权接口的请求/响应结构。", ["endpoints"], "running"),
    ("harness", "S2 签名复现脚手架", "exec", "重新实现令牌推导并与应用对比。", ["protocol"], "todo"),
    ("script", "S3 单文件脚本", "ship", "产出自包含脚本，含启动自检。", ["harness"], "todo"),
    ("selfcheck", "S3 自检运行", "exec", "在本机运行脚本自带的自检。", ["script"], "todo"),
    ("device", "S4 设备身份链", "exec", "任何操作前先观测测试机属性。", ["signature"], "review"),
    ("uia", "S4 界面会话", "exec", "驱动授权界面并抓取前后状态。", ["device"], "todo"),
    ("capture", "S4 抓包关联", "evidence", "把 HAR 流量与界面实际发起的调用对应起来。", ["uia"], "todo"),
    ("consolidate", "S5 证据合并", "evidence", "让每条断言都挂到可核验的产物上。", ["secrets", "capture"], "todo"),
    ("review", "S5 独立审查", "review", "不信任作者，逐条复核断言。", ["consolidate"], "todo"),
    ("report", "S7 报告草稿", "report", "汇总时间线、证据链与结论。", ["review"], "todo"),
    ("ship", "S6 三日窗口", "exec", "在保留会话的前提下跑每日窗口。", ["selfcheck"], "todo"),
    ("brief", "S7 运营简报", "ship", "一页纸：证明了什么、没证明什么、下一步做什么。", ["report"], "todo"),
]

STATUS_CHAIN = ("TODO", "RUNNING", "REVIEW")


def _approve_done(task_id: str, project_id: str) -> None:
    from apkplat.services import tasks as tasks_service

    approval_id = tasks_service.request_approval(
        project_id, task_id=task_id, kind="task_done", requested_by="p7-seed", reason="demo card"
    )
    tasks_service.decide_approval(approval_id, "approved", decided_by="human")
    tasks_service.update(task_id, actor="human", status="DONE", approval_id=approval_id, reason="demo completion")


def _walk_to(task_id: str, project_id: str, target: str) -> None:
    from apkplat.services import tasks as tasks_service

    current = tasks_service.get(task_id)["status"]
    if current == target:
        return
    if target == "DONE":
        for step in ("RUNNING", "REVIEW"):
            if tasks_service.get(task_id)["status"] != step:
                tasks_service.update(task_id, actor="agent", status=step, reason="demo")
        _approve_done(task_id, project_id)
        return
    for step in STATUS_CHAIN[STATUS_CHAIN.index(current) + 1 : STATUS_CHAIN.index(target) + 1]:
        tasks_service.update(task_id, actor="agent", status=step, reason="demo")


def _clean(projects_service) -> int:
    removed = 0
    for row in projects_service.list_projects(limit=200):
        if row["name"].startswith(("Screenshot demo", "截图复刻演示")) or row.get("goal") == DEMO_MARKER:
            projects_service.delete(row["id"], actor="p7-seed") if hasattr(projects_service, "delete") else None
            removed += 1
    return removed


def seed(project_name: str = "截图复刻演示（合成数据）", *, apk: Path | None = None) -> dict[str, Any]:
    """Create the demo project and its 21 cards. Idempotent per project name."""
    from apkplat.services import dag as dag_service
    from apkplat.services import events as events_service
    from apkplat.services import projects as projects_service
    from apkplat.services import review as review_service
    from apkplat.services import tasks as tasks_service

    apk = apk or ROOT / "samples" / "sample-app.apk"
    existing = [row for row in projects_service.list_projects(limit=200) if row["name"] == project_name]
    if existing:
        project_id = existing[0]["id"]
        cards = tasks_service.list_tasks(project_id)
        if len(cards) >= len(CARDS):
            return {"project_id": project_id, "created": False, "cards": len(cards)}
    else:
        project = projects_service.create(
            name=project_name, apk_source=apk, filename=apk.name, goal=DEMO_MARKER, actor="p7-seed"
        )
        project_id = project["id"]

    made: dict[str, str] = {}
    for key, title, role, goal, parents, outcome in CARDS:
        task = tasks_service.create(
            project_id,
            role=role,
            title=title,
            goal=goal,
            depends_on=[made[parent] for parent in parents if parent in made] or None,
            actor="p7-seed",
            status="TODO",
        )
        made[key] = task["id"]
        for parent in parents:
            dag_service.add_edge(project_id, made[parent], task["id"], "blocks", "p7-seed")
        if outcome in ("running", "review"):
            _walk_to(task["id"], project_id, outcome.upper())
        elif outcome == "done":
            _walk_to(task["id"], project_id, "DONE")
            review_service.record_check(
                project_id,
                task["id"],
                verdict="PASS",
                criterion=f"{title}：已产出承诺的产物",
                detail={"seeded": True},
                actor="p7-seed",
            )

    events_service.emit("note", project_id=project_id, payload={"seeded_cards": len(CARDS), "marker": DEMO_MARKER})
    cards = tasks_service.list_tasks(project_id)
    return {
        "project_id": project_id,
        "created": True,
        "cards": len(cards),
        "by_status": {status: sum(1 for c in cards if c["status"] == status) for status in sorted({c["status"] for c in cards})},
        "ready": [c["title"] for c in cards if dag_service.ready(c["id"])],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="seed the 21-card synthetic demo project")
    parser.add_argument("--name", default="截图复刻演示（合成数据）")
    parser.add_argument("--apk", default=None)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    from apkplat.db import db

    db.migrate()
    result = seed(args.name, apk=Path(args.apk) if args.apk else None)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"project {result['project_id']} cards={result['cards']} created={result['created']}")
        for status, count in result["by_status"].items():
            print(f"  {status}: {count}")
        print(f"  ready now: {len(result['ready'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
