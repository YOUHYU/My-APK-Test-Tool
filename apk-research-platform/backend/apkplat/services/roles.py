"""Role registry (P2).

The taskbook is explicit that permissions must be enforced by the backend, not by what an
agent says it is. The registry is the single place a role's tool surface, budgets and
review requirement live; capabilities are issued from it, so a policy change is a row update
plus a `policy_version` bump that lands in every run's audit.

Seeded from ``services.capabilities.ROLE_TEMPLATES`` so P1 keeps working unchanged.
"""

from __future__ import annotations

from typing import Any, Iterable

from ..db import db, utcnow
from ..util import dumps, loads
from .capabilities import DEFAULT_BUDGET, ROLE_ALIASES, ROLE_TEMPLATES, CapabilityError, canonical_role
from .review import ReviewError

DEFAULT_RETRY_LIMIT = 2


def seed(actor: str = "system") -> int:
    """Idempotently write the built-in roles. Returns how many rows were inserted/updated."""
    written = 0
    now = utcnow()
    for role_id, tool_set in ROLE_TEMPLATES.items():
        tools = sorted(tool_set)
        existing = db.one("SELECT * FROM role_registry WHERE role_id = ?", (role_id,))
        payload = (
            role_id,
            _title(role_id),
            dumps(tools),
            int(DEFAULT_BUDGET["max_model_calls"]),
            int(DEFAULT_BUDGET["max_tool_calls"]),
            "required",
            "human" if role_id == "review" else "none",
            "light",
            DEFAULT_RETRY_LIMIT,
            "v1",
            now,
        )
        with db.tx():
            if existing:
                db.execute(
                    "UPDATE role_registry SET title=?, allowed_tools_json=?, max_model_calls=?, max_tool_calls=?,"
                    " review_requirement=?, approval_class=?, resource_class=?, retry_limit=?,"
                    " instructions_version=?, updated_at=? WHERE role_id=?",
                    (payload[1], payload[2], payload[3], payload[4], payload[5], payload[6], payload[7], payload[8], payload[9], payload[10], role_id),
                )
            else:
                db.execute(
                    "INSERT INTO role_registry (role_id, title, allowed_tools_json, max_model_calls, max_tool_calls,"
                    " review_requirement, approval_class, resource_class, retry_limit, instructions_version, updated_at)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    payload,
                )
        written += 1
    return written


def _title(role_id: str) -> str:
    return {
        "plan": "Planner",
        "exec": "Executor",
        "review": "Reviewer",
        "ship": "Release engineer",
        "evidence": "Evidence clerk",
        "report": "Reporter",
    }.get(role_id, role_id.title())


def get(role_id: str) -> dict[str, Any] | None:
    row = db.one("SELECT * FROM role_registry WHERE role_id = ?", (canonical_role(role_id),))
    if row is None:
        return None
    return _to_dict(row)


def _to_dict(row) -> dict[str, Any]:
    return {
        "role_id": row["role_id"],
        "title": row["title"],
        "allowed_tools": loads(row["allowed_tools_json"], []),
        "max_model_calls": int(row["max_model_calls"]),
        "max_tool_calls": int(row["max_tool_calls"]),
        "review_requirement": row["review_requirement"],
        "approval_class": row["approval_class"],
        "resource_class": row["resource_class"],
        "retry_limit": int(row["retry_limit"]),
        "instructions_version": row["instructions_version"],
        "updated_at": row["updated_at"],
    }


def listing() -> list[dict[str, Any]]:
    return [_to_dict(row) for row in db.query("SELECT * FROM role_registry ORDER BY role_id")]


def retry_limit(role_id: str) -> int:
    role = get(role_id)
    return int(role["retry_limit"]) if role else DEFAULT_RETRY_LIMIT


def budget(role_id: str) -> dict[str, int]:
    role = get(role_id)
    if not role:
        return {"max_model_calls": 8, "max_tool_calls": 24}
    return {"max_model_calls": role["max_model_calls"], "max_tool_calls": role["max_tool_calls"]}


def tools(role_id: str) -> list[str]:
    role = get(role_id)
    return list(role["allowed_tools"]) if role else []


def update(role_id: str, *, fields: dict[str, Any], actor: str = "operator") -> dict[str, Any]:
    try:
        role = get(role_id)
    except CapabilityError as exc:  # unknown role: surface it the way the API expects (404)
        raise KeyError(role_id) from exc
    if role is None:
        raise KeyError(role_id)
    allowed = {"title", "max_model_calls", "max_tool_calls", "review_requirement", "approval_class", "resource_class", "retry_limit", "instructions_version", "allowed_tools"}
    sets: list[str] = []
    params: list[Any] = []
    for key, value in fields.items():
        if key not in allowed:
            raise ReviewError("field_not_editable", f"field {key!r} is not editable", 422)
        if key == "allowed_tools":
            sets.append("allowed_tools_json = ?")
            params.append(dumps(list(value)))
        else:
            sets.append(f"{key} = ?")
            params.append(value)
    if not sets:
        return role
    sets.append("updated_at = ?")
    params.append(utcnow())
    params.append(canonical_role(role_id))
    with db.tx():
        db.execute(f"UPDATE role_registry SET {', '.join(sets)} WHERE role_id = ?", params)
    return get(role_id) or role


def aliases() -> Iterable[tuple[str, str]]:
    return ROLE_ALIASES.items()


def coverage() -> dict[str, Any]:
    """Which role may use which tool - the matrix the dashboard shows."""
    matrix: dict[str, list[str]] = {}
    for role in listing():
        matrix[role["role_id"]] = role["allowed_tools"]
    return {"roles": matrix, "retry_limits": {role["role_id"]: role["retry_limit"] for role in listing()}}
