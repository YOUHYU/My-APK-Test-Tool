"""Task state machine (single source of truth for legal transitions).

Kanban columns are a *projection* of the state machine; cards never move because
a UI said so. Every transition is validated here, then written with optimistic
concurrency (expected_version) and an append-only audit event.
"""
from __future__ import annotations

KANBAN_COLUMNS = ("TODO", "RUNNING", "REVIEW", "DONE")

STATUSES = (
    "TODO",
    "RUNNING",
    "REVIEW",
    "DONE",
    "WAITING_MODEL",
    "WAITING_DEVICE",
    "WAITING_APPROVAL",
    "BLOCKED",
    "FAILED",
    "CANCELLED",
    "RETRYING",
    "STALE",
)

TERMINAL = {"DONE", "CANCELLED"}

#: status -> kanban column shown in the board
COLUMN_OF = {
    "TODO": "TODO",
    "RETRYING": "TODO",
    "STALE": "TODO",
    "RUNNING": "RUNNING",
    "RETRYING_RUNNING": "RUNNING",
    "WAITING_MODEL": "RUNNING",
    "WAITING_DEVICE": "RUNNING",
    "WAITING_APPROVAL": "RUNNING",
    "BLOCKED": "RUNNING",
    "REVIEW": "REVIEW",
    "DONE": "DONE",
    "FAILED": "REVIEW",
    "CANCELLED": "DONE",
}

TRANSITIONS: dict[str, set[str]] = {
    "TODO": {"RUNNING", "CANCELLED", "BLOCKED", "WAITING_APPROVAL"},
    "RUNNING": {
        "REVIEW",
        "DONE",
        "FAILED",
        "BLOCKED",
        "CANCELLED",
        "RETRYING",
        "STALE",
        "WAITING_MODEL",
        "WAITING_DEVICE",
        "WAITING_APPROVAL",
    },
    "WAITING_MODEL": {"RUNNING", "TODO", "BLOCKED", "CANCELLED", "FAILED"},
    "WAITING_DEVICE": {"RUNNING", "TODO", "BLOCKED", "CANCELLED", "FAILED"},
    "WAITING_APPROVAL": {"RUNNING", "TODO", "BLOCKED", "CANCELLED"},
    "RETRYING": {"RUNNING", "FAILED", "CANCELLED"},
    "STALE": {"RUNNING", "TODO", "FAILED", "CANCELLED"},
    "BLOCKED": {"TODO", "RUNNING", "CANCELLED", "FAILED"},
    "FAILED": {"RETRYING", "TODO", "CANCELLED", "BLOCKED"},
    "REVIEW": {"DONE", "RUNNING", "BLOCKED", "FAILED", "CANCELLED"},
    "DONE": set(),
    "CANCELLED": set(),
}

#: actors allowed to perform a transition to the given status
GUARDED_TARGETS = {
    "DONE": {"human", "reviewer"},
    "CANCELLED": {"human", "reviewer"},
    "BLOCKED": {"human", "reviewer", "agent", "system"},
}

#: statuses an approval may unlock for a non-privileged actor. Approval buys the
#: closing move of a *reviewed* task, never the right to skip review entirely.
APPROVABLE_FROM = {"REVIEW"}


class TransitionError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def validate_transition(
    current: str,
    target: str,
    actor: str = "agent",
    approved: bool = False,
) -> None:
    if current not in STATUSES:
        raise TransitionError("unknown_status", f"unknown current status {current!r}")
    if target not in STATUSES:
        raise TransitionError("unknown_status", f"unknown target status {target!r}")
    if target == current:
        return
    allowed = TRANSITIONS.get(current, set())
    if target not in allowed:
        raise TransitionError(
            "illegal_transition", f"{current} -> {target} is not allowed (allowed: {sorted(allowed)})"
        )
    guards = GUARDED_TARGETS.get(target)
    if guards and actor not in guards:
        if approved and current in APPROVABLE_FROM:
            return
        raise TransitionError(
            "approval_required",
            f"actor {actor!r} may not move a task to {target} without human approval"
            + ("" if current in APPROVABLE_FROM else f" (only from {sorted(APPROVABLE_FROM)})"),
        )


def column_of(status: str) -> str:
    return COLUMN_OF.get(status, "TODO")
