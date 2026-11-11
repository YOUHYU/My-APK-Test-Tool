"""State machine: the board is a projection, the transition table is the law."""
from __future__ import annotations

import pytest

from apkplat.state import STATUSES, TERMINAL, TransitionError, column_of, validate_transition


@pytest.mark.parametrize(
    "current,target,actor",
    [
        ("TODO", "RUNNING", "agent"),
        ("RUNNING", "REVIEW", "agent"),
        ("REVIEW", "DONE", "reviewer"),
        ("REVIEW", "DONE", "human"),
        ("RUNNING", "WAITING_DEVICE", "agent"),
        ("WAITING_DEVICE", "RUNNING", "agent"),
        ("RUNNING", "STALE", "system"),
        ("FAILED", "RETRYING", "system"),
        ("BLOCKED", "TODO", "agent"),
    ],
)
def test_legal_transitions(current, target, actor):
    validate_transition(current, target, actor=actor)


@pytest.mark.parametrize(
    "current,target",
    [
        ("TODO", "DONE"),  # cannot skip work
        ("TODO", "REVIEW"),
        ("DONE", "RUNNING"),  # terminal
        ("CANCELLED", "TODO"),
        ("REVIEW", "WAITING_DEVICE"),
    ],
)
def test_illegal_transitions(current, target):
    with pytest.raises(TransitionError) as exc:
        validate_transition(current, target, actor="human", approved=True)
    assert exc.value.code == "illegal_transition"


def test_agent_cannot_close_without_approval():
    with pytest.raises(TransitionError) as exc:
        validate_transition("REVIEW", "DONE", actor="agent")
    assert exc.value.code == "approval_required"

    # ... and approval unlocks exactly that move: closing a reviewed task
    validate_transition("REVIEW", "DONE", actor="agent", approved=True)

    # approval never buys a shortcut around review
    with pytest.raises(TransitionError) as exc:
        validate_transition("RUNNING", "DONE", actor="agent", approved=True)
    assert exc.value.code == "approval_required"


def test_system_actor_can_block_but_not_close():
    validate_transition("RUNNING", "BLOCKED", actor="system")
    with pytest.raises(TransitionError) as exc:
        validate_transition("RUNNING", "CANCELLED", actor="system")
    assert exc.value.code == "approval_required"


def test_unknown_status_rejected():
    with pytest.raises(TransitionError) as exc:
        validate_transition("RUNNING", "DONEISH", actor="human")
    assert exc.value.code == "unknown_status"


def test_every_status_has_a_column():
    for status in STATUSES:
        assert column_of(status) in {"TODO", "RUNNING", "REVIEW", "DONE"}
    assert TERMINAL == {"DONE", "CANCELLED"}
    assert column_of("DONE") == "DONE"
