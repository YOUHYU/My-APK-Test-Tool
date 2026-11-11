"""P5 unit tests: the cleanup matrix must be data, and it must be conservative by default."""

from __future__ import annotations

import pytest

from apkplat import dynamic


PKG = "com.example.reef"


def _actions(mode: str, *, installed_by_us: bool) -> dict[str, dict]:
    plan = dynamic.cleanup_plan(mode, package=PKG, installed_by_us=installed_by_us)
    return {row["action"]: row for row in plan}


@pytest.mark.parametrize("mode", dynamic.CLEANUP_MODES)
def test_every_mode_covers_the_known_actions(mode: str) -> None:
    plan = dynamic.cleanup_plan(mode, package=PKG, installed_by_us=True)
    assert plan, mode
    for row in plan:
        assert row["action"] in dynamic.CLEANUP_ACTIONS
        assert isinstance(row["allowed"], bool)
        if not row["allowed"]:
            assert row.get("skip_reason"), f"{mode}/{row['action']} skipped without a reason"


def test_ephemeral_uninstalls_only_what_we_installed() -> None:
    ours = _actions("EPHEMERAL", installed_by_us=True)
    assert ours["stop_app"]["allowed"] is True
    assert ours["uninstall_app"]["allowed"] is True
    assert ours["clear_scratch"]["allowed"] is True

    theirs = _actions("EPHEMERAL", installed_by_us=False)
    assert theirs["stop_app"]["allowed"] is True
    assert theirs["uninstall_app"]["allowed"] is False
    assert "not ours" in theirs["uninstall_app"]["skip_reason"]


def test_preserve_app_never_uninstalls() -> None:
    for installed_by_us in (True, False):
        rows = _actions("PRESERVE_APP", installed_by_us=installed_by_us)
        assert rows["stop_app"]["allowed"] is True
        assert "uninstall_app" not in rows or rows["uninstall_app"]["allowed"] is False


def test_preserve_session_touches_nothing_but_scratch() -> None:
    rows = _actions("PRESERVE_SESSION", installed_by_us=True)
    assert rows["clear_scratch"]["allowed"] is True
    assert rows.get("stop_app", {"allowed": False})["allowed"] is False
    assert rows.get("uninstall_app", {"allowed": False})["allowed"] is False
    # A session we promised to keep must not even be stopped, let alone uninstalled.
    stopped = [row for row in dynamic.cleanup_plan("PRESERVE_SESSION", package=PKG, installed_by_us=True)
               if row["action"] == "stop_app"]
    assert stopped and stopped[0]["allowed"] is False
    assert [call for call in dynamic.CLEANUP_ACTIONS if call in rows and rows[call]["allowed"]] == ["clear_scratch"]


def test_quarantine_is_the_only_destructive_free_escape() -> None:
    rows = _actions("QUARANTINE", installed_by_us=True)
    assert rows["quarantine"]["allowed"] is True
    assert rows["stop_app"]["allowed"] is False
    assert rows["uninstall_app"]["allowed"] is False
    assert rows["clear_scratch"]["allowed"] is False


def test_unknown_mode_is_refused() -> None:
    with pytest.raises(dynamic.DynamicError) as excinfo:
        dynamic.cleanup_plan("YOLO", package=PKG, installed_by_us=True)
    assert excinfo.value.code == "unknown_cleanup_mode"
    assert excinfo.value.retryable is False
