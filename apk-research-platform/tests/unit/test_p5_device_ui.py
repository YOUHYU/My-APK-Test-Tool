"""P5 unit tests: the UI driver parses and picks correctly, and says so when it cannot."""

from __future__ import annotations

from apkplat import dynamic
from apkplat.services import device_ui


SIM_XML = """<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>
<hierarchy rotation="0">
  <node index="0" text="" resource-id="" class="android.widget.FrameLayout" package="com.example.reef" bounds="[0,0][1080,2340]">
    <node index="1" text="Sign in" resource-id="com.example.reef:id/sign_in" class="android.widget.Button" package="com.example.reef" clickable="true" enabled="true" bounds="[40,300][1040,420]" />
    <node index="2" text="Cancel" resource-id="com.example.reef:id/cancel" class="android.widget.Button" package="com.example.reef" clickable="true" bounds="[40,440][1040,560]" />
  </node>
</hierarchy>
"""


def test_parse_bounds_uses_both_corners() -> None:
    assert device_ui.parse_bounds("[40,300][1040,420]") == (40, 300, 1040, 420)
    assert device_ui.parse_bounds("[1,2]") is None
    assert device_ui.parse_bounds("nonsense") is None


def test_parse_hierarchy_returns_nodes_and_stable_digest() -> None:
    nodes, digest = device_ui.parse_hierarchy(SIM_XML)
    assert len(nodes) == 3
    assert digest == device_ui.parse_hierarchy(SIM_XML)[1]
    button = [n for n in nodes if n.resource_id.endswith("sign_in")][0]
    assert button.text == "Sign in"
    assert button.center == (540, 360)
    assert button.clickable is True


def test_parse_hierarchy_rejects_non_xml() -> None:
    try:
        device_ui.parse_hierarchy("not xml at all")
    except device_ui.UiError as exc:
        assert exc.code == "hierarchy_unparsable"
    else:  # pragma: no cover - the parser must not silently accept junk
        raise AssertionError("junk was accepted as a hierarchy")


def test_pick_prefers_resource_id_over_text() -> None:
    nodes, _ = device_ui.parse_hierarchy(SIM_XML)
    by_id = device_ui.pick(nodes, resource_id="com.example.reef:id/cancel", text="Sign in")
    assert by_id is not None and by_id.text == "Cancel"
    by_text = device_ui.pick(nodes, text="Sign in")
    assert by_text is not None and by_text.resource_id.endswith("sign_in")
    by_contains = device_ui.pick(nodes, contains="ign i")
    assert by_contains is not None and by_contains.text == "Sign in"
    assert device_ui.pick(nodes, text="no such label") is None


def test_dialogs_detects_the_permission_sheet() -> None:
    nodes, _ = device_ui.parse_hierarchy(dynamic.SIM_HIERARCHY)
    report = device_ui.detect_dialogs(nodes, foreground="com.example.reef")
    assert report["count"] == 1
    dialog = report["dialogs"][0]
    assert dialog["kind"] == "permission"
    assert dialog["allow_resource_id"].endswith("permission_allow_button")
    assert dialog["deny_resource_id"].endswith("permission_deny_button")


def test_dialogs_ignores_an_ordinary_screen() -> None:
    nodes, _ = device_ui.parse_hierarchy(SIM_XML)
    report = device_ui.detect_dialogs(nodes, foreground="com.example.reef")
    assert report["count"] == 0 and report["dialogs"] == [] and report["unknown"] is False


def test_adb_ui_over_the_simulator_shares_the_real_code_path(tmp_path) -> None:
    sim = dynamic.make_transport("sim")
    ui = device_ui.AdbUi("192.168.43.1:5555", transport=sim)
    nodes, digest = ui.hierarchy()
    assert nodes and digest
    shot = ui.screenshot(tmp_path / "shot.png")
    assert shot["bytes"] > 0
    assert (tmp_path / "shot.png").read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"
    state = ui.screen_state()
    assert state["interactive"] is True
    assert ui.current_package()
    tap = ui.tap_node([n for n in nodes if n.resource_id.endswith("permission_allow_button")][0])
    assert tap["action"] == "tap"
    assert any("input tap" in " ".join(call) for call in sim.calls)
