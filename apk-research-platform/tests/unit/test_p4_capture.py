"""P4 capture layer: import, correlate, and the honest NOT_OBSERVED path."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from apkplat.config import settings
from apkplat.services import artifacts as artifacts_service
from apkplat.services import capture as capture_service
from apkplat.services import evidence as evidence_service
from apkplat.services import projects as projects_service
from apkplat.util import project_layout

URL = "https://api.example-reef.test/v1/license"


def har(entries: list[dict]) -> dict:
    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "probe", "version": "1"},
            "entries": entries,
        }
    }


def entry(url: str, *, method: str = "GET", status: int = 200, at: str = "2026-11-10T10:00:00.000Z") -> dict:
    return {
        "startedDateTime": at,
        "request": {"method": method, "url": url, "headers": [{"name": "X-Reef-Key", "value": "REEF-API-KEY-7781"}]},
        "response": {"status": status, "content": {"size": 512, "_at": at}},
    }


@pytest.fixture()
def project(tmp_path: Path) -> str:
    apk = Path(settings.storage).parent.parent / "samples" / "sample-app.apk"
    apk = Path(__file__).resolve().parents[2] / "samples" / "sample-app.apk"
    row = projects_service.create(name="capture-probe", apk_source=apk, filename=apk.name, actor="test")
    return row["id"]


def _static_url_evidence(project_id: str) -> str:
    """A network_endpoint evidence row, written the same way the static pipeline writes it."""
    layout = project_layout(project_id)
    path = Path(layout["artifacts"]) / "findings_probe.json"
    line = json.dumps({"url": URL, "file": "sources/HttpUploader.java", "line": 11}, indent=2)
    path.write_text(line + "\n", encoding="utf-8")
    artifact = artifacts_service.register(
        project_id, kind="findings", path=path, tool="apkplat.scan", tool_version="probe", actor="test"
    )
    row = evidence_service.record(
        project_id,
        kind="network_endpoint",
        locator={"url": URL, "file": "sources/HttpUploader.java", "line": 11},
        excerpt=line,
        artifact_id=artifact["id"],
        claim=f"Endpoint {URL} at sources/HttpUploader.java:11",
        created_by="test",
    )
    return artifact["id"]


def _write_capture(tmp_path: Path, name: str, payload: object) -> Path:
    path = Path(tmp_path) / name
    path.write_text(payload if isinstance(payload, str) else json.dumps(payload), encoding="utf-8")
    return path


def test_without_a_source_the_state_is_not_observed(project):
    result = capture_service.correlate(project)
    assert result["state"] == capture_service.NOT_OBSERVED
    assert result["flows"] == 0

    view = capture_service.query(project)
    assert view["state"] == capture_service.NOT_OBSERVED
    assert view["flows"] == []
    assert capture_service.summarize(project)["state"] == capture_service.NOT_OBSERVED


def test_har_import_is_idempotent_per_file(project, tmp_path):
    path = _write_capture(tmp_path, "session.har", har([entry(URL), entry(URL + "/refresh", method="POST")]))
    first = capture_service.import_source(project, path=path, actor="test")
    assert first["duplicate"] is False
    assert first["flows_imported"] == 2

    second = capture_service.import_source(project, path=path, actor="test")
    assert second["duplicate"] is True
    assert second["flows_imported"] == 0
    assert len(capture_service.query(project)["flows"]) == 2

    sources = capture_service.sources(project)
    assert len(sources) == 1
    assert sources[0]["kind"] == "har"
    # The raw file is kept as a registered artifact, never as a bare path.
    stored = Path(sources[0]["path"])
    assert stored.exists() and stored.parent.name == "capture"


def test_correlate_matches_static_literals(project, tmp_path):
    artifact_id = _static_url_evidence(project)
    path = _write_capture(tmp_path, "match.har", har([entry(URL), entry("https://unrelated.example.test/ping")]))
    capture_service.import_source(project, path=path, actor="test")

    result = capture_service.correlate(project)
    assert result["state"] == capture_service.CORRELATED
    assert result["correlated"] == 1
    detail = next(item for item in result["details"] if item["matched_literal"])
    assert detail["matched_literal"] == URL
    assert detail["matched_artifact_id"] == artifact_id

    matched = capture_service.query(project, matched_only=True)["flows"]
    assert [row["host"] for row in matched] == ["api.example-reef.test"]
    assert matched[0]["matched_line"] == 11


def test_step_window_attributes_flows_without_a_literal_match(project, tmp_path):
    path = _write_capture(tmp_path, "window.har", har([entry("https://cdn.example.test/a.js", at="2026-11-10T10:00:05.000Z")]))
    capture_service.import_source(project, path=path, actor="test")
    capture_service.record_step(
        project,
        step="login",
        started_at="2026-11-10T09:59:00.000Z",
        ended_at="2026-11-10T10:01:00.000Z",
        run_id="run_probe",
        device_serial="e74398f9",
    )

    result = capture_service.correlate(project)
    assert result["state"] == capture_service.CORRELATED
    flow = capture_service.query(project)["flows"][0]
    assert flow["step"] == "login"
    assert flow["run_id"] == "run_probe"
    assert flow["matched_artifact_id"] is None  # attributed by time, not by a claimed match


def test_pcap_is_refused_with_a_reason(project, tmp_path):
    path = _write_capture(tmp_path, "session.pcap", "not really a pcap")
    with pytest.raises(capture_service.CaptureError) as exc:
        capture_service.import_source(project, path=path, kind="pcap", actor="test")
    assert exc.value.code == "pcap_not_parseable"
    assert exc.value.status == 422


def test_unreadable_or_unknown_shapes_are_refused(project, tmp_path):
    broken = _write_capture(tmp_path, "broken.har", "{not json")
    with pytest.raises(capture_service.CaptureError) as exc:
        capture_service.import_source(project, path=broken, actor="test")
    assert exc.value.code == "capture_unreadable"

    odd = _write_capture(tmp_path, "odd.har", {"nothing": []})
    with pytest.raises(capture_service.CaptureError) as exc:
        capture_service.import_source(project, path=odd, actor="test")
    assert exc.value.code == "capture_shape_unknown"

    missing = Path(tmp_path) / "nope.har"
    with pytest.raises(capture_service.CaptureError) as exc:
        capture_service.import_source(project, path=missing, actor="test")
    assert exc.value.code == "capture_file_missing"

    with pytest.raises(capture_service.CaptureError) as exc:
        capture_service.import_source(project, path=broken, kind="telepathy", actor="test")
    assert exc.value.code == "unsupported_source_kind"


def test_probe_never_claims_proxypin_it_cannot_see(monkeypatch):
    monkeypatch.setattr(settings, "capture_dir", "")
    absent = capture_service.probe_proxy_pin()
    assert absent["available"] is False
    assert "APKPLAT_CAPTURE_DIR" in absent["reason"]


def test_query_filters_by_host_method_and_limit(project, tmp_path):
    path = _write_capture(
        tmp_path,
        "filters.har",
        har(
            [
                entry(URL),
                entry(URL + "/token", method="POST"),
                entry("https://other.example.test/x"),
            ]
        ),
    )
    capture_service.import_source(project, path=path, actor="test")

    by_host = capture_service.query(project, host="example-reef")
    assert len(by_host["flows"]) == 2
    posts = capture_service.query(project, method="post")
    assert [row["method"] for row in posts["flows"]] == ["POST"]
    assert len(capture_service.query(project, limit=1)["flows"]) == 1
