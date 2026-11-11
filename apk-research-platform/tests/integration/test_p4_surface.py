"""P4 surface over HTTP: cache introspection and the capture endpoints."""
from __future__ import annotations

import json
from pathlib import Path

from apkplat.config import settings


def _project(client, sample_apk: Path, name: str) -> str:
    with sample_apk.open("rb") as handle:
        response = client.post(
            "/api/projects",
            data={"name": name, "goal": "p4 surface", "ground_truth": json.dumps({"package_name": "com.example.reef"})},
            files={"apk": (sample_apk.name, handle, "application/vnd.android.package-archive")},
        )
    assert response.status_code == 201, response.text
    return response.json()["project"]["id"]


def _har(tmp_path: Path) -> Path:
    payload = {
        "log": {
            "entries": [
                {
                    "startedDateTime": "2026-11-10T10:00:00.000Z",
                    "request": {"method": "POST", "url": "https://api.example-reef.test/v1/license", "headers": []},
                    "response": {"status": 200, "content": {"size": 128, "_at": "2026-11-10T10:00:00.100Z"}},
                }
            ]
        }
    }
    path = Path(tmp_path) / "surface.har"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_cache_endpoints_report_what_was_stored(app_client, sample_apk):
    client = app_client
    stats = client.get("/api/cache/stats")
    assert stats.status_code == 200
    body = stats.json()
    assert {"entries", "apk_bytes", "cache_bytes", "hits", "limit_mb", "enabled"} <= set(body)

    entries = client.get("/api/cache/entries")
    assert entries.status_code == 200
    assert "entries" in entries.json()


def test_capture_round_trip(app_client, sample_apk, tmp_path):
    client = app_client
    project_id = _project(client, sample_apk, "capture-surface")
    har = _har(tmp_path)

    missing = client.post(f"/api/projects/{project_id}/capture/import", json={})
    assert missing.status_code == 422
    assert missing.json()["detail"]["error_code"] == "path_required"

    imported = client.post(
        f"/api/projects/{project_id}/capture/import", json={"path": str(har), "label": "surface"}
    )
    assert imported.status_code == 201, imported.text
    assert imported.json()["flows_imported"] == 1

    sources = client.get(f"/api/projects/{project_id}/capture/sources")
    assert sources.status_code == 200
    assert sources.json()["summary"]["state"] == "IMPORTED"

    correlate = client.post(f"/api/projects/{project_id}/capture/correlate", json={})
    assert correlate.status_code == 200
    assert correlate.json()["state"] in {"IMPORTED", "CORRELATED"}

    flows = client.get(f"/api/projects/{project_id}/capture/flows", params={"host": "example-reef"})
    assert flows.status_code == 200
    assert len(flows.json()["flows"]) == 1

    bad_step = client.post(f"/api/projects/{project_id}/capture/steps", json={"step": "login"})
    assert bad_step.status_code == 422
    assert bad_step.json()["detail"]["error_code"] == "step_and_started_at_required"

    step = client.post(
        f"/api/projects/{project_id}/capture/steps",
        json={"step": "login", "started_at": "2026-11-10T09:59:00.000Z", "device_serial": "e74398f9"},
    )
    assert step.status_code == 201, step.text
    steps = client.get(f"/api/projects/{project_id}/capture/steps")
    assert steps.json()["count"] == 1


def test_capture_probe_is_honest_about_proxypin(app_client, monkeypatch):
    monkeypatch.setattr(settings, "capture_dir", "")
    response = app_client.get("/api/capture/probe")
    assert response.status_code == 200
    body = response.json()
    assert body["available"] is False
    assert "APKPLAT_CAPTURE_DIR" in body["reason"]


def test_unknown_project_is_a_404_not_a_crash(app_client):
    client = app_client
    assert client.get("/api/projects/prj_missing/capture/flows").status_code == 404
    assert client.post("/api/projects/prj_missing/capture/correlate", json={}).status_code == 404
    assert client.get("/api/projects/prj_missing/capture/sources").status_code == 404
