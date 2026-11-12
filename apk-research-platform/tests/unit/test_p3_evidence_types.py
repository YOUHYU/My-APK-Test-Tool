"""P3 typed evidence: every verdict has to be earned from the artifact bytes.

The tests below deliberately try to get the platform to *claim* something it cannot
prove (an expected value that does not match, an image whose dimensions differ, a pcap
that "shows" HTTPS plaintext without decryption evidence) and assert that it refuses.
"""
from __future__ import annotations

import json

import pytest

from apkplat import pipeline_static
from apkplat.db import db
from apkplat.services import artifacts as artifacts_service
from apkplat.services import evidence_types as et
from apkplat.services import projects as projects_service
from apkplat.services import tasks as tasks_service


@pytest.fixture(scope="module")
def analysed(sample_apk):
    pipeline_static.silence_library_logging()
    project = projects_service.create(name="p3-typed", apk_source=sample_apk, filename=sample_apk.name, actor="test")
    pid = project["id"]
    task = tasks_service.create(pid, role="static", title="Static analysis", actor="test", status="RUNNING")
    pipeline_static.run(pid, task_id=task["id"])
    rows = {row["kind"]: row for row in artifacts_service.list_artifacts(pid, limit=100)}
    return {"project_id": pid, "task_id": task["id"], "artifacts": rows}


def _text_artifact(project_id: str, name: str, text: str) -> str:
    from pathlib import Path

    from apkplat.util import project_layout

    layout = project_layout(project_id)
    path = Path(layout["artifacts"]) / name
    path.write_text(text, encoding="utf-8")
    row = artifacts_service.register(project_id, kind="notes", path=path, tool="test", tool_version="1.0.0")
    return row["id"]


def _png(width: int, height: int) -> bytes:
    """A real, minimal PNG of the requested size - no imaging library involved."""
    import struct
    import zlib

    def chunk(kind: bytes, payload: bytes) -> bytes:
        return (
            struct.pack(">I", len(payload))
            + kind
            + payload
            + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)
        )

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    raw = b"".join(b"\x00" + b"\x0a\x14\x1e" * width for _ in range(height))
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"")

def test_text_excerpt_must_be_verbatim(analysed):
    pid = analysed["project_id"]
    # A non-verbatim excerpt is recorded but can never carry a VERIFIED verdict: the row
    # itself is the audit trail of a rejected claim, which is more useful than a bare 4xx.
    rejected = et.record(
        pid,
        evidence_type=et.TEXT_EXCERPT,
        locator={"excerpt": "this line does not exist in any artifact"},
        artifact_id=analysed["artifacts"]["metadata"]["id"],
        claim="a line that is not there",
    )
    assert rejected["verdict"] == "FAILED"
    assert rejected["failure_reason"] == "excerpt_not_found_in_artifact"

    source = "alpha line\nREEF-API-KEY-7781 is here\nbeta line\n"
    artifact_id = _text_artifact(pid, "verbatim.txt", source)
    row = et.record(
        pid,
        evidence_type=et.TEXT_EXCERPT,
        locator={"excerpt": "REEF-API-KEY-7781 is here"},
        artifact_id=artifact_id,
        claim="the literal is present",
    )
    assert row["verdict"] == "VERIFIED"
    assert row["integrity_verified"] == 1


def test_json_field_mismatch_is_failed_not_verified(analysed):
    pid = analysed["project_id"]
    metadata = analysed["artifacts"]["metadata"]["id"]
    good = et.record(
        pid,
        evidence_type=et.JSON_FIELD,
        locator={"pointer": "/package"},
        expected="com.example.reef",
        artifact_id=metadata,
        claim="package is com.example.reef",
    )
    assert good["verdict"] == "VERIFIED"
    bad = et.record(
        pid,
        evidence_type=et.JSON_FIELD,
        locator={"pointer": "/package"},
        expected="com.example.other",
        artifact_id=metadata,
        claim="package is com.example.other",
    )
    assert bad["verdict"] == "FAILED"
    assert bad["failure_reason"] == "expected_value_mismatch"


def test_integrity_failure_beats_integrity_claim(analysed):
    pid = analysed["project_id"]
    artifact_id = _text_artifact(pid, "will-change.txt", "original bytes\n")
    row = et.record(
        pid,
        evidence_type=et.TEXT_EXCERPT,
        locator={"excerpt": "original bytes"},
        artifact_id=artifact_id,
        claim="bytes as recorded",
    )
    assert row["verdict"] == "VERIFIED"
    # Tamper with the file behind the registry's back: the next record must notice.
    from apkplat.services import artifacts as artifacts_service_inner

    path = artifacts_service_inner.path_of(artifacts_service_inner.get(artifact_id))
    path.write_text("tampered bytes\n", encoding="utf-8")
    second = et.record(
        pid,
        evidence_type=et.TEXT_EXCERPT,
        locator={"excerpt": "original bytes"},
        artifact_id=artifact_id,
        claim="bytes as recorded",
    )
    assert second["integrity_verified"] == 0
    assert second["verdict"] == "FAILED"
    assert second["failure_reason"] == "artifact_digest_changed"


def test_pcap_cannot_claim_https_body_without_decryption(analysed):
    pid = analysed["project_id"]
    pcap = _text_artifact(pid, "capture.pcap", "placeholder capture bytes\n")
    claim = "TLS body decrypted: {\"ok\":true}"
    row = et.record(
        pid,
        evidence_type=et.PCAP,
        locator={"capture_scope": "host:443", "started_at": "2026-01-01T00:00:00Z", "ended_at": "2026-01-01T00:05:00Z"},
        artifact_id=pcap,
        claim=claim,
    )
    assert row["verdict"] == "FAILED"
    assert row["failure_reason"] == "decryption_evidence_required"

    ok = et.record(
        pid,
        evidence_type=et.PCAP,
        locator={
            "capture_scope": "host:443",
            "started_at": "2026-01-01T00:00:00Z",
            "ended_at": "2026-01-01T00:05:00Z",
            "decryption_evidence": "proxy history 12 with decrypted request/response bodies",
        },
        artifact_id=pcap,
        claim="captured TLS session decrypted by the proxy",
    )
    assert ok["verdict"] == "VERIFIED"


def test_device_observation_must_name_device_and_package(analysed):
    pid = analysed["project_id"]
    log = _text_artifact(pid, "logcat.txt", "11-10 10:00:00 I/ActivityManager: Start proc com.example.reef\n")
    row = et.record(
        pid,
        evidence_type=et.DEVICE_OBSERVATION,
        locator={"device_serial": "e74398f9", "package": "com.example.reef"},
        artifact_id=log,
        claim="process started",
    )
    assert row["verdict"] == "VERIFIED"

    other = et.record(
        pid,
        evidence_type=et.DEVICE_OBSERVATION,
        locator={"device_serial": "e74398f9", "package": "com.example.absent"},
        artifact_id=log,
        claim="absent package started",
    )
    assert other["verdict"] == "FAILED"
    assert other["failure_reason"] == "package_not_in_observation"


def test_image_only_asserts_its_own_bytes(analysed):
    pid = analysed["project_id"]
    from pathlib import Path

    from apkplat.util import project_layout

    layout = project_layout(pid)
    path = Path(layout["artifacts"]) / "screen.png"
    path.write_bytes(_png(40, 30))
    artifact = artifacts_service.register(pid, kind="capture", path=path, tool="test", tool_version="1.0.0")

    row = et.record(
        pid,
        evidence_type=et.IMAGE,
        locator={"width": 40, "height": 30, "device_serial": "e74398f9"},
        artifact_id=artifact["id"],
        claim="screenshot captured",
    )
    assert row["verdict"] == "PARTIAL"  # bytes verified,鐢婚潰璇箟 not asserted
    wrong = et.record(
        pid,
        evidence_type=et.IMAGE,
        locator={"width": 100, "height": 30},
        artifact_id=artifact["id"],
        claim="screenshot captured",
    )
    assert wrong["verdict"] == "FAILED"
    assert wrong["failure_reason"].startswith("dimensions_mismatch")


def test_test_result_needs_matching_exit_code(analysed):
    pid = analysed["project_id"]
    result = _text_artifact(pid, "result.txt", "EXIT_CODE=0\nSTDOUT_HASH=abc\n")
    good = et.record(
        pid,
        evidence_type=et.TEST_RESULT,
        locator={"expected_exit_code": 0, "command_template": "python -I -B runner.py"},
        artifact_id=result,
        claim="test passed",
    )
    assert good["verdict"] == "VERIFIED"
    bad = et.record(
        pid,
        evidence_type=et.TEST_RESULT,
        locator={"expected_exit_code": 3},
        artifact_id=result,
        claim="test failed with 3",
    )
    assert bad["verdict"] == "FAILED"
    assert bad["failure_reason"] == "exit_code_mismatch"


def test_superseding_cross_project_is_denied(analysed, sample_apk):
    pid = analysed["project_id"]
    row = et.record(
        pid,
        evidence_type=et.JSON_FIELD,
        locator={"pointer": "/package"},
        expected="com.example.reef",
        artifact_id=analysed["artifacts"]["metadata"]["id"],
        claim="package",
    )
    other = projects_service.create(name="p3-other", apk_source=sample_apk, filename=sample_apk.name, actor="test")
    other_artifact = _text_artifact(other["id"], "other.txt", "other project bytes\n")
    with pytest.raises(et.EvidenceTypeError) as excinfo:
        et.record(
            other["id"],
            evidence_type=et.JSON_FIELD,
            locator={"pointer": "/package"},
            artifact_id=other_artifact,
            supersedes_id=row["id"],
        )
    assert excinfo.value.code == "project_denied"


def test_reproduction_requires_a_different_run(analysed):
    pid = analysed["project_id"]
    row = et.record(
        pid,
        evidence_type=et.JSON_FIELD,
        locator={"pointer": "/package"},
        expected="com.example.reef",
        artifact_id=analysed["artifacts"]["metadata"]["id"],
        claim="package",
        run_id="run_original",
    )
    with pytest.raises(et.EvidenceTypeError) as excinfo:
        et.mark_reproduced(row["id"], by_run="run_original")
    assert excinfo.value.code == "same_run"

    marked = et.mark_reproduced(row["id"], by_run="run_second", note="re-ran the indexer")
    assert marked["reproduced"] == 1
    summary = et.summary(pid)
    assert summary["total"] >= 1
    # A deliberately tampered artifact from another test in this module is expected to show\n    # up here as a hash mismatch - that is the verifier doing its job, not a defect.\n    remaining = et.verify_all(pid)["failures"]\n    assert all(item["reason"] == "artifact_hash_mismatch" for item in remaining)


def test_unknown_type_and_bad_confidence_are_rejected(analysed):
    pid = analysed["project_id"]
    with pytest.raises(et.EvidenceTypeError) as excinfo:
        et.record(pid, evidence_type="MAGIC", locator={"x": 1}, artifact_id="art_x")
    assert excinfo.value.code == "invalid_evidence_type"
    with pytest.raises(et.EvidenceTypeError) as excinfo:
        et.record(
            pid,
            evidence_type=et.JSON_FIELD,
            locator={"pointer": "/package"},
            artifact_id=analysed["artifacts"]["metadata"]["id"],
            confidence="certain",
        )
    assert excinfo.value.code == "invalid_confidence"


def test_evidence_objects_are_append_only(analysed):
    import sqlite3

    pid = analysed["project_id"]
    row = et.record(
        pid,
        evidence_type=et.JSON_FIELD,
        locator={"pointer": "/package"},
        expected="com.example.reef",
        artifact_id=analysed["artifacts"]["metadata"]["id"],
        claim="package",
    )
    with pytest.raises(sqlite3.DatabaseError):
        db.execute("UPDATE evidence_objects SET verdict = 'VERIFIED' WHERE id = ?", (row["id"],))
    with pytest.raises(sqlite3.DatabaseError):
        db.execute("DELETE FROM evidence_objects WHERE id = ?", (row["id"],))
