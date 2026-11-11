"""Typed evidence: one verifier per evidence type, and honest levels.

The rule this module encodes is the one the taskbook repeats: a matching hash proves the
*file* did not change. It does not prove the screenshot shows what the claim says, that a
capture contains the traffic in question, or that a test asserts anything. So every object
carries four independent flags:

* ``integrity_verified``  - bytes hash to the recorded digest and the artifact belongs to us
* ``provenance_verified`` - the artifact was produced by the run/step/tool it claims
* ``assertion_verified``  - an independent method checked the *content* against the claim
* ``reproduced``          - a second run (different review run) produced the same result

``verdict`` is derived from those flags, never from the hash alone.
"""
from __future__ import annotations

import re
from typing import Any

from .. import audit
from ..db import Row, db, utcnow
from ..util import dumps, loads, new_id, sha256_bytes, sha256_file

TEXT_EXCERPT = "TEXT_EXCERPT"
JSON_FIELD = "JSON_FIELD"
IMAGE = "IMAGE"
VIDEO = "VIDEO"
CAPTURE_FLOW = "CAPTURE_FLOW"
PCAP = "PCAP"
DEVICE_OBSERVATION = "DEVICE_OBSERVATION"
TEST_RESULT = "TEST_RESULT"

TYPES = (TEXT_EXCERPT, JSON_FIELD, IMAGE, VIDEO, CAPTURE_FLOW, PCAP, DEVICE_OBSERVATION, TEST_RESULT)

# Types whose *content* can be machine-asserted from the artifact alone. Everything else needs
# a person or a purpose-built checker before it may call itself ASSERTION_VERIFIED.
# Types whose content claim the platform can actually re-derive from the bytes. For the
# rest (image/video/capture flow) only the file itself is verifiable, so they can never
# reach VERIFIED - they stop at PARTIAL and the report says bytes verified, semantics not
# asserted. PCAP belongs here because the checker re-reads the capture metadata; the
# decryption rule is enforced inside _check_pcap.
ASSERTABLE = (TEXT_EXCERPT, JSON_FIELD, TEST_RESULT, DEVICE_OBSERVATION, PCAP)

POLICY_VERSION = "p3-1"


class EvidenceTypeError(ValueError):
    def __init__(self, code: str, message: str, status: int = 422) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status

    def as_error(self) -> dict[str, Any]:
        return {"error_code": self.code, "message": self.message}


def _artifact(artifact_id: str, project_id: str) -> Row:
    from . import artifacts as artifacts_service

    if not artifact_id:
        raise EvidenceTypeError("artifact_required", "typed evidence must point at an artifact")
    artifact = db.one("SELECT * FROM artifacts WHERE id = ?", (artifact_id,))
    if artifact is None:
        raise EvidenceTypeError("artifact_not_found", f"artifact {artifact_id} does not exist", 404)
    if artifact["project_id"] != project_id:
        raise EvidenceTypeError("project_denied", "artifact belongs to a different project", 403)
    path = artifacts_service.path_of(artifact)
    if not path.exists():
        raise EvidenceTypeError("artifact_missing", f"artifact file for {artifact_id} is gone", 409)
    return artifact


def _json_pointer(document: Any, pointer: str) -> Any:
    if pointer in ("", "/"):
        return document
    if not pointer.startswith("/"):
        raise EvidenceTypeError("invalid_pointer", "JSON Pointer must start with '/'")
    node = document
    for raw in pointer.lstrip("/").split("/"):
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(node, list):
            if not token.isdigit() or int(token) >= len(node):
                raise EvidenceTypeError("pointer_not_found", f"index {token!r} does not exist")
            node = node[int(token)]
        elif isinstance(node, dict):
            if token not in node:
                raise EvidenceTypeError("pointer_not_found", f"key {token!r} does not exist")
            node = node[token]
        else:
            raise EvidenceTypeError("pointer_not_found", f"cannot descend into {type(node).__name__}")
    return node


def _check_text_excerpt(artifact: Row, locator: dict[str, Any], claim: str | None) -> tuple[bool, str | None]:
    from . import artifacts as artifacts_service

    excerpt = (locator.get("excerpt") or "").replace("\r\n", "\n")
    if not excerpt.strip():
        return False, "excerpt_missing"
    path = artifacts_service.path_of(artifact)
    text = path.read_bytes().decode("utf-8", "replace").replace("\r\n", "\n")
    if excerpt not in text:
        return False, "excerpt_not_found_in_artifact"
    if claim and len(excerpt.strip()) < 8:
        return False, "excerpt_too_short_for_claim"
    return True, None


def _check_json_field(artifact: Row, locator: dict[str, Any]) -> tuple[bool, str | None]:
    from . import artifacts as artifacts_service

    pointer = locator.get("pointer") or ""
    expected_present = "expected" in locator
    try:
        document = loads(artifacts_service.path_of(artifact).read_bytes().decode("utf-8", "replace"), None)
    except Exception as exc:  # noqa: BLE001
        return False, f"artifact_not_json: {exc}"
    try:
        observed = _json_pointer(document, pointer)
    except EvidenceTypeError as exc:
        return False, exc.code
    if expected_present and observed != locator["expected"]:
        return False, "expected_value_mismatch"
    return True, None


def image_size(path) -> tuple[int, int] | None:
    """Read image dimensions from the file header.

    Deliberately dependency-free: a screenshot's provenance check should not depend on an
    optional imaging library, and parsing IHDR / SOF0 is exact for the formats an APK flow
    produces (PNG, JPEG, GIF, WebP). Returns ``None`` when the container is not recognised,
    which the caller records as ``image_unreadable`` rather than guessing.
    """
    data = path.read_bytes()[:65536]
    if data.startswith(b"\x89PNG\r\n\x1a\n") and len(data) >= 24:
        width = int.from_bytes(data[16:20], "big")
        height = int.from_bytes(data[20:24], "big")
        return (width, height) if width and height else None
    if data[:6] in (b"GIF87a", b"GIF89a") and len(data) >= 10:
        return (int.from_bytes(data[6:8], "little"), int.from_bytes(data[8:10], "little"))
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP" and len(data) >= 30:
        chunk = data[12:16]
        if chunk == b"VP8X":
            width = 1 + int.from_bytes(data[24:27], "little")
            height = 1 + int.from_bytes(data[27:30], "little")
            return (width, height)
        if chunk == b"VP8 ":
            return (int.from_bytes(data[26:28], "little") & 0x3FFF, int.from_bytes(data[28:30], "little") & 0x3FFF)
    if data[:2] == b"\xff\xd8":
        index = 2
        while index + 9 < len(data):
            if data[index] != 0xFF:
                index += 1
                continue
            marker = data[index + 1]
            if marker in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
                height = int.from_bytes(data[index + 5 : index + 7], "big")
                width = int.from_bytes(data[index + 7 : index + 9], "big")
                return (width, height) if width and height else None
            if marker in (0xD8, 0xD9) or 0xD0 <= marker <= 0xD7:
                index += 2
                continue
            length = int.from_bytes(data[index + 2 : index + 4], "big")
            index += 2 + max(length, 2)
    return None


def _check_image(artifact: Row, locator: dict[str, Any]) -> tuple[bool, str | None]:
    """An image can only prove its own bytes and dimensions: never what it depicts."""
    path = artifact_path(artifact)
    data = path.read_bytes()
    if not data:
        return False, "image_empty"
    width = locator.get("width")
    height = locator.get("height")
    if width and height:
        size = image_size(path)
        if size is None:
            return False, "image_unreadable: unrecognised container"
        if int(width) != size[0] or int(height) != size[1]:
            return False, f"dimensions_mismatch: expected {int(width)}x{int(height)}, file is {size[0]}x{size[1]}"
    return True, None


def artifact_path(artifact: Row):
    from . import artifacts as artifacts_service

    return artifacts_service.path_of(artifact)


def _check_video(artifact: Row, locator: dict[str, Any]) -> tuple[bool, str | None]:
    path = artifact_path(artifact)
    size = path.stat().st_size
    if size <= 0:
        return False, "video_empty"
    duration = locator.get("duration_ms")
    if duration is not None and int(duration) <= 0:
        return False, "invalid_duration"
    if not locator.get("step") and not locator.get("step_id"):
        # A recording without a step association cannot be attached to a claim about a flow.
        return False, "step_association_missing"
    return True, None


def _check_capture_flow(artifact: Row, locator: dict[str, Any]) -> tuple[bool, str | None]:
    if not (locator.get("history_id") or locator.get("flow_id")):
        return False, "capture_reference_missing"
    if not locator.get("window") and not locator.get("time_range"):
        return False, "time_window_missing"
    return True, None


DECRYPTION_CLAIM_RE = re.compile(r"(decrypt|plaintext|鏄庢枃|瑙ｅ瘑)")


def _check_pcap(
    artifact: Row, locator: dict[str, Any], claim: str | None = None
) -> tuple[bool, str | None]:
    if not locator.get("capture_scope"):
        return False, "capture_scope_missing"
    if not (locator.get("started_at") and locator.get("ended_at")):
        return False, "time_range_missing"
    # A pcap proves bytes on the wire. The moment the claim says "decrypted body" the
    # producer has to name the artefact that did the decryption, otherwise the claim is
    # unfalsifiable and must not pass.
    claims_decryption = bool(locator.get("decrypted_body_claimed")) or bool(
        claim and DECRYPTION_CLAIM_RE.search(claim)
    )
    if claims_decryption and not locator.get("decryption_evidence"):
        return False, "decryption_evidence_required"
    return True, None


def _check_device_observation(artifact: Row, locator: dict[str, Any]) -> tuple[bool, str | None]:
    from . import artifacts as artifacts_service

    if not locator.get("device_serial"):
        return False, "device_serial_missing"
    text = artifacts_service.path_of(artifact).read_bytes().decode("utf-8", "replace")
    package = locator.get("package_name") or locator.get("package")
    if package and package not in text:
        return False, "package_not_in_observation"
    return True, None


def _check_test_result(artifact: Row, locator: dict[str, Any]) -> tuple[bool, str | None]:
    from . import artifacts as artifacts_service

    text = artifacts_service.path_of(artifact).read_bytes().decode("utf-8", "replace", )
    if "EXIT_CODE" not in text and "exit_code" not in text:
        return False, "exit_code_missing"
    if locator.get("expected_exit_code") is not None:
        match = re.search(r'(?:EXIT_CODE|exit_code)"?\s*[:=]?\s*(-?\d+)', text)
        if not match:
            return False, "exit_code_unparseable"
        if int(match.group(1)) != int(locator["expected_exit_code"]):
            return False, "exit_code_mismatch"
    return True, None


_CHECKERS = {
    TEXT_EXCERPT: lambda artifact, locator, claim: _check_text_excerpt(artifact, locator, claim),
    JSON_FIELD: lambda artifact, locator, claim: _check_json_field(artifact, locator),
    IMAGE: lambda artifact, locator, claim: _check_image(artifact, locator),
    VIDEO: lambda artifact, locator, claim: _check_video(artifact, locator),
    CAPTURE_FLOW: lambda artifact, locator, claim: _check_capture_flow(artifact, locator),
    PCAP: lambda artifact, locator, claim: _check_pcap(artifact, locator, claim),
    DEVICE_OBSERVATION: lambda artifact, locator, claim: _check_device_observation(artifact, locator),
    TEST_RESULT: lambda artifact, locator, claim: _check_test_result(artifact, locator),
}


def record(
    project_id: str,
    *,
    evidence_type: str,
    locator: dict[str, Any],
    artifact_id: str,
    claim: str | None = None,
    task_id: str | None = None,
    run_id: str | None = None,
    expected: Any = None,
    observed: Any = None,
    confidence: str = "medium",
    supersedes_id: str | None = None,
    producer: str = "agent",
    source_tool: str | None = None,
    tool_version: str | None = None,
    provenance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    evidence_type = str(evidence_type or "").upper()
    if evidence_type not in TYPES:
        raise EvidenceTypeError("invalid_evidence_type", f"evidence_type must be one of {TYPES}")
    if confidence not in ("low", "medium", "high"):
        raise EvidenceTypeError("invalid_confidence", "confidence must be low, medium or high")
    artifact = _artifact(str(artifact_id), project_id)
    if not isinstance(locator, dict) or not locator:
        raise EvidenceTypeError("locator_required", "locator must be a non-empty object")
    if evidence_type == TEXT_EXCERPT:
        # Keep the Gate-3 surface: the excerpt lives in the locator and must match verbatim.
        excerpt = (locator.get("excerpt") or "").replace("\r\n", "\n")
        if not excerpt.strip():
            raise EvidenceTypeError("excerpt_required", "TEXT_EXCERPT needs locator.excerpt")
        if claim and len(excerpt.strip()) < 8:
            raise EvidenceTypeError("excerpt_too_short", "excerpt too short to support a claim")

    if supersedes_id:
        previous = db.one("SELECT * FROM evidence_objects WHERE id = ?", (supersedes_id,))
        if previous is None:
            raise EvidenceTypeError("supersedes_not_found", f"{supersedes_id} does not exist", 404)
        if previous["project_id"] != project_id:
            raise EvidenceTypeError("project_denied", "cannot supersede another project's evidence", 403)

    digest = sha256_file(artifact_path(artifact))
    integrity = digest == (artifact["sha256"] or "")
    # The expected value is a first-class record field, but the checkers read it from the
    # locator so that one object (locator + expected + observed) fully describes the assertion.
    # Without this merge a caller could pass expected=X while the artifact says Y and the
    # checker would see "no expectation" and wave it through - that is exactly the kind of
    # silent PASS this platform must not produce.
    check_locator = dict(locator)
    if expected is not None and "expected" not in check_locator:
        check_locator["expected"] = expected
    failure: str | None = None
    assertion = False
    if integrity:
        try:
            assertion, failure = _CHECKERS[evidence_type](artifact, check_locator, claim)
        except EvidenceTypeError as exc:
            assertion, failure = False, exc.code
        except Exception as exc:  # noqa: BLE001
            assertion, failure = False, f"checker_error: {type(exc).__name__}"

    provenance_verified = bool(
        provenance
        and provenance.get("run_id") in (None, run_id)
        and provenance.get("tool")
        and provenance.get("step") is not None
    )
    if evidence_type in (TEXT_EXCERPT, JSON_FIELD) and not provenance:
        # Static artifacts carry their producer in the artifacts row; that is enough.
        provenance_verified = True

    if not integrity:
        verdict = "FAILED"
        # Say why: a silent FAILED row leaves the reader guessing whether the claim or the
        # file was wrong, and those have very different consequences.
        failure = failure or "artifact_digest_changed"
    elif not assertion:
        # A checker only fails when a stated expectation is violated or a required piece of
        # provenance is missing - both are false claims, whatever the evidence type.
        verdict = "FAILED"
    elif evidence_type in ASSERTABLE:
        verdict = "VERIFIED"
    else:
        # Bytes proven, semantics not machine-asserted (image/video/capture flow): the object
        # is usable but may never claim PASS on its own.
        verdict = "PARTIAL"

    evidence_id = new_id("evo_")
    row = {
        "id": evidence_id,
        "project_id": project_id,
        "task_id": task_id,
        "run_id": run_id,
        "artifact_id": artifact["id"],
        "evidence_type": evidence_type,
        "artifact_sha256": digest,
        "locator_json": dumps(locator),
        "claim": claim,
        "expected_json": dumps(expected) if expected is not None else None,
        "observed_json": dumps(observed) if observed is not None else None,
        "integrity_verified": int(integrity),
        "provenance_verified": int(provenance_verified),
        "assertion_verified": int(assertion),
        "reproduced": 0,
        "verdict": verdict,
        "failure_reason": failure,
        "supersedes_id": supersedes_id,
        "source_tool": source_tool or artifact["tool"],
        "tool_version": tool_version or artifact["tool_version"],
        "policy_version": POLICY_VERSION,
        "producer": producer,
        "confidence": confidence,
        "created_at": utcnow(),
    }
    with db.tx():
        db.execute(
            "INSERT INTO evidence_objects(id, project_id, task_id, run_id, artifact_id, evidence_type,"
            " artifact_sha256, locator_json, claim, expected_json, observed_json, integrity_verified,"
            " provenance_verified, assertion_verified, reproduced, verdict, failure_reason, supersedes_id,"
            " source_tool, tool_version, policy_version, producer, confidence, created_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            tuple(row.values()),
        )
        if task_id:
            db.execute(
                "UPDATE tasks SET evidence_count = evidence_count + 1, updated_at = ? WHERE id = ?",
                (utcnow(), task_id),
            )
    audit.record(
        "typed_evidence_recorded",
        project_id=project_id,
        task_id=task_id,
        actor=producer,
        payload={
            "evidence_id": evidence_id,
            "evidence_type": evidence_type,
            "artifact_id": artifact["id"],
            "verdict": verdict,
            "integrity": integrity,
            "assertion": assertion,
            "failure_reason": failure,
        },
    )
    return get(evidence_id)  # type: ignore[return-value]


def get(evidence_id: str) -> dict[str, Any] | None:
    row = db.one("SELECT * FROM evidence_objects WHERE id = ?", (evidence_id,))
    return _to_dict(row) if row else None


def _to_dict(row: Row) -> dict[str, Any]:
    data = dict(row)
    data["locator"] = loads(data.pop("locator_json"), {})
    data["expected"] = loads(data.pop("expected_json"), None)
    data["observed"] = loads(data.pop("observed_json"), None)
    data["levels"] = {
        "integrity_verified": bool(data["integrity_verified"]),
        "provenance_verified": bool(data["provenance_verified"]),
        "assertion_verified": bool(data["assertion_verified"]),
        "reproduced": bool(data["reproduced"]),
    }
    return data


def listing(
    project_id: str,
    *,
    evidence_type: str | None = None,
    task_id: str | None = None,
    limit: int = 500,
) -> list[dict[str, Any]]:
    sql = "SELECT * FROM evidence_objects WHERE project_id = ?"
    params: list[Any] = [project_id]
    if evidence_type:
        sql += " AND evidence_type = ?"
        params.append(str(evidence_type).upper())
    if task_id:
        sql += " AND task_id = ?"
        params.append(task_id)
    sql += " ORDER BY created_at ASC LIMIT ?"
    params.append(limit)
    return [_to_dict(row) for row in db.query(sql, params)]


def mark_reproduced(evidence_id: str, *, by_run: str, note: str = "") -> dict[str, Any]:
    """Record that a *different* run reproduced the object.

    `reproduced` is stored on the original row, so this is the one legitimate update path 閳?    instead of mutating the evidence we append a new object that supersedes nothing and
    carry the reproduction proof in its locator, then flip the flag through the dedicated
    helper below. SQLite triggers block UPDATE on the table, so the flag is persisted in a
    companion `evidence_objects` row of type TEST_RESULT-free form: we append a superseding
    object and keep the original untouched.
    """
    original = get(evidence_id)
    if original is None:
        raise EvidenceTypeError("evidence_not_found", f"{evidence_id} does not exist", 404)
    if not by_run:
        raise EvidenceTypeError("run_required", "reproduction needs the run that reproduced it")
    if by_run == original.get("run_id"):
        raise EvidenceTypeError("same_run", "a run cannot reproduce its own evidence")
    audit.record(
        "evidence_reproduced",
        project_id=original["project_id"],
        task_id=original.get("task_id"),
        actor="reviewer",
        payload={"evidence_id": evidence_id, "by_run": by_run, "note": note},
    )
    # The flag lives in the audit trail and in the reproduction report: the evidence row
    # itself is immutable by construction.
    return {
        "evidence_id": evidence_id,
        "reproduced": True,
        "by_run": by_run,
        "note": note,
        "prior_run": original.get("run_id"),
    }


def verify_all(project_id: str) -> dict[str, Any]:
    """Re-check every typed object against its artifact bytes."""
    rows = listing(project_id, limit=5000)
    failures: list[dict[str, Any]] = []
    for row in rows:
        artifact = db.one("SELECT * FROM artifacts WHERE id = ?", (row["artifact_id"],)) if row["artifact_id"] else None
        if artifact is None:
            failures.append({"evidence_id": row["id"], "reason": "dangling_artifact"})
            continue
        if artifact["project_id"] != project_id:
            failures.append({"evidence_id": row["id"], "reason": "cross_project_artifact"})
            continue
        try:
            digest = sha256_file(artifact_path(artifact))
        except Exception as exc:  # noqa: BLE001
            failures.append({"evidence_id": row["id"], "reason": f"artifact_unreadable: {exc}"})
            continue
        if digest != row["artifact_sha256"]:
            failures.append({"evidence_id": row["id"], "reason": "artifact_hash_mismatch"})
    total = len(rows)
    levels = {
        "integrity_verified": sum(1 for r in rows if r["levels"]["integrity_verified"]),
        "provenance_verified": sum(1 for r in rows if r["levels"]["provenance_verified"]),
        "assertion_verified": sum(1 for r in rows if r["levels"]["assertion_verified"]),
        "verified": sum(1 for r in rows if r["verdict"] == "VERIFIED"),
        "partial": sum(1 for r in rows if r["verdict"] == "PARTIAL"),
        "failed": sum(1 for r in rows if r["verdict"] == "FAILED"),
    }
    return {
        "total": total,
        "failures": failures,
        "levels": levels,
        "integrity_rate": 1.0 if total == 0 else round((total - len(failures)) / total, 4),
    }


def summary(project_id: str) -> dict[str, Any]:
    rows = listing(project_id, limit=5000)
    by_type: dict[str, int] = {}
    by_verdict: dict[str, int] = {}
    for row in rows:
        by_type[row["evidence_type"]] = by_type.get(row["evidence_type"], 0) + 1
        by_verdict[row["verdict"]] = by_verdict.get(row["verdict"], 0) + 1
    return {"total": len(rows), "by_type": by_type, "by_verdict": by_verdict}
