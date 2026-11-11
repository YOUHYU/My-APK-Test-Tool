"""Hostile APK corpus: every malformed container must be refused with a named code.

The variants are produced by ``scripts/build_sample_apk.py`` so they are byte-real,
not mocked: truncated zip, non-zip, zip-slip entry, missing manifest, missing dex and
a decompression bomb.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from apkplat.apkfile import ApkError, MAX_ENTRIES, safe_extract, validate_apk

SAMPLES = Path(__file__).resolve().parents[2] / "samples"

CASES = {
    "sample-app.apk": None,  # the good one
    "hostile-truncated.apk": "corrupt_zip",
    "hostile-not-zip.apk": "not_a_zip",
    "hostile-zip-slip.apk": "zip_slip",
    "hostile-no-manifest.apk": "missing_manifest",
    "hostile-no-dex.apk": "missing_dex",
    "hostile-bomb.apk": "zip_bomb",
}


@pytest.fixture(scope="module", autouse=True)
def _ensure_samples():
    missing = [name for name in CASES if not (SAMPLES / name).exists()]
    if missing:
        pytest.skip(f"run scripts/build_sample_apk.py first (missing {missing})")


@pytest.mark.parametrize("name,expected", sorted(CASES.items()))
def test_validation_verdict(name, expected):
    result = validate_apk(SAMPLES / name, max_unzipped_mb=2048)
    if expected is None:
        assert result.ok, result.error_code
        assert result.has_manifest and result.has_dex
        assert result.entries >= 5
        assert result.uncompressed_bytes > 0
        assert not result.warnings or all(isinstance(w, str) for w in result.warnings)
    else:
        assert not result.ok
        assert result.error_code == expected


def test_zip_slip_names_are_reported():
    result = validate_apk(SAMPLES / "hostile-zip-slip.apk")
    assert result.error_code == "zip_slip"
    assert any("../" in entry for entry in (result.bad_entries or [])), result.bad_entries


def test_safe_extract_refuses_traversal(tmp_path):
    with pytest.raises(ApkError) as exc:
        safe_extract(SAMPLES / "hostile-zip-slip.apk", tmp_path / "out")
    assert exc.value.code == "zip_slip"
    # nothing escaped the destination
    assert not (tmp_path / "escaped.txt").exists()


def test_entry_budget_is_finite():
    assert MAX_ENTRIES > 0
    result = validate_apk(SAMPLES / "sample-app.apk")
    assert result.entries < MAX_ENTRIES


def test_missing_file_is_an_error_not_a_crash(tmp_path):
    result = validate_apk(tmp_path / "nope.apk")
    assert not result.ok
    assert result.error_code in {"not_a_zip", "missing_file", "apk_too_small"}


def test_metadata_of_sample_matches_ground_truth(ground_truth):
    from apkplat.apkfile import parse_metadata

    meta = parse_metadata(SAMPLES / "sample-app.apk")
    assert meta["package"] == ground_truth["package"]
    assert meta["version_name"] == ground_truth["version_name"]
    assert meta["version_code"] == ground_truth["version_code"]
    assert meta["target_sdk"] == ground_truth["target_sdk"]
    assert "android.permission.INTERNET" in meta["permissions"]


def test_certificate_digest_matches_ground_truth(ground_truth):
    from apkplat.apkfile import parse_metadata

    meta = parse_metadata(SAMPLES / "sample-app.apk")
    assert meta["certificate_sha256"] == ground_truth["certificate_sha256"]
    assert meta["signing"]["agrees_with_androguard"] is True
    assert {"v2", "v3"} & {k for k in meta["signing"] if isinstance(meta["signing"][k], list)}
