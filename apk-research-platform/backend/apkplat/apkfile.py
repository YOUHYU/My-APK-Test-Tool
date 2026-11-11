"""APK container validation, safe extraction and metadata extraction.

Two independent layers:

``validate_apk``  pure-stdlib structural gate (magic, zip integrity, zip-slip
                  names, encryption, entry/size budgets). Runs before anything
                  else touches the file and is what rejects hostile inputs.
``parse_metadata`` androguard-based semantic extraction (package, sdk levels,
                  permissions, components, signature digests, dex inventory).
                  Failures here are *reported*, never silently swallowed.
"""
from __future__ import annotations

import hashlib
import io
import json
import shutil
import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import settings

MAX_ENTRIES = 200_000
#: a legitimate APK stays well under this ratio; a bomb does not (measured 1023:1)
ZIP_RATIO_LIMIT = 100
#: only apply the ratio rule once the declared payload is worth protecting
ZIP_RATIO_FLOOR = 32 * 1024 * 1024
LOCAL_MAGIC = b"PK\x03\x04"
EMPTY_MAGIC = b"PK\x05\x06"
AXML_MAGIC = b"\x03\x00\x08\x00"


class ApkError(ValueError):
    def __init__(self, code: str, message: str, detail: dict | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.detail = detail or {}


@dataclass
class Validation:
    ok: bool
    error_code: str | None = None
    message: str = ""
    compressed_bytes: int = 0
    uncompressed_bytes: int = 0
    entries: int = 0
    has_manifest: bool = False
    has_dex: bool = False
    dex_files: list[str] = field(default_factory=list)
    native_libs: list[str] = field(default_factory=list)
    resources_arsc: bool = False
    warnings: list[str] = field(default_factory=list)
    bad_entries: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "error_code": self.error_code,
            "message": self.message,
            "compressed_bytes": self.compressed_bytes,
            "uncompressed_bytes": self.uncompressed_bytes,
            "entries": self.entries,
            "has_manifest": self.has_manifest,
            "has_dex": self.has_dex,
            "dex_files": self.dex_files,
            "native_libs": self.native_libs,
            "resources_arsc": self.resources_arsc,
            "warnings": self.warnings,
            "bad_entries": self.bad_entries,
        }


def validate_apk(path: Path, max_unzipped_mb: int | None = None) -> Validation:
    """Return a verdict; never raise for bad content.

    A refused APK is a normal business outcome (it is recorded as an audit event and
    shown to the operator), so contamination checks live in one place: the caller
    only ever asks "ok?" and reads ``error_code``.
    """
    if not Path(path).exists():
        return Validation(ok=False, error_code="missing_file", message=f"no such file: {path}")
    try:
        return _inspect(path, max_unzipped_mb)
    except ApkError as exc:
        partial = getattr(exc, "partial", None)
        if isinstance(partial, Validation):
            partial.ok = False
            partial.error_code = exc.code
            partial.message = exc.message
            return partial
        return Validation(ok=False, error_code=exc.code, message=exc.message)


def _fail(result: Validation, code: str, message: str) -> None:
    """Raise with the partial verdict attached, so callers keep what was learned."""
    err = ApkError(code, message)
    err.partial = result  # type: ignore[attr-defined]
    raise err


def _inspect(path: Path, max_unzipped_mb: int | None = None) -> Validation:
    max_unzipped = (max_unzipped_mb or settings.max_unzipped_mb) * 1024 * 1024
    size = path.stat().st_size
    if size < 1024:
        raise ApkError("apk_too_small", f"file is only {size} bytes")
    if size > settings.max_upload_mb * 1024 * 1024:
        raise ApkError("apk_too_large", f"file is {size} bytes, limit {settings.max_upload_mb} MB")
    with open(path, "rb") as fh:
        head = fh.read(4)
    if head not in (LOCAL_MAGIC, EMPTY_MAGIC):
        raise ApkError("not_a_zip", f"leading magic {head!r} is not a zip/apk container")

    result = Validation(ok=True, compressed_bytes=size)
    try:
        zf = zipfile.ZipFile(path)
    except zipfile.BadZipFile as exc:
        raise ApkError("corrupt_zip", f"zip central directory unreadable: {exc}") from exc

    with zf:
        infos = zf.infolist()
        result.entries = len(infos)
        if len(infos) > MAX_ENTRIES:
            raise ApkError("too_many_entries", f"{len(infos)} entries exceeds {MAX_ENTRIES}")
        total = 0
        for info in infos:
            name = info.filename
            if name.startswith("/") or ".." in Path(name.replace("\\", "/")).parts:
                result.bad_entries.append(name)
                continue
            if info.flag_bits & 0x1:
                raise ApkError("encrypted_entry", f"encrypted entry not supported: {name!r}")
            total += info.file_size
            if total > max_unzipped:
                raise ApkError(
                    "zip_bomb", f"declared uncompressed size exceeds {max_unzipped // (1024 * 1024)} MB at {name!r}"
                )
            if name == "AndroidManifest.xml":
                result.has_manifest = True
            elif name.startswith("classes") and name.endswith(".dex"):
                result.dex_files.append(name)
            elif name.startswith("lib/") and name.endswith(".so"):
                result.native_libs.append(name)
            elif name == "resources.arsc":
                result.resources_arsc = True
        by_ratio = len(infos) >= 2 and size > 0 and total / size >= ZIP_RATIO_LIMIT and total >= ZIP_RATIO_FLOOR
        result.dex_files.sort()
        result.uncompressed_bytes = total
        result.has_dex = bool(result.dex_files)
        if result.bad_entries:
            _fail(
                result,
                "zip_slip",
                f"{len(result.bad_entries)} entry names escape the archive root: {result.bad_entries[:5]}",
            )
        if by_ratio:
            _fail(
                result,
                "zip_bomb",
                f"declared {total // (1024 * 1024)} MB from {size} bytes (ratio {round(total / size)}:1)",
            )
        # verify the first dex actually inflates (catches truncated downloads)
        probe = [n for n in result.dex_files if n.startswith("classes")]
        if probe:
            try:
                with zf.open(sorted(probe)[0]) as fh:
                    fh.read(8)
            except Exception as exc:  # noqa: BLE001
                raise ApkError("corrupt_dex", f"cannot read {probe[0]}: {exc}") from exc
        if not result.has_manifest:
            _fail(result, "missing_manifest", "AndroidManifest.xml missing from archive")
        if not result.has_dex:
            _fail(result, "missing_dex", "no classes*.dex in archive")
        try:
            with zf.open("AndroidManifest.xml") as fh:
                magic = fh.read(8)
            if not magic.startswith(AXML_MAGIC) and not magic.lstrip().startswith(b"<"):
                raise ApkError("manifest_not_android", "AndroidManifest.xml is neither binary AXML nor XML text")
        except KeyError as exc:  # pragma: no cover
            raise ApkError("missing_manifest", str(exc)) from exc
    return result


def safe_extract(path: Path, dest: Path, max_bytes: int | None = None) -> dict[str, Any]:
    """Extract an already-validated APK with path and size guards."""
    dest.mkdir(parents=True, exist_ok=True)
    cap = max_bytes or settings.max_unzipped_mb * 1024 * 1024
    written = 0
    count = 0
    skipped: list[str] = []
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            name = info.filename.replace("\\", "/")
            target = (dest / name).resolve()
            if not str(target).startswith(str(dest.resolve())):
                raise ApkError("zip_slip", f"entry escapes extraction root: {name!r}")
            written += info.file_size
            if written > cap:
                raise ApkError("extract_cap", "extraction exceeded configured byte budget")
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, target.open("wb") as out:
                shutil.copyfileobj(src, out, 1 << 20)
            count += 1
    return {"files": count, "bytes": written, "skipped": skipped, "dest": str(dest)}


# ---------------------------------------------------------------------------
# APK Signing Block (v2/v3) - certificate digests without external tooling
# ---------------------------------------------------------------------------
SIG_BLOCK_MAGIC = b"APK Sig Block 42"


def signing_cert_sha256(path: Path) -> dict[str, Any]:
    """Certificate digests for v2/v3 signing blocks plus v1 JAR signatures."""
    out: dict[str, Any] = {"v1": [], "v2": [], "v3": [], "schemes": []}
    try:
        data = path.read_bytes()
    except OSError:
        return out
    try:
        eocd = data.rfind(b"PK\x05\x06")
        if eocd < 0:
            raise ValueError("no EOCD")
        cd_offset = struct.unpack("<I", data[eocd + 16 : eocd + 20])[0]
        magic_at = cd_offset - 16
        if magic_at <= 0 or data[magic_at:cd_offset] != SIG_BLOCK_MAGIC:
            raise ValueError("no signing block")
        size_of_block = struct.unpack("<Q", data[cd_offset - 24 : cd_offset - 16])[0]
        block_start = cd_offset - size_of_block - 8
        if block_start < 0:
            raise ValueError("bad block size")
        pos = block_start + 8
        end = cd_offset - 24
        while pos + 12 <= end:
            pair_len = struct.unpack("<Q", data[pos : pos + 8])[0]
            pair_id = struct.unpack("<I", data[pos + 8 : pos + 12])[0]
            value = data[pos + 12 : pos + 8 + pair_len]
            if pair_id == 0x7109871A:
                out["v2"] = [{"sha256": d} for d in _v2_v3_certs(value)]
                out["schemes"].append("v2")
            elif pair_id == 0xF05368C0:
                out["v3"] = [{"sha256": d} for d in _v2_v3_certs(value)]
                out["schemes"].append("v3")
            pos += 8 + pair_len
    except Exception as exc:  # noqa: BLE001
        out["block_error"] = str(exc)
    finally:
        _v1_certs(path, out)
    return out


def _lp(buf: bytes, pos: int) -> tuple[bytes, int]:
    n = struct.unpack("<I", buf[pos : pos + 4])[0]
    start = pos + 4
    return buf[start : start + n], start + n


def _lp_all(buf: bytes) -> list[bytes]:
    items, pos = [], 0
    while pos + 4 <= len(buf):
        chunk, pos = _lp(buf, pos)
        items.append(chunk)
    return items


def _v2_v3_certs(block: bytes) -> list[str]:
    digests: list[str] = []
    try:
        signers_blob, _ = _lp(block, 0)
        for signer in _lp_all(signers_blob):
            signed_data, _ = _lp(signer, 0)
            # offsets inside ``signed_data`` are relative to its own start
            pos = 0
            _digests, pos = _lp(signed_data, pos)  # digests sequence
            certs_blob, pos = _lp(signed_data, pos)  # certificates sequence
            for cert in _lp_all(certs_blob):
                digests.append(hashlib.sha256(cert).hexdigest())
    except Exception:  # noqa: BLE001
        pass
    return digests


def _v1_certs(path: Path, out: dict[str, Any]) -> dict[str, Any]:
    """V1/JAR signature certificate digests (META-INF/*.RSA|DSA|EC)."""
    try:
        with zipfile.ZipFile(path) as zf:
            names = [n for n in zf.namelist() if n.upper().startswith("META-INF/") and n.upper().endswith((".RSA", ".DSA", ".EC"))]
            for name in names:
                data = zf.read(name)
                try:
                    digest = _pkcs7_cert_sha256(data)
                    if digest:
                        out["v1"].append({"file": name, "sha256": digest})
                except Exception:  # noqa: BLE001
                    out["v1"].append({"file": name, "sha256": None, "note": "unparsed"})
            if names:
                out["schemes"].append("v1")
    except Exception:  # noqa: BLE001
        pass
    return out


def _pkcs7_cert_sha256(der: bytes) -> str | None:
    """Extract the first certificate from a PKCS#7 SignedData blob by scanning
    for a DER SEQUENCE that parses as an X.509 certificate."""
    # Certificate ::= SEQUENCE { tbsCertificate SEQUENCE, sigAlg SEQUENCE, sig BIT STRING }
    for offset in _der_sequence_offsets(der):
        try:
            length, hdr = _der_len(der, offset)
            body = der[offset + hdr : offset + hdr + length]
            if len(body) < 32 or body[0] != 0x30:
                continue
            inner_len, inner_hdr = _der_len(body, 0)
            inner = body[inner_hdr : inner_hdr + inner_len]
            if not inner or inner[0] != 0x30:
                continue
            cert = der[offset : offset + hdr + length]
            if len(cert) < 200 or len(cert) > 8000:
                continue
            return hashlib.sha256(cert).hexdigest()
        except Exception:  # noqa: BLE001
            continue
    return None


def _der_len(buf: bytes, pos: int) -> tuple[int, int]:
    first = buf[pos + 1]
    if first < 0x80:
        return first, 2
    n = first & 0x7F
    if n == 0 or n > 4:
        raise ValueError("unsupported length")
    return int.from_bytes(buf[pos + 2 : pos + 2 + n], "big"), 2 + n


def _der_sequence_offsets(buf: bytes):
    for i, byte in enumerate(buf[:-4]):
        if byte == 0x30:
            yield i


# ---------------------------------------------------------------------------
# androguard metadata
# ---------------------------------------------------------------------------
def parse_metadata(path: Path) -> dict[str, Any]:
    from androguard.core.apk import APK  # local import: heavy module

    meta: dict[str, Any] = {}
    # androguard >= 4: ``raw=True`` means the first argument is bytes, not a path.
    apk = APK(str(path))
    meta["package"] = apk.get_package()
    meta["app_name"] = apk.get_app_name()
    meta["version_name"] = apk.get_androidversion_name()
    meta["version_code"] = apk.get_androidversion_code()
    meta["min_sdk"] = apk.get_min_sdk_version()
    meta["target_sdk"] = apk.get_target_sdk_version()
    meta["max_sdk"] = apk.get_max_sdk_version()
    meta["permissions"] = sorted(apk.get_permissions() or [])
    meta["declared_permissions"] = sorted(apk.get_declared_permissions() or [])
    meta["activities"] = sorted(apk.get_activities() or [])
    meta["services"] = sorted(apk.get_services() or [])
    meta["receivers"] = sorted(apk.get_receivers() or [])
    meta["providers"] = sorted(apk.get_providers() or [])
    meta["main_activity"] = apk.get_main_activity()
    meta["features"] = sorted(apk.get_features() or [])
    meta["libraries"] = sorted(apk.get_libraries() or [])
    meta["is_signed_v1"] = bool(apk.is_signed_v1())
    meta["is_signed_v2"] = bool(apk.is_signed_v2())
    meta["is_signed_v3"] = bool(apk.is_signed_v3())
    try:
        certs = apk.get_certificates() or []
        meta["certificates"] = [_certificate_info(c) for c in certs]
    except Exception as exc:  # noqa: BLE001
        meta["certificates"] = []
        meta["certificate_error"] = str(exc)
    # Own parser (independent implementation) vs androguard: they must agree.
    meta["signing"] = signing_cert_sha256(path)
    ag_digests: list[str] = []
    for getter in ("get_certificates_der_v3", "get_certificates_der_v2", "get_certificate_der"):
        fn = getattr(apk, getter, None)
        if not fn:
            continue
        try:
            blob = fn()
        except Exception:  # noqa: BLE001
            continue
        items = blob if isinstance(blob, list) else [blob]
        digests = [hashlib.sha256(item).hexdigest() for item in items if item]
        if digests:
            ag_digests = digests
            meta["signing"]["androguard_scheme"] = getter.replace("get_certificates_der_", "").replace("get_certificate_der", "v1")
            break
    meta["signing"]["androguard"] = ag_digests
    own = _primary_cert(meta["signing"])
    meta["signing"]["agrees_with_androguard"] = bool(own and ag_digests and own in ag_digests)
    meta["certificate_sha256"] = own or (ag_digests[0] if ag_digests else None)
    meta["file_size"] = path.stat().st_size
    meta["sha256"] = _sha256(path)
    return meta


def _certificate_info(cert) -> dict[str, Any]:
    """Human-readable certificate facts (asn1crypto reprs are useless in JSON)."""
    subject = getattr(cert, "subject", None)
    issuer = getattr(cert, "issuer", None)
    subject_text = getattr(subject, "human_friendly", None) or str(subject)
    issuer_text = getattr(issuer, "human_friendly", None) or str(issuer)
    digest = getattr(cert, "sha256", None)
    if isinstance(digest, bytes):
        digest = digest.hex()
    elif not digest:
        digest = hashlib.sha256(cert.dump() if hasattr(cert, "dump") else b"").hexdigest()
    return {"subject": subject_text, "issuer": issuer_text, "sha256": digest}


def _primary_cert(signing: dict[str, Any]) -> str | None:
    """First certificate digest, preferring v3 > v2 > v1."""
    for scheme in ("v3", "v2", "v1"):
        for entry in signing.get(scheme) or []:
            if entry.get("sha256"):
                return entry["sha256"]
    return None


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def dex_inventory(extracted_dir: Path) -> list[dict[str, Any]]:
    out = []
    for dex in sorted(extracted_dir.glob("classes*.dex")):
        try:
            with open(dex, "rb") as fh:
                head = fh.read(0x70)
            magic = head[:8]
            if magic[:4] != b"dex\n":
                out.append({"file": dex.name, "ok": False, "error": "bad magic"})
                continue
            string_ids = struct.unpack("<I", head[56:60])[0]
            class_defs = struct.unpack("<I", head[96:100])[0]
            method_ids = struct.unpack("<I", head[88:92])[0]
            out.append(
                {
                    "file": dex.name,
                    "ok": True,
                    "bytes": dex.stat().st_size,
                    "version": magic[4:7].decode("ascii", "replace"),
                    "strings": string_ids,
                    "classes": class_defs,
                    "methods": method_ids,
                    "sha256": _sha256(dex),
                }
            )
        except Exception as exc:  # noqa: BLE001
            out.append({"file": dex.name, "ok": False, "error": str(exc)})
    return out


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
