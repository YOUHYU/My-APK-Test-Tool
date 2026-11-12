"""Static analysis pipeline: one APK in, an indexed project with evidence out.

Stages (each writes an artifact and an audit event, so a failure points at one
stage instead of at the pipeline):

1. validate + extract        (stdlib only, hostile input rejected here)
2. apktool decode            (resources + binary manifest, restricted run)
3. jadx decompile            (Java sources, restricted run)
4. metadata                  (androguard: package/sdk/permissions/components/signature)
5. inventory                 (dex strings, urls, secret-shaped literals)
6. index build               (per-project SQLite FTS)
7. evidence                  (one row per fact, excerpt quoted verbatim from the artifact)

Anything a tool did is in ``storage/projects/<id>/logs/<tool>.*.log`` and registered
as an artifact; nothing in the summary is asserted without a matching row.
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any, Callable, Sequence

from . import apkfile, indexer, toolchain
from .config import settings
from .services import artifacts as artifacts_service
from .services import evidence as evidence_service
from .services import cache
from .services import projects as projects_service
from .util import dumps, new_id, project_layout

URL_RE = re.compile(r"https?://[A-Za-z0-9][A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{3,200}")
SECRET_RES = [
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("generic_secret", re.compile(r"\b(?:API[_-]?KEY|SECRET[_-]?KEY|ACCESS[_-]?TOKEN)\b\s*[=:]\s*\"([^\"]{12,120})\"")),
    # jadx renames constants, so the *declaration name* is the reliable signal:
    # DEFAULT_SALT / STATIC_API_KEY / LICENSE_TOKEN / clientSecret ...
    (
        "named_credential_literal",
        re.compile(r"(?i)\b\w*(?:salt|key|secret|token|passw(?:or)?d|credential|license)\w*\s*=\s*\"([^\"]{6,200})\""),
    ),
    # prefixed literals such as REEF-API-KEY-7781 / AKIA... style hardcoded tokens
    ("prefixed_key_literal", re.compile(r"\"([A-Z0-9]{2,}(?:[-_][A-Z0-9]{2,}){2,})\"")),
    ("bearer_literal", re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{20,}\b")),
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
]


class StageError(RuntimeError):
    def __init__(self, stage: str, code: str, message: str, detail: dict | None = None) -> None:
        super().__init__(f"{stage}: {message}")
        self.stage = stage
        self.code = code
        self.message = message
        self.detail = detail or {}


def run(
    project_id: str,
    *,
    log: Callable[[str], None] | None = None,
    task_id: str | None = None,
    force: bool = False,
    check: Callable[[], None] | None = None,
) -> dict[str, Any]:
    """Run the static pipeline, reusing a cached analysis when the APK digest matches.

    ``force=True`` skips the cache read (the entry is refreshed afterwards), which is what a
    reviewer uses when the cached trees are suspected of coming from another build.

    ``check`` is the cooperative cancellation hook: the worker passes a callable that raises
    when the operator stopped the project, and each stage boundary calls it. A stage in flight
    (jadx, apktool) is never interrupted - only the boundary between stages is.
    """
    started = time.time()
    say = log or (lambda msg: None)
    checkpoint = check or (lambda: None)
    silence_library_logging()
    project = projects_service.get(project_id)
    if not project:
        raise StageError("load", "project_missing", f"project {project_id} does not exist")
    layout = project_layout(project_id)
    apk = projects_service.apk_path(project_id)
    say(f"apk {apk} ({apk.stat().st_size} bytes)")

    # -- 1. validate + extract -------------------------------------------
    validation = apkfile.validate_apk(apk)
    if not validation.ok:
        raise StageError("validate", validation.error_code or "invalid_apk", validation.message or "APK rejected")
    extracted = layout["artifacts"] / "extracted"
    apkfile.safe_extract(apk, extracted)
    validation_path = layout["artifacts"] / "validation.json"
    apkfile.write_json(validation_path, validation.to_dict())
    artifacts_service.register(project_id, kind="validation", path=validation_path, task_id=task_id, tool="apkplat.validate")
    say(f"validated: {validation.entries} entries, {validation.uncompressed_bytes} bytes uncompressed")

    checkpoint()
    apk_sha = cache.digest(apk)
    restored = None
    if settings.cache_enabled and not force:
        restored = cache.restore(project_id, apk_sha, task_id=task_id)
    if restored:
        say(f"cache hit {apk_sha[:12]}: restored {len(restored['registered'])} artifacts, tools not re-run")
        state = _state_from_cache(project_id, layout, apk_sha)
    else:
        state = _analyse(project_id, apk, layout, extracted, task_id, say, checkpoint)
        if settings.cache_enabled:
            stored = cache.put(project_id, apk_sha, metadata=state["metadata"])
            if stored is None:
                say("cache: entry not stored (size limit)")
    return _finish(project_id, layout, state, task_id, say, started, cache_hit=bool(restored), apk_sha=apk_sha)


def _state_from_cache(project_id: str, layout: dict[str, Path], apk_sha: str) -> dict[str, Any]:
    """Rebuild the pipeline state from restored artifacts. No tool is invoked here."""
    facts_path = layout["artifacts"] / "facts.json"
    findings_path = layout["artifacts"] / "findings.json"
    if not facts_path.exists() or not findings_path.exists():
        raise StageError("cache", "cache_restore_incomplete", "restored entry lacks facts.json or findings.json")
    metadata = json.loads(facts_path.read_text(encoding="utf-8"))
    findings = json.loads(findings_path.read_text(encoding="utf-8"))
    kinds: dict[str, Any] = {}
    for row in artifacts_service.list_artifacts(project_id, limit=200):
        kinds.setdefault(row["kind"], row)
    if "metadata" not in kinds or "index" not in kinds:
        raise StageError("cache", "cache_restore_incomplete", "restored entry lacks metadata or index artifacts")
    apktool = metadata.get("apktool") or {}
    jadx = metadata.get("jadx") or {}
    return {
        "metadata": metadata,
        "findings": findings,
        "facts_artifact": kinds["metadata"],
        "index_artifact": kinds["index"],
        "java_files": int(jadx.get("java_files") or 0),
        "index_stats": indexer.stats(project_id),
        "tools": {
            "apktool": {"exit": apktool.get("exit_code"), "ms": apktool.get("duration_ms")},
            "jadx": {"exit": jadx.get("exit_code"), "ms": jadx.get("duration_ms"), "timed_out": bool(jadx.get("timed_out"))},
        },
        "apk_sha256": apk_sha,
    }


def _analyse(
    project_id: str,
    apk: Path,
    layout: dict[str, Path],
    extracted: Path,
    task_id: str | None,
    say: Callable[[str], None],
    checkpoint: Callable[[], None] | None = None,
) -> dict[str, Any]:
    """Stages 2-6: decode, decompile, read metadata, scan literals, build the index."""
    tick = checkpoint or (lambda: None)
    tick()
    # -- 2. apktool (resources) ------------------------------------------
    apktool_dir = layout["artifacts"] / "apktool"
    log_dir = layout["logs"]
    apktool_result = toolchain.apktool_decode(apk, apktool_dir, log_dir, no_src=True)
    apktool_out = artifacts_service.register(
        project_id, kind="tool_stdout", path=apktool_result.stdout_path, task_id=task_id, tool="apktool", tool_version="3.0.3"
    )
    apktool_err = artifacts_service.register(
        project_id, kind="tool_stderr", path=apktool_result.stderr_path, task_id=task_id, tool="apktool", tool_version="3.0.3"
    )
    if not apktool_result.ok and not (apktool_dir / "AndroidManifest.xml").exists():
        raise StageError(
            "apktool",
            "apktool_failed",
            f"apktool decode exited {apktool_result.exit_code}",
            {"stdout_artifact": apktool_out["id"], "stderr_artifact": apktool_err["id"]},
        )
    say(f"apktool decode: exit {apktool_result.exit_code} in {apktool_result.duration_ms} ms")

    tick()
    # -- 3. jadx (code) ---------------------------------------------------
    jadx_dir = layout["artifacts"] / "jadx"
    jadx_result = toolchain.jadx_decompile(apk, jadx_dir, log_dir)
    jadx_out = artifacts_service.register(
        project_id, kind="tool_stdout", path=jadx_result.stdout_path, task_id=task_id, tool="jadx", tool_version="1.5.6"
    )
    jadx_err = artifacts_service.register(
        project_id, kind="tool_stderr", path=jadx_result.stderr_path, task_id=task_id, tool="jadx", tool_version="1.5.6"
    )
    java_sources = jadx_dir / "sources"
    if not jadx_result.ok and not java_sources.exists():
        raise StageError(
            "jadx",
            "jadx_failed" if not jadx_result.timed_out else "jadx_timeout",
            f"jadx exited {jadx_result.exit_code} after {jadx_result.duration_ms} ms",
            {"stdout_artifact": jadx_out["id"], "stderr_artifact": jadx_err["id"]},
        )
    java_count = sum(1 for _ in java_sources.rglob("*.java")) if java_sources.exists() else 0
    say(f"jadx: {java_count} java files, exit {jadx_result.exit_code}, {jadx_result.duration_ms} ms")

    tick()
    # -- 4. metadata ------------------------------------------------------
    try:
        metadata = apkfile.parse_metadata(apk)
    except Exception as exc:  # noqa: BLE001
        raise StageError("metadata", "metadata_failed", f"{type(exc).__name__}: {exc}") from exc
    dex_inventory = apkfile.dex_inventory(extracted)
    metadata["dex_inventory"] = dex_inventory
    metadata["apktool"] = {
        "exit_code": apktool_result.exit_code,
        "duration_ms": apktool_result.duration_ms,
        "manifest_decoded": (apktool_dir / "AndroidManifest.xml").exists(),
        "resource_dirs": sorted(p.name for p in apktool_dir.glob("res/*") if p.is_dir())[:32],
    }
    metadata["jadx"] = {
        "exit_code": jadx_result.exit_code,
        "duration_ms": jadx_result.duration_ms,
        "java_files": java_count,
        "timed_out": jadx_result.timed_out,
    }
    metadata["tool_artifacts"] = {
        "apktool_stdout": apktool_out["id"],
        "apktool_stderr": apktool_err["id"],
        "jadx_stdout": jadx_out["id"],
        "jadx_stderr": jadx_err["id"],
    }
    manifest_path = layout["artifacts"] / "facts.json"
    apkfile.write_json(manifest_path, metadata)
    facts_artifact = artifacts_service.register(
        project_id, kind="metadata", path=manifest_path, task_id=task_id, tool="androguard", tool_version="4.1.4"
    )

    tick()
    # -- 5. inventory (urls + secret-shaped literals) ----------------------
    dex_strings = _dex_strings(apk)
    findings = _scan_sources(java_sources, dex_strings)
    findings_path = layout["artifacts"] / "findings.json"
    apkfile.write_json(findings_path, findings)
    artifacts_service.register(project_id, kind="findings", path=findings_path, task_id=task_id, tool="apkplat.scan")

    tick()
    # -- 6. index ---------------------------------------------------------
    counts = indexer.build(
        project_id,
        apk=apk,
        java_root=java_sources if java_sources.exists() else None,
        apktool_dir=apktool_dir if apktool_dir.exists() else None,
        metadata=metadata,
        dex_strings=dex_strings,
        log=say,
    )
    index_stats = indexer.stats(project_id)
    index_path = layout["indexes"] / "index.db"
    index_artifact = artifacts_service.register(
        project_id, kind="index", path=index_path, task_id=task_id, tool="apkplat.indexer"
    )
    say(f"index: {counts}")
    return {
        "metadata": metadata,
        "findings": findings,
        "facts_artifact": facts_artifact,
        "index_artifact": index_artifact,
        "java_files": java_count,
        "index_stats": index_stats,
        "tools": {
            "apktool": {"exit": apktool_result.exit_code, "ms": apktool_result.duration_ms},
            "jadx": {"exit": jadx_result.exit_code, "ms": jadx_result.duration_ms, "timed_out": jadx_result.timed_out},
        },
    }


def _finish(
    project_id: str,
    layout: dict[str, Path],
    state: dict[str, Any],
    task_id: str | None,
    say: Callable[[str], None],
    started: float,
    *,
    cache_hit: bool,
    apk_sha: str,
) -> dict[str, Any]:
    """Stage 7 plus the summary: evidence rows, artifact registration, project status."""
    metadata = state["metadata"]
    findings = state["findings"]
    evidence_ids = _write_evidence(project_id, metadata, findings, state["facts_artifact"]["id"], task_id)
    say(f"evidence rows: {len(evidence_ids)}")
    summary = {
        "project_id": project_id,
        "package": metadata.get("package"),
        "version_name": metadata.get("version_name"),
        "java_files": state["java_files"],
        "index": state["index_stats"],
        "findings": {key: len(value) for key, value in findings.items()},
        "evidence_ids": evidence_ids,
        "artifacts": {"facts": state["facts_artifact"]["id"], "index": state["index_artifact"]["id"]},
        "tools": state["tools"],
        "cache_hit": cache_hit,
        "apk_sha256": apk_sha,
        "duration_ms": int((time.time() - started) * 1000),
        "stage": "done",
    }
    summary_path = layout["artifacts"] / "static_summary.json"
    apkfile.write_json(summary_path, summary)
    artifacts_service.register(project_id, kind="summary", path=summary_path, task_id=task_id, tool="apkplat.static")
    projects_service.set_status(project_id, "ANALYZED")
    return summary


def _dex_strings(apk: Path, limit: int = 20_000) -> list[str]:
    """All string literals from the dex files (androguard 4 returns plain ``str``)."""
    try:
        from androguard.core.dex import DEX

        data: list[str] = []
        import zipfile

        with zipfile.ZipFile(apk) as zf:
            names = sorted(n for n in zf.namelist() if re.fullmatch(r"classes\d*\.dex", n))
            for name in names[:8]:
                dex = DEX(zf.read(name))
                for value in dex.get_strings():
                    text = value if isinstance(value, str) else str(getattr(value, "get", lambda: value)())
                    if 4 <= len(text) <= 400:
                        data.append(text)
                    if len(data) >= limit:
                        return data
        return data
    except Exception:  # noqa: BLE001
        return []


def silence_library_logging() -> None:
    """androguard pipes DEBUG chatter through loguru; it pollutes worker stdout."""
    try:
        from loguru import logger as _lg

        _lg.remove()
    except Exception:  # noqa: BLE001
        pass


def _scan_sources(java_root: Path, dex_strings: list[str]) -> dict[str, list[dict]]:
    urls: dict[str, dict] = {}
    secrets: list[dict] = []
    seen_lines: set[tuple[str, int]] = set()  # one finding per source line
    if java_root.exists():
        for path in java_root.rglob("*.java"):
            try:
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            rel = path.relative_to(java_root.parent).as_posix()
            for lineno, line in enumerate(lines, start=1):
                for match in URL_RE.findall(line):
                    urls.setdefault(match, {"url": match, "file": rel, "line": lineno, "count": 0})
                    urls[match]["count"] += 1
                for name, pattern in SECRET_RES:
                    match = pattern.search(line)
                    if not match:
                        continue
                    literal = match.group(1) if match.groups() else match.group(0)
                    # header names and URLs are not credentials
                    if literal.lower().startswith(("http://", "https://")):
                        continue
                    if not any(ch.isdigit() for ch in literal) and len(literal) < 16:
                        continue
                    dedupe_key = (rel, lineno)
                    if dedupe_key in seen_lines:
                        break
                    seen_lines.add(dedupe_key)
                    secrets.append(
                        {"kind": name, "file": rel, "line": lineno, "literal": literal[:120], "excerpt": line.strip()[:300]}
                    )
                    break
    for value in dex_strings:
        for match in URL_RE.findall(value):
            urls.setdefault(match, {"url": match, "file": "dex:strings", "line": None, "count": 0})
            urls[match]["count"] += 1
    deduped_secrets = []
    seen = set()
    for item in secrets:
        key = (item["kind"], item["file"], item["line"])
        if key in seen:
            continue
        seen.add(key)
        deduped_secrets.append(item)
    return {"urls": sorted(urls.values(), key=lambda r: -r["count"])[:200], "secrets": deduped_secrets[:100]}


def _evidence_line(path: Path, needle: str) -> str | None:
    """Return the verbatim line of ``path`` containing ``needle``."""
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if needle in line:
                return line
    except OSError:
        return None
    return None


def _read_lines(path: Path) -> list[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def _block(path: Path, needles: Sequence[str]) -> str | None:
    """Return the verbatim slice of ``path`` spanning every ``needle``.

    Evidence has to be self-sufficient: a reviewer must be able to check the whole claim
    against the excerpt alone, so a claim that restates two JSON fields needs both lines.
    """
    lines = _read_lines(path)
    hits = [i for i, line in enumerate(lines) if any(n in line for n in needles)]
    if not hits:
        return None
    start, end = min(hits), max(hits)
    if end - start > 24:
        return "\n".join(lines[start : start + 24])
    return "\n".join(lines[start : end + 1])


def _object_block(path: Path, needles: Sequence[str], *, contains: Sequence[str] = ()) -> str | None:
    """Return the verbatim JSON object of ``path`` that contains every ``needle``.

    ``contains`` disambiguates repeated values (the same literal can appear in several
    files) by requiring extra strings inside the same object. Braces inside string
    literals do not count: secret excerpts often contain source code such as ``") {"``.
    """
    lines = _read_lines(path)
    for idx, line in enumerate(lines):
        if not all(n in line for n in needles):
            continue
        indent = len(line) - len(line.lstrip())
        start = None
        for k in range(idx, -1, -1):
            stripped = lines[k].strip()
            if stripped.endswith("{") and (len(lines[k]) - len(lines[k].lstrip())) < indent:
                start = k
                break
        if start is None:
            continue
        depth = 0
        in_string = False
        escaped = False
        end = None
        for j in range(start, min(len(lines), start + 40)):
            for ch in lines[j]:
                if in_string:
                    if escaped:
                        escaped = False
                    elif ch == "\\":
                        escaped = True
                    elif ch == '"':
                        in_string = False
                    continue
                if ch == '"':
                    in_string = True
                elif ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        end = j
                        break
            if end is not None:
                break
        if end is None:
            continue
        block = "\n".join(lines[start : end + 1])
        if all(c in block for c in contains):
            return block
    return None


_SECRET_KIND_ZH = {
    "named_credential_literal": "命名凭据字面量",
    "prefixed_key_literal": "前缀密钥字面量",
    "aws_access_key": "AWS 访问密钥",
    "google_api_key": "Google API 密钥",
    "generic_secret": "通用密钥赋值",
    "bearer_token": "Bearer 令牌",
    "private_key": "私钥块",
}


def _write_evidence(
    project_id: str, metadata: dict, findings: dict, facts_id: str, task_id: str | None
) -> list[str]:
    layout = project_layout(project_id)
    facts_path = layout["artifacts"] / "facts.json"
    findings_path = layout["artifacts"] / "findings.json"
    findings_artifact: dict | None = None
    ids: list[str] = []

    def add(kind: str, locator: dict, excerpt: str | None, claim: str | None, confidence: str = "high") -> None:
        if not excerpt:
            return
        try:
            row = evidence_service.record(
                project_id,
                kind=kind,
                locator=locator,
                excerpt=excerpt,
                artifact_id=facts_id if locator.get("source") == "facts" else _artifact_id(findings_path),
                task_id=task_id,
                claim=claim,
                confidence=confidence,
                created_by="static-pipeline",
            )
            ids.append(row["id"])
        except evidence_service.EvidenceError:
            return

    def _artifact_id(path: Path) -> str | None:
        for row in artifacts_service.list_artifacts(project_id, limit=200):
            from .util import abs_from_storage

            if abs_from_storage(row["rel_path"]) == path:
                return row["id"]
        return None

    add(
        "manifest_fact",
        {"source": "facts", "json_path": "$.package"},
        _block(facts_path, ['"package"']),
        f"应用包名为 {metadata.get('package')}",
    )
    add(
        "manifest_fact",
        {"source": "facts", "json_path": "$.version_name"},
        _block(facts_path, ['"version_name"', '"version_code"']),
        f"应用版本 {metadata.get('version_name')}（版本号 {metadata.get('version_code')}）",
    )
    add(
        "manifest_fact",
        {"source": "facts", "json_path": "$.target_sdk"},
        _block(facts_path, ['"min_sdk"', '"target_sdk"']),
        f"目标 SDK {metadata.get('target_sdk')}，最低 SDK {metadata.get('min_sdk')}",
    )
    for perm in (metadata.get("permissions") or [])[:20]:
        add(
            "permission",
            {"source": "facts", "json_path": "$.permissions", "value": perm},
            _evidence_line(facts_path, perm),
            f"声明权限 {perm}",
        )
    for entry in (findings.get("urls") or [])[:20]:
        url = entry.get("url") or ""
        add(
            "network_endpoint",
            {"source": "findings", "json_path": "$.urls", "file": entry.get("file"), "line": entry.get("line")},
            _object_block(findings_path, [url], contains=[str(entry.get("file") or "")])
            if url
            else _evidence_line(findings_path, entry.get("file") or ""),
            f"网络端点 {url}（{entry.get('file')}:{entry.get('line')}）",
            confidence="medium",
        )
    for entry in (findings.get("secrets") or [])[:20]:
        literal = entry.get("literal") or ""
        add(
            "secret_candidate",
            {
                "source": "findings",
                "json_path": "$.secrets",
                "file": entry.get("file"),
                "line": entry.get("line"),
                "literal": literal,
            },
            _object_block(findings_path, [literal], contains=[str(entry.get("file") or "")])
            if literal
            else _evidence_line(findings_path, entry.get("kind") or ""),
            f"疑似密钥字面量 {literal or '<unknown>'}（{_SECRET_KIND_ZH.get(str(entry.get('kind')), str(entry.get('kind')))}）位于 "
            f"{entry.get('file')}:{entry.get('line')}",
            confidence="medium",
        )
    return ids


def json_line(path: Path, needle: str) -> str | None:
    return _evidence_line(path, needle)


def plan_jobs(project_id: str) -> list[dict]:
    """What the orchestrator enqueues for a fresh project (static stage only)."""
    return [{"kind": "static_pipeline", "payload": {"project_id": project_id}}]
