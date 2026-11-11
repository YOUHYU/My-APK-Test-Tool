"""Small shared helpers: identifiers, hashing, JSON, paths, redaction."""
from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from pathlib import Path
from typing import Any

from .config import settings
from .db import utcnow

_ID_ALPHABET = "0123456789abcdef"


def new_id(prefix: str = "") -> str:
    raw = uuid.uuid4().hex
    return f"{prefix}{raw}" if prefix else raw


def short_id(value: str, n: int = 8) -> str:
    return value[:n]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)


def loads(value: str | None, default: Any = None) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


def now() -> str:
    return utcnow()


def project_root(project_id: str) -> Path:
    return settings.project_dir(project_id)


def project_layout(project_id: str) -> dict[str, Path]:
    base = project_root(project_id)
    layout = {
        "base": base,
        "inputs": base / "inputs",
        "manifests": base / "manifests",
        "artifacts": base / "artifacts",
        "indexes": base / "indexes",
        "evidence": base / "evidence",
        "logs": base / "logs",
        "reports": base / "reports",
    }
    for path in layout.values():
        path.mkdir(parents=True, exist_ok=True)
    return layout


def rel_to_storage(path: Path) -> str:
    try:
        return path.resolve().relative_to(settings.storage.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def abs_from_storage(rel: str) -> Path:
    candidate = Path(rel)
    if candidate.is_absolute():
        return candidate
    return (settings.storage / rel).resolve()


_SAFE_SEGMENT = re.compile(r"[^A-Za-z0-9._-]+")


def safe_segment(name: str, fallback: str = "item") -> str:
    cleaned = _SAFE_SEGMENT.sub("_", name).strip("._") or fallback
    return cleaned[:120]


def is_within(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


_SECRET_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*[\"']?([A-Za-z0-9._\-]{6,})"),
    re.compile(r"sk-[A-Za-z0-9]{16,}"),
]


def redact(text: str) -> str:
    out = text
    out = _SECRET_PATTERNS[0].sub(lambda m: f"{m.group(1)}=<redacted>", out)
    out = _SECRET_PATTERNS[1].sub("<redacted-key>", out)
    return out


def env_flag(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def clamp(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit] + f"\n... [truncated {len(text) - limit} chars]"
