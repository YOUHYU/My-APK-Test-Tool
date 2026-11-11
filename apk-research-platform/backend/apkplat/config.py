"""Runtime configuration (environment driven, no secrets in repo)."""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path

try:  # optional: .env support when python-dotenv is installed
    from dotenv import load_dotenv

    load_dotenv(Path(__file__).resolve().parent.parent.parent / ".env")
except Exception:  # noqa: BLE001
    pass

ROOT = Path(__file__).resolve().parent.parent.parent


def _bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


@dataclass
class Settings:
    root: Path = ROOT
    storage: Path = field(default_factory=lambda: ROOT / "storage")
    tools: Path = field(default_factory=lambda: ROOT / "tools")
    reports: Path = field(default_factory=lambda: ROOT / "reports")

    db_url: str = os.environ.get("APKPLAT_DB_URL", "")
    host: str = os.environ.get("APKPLAT_HOST", "127.0.0.1")
    port: int = _int("APKPLAT_PORT", 8765)
    public_base_url: str = os.environ.get("APKPLAT_PUBLIC_URL", "http://127.0.0.1:8765")

    static_workers: int = _int("APKPLAT_STATIC_WORKERS", 2)
    dynamic_workers: int = _int("APKPLAT_DYNAMIC_WORKERS", 1)
    report_workers: int = _int("APKPLAT_REPORT_WORKERS", 1)
    model_concurrency: int = _int("APKPLAT_MODEL_CONCURRENCY", 1)

    job_lease_seconds: int = _int("APKPLAT_JOB_LEASE_SECONDS", 300)
    device_lease_seconds: int = _int("APKPLAT_DEVICE_LEASE_SECONDS", 900)
    max_upload_mb: int = _int("APKPLAT_MAX_UPLOAD_MB", 512)
    max_unzipped_mb: int = _int("APKPLAT_MAX_UNZIPPED_MB", 2048)

    token_ttl_seconds: int = _int("APKPLAT_TOKEN_TTL", 12 * 3600)
    require_auth: bool = _bool("APKPLAT_REQUIRE_AUTH", True)

    jadx_timeout: int = _int("APKPLAT_JADX_TIMEOUT", 900)
    apktool_timeout: int = _int("APKPLAT_APKTOOL_TIMEOUT", 900)
    jadx_heap: str = os.environ.get("APKPLAT_JADX_HEAP", "-Xmx1200m")

    model_base_url: str = os.environ.get("APKPLAT_MODEL_BASE_URL", "")
    model_api_key: str = os.environ.get("APKPLAT_MODEL_API_KEY", "")
    model_id: str = os.environ.get("APKPLAT_MODEL_ID", "")
    model_timeout: int = _int("APKPLAT_MODEL_TIMEOUT", 180)
    model_enabled: bool = _bool("APKPLAT_MODEL_ENABLED", True)
    model_max_tokens: int = _int("APKPLAT_MODEL_MAX_TOKENS", 3000)

    dynamic_transport: str = os.environ.get("APKPLAT_DYNAMIC_TRANSPORT", "adb")
    dynamic_step_timeout: int = _int("APKPLAT_DYNAMIC_STEP_TIMEOUT", 120)
    dynamic_observe_seconds: int = _int("APKPLAT_DYNAMIC_OBSERVE_SECONDS", 5)
    dynamic_max_tail: int = _int("APKPLAT_DYNAMIC_LOG_TAIL", 400)

    # P4: analysis cache. A cached APK re-import is a copy, not a re-decode.
    cache_enabled: bool = _bool("APKPLAT_CACHE_ENABLED", True)
    cache_max_mb: int = _int("APKPLAT_CACHE_MAX_MB", 2048)
    # P4: capture store. When no source is attached the platform reports NOT_OBSERVED rather
    # than inventing flows; a directory here points at a ProxyPin export or an offline fixture.
    capture_dir: str = os.environ.get("APKPLAT_CAPTURE_DIR", "")

    seccomp: bool = False  # windows host: no seccomp/AppArmor, documented deviation

    def __post_init__(self) -> None:
        self.storage = Path(os.environ.get("APKPLAT_STORAGE", self.storage)).resolve()
        self.tools = Path(os.environ.get("APKPLAT_TOOLS", self.tools)).resolve()
        self.reports = Path(os.environ.get("APKPLAT_REPORTS", self.reports)).resolve()
        self.db_url = self.db_url or f"sqlite:///{(self.storage / 'platform.db').as_posix()}"

    # -- derived -----------------------------------------------------------
    @property
    def projects_dir(self) -> Path:
        return self.storage / "projects"

    @property
    def secret_path(self) -> Path:
        return self.storage / "secret.key"

    def project_dir(self, project_id: str) -> Path:
        return self.projects_dir / project_id

    def ensure_dirs(self) -> None:
        for p in (self.storage, self.reports, self.projects_dir):
            p.mkdir(parents=True, exist_ok=True)

    def signing_secret(self) -> bytes:
        env = os.environ.get("APKPLAT_SECRET")
        if env:
            return env.encode("utf-8")
        path = self.secret_path
        if path.exists():
            return path.read_bytes()
        secret = secrets.token_bytes(48)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(secret)
        return secret


settings = Settings()
settings.ensure_dirs()
