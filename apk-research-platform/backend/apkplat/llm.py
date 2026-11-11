"""Model gateway: one place that talks to the pre-provisioned model API.

The host already runs DSH NEXT against a remote OpenAI-compatible endpoint; this
module is a *client* of that endpoint and changes nothing about it. What it adds:

* credential discovery that never writes a secret to disk or to the audit log
  (environment first, then the DSH credentials file the user already owns);
* a global concurrency gate (``APKPLAT_MODEL_CONCURRENCY``, default 1) so the
  platform cannot stampede the model API;
* one ``model_requests`` row plus one ``model_call`` audit event per request, which
  is where ``model_calls_per_task`` and ``model_api_latency_ms`` come from;
* a JSON helper that tolerates reasoning models (content may be empty while
  ``reasoning_content`` holds the text) and code fences.
"""
from __future__ import annotations

import json
import re
import threading
import time
from pathlib import Path
from typing import Any, Sequence

import httpx

from . import audit
from .config import settings
from .db import db, utcnow
from .util import new_id

DEFAULT_MODEL = "deepseek-v4.1-flash"
LOCAL_CANDIDATE = "http://127.0.0.1:8788/v1"
LAN_CANDIDATE = "http://192.168.43.1:8788/v1"

_semaphore: threading.BoundedSemaphore | None = None
_semaphore_lock = threading.Lock()
_resolved: dict[str, Any] | None = None


class ModelError(RuntimeError):
    def __init__(self, code: str, message: str, *, status: int | None = None, retryable: bool = False) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status
        self.retryable = retryable


def _gate() -> threading.BoundedSemaphore:
    global _semaphore
    with _semaphore_lock:
        if _semaphore is None:
            _semaphore = threading.BoundedSemaphore(max(1, settings.model_concurrency))
        return _semaphore


def _dsh_credentials_key() -> str | None:
    """Read the key the user already placed for DSH. Read-only, never logged."""
    candidates = []
    home = Path.home()
    candidates.append(home / ".dsh" / ".credentials.yaml")
    candidates.append(home / ".dsh" / "credentials.yaml")
    for path in candidates:
        if not path.exists():
            continue
        try:
            import yaml

            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except Exception:  # noqa: BLE001
            continue
        refs = data.get("refs") or {}
        for key in ("WB_PROXY_API_KEY", "APKPLAT_MODEL_API_KEY", "DEEPSEEK_API_KEY"):
            value = refs.get(key) if isinstance(refs, dict) else None
            if isinstance(value, str) and value.strip():
                return value.strip()
    return None


def _port_open(url: str, timeout: float = 0.6) -> bool:
    import socket
    from urllib.parse import urlparse

    parsed = urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def resolve(refresh: bool = False) -> dict[str, Any]:
    """Where to send model calls: explicit env > localhost proxy > LAN proxy."""
    global _resolved
    if _resolved is not None and not refresh:
        return _resolved
    base_url = settings.model_base_url.strip()
    source = "env:APKPLAT_MODEL_BASE_URL"
    if not base_url:
        source = "auto-discovery"
        base_url = LOCAL_CANDIDATE if _port_open(LOCAL_CANDIDATE) else LAN_CANDIDATE
        if base_url == LAN_CANDIDATE and not _port_open(LAN_CANDIDATE):
            raise ModelError("model_endpoint_unreachable", "no model API endpoint answered on this host")
    api_key = settings.model_api_key.strip()
    key_source = "env:APKPLAT_MODEL_API_KEY" if api_key else ""
    if not api_key:
        api_key = _dsh_credentials_key() or ""
        key_source = "dsh-credentials" if api_key else "missing"
    model = settings.model_id.strip() or DEFAULT_MODEL
    _resolved = {
        "base_url": base_url.rstrip("/"),
        "api_key": api_key,
        "key_source": key_source,
        "model": model,
        "source": source,
        "enabled": bool(settings.model_enabled and api_key),
    }
    return _resolved


def status() -> dict[str, Any]:
    """Secret-free view for /api/health."""
    try:
        info = resolve(refresh=True)
    except ModelError as exc:
        return {"enabled": False, "error": exc.code, "concurrency": settings.model_concurrency}
    return {
        "enabled": info["enabled"],
        "base_url": info["base_url"],
        "model": info["model"],
        "key_source": info["key_source"],
        "endpoint_source": info["source"],
        "concurrency": settings.model_concurrency,
    }


def _record(
    *,
    project_id: str | None,
    task_id: str | None,
    model: str,
    purpose: str,
    status_value: str,
    http_status: int | None,
    latency_ms: int,
    prompt_tokens: int | None,
    output_tokens: int | None,
    error_type: str | None,
) -> None:
    request_id = new_id("mdl_")
    db.execute(
        "INSERT INTO model_requests(id, project_id, task_id, model_id, purpose, status, http_status, latency_ms,"
        " prompt_tokens, output_tokens, error_type, created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            request_id,
            project_id,
            task_id,
            model,
            purpose,
            status_value,
            http_status,
            latency_ms,
            prompt_tokens,
            output_tokens,
            error_type,
            utcnow(),
        ),
    )
    audit.record(
        "model_call",
        project_id=project_id,
        task_id=task_id,
        actor="model-gateway",
        payload={
            "request_id": request_id,
            "model": model,
            "purpose": purpose,
            "status": status_value,
            "http_status": http_status,
            "latency_ms": latency_ms,
            "prompt_tokens": prompt_tokens,
            "output_tokens": output_tokens,
            "error_type": error_type,
        },
    )
    if task_id:
        try:
            db.execute("UPDATE tasks SET model_calls = model_calls + 1 WHERE id = ?", (task_id,))
        except Exception:  # noqa: BLE001
            pass


def complete(
    messages: Sequence[dict],
    *,
    purpose: str,
    project_id: str | None = None,
    task_id: str | None = None,
    tools: list[dict] | None = None,
    json_mode: bool = False,
    max_tokens: int = 1024,
    temperature: float = 0.2,
    timeout: float | None = None,
) -> dict[str, Any]:
    info = resolve()
    if not info["enabled"]:
        raise ModelError("model_disabled", "no model API key available to the platform", retryable=False)
    payload: dict[str, Any] = {
        "model": info["model"],
        "messages": list(messages),
        "max_tokens": max_tokens,
        "temperature": temperature,
    }
    if json_mode:
        payload["response_format"] = {"type": "json_object"}
    if tools:
        payload["tools"] = tools
        payload["tool_choice"] = "auto"
    headers = {"Authorization": f"Bearer {info['api_key']}", "Content-Type": "application/json"}
    url = f"{info['base_url']}/chat/completions"
    started = time.time()
    with _gate():
        try:
            # trust_env=False on purpose: this host exports NO_PROXY with a bracketed
            # IPv6 literal that httpx cannot parse, and the model API is on the LAN.
            with httpx.Client(timeout=timeout or settings.model_timeout, trust_env=False) as client:
                response = client.post(url, json=payload, headers=headers)
        except (httpx.HTTPError, ValueError) as exc:
            latency = int((time.time() - started) * 1000)
            _record(
                project_id=project_id,
                task_id=task_id,
                model=info["model"],
                purpose=purpose,
                status_value="error",
                http_status=None,
                latency_ms=latency,
                prompt_tokens=None,
                output_tokens=None,
                error_type=type(exc).__name__,
            )
            raise ModelError("model_transport_error", str(exc), retryable=True) from exc
    latency = int((time.time() - started) * 1000)
    if response.status_code != 200:
        _record(
            project_id=project_id,
            task_id=task_id,
            model=info["model"],
            purpose=purpose,
            status_value="error",
            http_status=response.status_code,
            latency_ms=latency,
            prompt_tokens=None,
            output_tokens=None,
            error_type="http_error",
        )
        raise ModelError(
            "model_http_error",
            f"model API returned {response.status_code}: {response.text[:300]}",
            status=response.status_code,
            retryable=response.status_code in {429, 500, 502, 503, 504},
        )
    try:
        body = response.json()
    except ValueError as exc:
        raise ModelError("model_bad_json", f"model API returned non-JSON: {response.text[:200]}") from exc
    choice = (body.get("choices") or [{}])[0]
    message = choice.get("message") or {}
    usage = body.get("usage") or {}
    content = message.get("content") or ""
    reasoning = message.get("reasoning_content") or ""
    _record(
        project_id=project_id,
        task_id=task_id,
        model=body.get("model") or info["model"],
        purpose=purpose,
        status_value="ok",
        http_status=200,
        latency_ms=latency,
        prompt_tokens=usage.get("prompt_tokens"),
        output_tokens=usage.get("completion_tokens"),
        error_type=None,
    )
    return {
        "content": content,
        "reasoning": reasoning,
        "tool_calls": message.get("tool_calls") or [],
        "usage": usage,
        "latency_ms": latency,
        "model": body.get("model") or info["model"],
        "raw_id": body.get("id"),
    }


_JSON_BLOCK = re.compile(r"```(?:json)?\s*(.*?)```", re.S)


def parse_json_object(text: str) -> dict:
    """Best-effort extraction of one JSON object from a model answer."""
    text = (text or "").strip()
    if not text:
        raise ModelError("model_empty_answer", "model returned no text")
    candidates: list[str] = []
    block = _JSON_BLOCK.search(text)
    if block:
        candidates.append(block.group(1).strip())
    candidates.append(text)
    first, last = text.find("{"), text.rfind("}")
    if first != -1 and last > first:
        candidates.append(text[first : last + 1])
    for candidate in candidates:
        try:
            value = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    raise ModelError("model_bad_json", f"no JSON object in model answer: {text[:200]}")


def complete_json(
    messages: Sequence[dict],
    *,
    purpose: str,
    project_id: str | None = None,
    task_id: str | None = None,
    max_tokens: int = 1024,
) -> dict:
    """Ask for JSON, tolerating reasoning models that spend budget thinking first.

    A reasoning model can burn the whole completion budget inside ``reasoning_content``
    and emit no ``content`` at all. So: try the answer, then the reasoning text, then
    retry once with double the budget and an explicit "no analysis, JSON only" nudge.
    """
    working = list(messages)
    last: ModelError | None = None
    budget = max(512, max_tokens)
    for attempt in range(2):
        result = complete(
            working,
            purpose=purpose,
            project_id=project_id,
            task_id=task_id,
            json_mode=True,
            max_tokens=budget,
        )
        for candidate in (result["content"], result["reasoning"]):
            if not (candidate or "").strip():
                continue
            try:
                parsed = parse_json_object(candidate)
            except ModelError as exc:
                last = exc
                continue
            parsed["_latency_ms"] = result["latency_ms"]
            parsed["_model"] = result["model"]
            return parsed
        working = list(messages) + [
            {
                "role": "user",
                "content": (
                    "Answer with one JSON object only. Do not explain your reasoning, do not add prose, "
                    "do not use code fences."
                ),
            }
        ]
        budget *= 2
    raise last or ModelError("model_bad_json", "model did not return usable JSON")
