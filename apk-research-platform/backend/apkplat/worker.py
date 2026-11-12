"""Outbox worker: claims jobs from the DB, runs them, heartbeats the lease.

There is no in-process job registry and no memory of "what I was doing" 鈥?a job
either holds a lease row or it does not. That is what makes restart recovery a
database operation instead of a hope:

* on start the worker reclaims expired leases (crash leftovers), auditing each one;
* while a job runs a heartbeat thread extends the lease, so a long jadx run is not
  stolen by a second worker;
* a failure records the stage and toggles ``retryable`` so the queue can apply
  backoff; a cancelled project stops its remaining jobs.
"""
from __future__ import annotations

import argparse
import signal
import sys
import threading
import time
import traceback
from typing import Any, Callable

from . import agents as agents_module
from . import audit, dynamic, pipeline_static, reports
from .config import settings
from .db import utcnow
from . import clock
from .services import artifacts as artifacts_service
from .services import queue as queue_service
from .services import control as control_service
from .services import tasks as tasks_service


def _static_handler(job: dict) -> dict[str, Any]:
    project_id = job["payload"].get("project_id") or job["project_id"]
    task_id = job.get("task_id")
    if not task_id:
        # Ingest does not pre-create a task, so the pipeline opens one: without it the
        # kanban would show an empty board for a project that clearly did work.
        task = tasks_service.create(
            project_id,
            role="static",
            title="静态分析",
            actor="worker",
            status="RUNNING",
        )
        task_id = task["id"]
        audit.record(
            "task_auto_created",
            project_id=project_id,
            task_id=task_id,
            actor="worker",
            payload={"job_id": job["id"], "role": "static"},
        )
        queue_service.attach_task(job["id"], task_id)
        job["task_id"] = task_id
    summary = pipeline_static.run(
        project_id,
        log=lambda m: _job_log(job["id"], m),
        task_id=task_id,
        check=control_service.check_callable(job),
    )
    summary.setdefault("task_id", task_id)
    return summary


def _report_handler(job: dict) -> dict[str, Any]:
    project_id = job["payload"].get("project_id") or job["project_id"]
    result = reports.generate(project_id, task_id=job.get("task_id"), actor="worker")
    return {"artifact_id": result["artifact_id"], "verification_ok": result["verification_ok"]}


def _agents_handler(job: dict) -> dict[str, Any]:
    project_id = job["payload"].get("project_id") or job["project_id"]
    use_model = job["payload"].get("use_model")
    return agents_module.orchestrate(project_id, use_model=use_model)


def _dynamic_handler(job: dict) -> dict[str, Any]:
    project_id = job["payload"].get("project_id") or job["project_id"]
    return dynamic.run_task(
        project_id,
        task_id=job.get("task_id"),
        worker_id=job.get("lease_owner") or "dynamic-worker",
        transport_name=job["payload"].get("transport"),
        device_id=job["payload"].get("device_id"),
        log=lambda m: _job_log(job["id"], m),
        check=control_service.check_callable(job),
    )


HANDLERS: dict[str, Callable[[dict], dict]] = {
    "static_pipeline": _static_handler,
    "report_generate": _report_handler,
    "agent_orchestrate": _agents_handler,
    "dynamic_analysis": _dynamic_handler,
}

RETRYABLE_CODES = {
    "timeout",
    "jadx_timeout",
    "apktool_timeout",
    "tool_missing",
    "project_missing",
    "lease_lost",
    "zip_locked",
    "os_error",
    "device_unavailable",
    "dynamic_timeout",
}


def _job_log(job_id: str, message: str) -> None:
    print(f"[job {job_id[:8]}] {message}", flush=True)


class Worker:
    def __init__(
        self,
        worker_id: str,
        kinds: list[str] | None = None,
        *,
        poll_interval: float = 1.0,
        lease_seconds: int | None = None,
        reap_interval: float | None = None,
    ) -> None:
        self.worker_id = worker_id
        self.kinds = kinds or list(HANDLERS)
        self.poll_interval = poll_interval
        self.lease_seconds = lease_seconds or settings.job_lease_seconds
        # How often an idle worker looks for leases that died elsewhere. Callable code
        # never sets this; tests shrink it and the default keeps it well under a lease.
        self.reap_interval = reap_interval or max(15.0, min(60.0, self.lease_seconds / 4.0))
        self.stop = threading.Event()
        self.current: dict | None = None
        self._hb: threading.Thread | None = None

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> None:
        reclaimed = queue_service.reclaim_expired(self.worker_id)
        for item in reclaimed:
            job = queue_service.get(item["job_id"])
            if item["status"] == queue_service.RETRYING:
                audit.record(
                    "job_recovered_after_restart",
                    project_id=job["project_id"] if job else None,
                    task_id=job["task_id"] if job else None,
                    actor=self.worker_id,
                    payload={
                        "job_id": item["job_id"],
                        "kind": job["kind"] if job else None,
                        "previous_owner": item.get("previous_owner"),
                        "requeued_as": item["status"],
                    },
                )
                print(
                    f"[worker {self.worker_id}] recovered job {item['job_id'][:8]} after restart (requeued)",
                    flush=True,
                )
            else:
                audit.record(
                    "job_recovery_failed",
                    project_id=job["project_id"] if job else None,
                    task_id=job["task_id"] if job else None,
                    actor=self.worker_id,
                    payload={
                        "job_id": item["job_id"],
                        "kind": job["kind"] if job else None,
                        "previous_owner": item.get("previous_owner"),
                        "reason": "retry budget exhausted",
                    },
                )
                print(
                    f"[worker {self.worker_id}] job {item['job_id'][:8]} exhausted its retry budget while orphaned",
                    flush=True,
                )
        audit.record("worker_started", actor=self.worker_id, payload={"kinds": self.kinds})

    def stop_gracefully(self) -> None:
        self.stop.set()

    def run(self, max_jobs: int | None = None, idle_timeout: float | None = None) -> int:
        """Drain the queue.

        ``max_jobs`` caps how many jobs are executed. ``idle_timeout`` makes the call
        return after that many seconds of an empty queue - without it a bounded run
        (``worker --once``) would wait forever whenever the queue ran dry first.
        """
        self.start()
        processed = 0
        idle_since = clock.monotonic()
        # A long-lived worker still has to pick up leases that died elsewhere (a crashed
        # sibling worker, a killed API process). Reaping on a timer is what makes
        # "restart the worker" optional instead of mandatory after an interruption.
        reap_every = self.reap_interval
        last_reap = clock.monotonic()
        while not self.stop.is_set():
            if clock.monotonic() - last_reap >= reap_every:
                last_reap = clock.monotonic()
                recovered = queue_service.reclaim_expired(self.worker_id)
                if recovered:
                    print(
                        f"[worker {self.worker_id}] reaped {len(recovered)} expired lease(s)",
                        flush=True,
                    )
            job = queue_service.claim(self.worker_id, self.kinds, self.lease_seconds)
            if not job:
                if max_jobs is not None and processed >= max_jobs:
                    break
                if idle_timeout is not None and clock.monotonic() - idle_since >= idle_timeout:
                    print(f"[worker {self.worker_id}] idle for {idle_timeout}s; stopping", flush=True)
                    break
                clock.sleep(self.poll_interval)
                continue
            idle_since = clock.monotonic()
            self._run_one(job)
            processed += 1
            if max_jobs is not None and processed >= max_jobs:
                break
        audit.record("worker_stopped", actor=self.worker_id, payload={"processed": processed})
        return processed

    # -- one job -----------------------------------------------------------
    def _run_one(self, job: dict) -> None:
        self.current = job
        self._hb = threading.Thread(target=self._heartbeat_loop, args=(job["id"],), daemon=True)
        self._hb.start()
        started = time.time()
        handler = HANDLERS.get(job["kind"])
        if not handler:
            queue_service.fail(job["id"], f"no handler for kind {job['kind']}", retryable=False)
            return
        try:
            result = handler(job)
            queue_service.complete(job["id"], result=result)
            _merge_task_result(job, result)
            audit.record(
                "job_succeeded",
                project_id=job.get("project_id"),
                task_id=job.get("task_id"),
                actor=self.worker_id,
                payload={"job_id": job["id"], "kind": job["kind"], "duration_ms": int((time.time() - started) * 1000)},
            )
        except control_service.JobCancelled as exc:
            self._cancelled(job, exc, started)
        except pipeline_static.StageError as exc:
            self._fail(job, exc.code, exc.message, {"stage": exc.stage, **exc.detail}, started)
        except Exception as exc:  # noqa: BLE001
            self._fail(
                job,
                type(exc).__name__,
                str(exc)[:2000],
                {"traceback": traceback.format_exc()[-4000:]},
                started,
            )
        finally:
            self.current = None
            _release_identity(job)

    def _cancelled(self, job: dict, exc: "control_service.JobCancelled", started: float) -> None:
        """The operator asked this job to stop: mark the row CANCELLED and close the card.

        A stop is not a failure - retrying it would resurrect exactly what the operator
        cancelled - so it bypasses the retry/backoff path entirely.
        """
        fresh = queue_service.get(job["id"])
        if fresh is not None and fresh["task_id"] and not job.get("task_id"):
            job = {**job, "task_id": fresh["task_id"]}
        queue_service.cancel(job["id"], actor="human")
        if job.get("task_id"):
            try:
                tasks_service.update(
                    job["task_id"],
                    status="CANCELLED",
                    actor="human",
                    reason="operator stop",
                )
            except Exception:  # noqa: BLE001 - the job is cancelled either way
                pass
        audit.record(
            "job_cancelled",
            project_id=job.get("project_id"),
            task_id=job.get("task_id"),
            actor=self.worker_id,
            payload={
                "job_id": job["id"],
                "kind": job["kind"],
                "reason": exc.reason,
                "duration_ms": int((time.time() - started) * 1000),
            },
        )

    def _fail(self, job: dict, code: str, message: str, detail: dict, started: float) -> None:
        # The handler may have created a task mid-flight and attached it to the row, so
        # the in-memory job dict can be older than the database.
        fresh = queue_service.get(job["id"])
        if fresh is not None and fresh["task_id"] and not job.get("task_id"):
            job = {**job, "task_id": fresh["task_id"]}
        retryable = code in RETRYABLE_CODES or "timeout" in code.lower()
        queue_service.fail(job["id"], code, message, retryable=retryable, worker_id=self.worker_id)
        audit.record(
            "job_failed",
            project_id=job.get("project_id"),
            task_id=job.get("task_id"),
            actor=self.worker_id,
            payload={
                "job_id": job["id"],
                "kind": job["kind"],
                "error_code": code,
                "message": message[:500],
                "retryable": retryable,
                "duration_ms": int((time.time() - started) * 1000),
            },
        )
        if job.get("task_id"):
            try:
                task = tasks_service.get(job["task_id"])
                if task and task["status"] in {"RUNNING", "RETRYING", "TODO", "WAITING_DEVICE"}:
                    tasks_service.update(
                        job["task_id"],
                        actor="system",
                        status="RETRYING" if retryable else "FAILED",
                        fields={
                            "error_code": code,
                            "error_message": message[:1000],
                            "retryable": retryable,
                        },
                        reason=f"job {job['id']} failed with {code}",
                    )
            except Exception:  # noqa: BLE001
                pass

    def _heartbeat_loop(self, job_id: str) -> None:
        interval = max(5, self.lease_seconds // 3)
        while not self.stop.is_set():
            clock.sleep(interval)
            try:
                queue_service.heartbeat(job_id)
            except Exception:  # noqa: BLE001
                return


def _release_identity(job: dict) -> None:
    """Hand a periodic run's test identity back when its job is done.

    The scheduler leases the identity for the duration of the work. Releasing it here (and
    not relying on the 15-minute expiry) is what keeps the next window from being refused
    for a lease nobody still needs.
    """
    payload = job.get("payload") or {}
    lease_id = payload.get("identity_lease_id")
    if not lease_id:
        return
    from .services import scheduler as scheduler_service

    try:
        scheduler_service.release_identity(lease_id, reason="job_finished")
    except Exception as exc:  # noqa: BLE001 - a stale lease must not fail the job
        audit.record(
            "identity_release_failed",
            project_id=job.get("project_id"),
            task_id=job.get("task_id"),
            actor="worker",
            payload={"lease_id": lease_id, "error": f"{type(exc).__name__}: {exc}"[:300]},
        )


def _merge_task_result(job: dict, result: dict) -> None:
    """Move the task behind a job to REVIEW after the job succeeded.

    ``evidence_count`` is *not* merged here: ``evidence_service.record`` already
    increments it per row, and it is not an editable field (a ``fields`` entry it
    does not allow raises ValueError). An exception raised here used to be swallowed
    and the card stayed in RUNNING for ever, so failures are now audited instead of
    disappearing.
    """
    task_id = job.get("task_id")
    if not task_id:
        return
    try:
        task = tasks_service.get(task_id)
        if not task:
            return
        if task["status"] in {"RUNNING", "RETRYING"}:
            tasks_service.update(
                task_id,
                actor="system",
                status="REVIEW",
                reason="job finished; awaiting review",
            )
    except Exception as exc:  # noqa: BLE001
        audit.record(
            "task_status_update_failed",
            project_id=job.get("project_id"),
            task_id=task_id,
            actor="worker",
            payload={"job_id": job.get("id"), "error": f"{type(exc).__name__}: {exc}"[:400]},
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="apkplat outbox worker")
    parser.add_argument(
        "--kinds", default=",".join(HANDLERS), help="comma separated job kinds (default: every registered kind)"
    )
    parser.add_argument("--id", default=None, help="worker id (default: generated)")
    parser.add_argument("--once", action="store_true", help="stop when the queue is empty")
    parser.add_argument("--max-jobs", type=int, default=None)
    parser.add_argument("--poll", type=float, default=1.0)
    parser.add_argument("--idle-timeout", type=float, default=None, help="stop after N idle seconds")
    args = parser.parse_args(argv)
    worker_id = args.id or f"worker-{utcnow().replace(':', '').replace('-', '')[:15]}"
    worker = Worker(worker_id, [k.strip() for k in args.kinds.split(",") if k.strip()], poll_interval=args.poll)
    if args.once and args.max_jobs is None:
        args.idle_timeout = 3.0
    signal.signal(signal.SIGINT, lambda *_: worker.stop_gracefully())
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, lambda *_: worker.stop_gracefully())
    processed = worker.run(max_jobs=args.max_jobs, idle_timeout=getattr(args, "idle_timeout", None))
    print(f"[worker {worker_id}] processed {processed} job(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
