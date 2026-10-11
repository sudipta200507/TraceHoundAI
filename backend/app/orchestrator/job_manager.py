"""Process-local scan job manager (Phase 11) — local-first, no Celery/Redis.

A single FIFO worker thread executes jobs sequentially, so two stages never
touch canonical processed files concurrently and checkpoints cannot race.
Job state is PROCESS-LOCAL: it does not survive restarts (checkpoints on
disk do, and resume rebuilds from them). IDs are deterministic per process:
`<slug>-<counter>`, or a validated client-supplied scan_id.
"""

from __future__ import annotations

import queue
import re
import threading
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from pydantic import BaseModel, Field

from backend.app.core.logger import get_logger, stage_log
from backend.app.orchestrator.stages import STAGE_IDS, StageResult

JobStatus = str

_SCAN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
log = get_logger("tracehound.jobs")


class ScanJob(BaseModel):
    scan_id: str
    target: str
    status: str = "queued"
    scan_mode: str = "passive"
    current_stage: str = ""
    started_at: str = ""
    completed_at: str = ""
    stage_results: list[StageResult] = Field(default_factory=list)
    error: str = ""
    report_path: str = ""
    cancel_requested: bool = False

    model_config = {"arbitrary_types_allowed": True}


def slugify_target(target: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", target.strip().lower()).strip("-")
    return slug[:48] or "scan"


def validate_scan_id(scan_id: str) -> str:
    if not _SCAN_ID_RE.match(scan_id or ""):
        raise ValueError(f"invalid scan_id: {scan_id!r}")
    return scan_id


class JobManager:
    """Thread-safe registry + FIFO background worker (process-local)."""

    def __init__(self, pipeline_fn: Optional[Callable[..., Any]] = None) -> None:
        from backend.app.orchestrator import pipeline as pipeline_module

        self._pipeline_fn = pipeline_fn or pipeline_module.run_pipeline
        self._jobs: dict[str, ScanJob] = {}
        self._lock = threading.Lock()
        self._counter = 0
        self._queue: "queue.Queue[dict[str, Any]]" = queue.Queue()
        self._worker: Optional[threading.Thread] = None

    # -- registry ---------------------------------------------------------
    def generate_scan_id(self, target: str) -> str:
        with self._lock:
            self._counter += 1
            return f"{slugify_target(target)}-{self._counter:04d}"

    def create_job(self, target: str, scan_id: Optional[str] = None,
                   scan_mode: str = "passive") -> ScanJob:
        sid = validate_scan_id(scan_id) if scan_id else self.generate_scan_id(target)
        with self._lock:
            if sid in self._jobs:
                raise ValueError(f"duplicate scan_id: {sid}")
            job = ScanJob(scan_id=sid, target=target, scan_mode=scan_mode)
            self._jobs[sid] = job
            return job

    def get_job(self, scan_id: str) -> Optional[ScanJob]:
        with self._lock:
            return self._jobs.get(scan_id)

    def request_cancel(self, scan_id: str) -> Optional[ScanJob]:
        with self._lock:
            job = self._jobs.get(scan_id)
            if job is None or job.status in ("completed", "failed", "cancelled"):
                return job
            job.cancel_requested = True
            if job.status == "queued":
                job.status = "cancelled"
                job.completed_at = datetime.now(timezone.utc).isoformat()
            return job

    def _set(self, job: ScanJob) -> None:
        with self._lock:
            self._jobs[job.scan_id] = job

    # -- background execution ---------------------------------------------
    def submit(self, scan_id: str, payload: Optional[dict[str, Any]] = None) -> ScanJob:
        job = self.get_job(scan_id)
        if job is None:
            raise ValueError(f"unknown scan_id: {scan_id}")
        with self._lock:
            if job.status not in ("queued",):
                raise ValueError(f"job {scan_id} already {job.status}")
        self._ensure_worker()
        self._queue.put({"scan_id": scan_id, **(payload or {})})
        return self.get_job(scan_id)

    def _ensure_worker(self) -> None:
        with self._lock:
            if self._worker is None or not self._worker.is_alive():
                thread = threading.Thread(target=self._work, daemon=True,
                                          name="tracehound-worker")
                self._worker = thread
                thread.start()

    def _work(self) -> None:
        while True:
            try:
                item = self._queue.get(timeout=0.5)
            except queue.Empty:
                return
            scan_id = item.pop("scan_id")
            job = self.get_job(scan_id)
            if job is None or job.status != "queued":
                self._queue.task_done()
                continue
            job.status = "running"
            job.started_at = datetime.now(timezone.utc).isoformat()
            self._set(job)
            stage_log(log, scan_id, "<job>", "running")

            def _publish(result) -> None:
                current = self.get_job(scan_id)
                if current is None:
                    return
                with self._lock:
                    current.stage_results = [
                        r for r in current.stage_results
                        if r.stage_id != result.stage_id
                    ] + [result]
                    current.current_stage = result.stage_id
                    self._jobs[scan_id] = current

            try:
                result = self._pipeline_fn(
                    scan_id=scan_id, target=job.target,
                    should_stop=lambda: bool(self.get_job(scan_id)
                                             and self.get_job(scan_id).cancel_requested),
                    on_stage=_publish,
                    **{k: v for k, v in item.items()})
                job = self.get_job(scan_id)
                # Operator intent wins: a requested cancel marks cancelled
                # even if the run just finished; evidence is still preserved.
                job.status = "cancelled" if job.cancel_requested else result.status
                if job.status == "completed":
                    job.report_path = result.report_path or ""
                job.current_stage = ""
                job.stage_results = result.stages
                job.error = result.error or ""
                job.completed_at = datetime.now(timezone.utc).isoformat()
                self._set(job)
                stage_log(log, scan_id, "<job>", job.status)
            except Exception as exc:
                job = self.get_job(scan_id)
                job.status = "failed" if not job.cancel_requested else "cancelled"
                job.error = str(exc)[:1000]
                job.completed_at = datetime.now(timezone.utc).isoformat()
                self._set(job)
                stage_log(log, scan_id, "<job>", job.status)
            finally:
                self._queue.task_done()

    def reset(self) -> None:
        """Test helper: clear registry and counter (process-local state)."""
        with self._lock:
            self._jobs.clear()
            self._counter = 0
