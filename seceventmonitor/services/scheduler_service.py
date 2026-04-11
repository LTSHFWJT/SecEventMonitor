from __future__ import annotations

import logging
import threading
from collections.abc import Callable

from seceventmonitor.extensions import db
from seceventmonitor.models import GithubMonitoredTool
from seceventmonitor.services import settings as settings_service
from seceventmonitor.services.sync_service import (
    GITHUB_POC_SYNC_SOURCE,
    GITHUB_TOOLS_SYNC_SOURCE,
    get_vulnerability_sync_sources,
    start_sync_async,
)


logger = logging.getLogger(__name__)


class IntervalSyncScheduler:
    def __init__(
        self,
        *,
        scheduler_name: str,
        thread_name: str,
        load_interval_minutes: Callable[[], int],
        trigger_callback: Callable[[], None],
    ) -> None:
        self.scheduler_name = scheduler_name
        self.thread_name = thread_name
        self._load_interval_minutes = load_interval_minutes
        self._trigger_callback = trigger_callback
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._wake_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._interval_minutes = 60

    def start(self) -> None:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._interval_minutes = self._safe_load_interval_minutes()
            self._stop_event = threading.Event()
            self._wake_event = threading.Event()
            self._thread = threading.Thread(
                target=self._run_loop,
                name=self.thread_name,
                daemon=True,
            )
            self._thread.start()
            logger.info("%s started with interval=%s minutes", self.scheduler_name, self._interval_minutes)

    def reload(self) -> None:
        with self._lock:
            self._interval_minutes = self._safe_load_interval_minutes()
            if self._thread is None or not self._thread.is_alive():
                self._stop_event = threading.Event()
                self._wake_event = threading.Event()
                self._thread = threading.Thread(
                    target=self._run_loop,
                    name=self.thread_name,
                    daemon=True,
                )
                self._thread.start()
                logger.info("%s started with interval=%s minutes", self.scheduler_name, self._interval_minutes)
                return
            self._wake_event.set()
            logger.info("%s reloaded with interval=%s minutes", self.scheduler_name, self._interval_minutes)

    def stop(self) -> None:
        with self._lock:
            thread = self._thread
            if thread is None:
                return
            self._stop_event.set()
            self._wake_event.set()
        thread.join(timeout=5)
        with self._lock:
            if self._thread is thread:
                self._thread = None
        logger.info("%s stopped", self.scheduler_name)

    def snapshot(self) -> dict[str, int | bool]:
        with self._lock:
            return {
                "running": bool(self._thread and self._thread.is_alive()),
                "interval_minutes": self._interval_minutes,
            }

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            timeout = max(float(self._interval_minutes) * 60.0, 1.0)
            interrupted = self._wake_event.wait(timeout=timeout)
            self._wake_event.clear()
            if self._stop_event.is_set():
                break
            if interrupted:
                continue
            self._trigger_sync()
            with self._lock:
                self._interval_minutes = self._safe_load_interval_minutes()

    def _trigger_sync(self) -> None:
        try:
            self._trigger_callback()
        except Exception:
            logger.exception("%s dispatch failed", self.scheduler_name)
        finally:
            db.remove()

    def _safe_load_interval_minutes(self) -> int:
        try:
            return self._load_interval_minutes()
        finally:
            db.remove()


def _trigger_vulnerability_sync() -> None:
    result = start_sync_async(source=get_vulnerability_sync_sources())
    logger.info("scheduled vulnerability sync dispatch result=%s", result.get("status"))


def _trigger_github_monitor_sync() -> None:
    sources = [GITHUB_POC_SYNC_SOURCE]
    if GithubMonitoredTool.query.count() > 0:
        sources.append(GITHUB_TOOLS_SYNC_SOURCE)
    else:
        logger.info("scheduled github tool sync skipped because no monitored tools configured")
    result = start_sync_async(source=sources)
    logger.info("scheduled github monitor sync dispatch result=%s sources=%s", result.get("status"), sources)


_VULNERABILITY_SCHEDULER = IntervalSyncScheduler(
    scheduler_name="vulnerability sync scheduler",
    thread_name="vulnerability-sync-scheduler",
    load_interval_minutes=settings_service.get_monitor_interval_minutes,
    trigger_callback=_trigger_vulnerability_sync,
)

_GITHUB_MONITOR_SCHEDULER = IntervalSyncScheduler(
    scheduler_name="github monitor scheduler",
    thread_name="github-monitor-scheduler",
    load_interval_minutes=settings_service.get_github_monitor_interval_minutes,
    trigger_callback=_trigger_github_monitor_sync,
)


def start_scheduler() -> None:
    _VULNERABILITY_SCHEDULER.start()
    _GITHUB_MONITOR_SCHEDULER.start()


def reload_scheduler() -> None:
    _VULNERABILITY_SCHEDULER.reload()
    _GITHUB_MONITOR_SCHEDULER.reload()


def stop_scheduler() -> None:
    _VULNERABILITY_SCHEDULER.stop()
    _GITHUB_MONITOR_SCHEDULER.stop()


def get_scheduler_snapshot() -> dict[str, dict[str, int | bool]]:
    return {
        "vulnerability": _VULNERABILITY_SCHEDULER.snapshot(),
        "github_monitor": _GITHUB_MONITOR_SCHEDULER.snapshot(),
    }
