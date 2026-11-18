"""Event-driven monitoring plus periodic reconciliation.

Uses watchdog's macOS FSEvents observer on macOS. Never watches user documents
or other personal file contents. All processing is metadata-only.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
import platform
import signal
import threading
import time
from pathlib import Path

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from .discovery import discover
from .storage import connect, reconcile

LOG = logging.getLogger(__name__)

RECONCILE_SECONDS = 30 * 60
DEBOUNCE_SECONDS = 5
WEEK_SECONDS = 7 * 24 * 60 * 60
WAKE_GAP_SECONDS = 120


def deep_scan_due(last_deep: str | None, now: datetime) -> bool:
    if not last_deep:
        return True
    try:
        previous = datetime.fromisoformat(last_deep)
    except ValueError:
        return True
    if previous.tzinfo is None:
        return True
    return now - previous >= timedelta(seconds=WEEK_SECONDS)


def last_deep_scan(conn: object) -> str | None:
    result = conn.execute(
        "SELECT finished_at FROM scans WHERE kind = ? AND status = ? "
        "AND finished_at IS NOT NULL ORDER BY id DESC LIMIT 1",
        ("deep", "success"),
    ).fetchone()
    return result[0] if result else None


class ChangeHandler(FileSystemEventHandler):
    def __init__(self, pending: threading.Event) -> None:
        super().__init__()
        self.pending = pending
        self.last_change = 0.0

    def on_any_event(self, event: FileSystemEvent) -> None:
        # FSEvents notifications are hints, not proof of a configuration change.
        if event.event_type not in {"opened", "closed", "closed_no_write"}:
            self.last_change = time.monotonic()
            self.pending.set()


def paths_to_watch() -> list[Path]:
    # Controlled roots only. Do not traverse ~/Documents, ~/Downloads, etc.
    return [p for p in (
        Path("/Applications"),
        Path.home() / "Applications",
        Path("/opt/homebrew/Cellar"),
        Path("/opt/homebrew/Caskroom"),
        Path("/usr/local/Cellar"),
        Path("/usr/local/Caskroom"),
    ) if p.is_dir()]


def run() -> None:
    if platform.system() != "Darwin":
        raise RuntimeError("The real-time monitor requires macOS")
    pending = threading.Event()
    handler = ChangeHandler(pending)
    observer = Observer()
    for root in paths_to_watch():
        observer.schedule(handler, str(root), recursive=True)

    stop = threading.Event()
    def request_stop(signum: int, frame: object) -> None:
        stop.set()
    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)

    observer.start()
    next_periodic = time.monotonic()  # Initial discovery at startup.
    last_wall = time.time()
    try:
        while not stop.is_set():
            now = time.monotonic()
            wall = time.time()
            woke = wall - last_wall > WAKE_GAP_SECONDS
            last_wall = wall
            event_ready = pending.is_set() and now - handler.last_change >= DEBOUNCE_SECONDS
            scheduled = now >= next_periodic or woke
            if event_ready or scheduled:
                pending.clear()
                try:
                    with connect() as conn:
                        kind = "deep" if deep_scan_due(last_deep_scan(conn), datetime.now(timezone.utc)) else "routine"
                        inventory = discover(mode=kind)
                        reconcile(conn, inventory.observations, kind=kind,
                                  completed_categories=inventory.completed_categories)
                except Exception:
                    LOG.exception("Reconciliation failed; previous state preserved")
                next_periodic = time.monotonic() + RECONCILE_SECONDS
            stop.wait(1)
    finally:
        observer.stop()
        observer.join(timeout=10)
