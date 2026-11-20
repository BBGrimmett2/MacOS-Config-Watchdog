"""Bounded, read-only macOS unified log signals; never retain message contents."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import json
import os
import platform
import re
import selectors
import subprocess
import time
from typing import Any

WINDOW_MINUTES = 5
MAX_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_RECORDS = 10000
TIMEOUT_SECONDS = 20
# Restrict unified log collection to known macOS service processes.
# Log lines are untrusted data; no log text is ever written to disk.
PROCESSES = frozenset({"launchd", "trustd", "mDNSResponder", "configd"})
SIGNALS = {
    "launchd": (
        ("service_crash", re.compile(r"\b(?:crash(?:ed|ing)?|exited abnormally|segmentation fault)\b", re.I)),
        ("service_restart", re.compile(r"\b(?:throttl(?:ed|ing)|respawn(?:ed|ing)?|restarting)\b", re.I)),
    ),
    "trustd": (
        ("certificate_failure", re.compile(r"\b(?:certificate|trust evaluation|revocation)\b.{0,100}\b(?:fail(?:ed|ure)?|invalid|expired|rejected)\b", re.I)),
    ),
    "mDNSResponder": (
        ("dns_failure", re.compile(r"\b(?:dns|resolver|query)\b.{0,100}\b(?:fail(?:ed|ure)?|timeout|timed out)\b", re.I)),
    ),
    "configd": (
        ("network_failure", re.compile(r"\b(?:network|interface|route)\b.{0,100}\b(?:fail(?:ed|ure)?|timeout|unreachable)\b", re.I)),
    ),
}
# Filter at the macOS log query itself, before any sensitive message reaches
# Python. These static prefilters intentionally over-include candidate messages;
# the more specific SIGNALS regexes remain authoritative for classification.
# Process AND fault predicates prevent unrelated high-volume log records
# (including routine launchd and DNS activity) consuming the byte budget.
FAULT_TERMS = {
    "launchd": ("crash", "abnormal", "segmentation fault", "throttl", "respawn", "restart"),
    "trustd": ("fail", "invalid", "expired", "rejected"),
    "mDNSResponder": ("fail", "timeout", "timed out"),
    "configd": ("fail", "timeout", "unreachable"),
}
CONTEXT_TERMS = {
    "trustd": ("certificate", "trust evaluation", "revocation"),
    "mDNSResponder": ("dns", "resolver", "query"),
    "configd": ("network", "interface", "route"),
}


def _message_predicate(terms: tuple[str, ...]) -> str:
    return "(" + " OR ".join(
        f'eventMessage CONTAINS[c] "{term}"' for term in terms
    ) + ")"


def _log_predicate() -> str:
    clauses = []
    for process in sorted(PROCESSES):
        conditions = [f'process == "{process}"', _message_predicate(FAULT_TERMS[process])]
        if process in CONTEXT_TERMS:
            conditions.append(_message_predicate(CONTEXT_TERMS[process]))
        clauses.append("(" + " AND ".join(conditions) + ")")
    return " OR ".join(clauses)


PREDICATE = _log_predicate()


def _read_bounded(argv: list[str]) -> bytes:
    """Read stdout with hard byte and elapsed-time budgets, no shell or raw log files."""
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    selector = selectors.DefaultSelector()
    output = bytearray()
    started = time.monotonic()
    try:
        assert proc.stdout is not None
        selector.register(proc.stdout, selectors.EVENT_READ)
        while True:
            remaining = TIMEOUT_SECONDS - (time.monotonic() - started)
            if remaining <= 0:
                raise TimeoutError("Unified log query exceeded time budget")
            ready = selector.select(timeout=remaining)
            if not ready:
                raise TimeoutError("Unified log query exceeded time budget")
            chunk = os.read(proc.stdout.fileno(), min(65536, MAX_OUTPUT_BYTES + 1 - len(output)))
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > MAX_OUTPUT_BYTES:
                raise ValueError("Unified log query exceeded byte budget")
        remaining = max(0, TIMEOUT_SECONDS - (time.monotonic() - started))
        try:
            rc = proc.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError("Unified log query exceeded time budget") from exc
        if rc:
            raise RuntimeError("Unified log query failed or permissions are insufficient")
        return bytes(output)
    finally:
        selector.close()
        if proc.poll() is None:
            proc.kill()
        proc.wait()


def _signal(record: Any) -> tuple[str, str] | None:
    """Classify only static process/severity signals; never return message content."""
    if not isinstance(record, dict):
        return None
    process = record.get("process")
    message = record.get("eventMessage")
    if process not in PROCESSES or not isinstance(message, str):
        return None
    if len(message) > 4096:
        return None
    for label, pattern in SIGNALS[process]:
        if pattern.search(message):
            return (process, label)
    return None


def parse_events(raw: bytes) -> dict[tuple[str, str], int]:
    """A failed/incomplete query must never be interpreted as an empty successful window."""
    if len(raw) > MAX_OUTPUT_BYTES:
        raise ValueError("Unified log query exceeded byte budget")
    counts: Counter[tuple[str, str]] = Counter()
    for index, line in enumerate(raw.splitlines()):
        if index >= MAX_RECORDS:
            raise ValueError("Unified log query exceeded record budget")
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except (UnicodeDecodeError, ValueError) as exc:
            raise ValueError("Malformed unified log record") from exc
        match = _signal(record)
        if match is not None:
            counts[match] += 1
    return dict(counts)


def collect() -> dict[tuple[str, str], int]:
    if platform.system() != "Darwin":
        raise RuntimeError("Unified log collection requires macOS")
    raw = _read_bounded([
        "/usr/bin/log", "show", "--style", "ndjson", "--last",
        f"{WINDOW_MINUTES}m", "--predicate", PREDICATE,
    ])
    return parse_events(raw)


def collect_and_store(conn: Any) -> dict[str, Any]:
    """Persist aggregated, privacy-safe counts only after a complete log query."""
    from .storage import store_log_signals
    counts = collect()
    return store_log_signals(conn, counts, collected_at=datetime.now(timezone.utc))
