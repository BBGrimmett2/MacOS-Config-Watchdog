"""On-demand read-only local AI review of anonymous watchdog aggregate counts.

No resource IDs, paths, raw logs, prompts from files, network fallback or tools.
The model can only return untrusted advisory text with a strict schema.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import http.client
import json
import signal
import threading
from contextlib import contextmanager
from collections.abc import Iterator
import sqlite3
from typing import Any

MODEL = "qwen3:8b"
HOST = "127.0.0.1"
PORT = 11434
TIMEOUT_SECONDS = 30
MAX_RESPONSE_BYTES = 16 * 1024
MAX_PROMPT_BYTES = 4096
SIGNAL_TYPES = frozenset({
    ("launchd", "service_crash"), ("launchd", "service_restart"),
    ("trustd", "certificate_failure"), ("mDNSResponder", "dns_failure"),
    ("configd", "network_failure"),
})
CHANGE_CATEGORIES = frozenset({
    "app", "brew_formula", "brew_cask", "pkg_receipt", "launchd", "macos_build",
})
CHANGE_OPERATIONS = frozenset({"added", "changed", "removed"})
# The model selects a structured focus only. Displayed text is code-owned.
FOCUS_SUMMARIES = {
    "service": "Service instability signals were recorded in the selected period.",
    "certificate": "Certificate validation failure signals were recorded in the selected period.",
    "network": "Network or name-resolution failure signals were recorded in the selected period.",
    "inventory": "Configuration inventory changes were recorded in the selected period.",
}
CHECKS = {
    "service": "Inspect service stability using trusted local diagnostics.",
    "certificate": "Review certificate validation failures through trusted local diagnostics.",
    "network": "Review network and name-resolution stability using trusted local diagnostics.",
    "inventory": "Review recent inventory changes against the Ansible expected-state manifest.",
}
OUTPUT_FORMAT = {
    "type": "object",
    "properties": {
        "focus": {"type": "string", "enum": sorted(FOCUS_SUMMARIES)},
        "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
    },
    "required": ["focus", "confidence"],
    "additionalProperties": False,
}
SYSTEM_PROMPT = (
    "Classify anonymous macOS aggregate counts. Choose only a focus "
    "category present in the supplied input. Return JSON matching the "
    "required schema. Never generate prose, instructions, or identifiers."
)


@contextmanager
def _hard_deadline() -> Iterator[None]:
    """Bound the entire inference, including slow headers and trickled bytes."""
    if threading.current_thread() is not threading.main_thread():
        raise RuntimeError("Local inference requires the main thread")
    if signal.getitimer(signal.ITIMER_REAL)[0] > 0:
        raise RuntimeError("Existing alarm prevents bounded local inference")
    previous = signal.getsignal(signal.SIGALRM)

    def timed_out(_signum: int, _frame: Any) -> None:
        raise TimeoutError("Local model exceeded total 30-second budget")

    signal.signal(signal.SIGALRM, timed_out)
    signal.setitimer(signal.ITIMER_REAL, TIMEOUT_SECONDS)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def _aggregate(conn: sqlite3.Connection, now: datetime) -> dict[str, Any]:
    """SQL reads only. Whitelisted dimensions, no names/IDs/message content."""
    if now.tzinfo is None:
        raise ValueError("Timestamp must be timezone-aware")
    cutoff = (now.astimezone(timezone.utc) - timedelta(hours=24)).isoformat()
    signals = []
    for row in conn.execute(
        "SELECT process,signal,SUM(count) AS total FROM log_signals "
        "WHERE window_start >= ? GROUP BY process,signal ORDER BY process,signal",
        (cutoff,),
    ):
        key = (row["process"], row["signal"])
        if key not in SIGNAL_TYPES or type(row["total"]) is not int or row["total"] < 0:
            raise ValueError("Unexpected log signal metadata")
        signals.append({"process": key[0], "signal": key[1], "count": min(row["total"], 1000000)})
    changes = []
    for row in conn.execute(
        "SELECT r.category AS category,c.operation AS operation,COUNT(*) AS total "
        "FROM changes c JOIN resources r ON r.resource_id=c.resource_id "
        "WHERE c.occurred_at >= ? GROUP BY r.category,c.operation "
        "ORDER BY r.category,c.operation",
        (cutoff,),
    ):
        if row["category"] not in CHANGE_CATEGORIES or row["operation"] not in CHANGE_OPERATIONS:
            raise ValueError("Unexpected inventory change metadata")
        changes.append({
            "category": row["category"], "operation": row["operation"],
            "count": min(row["total"], 1000000),
        })
    return {"window_hours": 24, "log_signals": signals, "inventory_changes": changes}


def _allowed_focus(aggregate: dict[str, Any]) -> set[str]:
    kinds = {(row["process"], row["signal"]) for row in aggregate["log_signals"]
             if row["count"] > 0}
    allowed: set[str] = set()
    if any(process == "launchd" for process, _ in kinds):
        allowed.add("service")
    if ("trustd", "certificate_failure") in kinds:
        allowed.add("certificate")
    if any(process in {"mDNSResponder", "configd"} for process, _ in kinds):
        allowed.add("network")
    if aggregate["inventory_changes"]:
        allowed.add("inventory")
    return allowed


def _validate_result(result: Any, *, allowed: set[str]) -> dict[str, str]:
    if not isinstance(result, dict) or set(result) != {"focus", "confidence"}:
        raise ValueError("AI response has unsupported schema")
    focus, confidence = result["focus"], result["confidence"]
    if not isinstance(focus, str) or focus not in FOCUS_SUMMARIES or focus not in allowed:
        raise ValueError("AI response contains an unobserved focus")
    if not isinstance(confidence, str) or confidence not in {"low", "medium", "high"}:
        raise ValueError("AI response has invalid confidence")
    return {"focus": focus, "confidence": confidence}


def _assess(aggregate: dict[str, Any]) -> dict[str, Any]:
    """Advisory severity never escalates initial inventory additions."""
    allowed = _allowed_focus(aggregate)
    checks = [CHECKS[name] for name in ("service", "certificate", "network", "inventory")
              if name in allowed]
    return {
        "severity": "warning" if aggregate["log_signals"] else "info",
        "recommendations": checks,
        "severity_source": "deterministic_rules",
    }


def _ask_local_model(payload: dict[str, Any]) -> dict[str, str]:
    allowed = _allowed_focus(payload)
    if not allowed:
        raise ValueError("No observed focus for local inference")
    user_message = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    if len(user_message.encode("utf-8")) > MAX_PROMPT_BYTES:
        raise ValueError("Aggregated AI input exceeded size budget")
    request = json.dumps({
        "model": MODEL, "stream": False, "think": False, "format": OUTPUT_FORMAT,
        "options": {"temperature": 0, "num_predict": 128},
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_message},
        ],
    }, separators=(",", ":")).encode("utf-8")
    with _hard_deadline():
        connection = http.client.HTTPConnection(HOST, PORT, timeout=TIMEOUT_SECONDS)
        try:
            connection.request(
                "POST", "/api/chat", body=request,
                headers={"Content-Type": "application/json", "Connection": "close"},
            )
            response = connection.getresponse()
            if response.status != 200:
                raise RuntimeError("Local Ollama request failed; model may not be installed")
            length = response.getheader("Content-Length")
            if length is not None:
                try:
                    size = int(length)
                except ValueError as exc:
                    raise ValueError("Invalid local model response length") from exc
                if size < 0 or size > MAX_RESPONSE_BYTES:
                    raise ValueError("Local model response exceeded size budget")
            raw = response.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                raise ValueError("Local model response exceeded size budget")
        finally:
            connection.close()
        try:
            envelope = json.loads(raw)
            if not isinstance(envelope, dict) or envelope.get("done") is not True:
                raise ValueError("Incomplete local model response")
            message = envelope.get("message")
            if not isinstance(message, dict) or not isinstance(message.get("content"), str):
                raise ValueError("Local model returned no message")
            result = json.loads(message["content"])
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError("Local model returned invalid JSON") from exc
        return _validate_result(result, allowed=allowed)


def review(conn: sqlite3.Connection, *, now: datetime | None = None) -> dict[str, Any]:
    """Invoke only for meaningful changes; always surface monitoring gaps."""
    from .storage import collection_health
    now = now or datetime.now(timezone.utc)
    aggregate = _aggregate(conn, now)
    coverage = collection_health(conn, now=now)
    if not aggregate["log_signals"] and not aggregate["inventory_changes"]:
        return {
            "schema_version": 1, "mode": "read_only", "status": "no_findings",
            "coverage": coverage,
            "note": "No recorded findings; this does not establish system health.",
        }
    assessment = _assess(aggregate)
    meaningful_inventory = any(
        row["operation"] in {"changed", "removed"}
        for row in aggregate["inventory_changes"]
    )
    if not aggregate["log_signals"] and not meaningful_inventory:
        return {
            "schema_version": 1, "mode": "read_only",
            "status": "baseline_only", "coverage": coverage,
            "analysis": assessment,
            "note": "Only additions were recorded; no model inference performed.",
        }
    if aggregate["log_signals"] and coverage["status"] != "recent_sample_unverified":
        return {
            "schema_version": 1, "mode": "read_only",
            "status": "insufficient_coverage", "coverage": coverage,
            "analysis": assessment,
            "note": "Log sampling is stale or unverified; no model inference performed.",
        }
    verdict = _ask_local_model(aggregate)
    return {
        "schema_version": 1, "mode": "read_only", "status": "advisory",
        "model": MODEL, "window_hours": 24, "coverage": coverage,
        "analysis": {
            **assessment,
            "summary": FOCUS_SUMMARIES[verdict["focus"]],
            "focus": verdict["focus"], "confidence": verdict["confidence"],
        },
        "note": "Model selection is unverified. No actions were performed.",
    }
