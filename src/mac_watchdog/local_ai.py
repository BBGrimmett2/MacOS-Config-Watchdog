"""On-demand read-only local AI review of anonymous watchdog aggregate counts.

No resource IDs, paths, raw logs, prompts from files, network fallback or tools.
The model can only return untrusted advisory text with a strict schema.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import http.client
import json
import re
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
# Model output can contain an explanatory sentence ONLY. Recommended checks
# are selected from local constants, never returned by the model.
FORBIDDEN_TEXT = re.compile(
    r"(?:https?://|file://|/(?:Users|private|etc|var|opt|tmp)/|"
    r"[A-Za-z]:\\\\|[\\x00-\\x1f\\x7f]|"
    r"[\\w.+-]+@[\\w.-]+\\.[A-Za-z]{2,}|"
    r"\\b(?:sudo|chmod|chown|launchctl|rm|curl|wget|bash|zsh|"
    r"osascript|python3?|pip3?|brew|ansible-playbook|"
    r"execute|run|install|uninstall|disable|enable|delete|remove)\\b|"
    r"[;&|><`$])",
    re.I,
)
# These are conservative informational next checks, not runnable commands.
CHECKS = {
    "service": "Inspect service stability using trusted local diagnostics.",
    "certificate": "Review certificate validation failures through trusted local diagnostics.",
    "network": "Review network and name-resolution stability using trusted local diagnostics.",
    "inventory": "Review recent inventory changes against the Ansible expected-state manifest.",
}
SYSTEM_PROMPT = (
    "Analyze anonymous macOS monitoring counts. They contain only fixed "
    "categories and counts, not diagnostic evidence. Briefly explain the "
    "observed aggregate pattern without asserting a cause or system health. "
    "Return JSON with exactly two fields: summary (one declarative sentence "
    "without instructions, commands, paths, URLs, names or identifiers), "
    "confidence (low|medium|high). Do not recommend any actions; the "
    "application selects safe informational checks deterministically."
)


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


def _validate_text(value: Any, *, max_len: int) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= max_len:
        raise ValueError("Invalid AI text length or type")
    if FORBIDDEN_TEXT.search(value):
        raise ValueError("AI response contained unsupported text")
    return value


def _validate_result(result: Any) -> dict[str, Any]:
    if not isinstance(result, dict) or set(result) != {"summary", "confidence"}:
        raise ValueError("AI response has unsupported schema")
    if (not isinstance(result["confidence"], str)
            or result["confidence"] not in {"low", "medium", "high"}):
        raise ValueError("AI response has invalid confidence")
    return {
        "summary": _validate_text(result["summary"], max_len=360),
        "confidence": result["confidence"],
    }


def _assess(aggregate: dict[str, Any]) -> dict[str, Any]:
    """Deterministic advisory level and static, non-executable next checks.

    With aggregate-only evidence, never classify an incident as critical.
    Initial discovery's bulk 'added' events are informational, not faults.
    """
    kinds = {(row["process"], row["signal"]) for row in aggregate["log_signals"]
             if row["count"] > 0}
    checks = []
    if any(process == "launchd" for process, _ in kinds):
        checks.append(CHECKS["service"])
    if ("trustd", "certificate_failure") in kinds:
        checks.append(CHECKS["certificate"])
    if any(process in {"mDNSResponder", "configd"} for process, _ in kinds):
        checks.append(CHECKS["network"])
    if aggregate["inventory_changes"]:
        checks.append(CHECKS["inventory"])
    return {
        "severity": "warning" if kinds else "info",
        "recommendations": checks,
        "severity_source": "deterministic_rules",
    }


def _ask_local_model(payload: dict[str, Any]) -> dict[str, Any]:
    user_message = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    if len(user_message.encode("utf-8")) > MAX_PROMPT_BYTES:
        raise ValueError("Aggregated AI input exceeded size budget")
    request = json.dumps({
        "model": MODEL, "stream": False, "think": False, "format": "json",
        "options": {"temperature": 0, "num_predict": 400},
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_message},
        ],
    }, separators=(",", ":")).encode("utf-8")
    # Fixed loopback address: cannot be redirected to a cloud provider or proxy.
    connection = http.client.HTTPConnection(HOST, PORT, timeout=TIMEOUT_SECONDS)
    try:
        connection.request(
            "POST", "/api/chat", body=request,
            headers={"Content-Type": "application/json", "Connection": "close"},
        )
        response = connection.getresponse()
        if response.status != 200:
            raise RuntimeError("Local Ollama request failed; model may not be installed")
        if response.getheader("Content-Length") is not None:
            try:
                size = int(response.getheader("Content-Length"))
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
    return _validate_result(result)


def review(conn: sqlite3.Connection, *, now: datetime | None = None) -> dict[str, Any]:
    """Explicit invocation only; no model request for zero aggregate findings."""
    aggregate = _aggregate(conn, now or datetime.now(timezone.utc))
    if not aggregate["log_signals"] and not aggregate["inventory_changes"]:
        return {
            "schema_version": 1, "mode": "read_only",
            "status": "no_findings",
            "note": "No recorded signals or inventory changes in 24 hours; not proof of system health.",
        }
    assessment = _assess(aggregate)
    verdict = _ask_local_model(aggregate)
    return {
        "schema_version": 1, "mode": "read_only", "status": "advisory",
        "model": MODEL, "window_hours": 24,
        "analysis": {**assessment, **verdict},
        "note": "Model advice is unverified. No actions were performed.",
    }
