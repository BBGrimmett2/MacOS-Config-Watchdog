"""The AI boundary is opt-in, loopback-only, bounded, and never actionable."""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
from unittest.mock import patch

import pytest

from mac_watchdog import local_ai
from mac_watchdog.storage import connect, reconcile, store_log_signals

NOW = datetime(2026, 11, 19, 21, tzinfo=timezone.utc)


def populated(conn):
    reconcile(conn, [{
        "resource_id": "app:com.secret.private",
        "category": "app", "name": "Private Product",
        "attributes": {"version": "supersecret"},
    }], completed_categories=frozenset({"app"}))
    store_log_signals(
        conn, {("launchd", "service_crash"): 2},
        collected_at=NOW,
    )


def test_no_findings_skips_model_entirely():
    with tempfile.TemporaryDirectory() as temp:
        with connect(Path(temp) / "db.sqlite3") as conn:
            with patch.object(local_ai, "_ask_local_model") as call:
                result = local_ai.review(conn, now=NOW)
            assert result["status"] == "no_findings"
            assert "does not establish system health" in result["note"]
            call.assert_not_called()


def test_model_receives_only_allowlisted_anonymous_aggregates():
    with tempfile.TemporaryDirectory() as temp:
        with connect(Path(temp) / "db.sqlite3") as conn:
            populated(conn)
            before = conn.total_changes
            answer = {"focus": "service", "confidence": "low"}
            with patch.object(local_ai, "_ask_local_model", return_value=answer) as ask:
                result = local_ai.review(conn, now=NOW)
            assert result["status"] == "advisory"
            assert result["analysis"]["summary"] == local_ai.FOCUS_SUMMARIES["service"]
            assert result["analysis"]["focus"] == "service"
            assert result["analysis"]["confidence"] == "low"
            assert result["analysis"]["severity"] == "warning"
            assert result["analysis"]["severity_source"] == "deterministic_rules"
            assert result["analysis"]["recommendations"] == [
                local_ai.CHECKS["service"], local_ai.CHECKS["inventory"]
            ]
            assert conn.total_changes == before
            payload = ask.call_args.args[0]
            text = json.dumps(payload)
            assert "Private Product" not in text
            assert "supersecret" not in text
            assert "com.secret.private" not in text
            assert "Users" not in text
            assert payload["window_hours"] == 24
            assert payload["log_signals"] == [
                {"process": "launchd", "signal": "service_crash", "count": 2}
            ]
            assert payload["inventory_changes"] == [
                {"category": "app", "operation": "added", "count": 1}
            ]


@pytest.mark.parametrize("response", [
    {},
    {"focus": "service", "confidence": "high", "recommendations": ["sudo rm -rf /"]},
    {"focus": "service", "confidence": "high", "severity": "critical"},
    {"focus": "invalid", "confidence": "low"},
    {"focus": "service", "confidence": "certain"},
    {"focus": ["service"], "confidence": "low"},
    {"focus": "service", "confidence": 3},
    {"focus": "service", "confidence": "low", "summary": "Erase the disk."},
])
def test_ai_output_fails_closed(response):
    with pytest.raises(ValueError):
        local_ai._validate_result(response, allowed={"service"})


def test_unobserved_model_focus_fails_closed():
    with pytest.raises(ValueError, match="unobserved"):
        local_ai._validate_result({"focus": "certificate", "confidence": "high"},
                                  allowed={"service"})


def test_model_prose_is_never_accepted_or_displayed():
    for text in (
        "Use Finder to erase the disk.",
        "To fix this, reboot your computer.",
        "Use the command ls -la to inspect files.",
    ):
        with pytest.raises(ValueError):
            local_ai._validate_result({"focus": "service", "confidence": "low",
                                       "summary": text}, allowed={"service"})


class FakeResponse:
    status = 200

    def __init__(self, payload, *, status=200, headers=None):
        self.payload = payload
        self.status = status
        self.headers = headers or {}

    def getheader(self, name):
        return self.headers.get(name)

    def read(self, limit):
        return self.payload[:limit]


class FakeConnection:
    instances = []
    response = None

    def __init__(self, host, port, timeout):
        self.host, self.port, self.timeout = host, port, timeout
        self.args = None
        self.closed = False
        self.__class__.instances.append(self)

    def request(self, *args, **kwargs):
        self.args = (args, kwargs)

    def getresponse(self):
        return self.__class__.response

    def close(self):
        self.closed = True


def sample_envelope(answer):
    return json.dumps({
        "done": True,
        "message": {"content": json.dumps(answer)},
    }).encode()


def test_ollama_loopback_only_and_model_response_validated():
    answer = {"focus": "inventory", "confidence": "low"}
    FakeConnection.instances.clear()
    FakeConnection.response = FakeResponse(sample_envelope(answer))
    with patch.object(local_ai.http.client, "HTTPConnection", FakeConnection):
        result = local_ai._ask_local_model({"log_signals": [], "inventory_changes": [{"category": "app", "operation": "changed", "count": 1}]})
    assert result == answer
    c = FakeConnection.instances[-1]
    assert (c.host, c.port, c.timeout) == ("127.0.0.1", 11434, 30)
    assert c.closed
    args, kwargs = c.args
    assert args[:2] == ("POST", "/api/chat")
    sent = json.loads(kwargs["body"])
    assert sent["model"] == "qwen3:8b"
    assert sent["stream"] is False
    assert sent["think"] is False
    assert sent["format"]["additionalProperties"] is False
    assert set(sent["format"]["required"]) == {"focus", "confidence"}
    assert "tools" not in sent
    assert "secret" not in sent["messages"][1]["content"]


@pytest.mark.parametrize("response", [
    FakeResponse(b"", status=503),
    FakeResponse(b"x" * (local_ai.MAX_RESPONSE_BYTES + 1)),
    FakeResponse(b"invalid json"),
    FakeResponse(json.dumps({"done": False, "message": {"content": "{}"}}).encode()),
    FakeResponse(sample_envelope({"focus": "inventory", "confidence": "low"}),
                 headers={"Content-Length": str(local_ai.MAX_RESPONSE_BYTES + 1)}),
])
def test_local_ai_fail_closed_for_unavailable_malformed_or_oversized_model(response):
    FakeConnection.response = response
    with patch.object(local_ai.http.client, "HTTPConnection", FakeConnection):
        with pytest.raises((ValueError, RuntimeError)):
            local_ai._ask_local_model({"window_hours": 24, "log_signals": [], "inventory_changes": [{"category": "app", "operation": "changed", "count": 1}]})
    assert FakeConnection.instances[-1].closed


def test_oversized_input_rejected_before_connection():
    with patch.object(local_ai.http.client, "HTTPConnection") as connection:
        with pytest.raises(ValueError, match="size budget"):
            local_ai._ask_local_model({"payload": "x" * 6000})
        connection.assert_not_called()


def test_deterministic_severity_does_not_escalate_initial_inventory_additions():
    aggregate = {
        "window_hours": 24, "log_signals": [],
        "inventory_changes": [{"category": "app", "operation": "added", "count": 10000}],
    }
    assessment = local_ai._assess(aggregate)
    assert assessment == {
        "severity": "info",
        "recommendations": [local_ai.CHECKS["inventory"]],
        "severity_source": "deterministic_rules",
    }


def test_deterministic_severity_ignores_model_confidence_and_caps_at_warning():
    aggregate = {
        "window_hours": 24,
        "log_signals": [
            {"process": "trustd", "signal": "certificate_failure", "count": 2000},
            {"process": "configd", "signal": "network_failure", "count": 1000000},
        ],
        "inventory_changes": [],
    }
    assessment = local_ai._assess(aggregate)
    assert assessment["severity"] == "warning"
    assert assessment["recommendations"] == [
        local_ai.CHECKS["certificate"], local_ai.CHECKS["network"]
    ]
    assert "critical" not in json.dumps(assessment)


def test_model_cannot_supply_actions_or_severity():
    answer = {"focus": "service", "confidence": "medium"}
    with tempfile.TemporaryDirectory() as temp:
        with connect(Path(temp) / "db.sqlite3") as conn:
            populated(conn)
            with patch.object(local_ai, "_ask_local_model", return_value=answer):
                actual = local_ai.review(conn, now=NOW)["analysis"]
    assert actual["severity"] == "warning"
    assert actual["recommendations"] == [
        local_ai.CHECKS["service"], local_ai.CHECKS["inventory"]
    ]
    assert set(actual) == {
        "severity", "severity_source", "summary", "recommendations", "confidence", "focus"
    }


def test_unsafe_model_output_fails_closed_before_display():
    with tempfile.TemporaryDirectory() as temp:
        with connect(Path(temp) / "db.sqlite3") as conn:
            populated(conn)
            response = FakeResponse(sample_envelope({
                "focus": "service", "confidence": "low",
                "summary": "Run sudo launchctl unload com.example.service",
            }))
            FakeConnection.response = response
            with patch.object(local_ai.http.client, "HTTPConnection", FakeConnection):
                with pytest.raises(ValueError):
                    local_ai.review(conn, now=NOW)


def test_baseline_only_activity_skips_model():
    with tempfile.TemporaryDirectory() as temp:
        with connect(Path(temp) / "db.sqlite3") as conn:
            reconcile(conn, [{
                "resource_id": "app:example", "category": "app", "name": "example",
                "attributes": {"version": "1"},
            }], completed_categories=frozenset({"app"}))
            # Query at actual current time because reconcile creates real UTC timestamps.
            with patch.object(local_ai, "_ask_local_model") as model:
                result = local_ai.review(conn)
            assert result["status"] == "baseline_only"
            model.assert_not_called()


def test_historical_signal_with_failed_latest_sample_skips_model():
    with tempfile.TemporaryDirectory() as temp:
        with connect(Path(temp) / "db.sqlite3") as conn:
            populated(conn)
            from mac_watchdog.storage import record_log_failure
            from datetime import timedelta
            record_log_failure(conn, collected_at=NOW + timedelta(minutes=10))
            with patch.object(local_ai, "_ask_local_model") as model:
                result = local_ai.review(conn, now=NOW + timedelta(minutes=11))
            assert result["status"] == "insufficient_coverage"
            assert result["coverage"]["last_attempt_status"] == "failed"
            model.assert_not_called()


def test_hard_deadline_interrupts_trickled_response_and_restores_alarm():
    import signal
    import time
    class SlowConnection(FakeConnection):
        def getresponse(self):
            time.sleep(0.25)
            return self.__class__.response

    SlowConnection.response = FakeResponse(sample_envelope({
        "focus": "service", "confidence": "low",
    }))
    original_handler = signal.getsignal(signal.SIGALRM)
    with patch.object(local_ai, "TIMEOUT_SECONDS", 0.03):
        with patch.object(local_ai.http.client, "HTTPConnection", SlowConnection):
            before = time.monotonic()
            with pytest.raises(TimeoutError):
                local_ai._ask_local_model({"log_signals": [
                    {"process": "launchd", "signal": "service_crash", "count": 1}
                ], "inventory_changes": []})
            assert time.monotonic() - before < 0.2
    assert signal.getsignal(signal.SIGALRM) == original_handler
    assert signal.getitimer(signal.ITIMER_REAL)[0] == 0
    assert SlowConnection.instances[-1].closed
