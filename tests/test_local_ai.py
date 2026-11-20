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
            assert "not proof" in result["note"]
            call.assert_not_called()


def test_model_receives_only_allowlisted_anonymous_aggregates():
    with tempfile.TemporaryDirectory() as temp:
        with connect(Path(temp) / "db.sqlite3") as conn:
            populated(conn)
            before = conn.total_changes
            answer = {"severity": "warning", "summary": "A service crash was detected.",
                      "recommendations": ["Review service stability locally."], "confidence": "low"}
            with patch.object(local_ai, "_ask_local_model", return_value=answer) as ask:
                result = local_ai.review(conn, now=NOW)
            assert result["status"] == "advisory"
            assert result["analysis"] == answer
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
    {}, {"severity": "warning", "summary": "ok", "recommendations": [], "confidence": "high", "execute": "rm -rf /"},
    {"severity": "critical", "summary": "visit https://example.com", "recommendations": [], "confidence": "high"},
    {"severity": "info", "summary": "Check /Users/private/file", "recommendations": [], "confidence": "low"},
    {"severity": "info", "summary": "ok", "recommendations": ["x"] * 6, "confidence": "low"},
    {"severity": "info", "summary": "ok", "recommendations": [], "confidence": "certain"},
    {"severity": "info", "summary": "ok", "recommendations": ["a" + chr(0) + "b"], "confidence": "low"},
])
def test_ai_output_fails_closed(response):
    with pytest.raises(ValueError):
        local_ai._validate_result(response)


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
    answer = {"severity": "warning", "summary": "Investigate repeated service exits.",
              "recommendations": ["Check locally recorded service health."], "confidence": "low"}
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
    assert "tools" not in sent
    assert "secret" not in sent["messages"][1]["content"]


@pytest.mark.parametrize("response", [
    FakeResponse(b"", status=503),
    FakeResponse(b"x" * (local_ai.MAX_RESPONSE_BYTES + 1)),
    FakeResponse(b"invalid json"),
    FakeResponse(json.dumps({"done": False, "message": {"content": "{}"}}).encode()),
    FakeResponse(sample_envelope({"severity": "info", "summary": "ok", "recommendations": [], "confidence": "low"}),
                 headers={"Content-Length": str(local_ai.MAX_RESPONSE_BYTES + 1)}),
])
def test_local_ai_fail_closed_for_unavailable_malformed_or_oversized_model(response):
    FakeConnection.response = response
    with patch.object(local_ai.http.client, "HTTPConnection", FakeConnection):
        with pytest.raises((ValueError, RuntimeError)):
            local_ai._ask_local_model({"window_hours": 24})
    assert FakeConnection.instances[-1].closed


def test_oversized_input_rejected_before_connection():
    with patch.object(local_ai.http.client, "HTTPConnection") as connection:
        with pytest.raises(ValueError, match="size budget"):
            local_ai._ask_local_model({"payload": "x" * 6000})
        connection.assert_not_called()
