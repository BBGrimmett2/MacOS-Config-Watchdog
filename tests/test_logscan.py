"""Privacy and failure semantics for bounded unified-log event correlation."""
from datetime import datetime, timedelta, timezone
import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from mac_watchdog import logscan
from mac_watchdog.storage import connect, recent_log_signals, store_log_signals


def sample(process, message, **other):
    return json.dumps({"process": process, "eventMessage": message, **other}).encode() + b"\n"


def test_grouping_never_emits_raw_logs_or_personal_details():
    raw = (
        sample("launchd", "service crashed for /Users/person/private/token=abc")
        + sample("launchd", "job crashing repeatedly /Users/person")
        + sample("mDNSResponder", "DNS query timeout user@example.com")
        + sample("unapproved", "service crashed")
    )
    counts = logscan.parse_events(raw)
    assert counts == {("launchd", "service_crash"): 2, ("mDNSResponder", "dns_failure"): 1}
    with tempfile.TemporaryDirectory() as root:
        conn = connect(Path(root) / "events.sqlite3")
        result = store_log_signals(conn, counts, collected_at=datetime(2026, 11, 19, 20, 2, tzinfo=timezone.utc))
        assert result["event_count"] == 3
        report = recent_log_signals(conn)
        assert len(report) == 2
        assert "person" not in str(report)
        assert "token" not in str(report)
        assert "example.com" not in str(report)
        assert "eventMessage" not in str(report)


def test_retries_do_not_double_count_and_history_is_pruned():
    with tempfile.TemporaryDirectory() as root:
        conn = connect(Path(root) / "events.sqlite3")
        now = datetime(2026, 11, 19, 20, 2, tzinfo=timezone.utc)
        counts = {("launchd", "service_restart"): 3}
        store_log_signals(conn, counts, collected_at=now - timedelta(days=8))
        store_log_signals(conn, counts, collected_at=now)
        store_log_signals(conn, counts, collected_at=now + timedelta(minutes=1))
        report = recent_log_signals(conn)
        assert len(report) == 1
        assert report[0]["count"] == 3
        assert report[0]["window_start"].endswith("20:00:00+00:00")


def test_failed_collection_is_not_a_successful_empty_window():
    with tempfile.TemporaryDirectory() as root:
        conn = connect(Path(root) / "events.sqlite3")
        before = conn.total_changes
        with patch.object(logscan, "collect", side_effect=TimeoutError("query timed out")):
            with pytest.raises(TimeoutError):
                logscan.collect_and_store(conn)
        assert conn.total_changes == before
        assert recent_log_signals(conn) == []


@pytest.mark.parametrize("raw", [b"not-json\n", b"{}\n" * (logscan.MAX_RECORDS + 1)])
def test_malformed_or_oversized_logs_fail_closed(raw):
    with pytest.raises(ValueError):
        logscan.parse_events(raw)


def test_unknown_signals_rejected_without_writes():
    with tempfile.TemporaryDirectory() as root:
        conn = connect(Path(root) / "events.sqlite3")
        before = conn.total_changes
        with pytest.raises(ValueError):
            store_log_signals(conn, {("launchd", "arbitrary_model_response"): 1},
                              collected_at=datetime.now(timezone.utc))
        assert conn.total_changes == before


def test_collector_uses_fixed_read_only_log_command():
    with patch.object(logscan.platform, "system", return_value="Darwin"):
        with patch.object(logscan, "_read_bounded", return_value=sample(
            "trustd", "certificate chain validation failed"
        )) as reader:
            assert logscan.collect() == {("trustd", "certificate_failure"): 1}
    argv = reader.call_args.args[0]
    assert argv[:3] == ["/usr/bin/log", "show", "--style"]
    assert argv[4:6] == ["--last", "5m"]
    assert argv[-2] == "--predicate"
    assert "launchd" in argv[-1]
    assert not any("sudo" in part for part in argv)


def test_non_macos_collection_disallowed():
    with patch.object(logscan.platform, "system", return_value="Linux"):
        with pytest.raises(RuntimeError, match="macOS"):
            logscan.collect()
