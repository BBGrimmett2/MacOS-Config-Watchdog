"""Tests don't query the host; mock all system collectors."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import plistlib
import tempfile
from unittest.mock import patch

from mac_watchdog import discovery
from mac_watchdog.monitor import deep_scan_due, last_deep_scan
from mac_watchdog.storage import connect, reconcile


def test_weekly_deep_scan_decision():
    now = datetime(2026, 11, 18, tzinfo=timezone.utc)
    assert deep_scan_due(None, now)
    assert deep_scan_due("malformed", now)
    assert not deep_scan_due((now - timedelta(days=6)).isoformat(), now)
    assert deep_scan_due((now - timedelta(days=7)).isoformat(), now)


def test_deep_inventory_has_additional_collectors():
    empty = discovery.Inventory([], frozenset())
    with (
        patch.object(discovery, "discover_apps", return_value=discovery.Inventory([], frozenset({"app"}))),
        patch.object(discovery, "discover_brew", return_value=empty),
        patch.object(discovery, "discover_receipts", return_value=discovery.Inventory([], frozenset({"pkg_receipt"}))) as receipts,
        patch.object(discovery, "discover_launchd", return_value=discovery.Inventory([], frozenset({"launchd"}))) as launchd,
        patch.object(discovery, "discover_os_build", return_value=discovery.Inventory([], frozenset({"macos_build"}))) as osbuild,
    ):
        routine = discovery.discover(mode="routine")
        assert routine.completed_categories == frozenset({"app"})
        receipts.assert_not_called()
        launchd.assert_not_called()
        osbuild.assert_not_called()
        deep = discovery.discover(mode="deep")
        assert deep.completed_categories == frozenset({"app", "pkg_receipt", "launchd", "macos_build"})


def test_launchd_collects_labels_not_arguments():
    with tempfile.TemporaryDirectory() as directory:
        agents = Path(directory) / "LaunchAgents"
        agents.mkdir()
        with (agents / "example.plist").open("wb") as handle:
            plistlib.dump({
                "Label": "org.example.test",
                "ProgramArguments": ["/private/secret/path", "--password=not-a-real-secret"],
                "EnvironmentVariables": {"TOKEN": "not-a-real-token"},
            }, handle)
        with patch.object(discovery.Path, "home", return_value=Path(directory)), patch.object(
            discovery, "_run", return_value=""
        ):
            # Patch directory roots by replacing the glob behavior; test in isolation.
            with patch.object(discovery.Path, "glob", autospec=True) as glob:
                glob.side_effect = lambda self, pattern: [agents / "example.plist"] if self == agents else []
                with patch.object(discovery.Path, "exists", autospec=True) as exists, patch.object(
                    discovery.Path, "is_dir", autospec=True
                ) as isdir:
                    exists.side_effect = lambda self: self == agents
                    isdir.side_effect = lambda self: self == agents
                    result = discovery.discover_launchd()
        assert len(result.observations) == 1
        row = result.observations[0]
        assert row["name"] == "org.example.test"
        assert "password" not in str(row)
        assert "TOKEN" not in str(row)


def test_deep_completion_persisted():
    with tempfile.TemporaryDirectory() as directory:
        with connect(Path(directory) / "test.db") as conn:
            assert last_deep_scan(conn) is None
            reconcile(conn, [], kind="deep", completed_categories=frozenset({"app"}))
            assert last_deep_scan(conn) is not None
            reconcile(conn, [], kind="routine", completed_categories=frozenset({"app"}))
            assert last_deep_scan(conn) is not None


def test_package_receipts_do_not_contain_filesystem_data():
    with patch.object(discovery, "_run", return_value="com.apple.pkg.BaseSystem\norg.example.app\n"):
        rows = discovery.discover_receipts().observations
    assert [row["name"] for row in rows] == ["com.apple.pkg.BaseSystem", "org.example.app"]
    assert all(set(row["attributes"]) == {"installed"} for row in rows)
