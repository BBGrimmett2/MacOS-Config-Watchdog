"""Opt-in on-Mac smoke test against real Ollama, using only synthetic data.

Run on a trusted Mac with Ollama running and qwen3:8b already installed:
  PYTHONPATH=src python3 tests/manual_ollama_integration.py

Never uses the user's watchdog DB, captures no system logs or config, and
never writes to the real machine except an ephemeral private temp directory.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile

from mac_watchdog.local_ai import review
from mac_watchdog.storage import connect, reconcile, store_log_signals


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="mac-watchdog-ai-test-") as root:
        with connect(Path(root) / "isolated.sqlite3") as conn:
            reconcile(conn, [{
                "resource_id": "app:synthetic.example",
                "category": "app",
                "name": "Synthetic Test App",
                "attributes": {"version": "0"},
            }], completed_categories=frozenset({"app"}))
            store_log_signals(
                conn, {("launchd", "service_crash"): 2},
                collected_at=datetime.now(timezone.utc),
            )
            result = review(conn)
            assert result["status"] == "advisory", result
            assert result["analysis"]["focus"] in {"service", "inventory"}
            assert result["analysis"]["severity"] == "warning"
            assert result["analysis"]["summary"]
            assert len(result["analysis"]["recommendations"]) <= 2
            assert "coverage" in result
            print(json.dumps(result, indent=2))
    print("PASS: real local Ollama advisory using synthetic-only, isolated data")


if __name__ == "__main__":
    main()
