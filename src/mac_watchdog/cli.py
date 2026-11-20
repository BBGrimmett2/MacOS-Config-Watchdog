"""Command-line entrypoints. Mutating actions affect local SQLite only."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .expected import compare, load_manifest

from .discovery import discover
from .storage import connect, export, reconcile

def main() -> int:
    parser = argparse.ArgumentParser(prog="mac-watchdog")
    parser.add_argument("command", choices=["scan", "export", "health", "monitor", "compare", "logs", "log-report", "ai-review"])
    parser.add_argument("--manifest", type=Path, help="local JSON expected-state manifest (compare only)")
    args = parser.parse_args()
    if args.command == "compare" and args.manifest is None:
        parser.error("compare requires --manifest")
    if args.command != "compare" and args.manifest is not None:
        parser.error("--manifest is supported only for compare")
    try:
        if args.command == "monitor":
            from .monitor import run
            run()
            return 0
        conn = connect()
        if args.command == "ai-review":
            from .local_ai import review
            print(json.dumps(review(conn), indent=2))
        elif args.command == "logs":
            from .logscan import collect_and_store
            print(json.dumps(collect_and_store(conn), indent=2))
        elif args.command == "log-report":
            from .storage import recent_log_signals
            print(json.dumps({"schema_version": 1, "mode": "read_only",
                              "signals": recent_log_signals(conn)}, indent=2))
        elif args.command == "compare":
            manifest = load_manifest(args.manifest)
            print(json.dumps(compare(conn, manifest), indent=2))
        elif args.command == "scan":
            inventory = discover(mode="deep")
            scan_id = reconcile(conn, inventory.observations, kind="deep", completed_categories=inventory.completed_categories)
            print(json.dumps({"scan_id": scan_id, "resources": len(inventory.observations), "status": "success"}))
        elif args.command == "export":
            print(json.dumps(export(conn), indent=2))
        elif args.command == "health":
            result = conn.execute("PRAGMA quick_check").fetchone()[0]
            last = conn.execute("SELECT kind,status,finished_at FROM scans ORDER BY id DESC LIMIT 1").fetchone()
            print(json.dumps({"database": result, "last_scan": dict(last) if last else None}))
            return 0 if result == "ok" else 1
        conn.close()
        return 0
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError, TimeoutError, __import__("subprocess").CalledProcessError) as exc:
        print(f"watchdog: {exc}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
