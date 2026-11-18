"""Command-line entrypoints. Mutating actions affect local SQLite only."""
from __future__ import annotations

import argparse
import json
import sys

from .discovery import discover
from .storage import connect, export, reconcile

def main() -> int:
    parser = argparse.ArgumentParser(prog="mac-watchdog")
    parser.add_argument("command", choices=["scan", "export", "health"])
    args = parser.parse_args()
    try:
        conn = connect()
        if args.command == "scan":
            inventory = discover()
            scan_id = reconcile(conn, inventory.observations, completed_categories=inventory.completed_categories)
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
    except (OSError, RuntimeError, ValueError, TimeoutError, __import__("subprocess").CalledProcessError) as exc:
        print(f"watchdog: {exc}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
