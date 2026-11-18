"""SQLite persistence; no system state is uploaded anywhere."""
from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from datetime import datetime, timezone
from typing import Any

SCHEMA_VERSION = 1

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()

def state_dir() -> Path:
    return Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local/state"))) / "mac-watchdog"

def database_path() -> Path:
    return state_dir() / "watchdog.sqlite3"

def connect(path: Path | None = None) -> sqlite3.Connection:
    db = path or database_path()
    db.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(db.parent, 0o700)
    conn = sqlite3.connect(db)
    os.chmod(db, 0o600)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.executescript("""
      CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS resources (
        resource_id TEXT PRIMARY KEY,
        category TEXT NOT NULL,
        name TEXT NOT NULL,
        attributes_json TEXT NOT NULL,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        present INTEGER NOT NULL DEFAULT 1
      );
      CREATE TABLE IF NOT EXISTS changes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        occurred_at TEXT NOT NULL,
        resource_id TEXT NOT NULL,
        operation TEXT NOT NULL,
        previous_json TEXT,
        current_json TEXT,
        transaction_id TEXT NOT NULL,
        FOREIGN KEY(resource_id) REFERENCES resources(resource_id)
      );
      CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        started_at TEXT NOT NULL,
        finished_at TEXT,
        kind TEXT NOT NULL,
        status TEXT NOT NULL,
        error TEXT
      );
    """)
    conn.execute("INSERT OR IGNORE INTO meta(key,value) VALUES('schema_version',?)", (str(SCHEMA_VERSION),))
    version = conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0]
    if int(version) != SCHEMA_VERSION:
        conn.close()
        raise RuntimeError(f"Unsupported database schema version: {version}")
    conn.commit()
    return conn

def reconcile(conn: sqlite3.Connection, observations: list[dict[str, Any]], kind: str = "inventory", *, completed_categories: frozenset[str] | None = None) -> int:
    """Commit a completed inventory atomically. Never reconcile an incomplete scan."""
    if completed_categories is None or not completed_categories:
        raise ValueError("Completed inventory categories must be explicitly specified")
    if any(item["category"] not in completed_categories for item in observations):
        raise ValueError("Observation outside completed inventory coverage")
    now = utc_now()
    transaction = now
    ids = [item["resource_id"] for item in observations]
    if len(set(ids)) != len(ids):
        raise ValueError("Duplicate resource ID in scan")
    with conn:
        cursor = conn.execute("INSERT INTO scans(started_at,kind,status) VALUES(?,?,?)", (now, kind, "running"))
        scan_id = cursor.lastrowid
        previous = {r["resource_id"]: r for r in conn.execute("SELECT * FROM resources")}
        for item in observations:
            rid = item["resource_id"]
            attributes = json.dumps(item["attributes"], sort_keys=True, separators=(",", ":"))
            old = previous.get(rid)
            operation = ("added" if old is None or not old["present"] else
                         "changed" if old["attributes_json"] != attributes else None)
            if operation:
                conn.execute(
                    "INSERT INTO changes(occurred_at,resource_id,operation,previous_json,current_json,transaction_id) VALUES(?,?,?,?,?,?)",
                    (now, rid, operation, old["attributes_json"] if old else None, attributes, transaction))
            conn.execute("""
                INSERT INTO resources(resource_id,category,name,attributes_json,first_seen,last_seen,present)
                VALUES(?,?,?,?,?,?,1)
                ON CONFLICT(resource_id) DO UPDATE SET
                category=excluded.category,name=excluded.name,
                attributes_json=excluded.attributes_json,last_seen=excluded.last_seen,present=1
            """, (rid, item["category"], item["name"], attributes, now, now))
        # Removal is safe only for categories fully covered by this scan.
        categories = completed_categories
        # An empty, explicitly completed inventory confirms the category is empty.
        for rid, old in previous.items():
            if old["present"] and rid not in ids and old["category"] in categories:
                conn.execute("UPDATE resources SET present=0,last_seen=? WHERE resource_id=?", (now, rid))
                conn.execute(
                    "INSERT INTO changes(occurred_at,resource_id,operation,previous_json,current_json,transaction_id) VALUES(?,?,?,?,?,?)",
                    (now, rid, "removed", old["attributes_json"], None, transaction))
        conn.execute("UPDATE scans SET finished_at=?,status='success' WHERE id=?", (utc_now(), scan_id))
    return int(scan_id)

def export(conn: sqlite3.Connection) -> dict[str, Any]:
    """Local JSON export; exclude raw evidence and hidden filesystem paths."""
    resources = [
        {"id": row["resource_id"], "category": row["category"], "name": row["name"], "present": bool(row["present"])}
        for row in conn.execute("SELECT resource_id,category,name,present FROM resources ORDER BY resource_id")
    ]
    changes = [
        {"id": row["id"], "occurred_at": row["occurred_at"], "resource_id": row["resource_id"],
         "operation": row["operation"], "transaction_id": row["transaction_id"]}
        for row in conn.execute("SELECT id,occurred_at,resource_id,operation,transaction_id FROM changes ORDER BY id DESC LIMIT 1000")
    ]
    last = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 1").fetchone()
    return {"schema_version": SCHEMA_VERSION, "generated_at": utc_now(),
            "last_scan": dict(last) if last else None,
            "resources": resources, "changes": changes}
