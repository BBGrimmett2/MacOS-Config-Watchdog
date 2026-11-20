"""SQLite persistence; no system state is uploaded anywhere."""
from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from datetime import datetime, timezone, timedelta
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
      CREATE TABLE IF NOT EXISTS log_signals (
        window_start TEXT NOT NULL,
        process TEXT NOT NULL,
        signal TEXT NOT NULL,
        count INTEGER NOT NULL CHECK(count >= 1),
        PRIMARY KEY(window_start, process, signal)
      );
      CREATE TABLE IF NOT EXISTS log_collections (
        window_start TEXT PRIMARY KEY,
        finished_at TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('success','failed')),
        event_count INTEGER NOT NULL CHECK(event_count >= 0)
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


def store_log_signals(conn: sqlite3.Connection, counts: dict[tuple[str, str], int], *,
                      collected_at: datetime) -> dict[str, Any]:
    """Retain only count/allowlisted labels for seven days; no raw log text."""
    from .logscan import PROCESSES, SIGNALS
    if collected_at.tzinfo is None:
        raise ValueError("Log collection timestamp must have a timezone")
    allowed = {process: {name for name, _ in patterns} for process, patterns in SIGNALS.items()}
    for (process, signal), count in counts.items():
        if process not in PROCESSES or signal not in allowed[process]:
            raise ValueError("Unsupported log signal")
        if type(count) is not int or count <= 0:
            raise ValueError("Log count must be a positive integer")
    at = collected_at.astimezone(timezone.utc)
    bucket = at.replace(minute=(at.minute // 5) * 5, second=0, microsecond=0)
    cutoff = (at - timedelta(days=7)).isoformat()
    with conn:
        for (process, signal), count in sorted(counts.items()):
            conn.execute("""
                INSERT INTO log_signals(window_start,process,signal,count)
                VALUES(?,?,?,?)
                ON CONFLICT(window_start,process,signal)
                DO UPDATE SET count=MAX(count,excluded.count)
            """, (bucket.isoformat(), process, signal, count))
        conn.execute("DELETE FROM log_signals WHERE window_start < ?", (cutoff,))
        conn.execute("""
            INSERT INTO log_collections(window_start,finished_at,status,event_count)
            VALUES(?,?,?,?)
            ON CONFLICT(window_start) DO UPDATE SET
              finished_at=excluded.finished_at,
              status=excluded.status,
              event_count=excluded.event_count
        """, (bucket.isoformat(), at.isoformat(), "success", sum(counts.values())))
        conn.execute("DELETE FROM log_collections WHERE window_start < ?", (cutoff,))
    return {
        "window_start": bucket.isoformat(), "signal_types": len(counts),
        "event_count": sum(counts.values()), "status": "success",
    }


def recent_log_signals(conn: sqlite3.Connection, limit: int = 100) -> list[dict[str, Any]]:
    if not 1 <= limit <= 100:
        raise ValueError("Log signal limit must be between 1 and 100")
    return [dict(row) for row in conn.execute(
        "SELECT window_start,process,signal,count FROM log_signals "
        "ORDER BY window_start DESC,process,signal LIMIT ?", (limit,)
    )]


def record_log_failure(conn: sqlite3.Connection, *, collected_at: datetime | None = None) -> None:
    """Persist only a failure status, never the exception or log data."""
    at = (collected_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    bucket = at.replace(minute=(at.minute // 5) * 5, second=0, microsecond=0)
    cutoff = (at - timedelta(days=7)).isoformat()
    with conn:
        conn.execute("""
            INSERT INTO log_collections(window_start,finished_at,status,event_count)
            VALUES(?,?,?,0)
            ON CONFLICT(window_start) DO UPDATE SET
              finished_at=excluded.finished_at,status=excluded.status,event_count=0
        """, (bucket.isoformat(), at.isoformat(), "failed"))
        conn.execute("DELETE FROM log_collections WHERE window_start < ?", (cutoff,))


def collection_health(conn: sqlite3.Connection, *, now: datetime | None = None) -> dict[str, Any]:
    """Coverage is never certified complete; missing samples are unknown."""
    at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    cutoff = (at - timedelta(hours=24)).isoformat()
    row = conn.execute("""
        SELECT finished_at,status FROM log_collections
        ORDER BY finished_at DESC LIMIT 1
    """).fetchone()
    counts = {r["status"]: r["total"] for r in conn.execute("""
        SELECT status,COUNT(*) AS total FROM log_collections
        WHERE finished_at >= ? AND finished_at <= ? GROUP BY status
    """, (cutoff, at.isoformat()))}
    recent = False
    if row:
        finished = datetime.fromisoformat(row["finished_at"])
        recent = bool(row["status"] == "success"
                      and timedelta(0) <= at - finished <= timedelta(minutes=15))
    scan = conn.execute("""
        SELECT kind,status,finished_at FROM scans WHERE finished_at IS NOT NULL
        ORDER BY id DESC LIMIT 1
    """).fetchone()
    return {
        "status": "recent_sample_unverified" if recent else "unknown_or_stale",
        "last_attempt_at": row["finished_at"] if row else None,
        "last_attempt_status": row["status"] if row else None,
        "successful_windows_24h": counts.get("success", 0),
        "failed_windows_24h": counts.get("failed", 0),
        "expected_windows_24h": 288,
        "inventory_scan": dict(scan) if scan else None,
        "note": "Log queries are partial samples, not proof of continuous coverage.",
    }
