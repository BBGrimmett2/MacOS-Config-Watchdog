import tempfile
from pathlib import Path

from mac_watchdog.storage import connect, export, reconcile

def test_reconcile_groups_and_deduplicates():
    with tempfile.TemporaryDirectory() as directory:
        conn = connect(Path(directory) / "state.sqlite3")
        first = [{"resource_id": "app:com.example.foo", "category": "app", "name": "Foo",
                  "attributes": {"version": "1"}}]
        reconcile(conn, first)
        reconcile(conn, first)
        assert conn.execute("SELECT count(*) FROM changes").fetchone()[0] == 1
        changed = [{**first[0], "attributes": {"version": "2"}}]
        reconcile(conn, changed)
        assert conn.execute("SELECT count(*) FROM changes").fetchone()[0] == 2
        doc = export(conn)
        assert doc["schema_version"] == 1
        assert len(doc["resources"]) == 1
        assert doc["last_scan"]["status"] == "success"
        conn.close()

def test_reconcile_duplicate_fails_without_changes():
    with tempfile.TemporaryDirectory() as directory:
        conn = connect(Path(directory) / "state.sqlite3")
        item = {"resource_id": "x", "category": "app", "name": "x", "attributes": {}}
        try:
            reconcile(conn, [item, item])
            assert False, "Expected duplicate rejection"
        except ValueError:
            pass
        assert conn.execute("SELECT count(*) FROM changes").fetchone()[0] == 0
        conn.close()
