import tempfile
from pathlib import Path

from mac_watchdog.storage import connect, export, reconcile

def test_reconcile_groups_and_deduplicates():
    with tempfile.TemporaryDirectory() as directory:
        conn = connect(Path(directory) / "state.sqlite3")
        first = [{"resource_id": "app:com.example.foo", "category": "app", "name": "Foo",
                  "attributes": {"version": "1"}}]
        reconcile(conn, first, completed_categories=frozenset({"app"}))
        reconcile(conn, first, completed_categories=frozenset({"app"}))
        assert conn.execute("SELECT count(*) FROM changes").fetchone()[0] == 1
        changed = [{**first[0], "attributes": {"version": "2"}}]
        reconcile(conn, changed, completed_categories=frozenset({"app"}))
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
            reconcile(conn, [item, item], completed_categories=frozenset({"app"}))
            assert False, "Expected duplicate rejection"
        except ValueError:
            pass
        assert conn.execute("SELECT count(*) FROM changes").fetchone()[0] == 0
        conn.close()

def test_empty_complete_scan_records_removal():
    with tempfile.TemporaryDirectory() as directory:
        conn = connect(Path(directory) / "state.sqlite3")
        item = {"resource_id": "app:x", "category": "app", "name": "X", "attributes": {}}
        reconcile(conn, [item], completed_categories=frozenset({"app"}))
        reconcile(conn, [], completed_categories=frozenset({"app"}))
        assert conn.execute("SELECT present FROM resources WHERE resource_id='app:x'").fetchone()[0] == 0
        assert conn.execute("SELECT operation FROM changes ORDER BY id DESC LIMIT 1").fetchone()[0] == "removed"


def test_incomplete_category_must_not_remove_resources():
    with tempfile.TemporaryDirectory() as directory:
        conn = connect(Path(directory) / "state.sqlite3")
        items = [
            {"resource_id": "app:x", "category": "app", "name": "X", "attributes": {}},
            {"resource_id": "brew_formula:y", "category": "brew_formula", "name": "Y", "attributes": {}},
        ]
        reconcile(conn, items, completed_categories=frozenset({"app", "brew_formula"}))
        reconcile(conn, [items[0]], completed_categories=frozenset({"app"}))
        assert conn.execute("SELECT present FROM resources WHERE resource_id='brew_formula:y'").fetchone()[0] == 1
