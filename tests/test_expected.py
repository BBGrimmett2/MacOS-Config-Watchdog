"""Expected-state reports are conservative, strictly validated, and read-only."""
import json
import tempfile
from pathlib import Path

import pytest

from mac_watchdog.expected import compare, load_manifest
from mac_watchdog.storage import connect, reconcile


def manifest(category="brew_formula", resources=None):
    return {
        "schema_version": 1,
        "managed_categories": [category],
        "resources": resources if resources is not None else [
            {"resource_id": "brew_formula:git", "category": "brew_formula",
             "attributes": {"installed": True}}
        ],
    }


def write_manifest(path, data):
    path.write_text(json.dumps(data))
    return load_manifest(path)


def test_match_unmanaged_and_not_observed_are_read_only():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        conn = connect(root / "state.sqlite3")
        reconcile(conn, [
            {"resource_id": "brew_formula:git", "category": "brew_formula",
             "name": "git", "attributes": {"installed": True}},
            {"resource_id": "brew_formula:curl", "category": "brew_formula",
             "name": "curl", "attributes": {"installed": True}},
            {"resource_id": "app:com.example.other", "category": "app",
             "name": "other", "attributes": {}},
        ], completed_categories=frozenset({"brew_formula", "app"}))
        spec = write_manifest(root / "expected.json", manifest(resources=[
            {"resource_id": "brew_formula:git", "category": "brew_formula",
             "attributes": {"installed": True}},
            {"resource_id": "brew_formula:missing", "category": "brew_formula"}
        ]))
        before = conn.total_changes
        result = compare(conn, spec)
        assert conn.total_changes == before
        assert result["summary"] == {
            "matched": 1, "attribute_mismatch": 0, "not_observed": 1, "unmanaged": 1, "dependency": 0
        }
        assert all(r["resource_id"] != "app:com.example.other" for r in result["results"])
        assert "not proof of absence" in result["note"]


def test_attribute_mismatch_only_checks_declared_keys():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        conn = connect(root / "state.sqlite3")
        reconcile(conn, [{
            "resource_id": "app:com.example.one", "category": "app", "name": "one",
            "attributes": {"version": "2.0", "bundle_id": "com.example.one"}
        }], completed_categories=frozenset({"app"}))
        spec = write_manifest(root / "expected.json", manifest("app", [
            {"resource_id": "app:com.example.one", "category": "app",
             "attributes": {"version": "1.0"}}
        ]))
        result = compare(conn, spec)
        assert result["summary"]["attribute_mismatch"] == 1
        assert result["results"][0]["differing_attributes"] == ["version"]


@pytest.mark.parametrize("bad", [
    {"schema_version": 2, "managed_categories": ["app"], "resources": []},
    {"schema_version": 1, "managed_categories": [], "resources": []},
    {"schema_version": 1, "managed_categories": ["app", "app"], "resources": []},
    {"schema_version": 1, "managed_categories": ["app"], "resources": [
        {"resource_id": "app:x", "category": "app"},
        {"resource_id": "app:x", "category": "app"}
    ]},
    {"schema_version": 1, "managed_categories": ["app"], "resources": [
        {"resource_id": "brew_formula:x", "category": "app"}
    ]},
    {"schema_version": 1, "managed_categories": ["app"], "resources": [
        {"resource_id": "app:x", "category": "app", "attributes": {"token": ["secret"]}}
    ]},
])
def test_invalid_manifest_is_rejected(bad):
    with tempfile.TemporaryDirectory() as directory:
        with pytest.raises(ValueError):
            write_manifest(Path(directory) / "bad.json", bad)


def test_version_aware_macos_build_identity():
    with tempfile.TemporaryDirectory() as directory:
        spec = manifest("macos_build", [
            {"resource_id": "macos:build", "category": "macos_build",
             "attributes": {"version": "15.1"}}
        ])
        assert write_manifest(Path(directory) / "expected.json", spec) == spec


def test_oversized_manifest_rejected():
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "huge.json"
        path.write_bytes(b" " * (1024 * 1024 + 1))
        with pytest.raises(ValueError):
            load_manifest(path)


def test_brew_dependencies_report_separately_from_requested_unmanaged_formulae():
    with tempfile.TemporaryDirectory() as directory:
        conn = connect(Path(directory) / "state.sqlite3")
        rows = [
            {"resource_id": "brew_formula:git", "category": "brew_formula", "name": "git",
             "attributes": {"installed": True, "installed_on_request": True}},
            {"resource_id": "brew_formula:libuv", "category": "brew_formula", "name": "libuv",
             "attributes": {"installed": True, "installed_on_request": False}},
            {"resource_id": "brew_formula:gh", "category": "brew_formula", "name": "gh",
             "attributes": {"installed": True, "installed_on_request": True}},
            {"resource_id": "brew_formula:legacy", "category": "brew_formula", "name": "legacy",
             "attributes": {"installed": True}},
        ]
        reconcile(conn, rows, completed_categories=frozenset({"brew_formula"}))
        wanted = manifest(resources=[
            {"resource_id": "brew_formula:git", "category": "brew_formula"}
        ])
        before = conn.total_changes
        report = compare(conn, wanted)
        assert before == conn.total_changes
        statuses = {row["resource_id"]: row["status"] for row in report["results"]}
        assert statuses == {
            "brew_formula:git": "matched",
            "brew_formula:libuv": "dependency",
            "brew_formula:gh": "unmanaged",
            "brew_formula:legacy": "unmanaged",
        }
        assert report["summary"]["dependency"] == 1
        assert report["summary"]["unmanaged"] == 2
