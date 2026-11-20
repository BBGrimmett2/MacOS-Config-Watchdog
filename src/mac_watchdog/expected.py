"""Strict, read-only desired-state comparison against observed SQLite metadata.

A missing observation is not proof of absence: coverage and scan freshness are
not yet persisted per category. Never use this report for automatic remediation.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

CATEGORIES = frozenset({
    "app", "brew_formula", "brew_cask", "pkg_receipt", "launchd", "macos_build"
})
MAX_MANIFEST_BYTES = 1024 * 1024


def load_manifest(path: Path) -> dict[str, Any]:
    if path.stat().st_size > MAX_MANIFEST_BYTES:
        raise ValueError("Expected-state manifest exceeds 1 MiB")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or set(data) != {"schema_version", "managed_categories", "resources"}:
        raise ValueError("Manifest must have schema_version, managed_categories, resources")
    if type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise ValueError("Unsupported expected-state manifest version")
    categories = data["managed_categories"]
    if not isinstance(categories, list) or not categories or any(
        not isinstance(cat, str) or cat not in CATEGORIES for cat in categories
    ) or len(categories) != len(set(categories)):
        raise ValueError("Invalid or duplicate managed categories")
    resources = data["resources"]
    if not isinstance(resources, list) or len(resources) > 20000:
        raise ValueError("Manifest resources must be a bounded array")
    ids: set[str] = set()
    for item in resources:
        if not isinstance(item, dict) or set(item) not in (
            {"resource_id", "category"}, {"resource_id", "category", "attributes"}
        ):
            raise ValueError("Each resource needs resource_id and category (optional attributes)")
        rid, category = item["resource_id"], item["category"]
        if (not isinstance(rid, str) or not rid or len(rid) > 512
                or not isinstance(category, str) or category not in categories
                or not rid.startswith(f"{category}:") or rid in ids):
            raise ValueError("Invalid or duplicate expected resource ID/category")
        ids.add(rid)
        attrs = item.get("attributes", {})
        if not isinstance(attrs, dict) or any(
            not isinstance(key, str) or not isinstance(value, (str, int, float, bool, type(None)))
            for key, value in attrs.items()
        ):
            raise ValueError("Expected attributes must be flat scalar metadata")
    return data


def compare(conn: sqlite3.Connection, manifest: dict[str, Any]) -> dict[str, Any]:
    """No writes and no remediation; observed-only claims are deliberately conservative."""
    managed = set(manifest["managed_categories"])
    actual = {}
    for row in conn.execute(
        "SELECT resource_id, category, attributes_json FROM resources WHERE present=1"
    ):
        if row["category"] in managed:
            actual[row["resource_id"]] = row
    expected = {item["resource_id"]: item for item in manifest["resources"]}
    results: list[dict[str, Any]] = []
    for rid, item in sorted(expected.items()):
        found = actual.pop(rid, None)
        if found is None:
            status = "not_observed"
            different: list[str] = []
        else:
            attributes = json.loads(found["attributes_json"])
            different = sorted(
                key for key, wanted in item.get("attributes", {}).items()
                if attributes.get(key) != wanted
            )
            status = "attribute_mismatch" if different else "matched"
        results.append({"resource_id": rid, "status": status, "differing_attributes": different})
    for rid in sorted(actual):
        results.append({"resource_id": rid, "status": "unmanaged", "differing_attributes": []})
    summary = {name: sum(r["status"] == name for r in results) for name in (
        "matched", "attribute_mismatch", "not_observed", "unmanaged"
    )}
    return {
        "schema_version": 1,
        "mode": "read_only",
        "managed_categories": sorted(managed),
        "summary": summary,
        "results": results,
        "note": "not_observed is not proof of absence; unmanaged is not proof of malicious drift",
    }
