"""Read-only Ollama model inventory and desired-state drift tests."""
import io
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import URLError

from mac_watchdog.discovery import discover_ollama_models
from mac_watchdog.expected import compare, load_manifest
from mac_watchdog.storage import connect, reconcile


DIGEST1 = "a" * 64
DIGEST2 = "b" * 64


class FakeResponse:
    def __init__(self, payload):
        self.data = io.BytesIO(json.dumps(payload).encode())

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self, n):
        return self.data.read(n)


class OllamaModelTests(unittest.TestCase):
    def test_observes_names_and_digests_without_private_metadata(self):
        payload = {"models": [{"name": "qwen3:8b", "digest": DIGEST1,
                                "details": {"private": "not stored"}}]}
        with patch("mac_watchdog.discovery.urllib.request.build_opener") as opener:\n            opener.return_value.open.return_value = FakeResponse(payload)
            result = discover_ollama_models()
        self.assertEqual(result.completed_categories, frozenset({"ollama_model"}))
        self.assertEqual(result.observations, [{
            "resource_id": "ollama_model:qwen3:8b", "category": "ollama_model",
            "name": "qwen3:8b", "attributes": {"digest": DIGEST1},
        }])

    def test_offline_does_not_claim_empty_inventory(self):
        with patch("mac_watchdog.discovery.urllib.request.build_opener") as opener:\n            opener.return_value.open.side_effect = URLError("connection refused")
            result = discover_ollama_models()
        self.assertEqual(result.observations, [])
        self.assertEqual(result.completed_categories, frozenset())

    def test_malformed_response_fails_closed(self):
        with patch("mac_watchdog.discovery.urllib.request.build_opener") as opener:\n            opener.return_value.open.return_value = FakeResponse({"models": [{"name": "qwen3:8b"}]})
            with self.assertRaises(ValueError):
                discover_ollama_models()

    def test_add_digest_change_removal_and_unmanaged_compare(self):
        with tempfile.TemporaryDirectory() as directory:
            conn = connect(Path(directory) / "models.sqlite3")
            expected = {
                "schema_version": 1, "managed_categories": ["ollama_model"],
                "resources": [{"category": "ollama_model", "resource_id": "ollama_model:qwen3:8b"}],
            }
            item = lambda digest: [{"resource_id": "ollama_model:qwen3:8b",
                                   "category": "ollama_model", "name": "qwen3:8b",
                                   "attributes": {"digest": digest}}]
            coverage = frozenset({"ollama_model"})
            reconcile(conn, item(DIGEST1), completed_categories=coverage)
            self.assertEqual(compare(conn, expected)["results"][0]["status"], "matched")
            reconcile(conn, item(DIGEST2), completed_categories=coverage)
            self.assertEqual(conn.execute(
                "SELECT operation FROM changes WHERE resource_id=? ORDER BY id DESC LIMIT 1",
                ("ollama_model:qwen3:8b",)).fetchone()[0], "changed")
            reconcile(conn, [], completed_categories=frozenset({"brew_cask"}))
            self.assertEqual(compare(conn, expected)["results"][0]["status"], "matched")
            reconcile(conn, [], completed_categories=coverage)
            self.assertEqual(compare(conn, expected)["results"][0]["status"], "not_observed")
            self.assertEqual(conn.execute(
                "SELECT operation FROM changes WHERE resource_id=? ORDER BY id DESC LIMIT 1",
                ("ollama_model:qwen3:8b",)).fetchone()[0], "removed")
            conn.close()


if __name__ == "__main__":
    unittest.main()
