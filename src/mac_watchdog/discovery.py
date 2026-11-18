"""Metadata-only discovery with explicit coverage reporting.

A missing optional source (such as Homebrew) is *not* a completed inventory.
Only categories that were successfully enumerated may drive removals.
"""
from __future__ import annotations

from dataclasses import dataclass
import plistlib
import shutil
import subprocess
from pathlib import Path
from typing import Any

CATEGORIES = frozenset({"app", "brew_formula", "brew_cask"})


@dataclass(frozen=True)
class Inventory:
    observations: list[dict[str, Any]]
    completed_categories: frozenset[str]


def _run(*args: str) -> str:
    result = subprocess.run(args, capture_output=True, text=True, timeout=30, check=True)
    return result.stdout


def discover_brew() -> Inventory:
    brew = shutil.which("brew")
    if brew is None:
        return Inventory([], frozenset())
    output: list[dict[str, Any]] = []
    for kind, flag in (("brew_formula", "--formula"), ("brew_cask", "--cask")):
        for name in sorted(set(_run(brew, "list", flag).splitlines())):
            name = name.strip()
            if name:
                output.append({"resource_id": f"{kind}:{name}", "category": kind,
                               "name": name, "attributes": {"installed": True}})
    return Inventory(output, frozenset({"brew_formula", "brew_cask"}))


def discover_apps() -> Inventory:
    output: list[dict[str, Any]] = []
    roots = (Path("/Applications"), Path.home() / "Applications")
    for root in roots:
        if not root.exists():
            continue
        if not root.is_dir():
            raise RuntimeError(f"Application inventory root is not a directory: {root.name}")
        for app in sorted(root.glob("*.app")):
            info = app / "Contents" / "Info.plist"
            try:
                with info.open("rb") as handle:
                    plist = plistlib.load(handle)
                bundle_id = plist.get("CFBundleIdentifier")
                version = plist.get("CFBundleShortVersionString") or plist.get("CFBundleVersion")
                if not isinstance(bundle_id, str) or not bundle_id:
                    raise ValueError("missing bundle identifier")
                output.append({"resource_id": f"app:{bundle_id}", "category": "app",
                               "name": app.stem,
                               "attributes": {"bundle_id": bundle_id, "version": str(version or "")}})
            except (OSError, ValueError, TypeError, plistlib.InvalidFileException):
                # Never interpret uninspectable applications as removed.
                raise RuntimeError("Application metadata inventory incomplete") from None
    # The same bundle may exist in both roots. A duplicate must be reviewed rather than
    # allowing an arbitrary copy to mask the other.
    return Inventory(output, frozenset({"app"}))


def discover() -> Inventory:
    applications = discover_apps()
    packages = discover_brew()
    return Inventory(
        applications.observations + packages.observations,
        applications.completed_categories | packages.completed_categories,
    )
