"""Allowlisted metadata-only system inventory for the initial implementation."""
from __future__ import annotations

import plistlib
import shutil
import subprocess
from pathlib import Path
from typing import Any

def _run(*args: str) -> str:
    # Fixed executable and arguments only; never allow the LLM to supply commands.
    result = subprocess.run(args, capture_output=True, text=True, timeout=30, check=True)
    return result.stdout

def discover_brew() -> list[dict[str, Any]]:
    brew = shutil.which("brew")
    if brew is None:
        return []
    output: list[dict[str, Any]] = []
    for kind, cmd in (("brew_formula", "formula"), ("brew_cask", "cask")):
        for name in sorted(set(_run(brew, "list", f"--{cmd}").splitlines())):
            name = name.strip()
            if name:
                output.append({"resource_id": f"{kind}:{name}", "category": kind,
                               "name": name, "attributes": {"installed": True}})
    return output

def discover_apps() -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    roots = (Path("/Applications"), Path.home() / "Applications")
    for root in roots:
        if not root.is_dir():
            continue
        for app in root.glob("*.app"):
            info = app / "Contents" / "Info.plist"
            try:
                with info.open("rb") as file:
                    plist = plistlib.load(file)
                bundle_id = plist.get("CFBundleIdentifier")
                version = plist.get("CFBundleShortVersionString") or plist.get("CFBundleVersion")
                if not isinstance(bundle_id, str) or not bundle_id:
                    continue
                output.append({"resource_id": f"app:{bundle_id}", "category": "app",
                               "name": app.stem,
                               "attributes": {"bundle_id": bundle_id, "version": str(version or "")}})
            except (OSError, ValueError, TypeError, plistlib.InvalidFileException):
                # Missing/unreadable metadata is not proof of removal; caller must treat partial inventories carefully.
                raise RuntimeError(f"Could not inspect application metadata for {app.name}") from None
    return output

def discover() -> list[dict[str, Any]]:
    return discover_apps() + discover_brew()
