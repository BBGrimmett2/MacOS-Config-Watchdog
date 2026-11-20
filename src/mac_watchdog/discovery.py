"""Allowlisted, metadata-only macOS inventory.

Only collectors that completed successfully contribute removal coverage.
Never read user document contents, key material, or launchd command arguments.
"""
from __future__ import annotations

from dataclasses import dataclass
import plistlib
import json
import urllib.error
import urllib.request
import shutil
import subprocess
from pathlib import Path
from typing import Any, Literal

Mode = Literal["routine", "deep"]


@dataclass(frozen=True)
class Inventory:
    observations: list[dict[str, Any]]
    completed_categories: frozenset[str]


def _run(*args: str) -> str:
    result = subprocess.run(args, capture_output=True, text=True, timeout=30, check=True)
    return result.stdout


def _homebrew_executable() -> str | None:
    """Find the installed Homebrew executable without relying on launchd PATH."""
    for location in ("/opt/homebrew/bin/brew", "/usr/local/bin/brew"):
        candidate = Path(location)
        if candidate.is_file() and candidate.stat().st_mode & 0o111:
            return str(candidate)
    return shutil.which("brew")


def discover_brew() -> Inventory:
    brew = _homebrew_executable()
    if brew is None:
        # An absent binary is not a trustworthy completed package inventory.
        return Inventory([], frozenset())
    # The installed-on-request flag is authoritative Homebrew metadata, unlike
    # brew leaves (which excludes requested packages used as dependencies).
    formulae = set(_run(brew, "list", "--formula").splitlines())
    requested = set(_run(brew, "list", "--formula", "--installed-on-request").splitlines())
    casks = set(_run(brew, "list", "--cask").splitlines())
    if not requested.issubset(formulae):
        raise RuntimeError("Homebrew request metadata incomplete")
    observations: list[dict[str, Any]] = []
    for name in sorted(formulae):
        if name.strip():
            observations.append({
                "resource_id": f"brew_formula:{name}", "category": "brew_formula",
                "name": name,
                "attributes": {"installed": True, "installed_on_request": name in requested},
            })
    for name in sorted(casks):
        if name.strip():
            observations.append({
                "resource_id": f"brew_cask:{name}", "category": "brew_cask",
                "name": name, "attributes": {"installed": True},
            })
    return Inventory(observations, frozenset({"brew_formula", "brew_cask"}))


def discover_ollama_models() -> Inventory:
    """Read model names and content digests from the local Ollama API only.

    An unavailable Ollama service is *not* a completed empty inventory.
    Consequently an offline service cannot cause synthetic model removals.
    """
    request = urllib.request.Request("http://127.0.0.1:11434/api/tags", method="GET")
    try:
        with urllib.request.urlopen(request, timeout=3) as response:
            data = response.read(1024 * 1024 + 1)
    except (OSError, urllib.error.URLError, TimeoutError):
        return Inventory([], frozenset())
    if len(data) > 1024 * 1024:
        raise ValueError("Ollama model metadata exceeded 1 MiB")
    try:
        payload = json.loads(data)
        models = payload["models"]
        if not isinstance(models, list) or len(models) > 20000:
            raise ValueError("Invalid Ollama model inventory")
        output = []
        seen = set()
        for model in models:
            name, digest = model["name"], model["digest"]
            if (not isinstance(name, str) or not name or len(name) > 400
                    or not isinstance(digest, str) or len(digest) != 64
                    or any(c not in "0123456789abcdef" for c in digest)
                    or name in seen):
                raise ValueError("Invalid or duplicate Ollama model metadata")
            seen.add(name)
            output.append({
                "resource_id": f"ollama_model:{name}",
                "category": "ollama_model",
                "name": name,
                "attributes": {"digest": digest},
            })
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid Ollama model response") from exc
    return Inventory(sorted(output, key=lambda item: item["resource_id"]),
                     frozenset({"ollama_model"}))


def discover_apps() -> Inventory:
    output: list[dict[str, Any]] = []
    for root in (Path("/Applications"), Path.home() / "Applications"):
        if not root.exists():
            continue
        if not root.is_dir():
            raise RuntimeError("Application inventory root is not a directory")
        for app in sorted(root.glob("*.app")):
            try:
                with (app / "Contents" / "Info.plist").open("rb") as handle:
                    plist = plistlib.load(handle)
                bundle_id = plist.get("CFBundleIdentifier")
                version = plist.get("CFBundleShortVersionString") or plist.get("CFBundleVersion")
                if not isinstance(bundle_id, str) or not bundle_id:
                    raise ValueError("missing bundle identifier")
                output.append({
                    "resource_id": f"app:{bundle_id}", "category": "app",
                    "name": app.stem, "attributes": {
                        "bundle_id": bundle_id, "version": str(version or ""),
                    },
                })
            except (OSError, ValueError, TypeError, plistlib.InvalidFileException):
                raise RuntimeError("Application metadata inventory incomplete") from None
    return Inventory(output, frozenset({"app"}))


def discover_receipts() -> Inventory:
    """Installed package receipt IDs only; no file lists or install paths."""
    receipts = sorted(set(_run("/usr/sbin/pkgutil", "--pkgs").splitlines()))
    output = [{
        "resource_id": f"pkg_receipt:{rid}",
        "category": "pkg_receipt",
        "name": rid,
        "attributes": {"installed": True},
    } for rid in receipts if rid.strip()]
    return Inventory(output, frozenset({"pkg_receipt"}))


def discover_launchd() -> Inventory:
    """Inventory only labels and scope; never read ProgramArguments or environment."""
    locations = (
        ("system_agent", Path("/Library/LaunchAgents")),
        ("system_daemon", Path("/Library/LaunchDaemons")),
        ("user_agent", Path.home() / "Library" / "LaunchAgents"),
    )
    observations: list[dict[str, Any]] = []
    for scope, directory in locations:
        if not directory.exists():
            continue
        if not directory.is_dir():
            raise RuntimeError("Launchd inventory root is not a directory")
        for file in sorted(directory.glob("*.plist")):
            try:
                with file.open("rb") as handle:
                    data = plistlib.load(handle)
                if not isinstance(data, dict):
                    raise ValueError("unexpected plist root")
                label = data.get("Label")
                # Some legitimate launchd files (e.g. Google Keystone) omit Label.
                # Use stable scoped filename identity without reading command arguments.
                has_label = isinstance(label, str) and bool(label.strip())
                identity = f"label:{label}" if has_label else f"file:{file.name}"
            except (OSError, ValueError, TypeError, plistlib.InvalidFileException):
                raise RuntimeError("Launchd metadata inventory incomplete") from None
            observations.append({
                "resource_id": f"launchd:{scope}:{identity}",
                "category": "launchd",
                "name": label if has_label else file.name,
                "attributes": {"scope": scope, "identity_source": "label" if has_label else "filename"},
            })
    return Inventory(observations, frozenset({"launchd"}))


def discover_os_build() -> Inventory:
    """Version-aware OS identity; no device identifiers or serial numbers."""
    product = _run("/usr/bin/sw_vers", "-productVersion").strip()
    build = _run("/usr/bin/sw_vers", "-buildVersion").strip()
    if not product or not build:
        raise RuntimeError("Incomplete macOS version information")
    return Inventory([{
        "resource_id": "macos:build",
        "category": "macos_build",
        "name": "macOS",
        "attributes": {"version": product, "build": build},
    }], frozenset({"macos_build"}))


def discover(mode: Mode = "deep") -> Inventory:
    if mode not in ("routine", "deep"):
        raise ValueError(f"Unsupported inventory mode: {mode}")
    collectors = [discover_apps, discover_brew, discover_ollama_models]
    if mode == "deep":
        collectors += [discover_receipts, discover_launchd, discover_os_build]
    observations: list[dict[str, Any]] = []
    categories: set[str] = set()
    for collector in collectors:
        result = collector()
        observations.extend(result.observations)
        categories.update(result.completed_categories)
    return Inventory(observations, frozenset(categories))
