# ADR 0008: Resolve Homebrew independent of launchd PATH

- Status: Accepted
- Date: 2026-11-19
- Related: ADR 0005

## Context
The user LaunchAgent inherits `/usr/bin:/bin:/usr/sbin:/sbin`, which excludes Apple Silicon Homebrew. A `shutil.which("brew")`-only collector therefore silently skips all formula and cask observations; expected-state comparison misleadingly reports everything as `not_observed`.

## Decision
Resolve the executable from the two standard Homebrew locations (`/opt/homebrew/bin/brew`, `/usr/local/bin/brew`) before considering shell PATH. Both existing files must be executable. If none is found, inventory remains explicitly incomplete, not an empty completed category; failed subprocesses still stop reconciliation without claiming removals. Read only package names, not package files.

## Consequences
Both Apple Silicon and Intel installations can be discovered under restricted launchd environments without broadening the LaunchAgent PATH. Unusual custom Homebrew locations still require an explicit executable on PATH; a future configurable path should be validated if needed.
