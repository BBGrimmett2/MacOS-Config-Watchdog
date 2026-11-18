# MacOS Config Watchdog

Local-first macOS configuration drift monitoring. This project is under active development; no monitoring agent is installed by cloning the repository.

Design: Ansible owns expected state and deployment; this repository owns discovery, local observation, SQLite history, and JSON interfaces. The personal Mac is the initial target.

## Current development status

PR #1 is a **development foundation**, not yet a deployed watchdog.
Supports inventory of top-level apps and Homebrew formulae/casks; local-only
SQLite changes, JSON export, and an event-driven watcher. It does **not** yet
provide stock-macOS classification, Ansible manifest reconciliation, weekly deep
collectors, or automatic deployment.

### Development commands

```sh
python3 -m pip install -e '.[test]'
python3 -m pytest -q
mac-watchdog scan
mac-watchdog health
mac-watchdog export
mac-watchdog monitor
```

`monitor` is macOS-only and observes selected application and Homebrew directories.
A launchd integration PR in the separate Ansible repository is required before
this will start automatically at login. By design, these commands do not modify
macOS configuration. Never paste local JSON exports into public GitHub issues.

See [ADRs](docs/adr/README.md) and [roadmap](docs/ROADMAP.md).
