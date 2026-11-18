# MacOS Config Watchdog

Local-first macOS configuration drift monitoring. This project is under active development; no monitoring agent is installed by cloning the repository.

Design: Ansible owns expected state and deployment; this repository owns discovery, local observation, SQLite history, and JSON interfaces. The personal Mac is the initial target.
