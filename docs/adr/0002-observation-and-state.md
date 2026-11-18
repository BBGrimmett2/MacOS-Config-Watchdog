# ADR 0002: Observation, baseline, local history and reports

- Status: Accepted
- Date: 2026-11-17

## Context
The watchdog must identify non-stock macOS components, distinguish unmanaged changes from expected Ansible configuration, and produce actionable grouped changes without flooding the system.

## Decision
Use a Python package installed via Ansible and supervised by macOS launchd. Watch supported filesystem changes with FSEvents and debounce bursts; reconcile system inventory every 30 minutes and after login/wake; run a deep inventory at initialization and weekly. Do not mistake absent permissions or incomplete scans for deletions.

Use Ansible as desired-state authority via a versioned expected-state manifest emitted by the shared Ansible reporting utility. Build version-aware stock macOS classification using OS build, trustworthy system metadata, package receipts and code-signature verification; Apple signing alone is not proof of stock status. Record changed resources and grouped transactions with retained technical evidence locally.

Store state in a permission-restricted local SQLite database with schema versioning and JSON export for a future menu bar app. Keep meaningful change history indefinitely, prune redundant snapshots after 30 days, and rotate logs. Never commit local databases, exported inventories, personal paths, diagnostic evidence, private keys or credentials. Monitor the watchdog itself, including an independent launchd-supervised health mechanism.

## Consequences
Deep discovery has measurable cost and must bound filesystem traversal. Event monitoring supplements rather than replaces reconciliation. The initial implementation is partial until FSEvents, weekly scans, Apple-aware classification, and manifest reconciliation are delivered and verified.
