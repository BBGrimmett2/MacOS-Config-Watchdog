# ADR 0001: Repository boundary and phased delivery

- Status: Accepted
- Date: 2026-11-17

## Context
The macOS Configuration Watchdog must evolve independently of the user's Ansible Mac setup. The initial target is the personal Mac, with future work Mac support requiring separate profiles and histories.

## Decision
Keep the watchdog Python package, local diagnostics, state model, and future menu bar interfaces in `BBGrimmett2/MacOS-Config-Watchdog`. Keep Ansible roles, installation, launchd configuration and expected-state manifest generation in `BBGrimmett2/Ansible-MacOS-Setup`. Integrate through a versioned manifest and compatible JSON contracts.

Deliver in phases: (1) observer/storage, (2) local AI/notifications, (3) GitHub workflows, (4) guarded Ansible deployment and rollback. Work through feature branches and PRs, never direct-to-main; merging can be automated only after required tests, security checks, ADR review and applicable branch protections succeed.

## Consequences
Cross-repository compatibility needs explicit versioning and tests. Future work-machine deployment must have isolated storage, policies and permissions rather than sharing personal inventories. No assumption that a design choice is already implemented.
