# ADR 0006: Identify launchd plists without a Label by filename

- Status: Accepted
- Date: 2026-11-19
- Supersedes: none
- Related: ADR 0002, ADR 0005

## Context
Some legitimate macOS LaunchAgent and LaunchDaemon property lists, including Google Keystone files, do not contain a Label key. Failing the entire deep scan on this condition prevented every collector from committing, leaving last_scan null even though the monitor was running.

## Decision
For a readable launchd plist that has a nonempty Label, use a scoped label identity. When Label is missing or empty, use the plist's basename as a scoped fallback identity, with an explicit identity_source attribute. This is metadata-only: never inventory ProgramArguments, EnvironmentVariables, or plist payloads. An unreadable or malformed plist still fails closed rather than claiming the category completed. Duplicate resource identities must still fail reconciliation; no automatic removals occur on incomplete scans.

## Consequences
Launchd resources may appear as added/removed if an existing plist gains or loses its Label, which is a meaningful metadata change. This is preferable to preventing all other inventory from completing. Future structured partial-collector failure reporting remains a separate task.
