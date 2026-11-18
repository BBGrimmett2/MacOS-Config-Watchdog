# ADR 0005: Deep discovery scheduling and category coverage

- Status: Accepted
- Date: 2026-11-18
- Related: [ADR 0002](0002-observation-and-state.md)

## Context
A full system inventory every 30 minutes would be expensive; scanning only events can miss
package and launchd changes. Deep scans must run on initial startup and weekly, even
if the observer process restarts.

## Decision
Separate routine collectors (apps and Homebrew metadata) from deep collectors
(package receipt identifiers, launchd job labels/scope, macOS version/build).
Each collector reports explicitly completed categories. Missing permissions,
invalid metadata or collection failure aborts reconciliation, and must never
be interpreted as resource removal. The scheduler reads the last successful
deep scan timestamp from SQLite rather than using a restart-reset timer.
Launchd triggers the monitor on login; an observed wall-clock gap triggers a
post-wake reconciliation attempt, but this wake detector is best-effort and
not a replacement for a platform wake notification.

Do not read launchd ProgramArguments or environment variables, user documents,
package file listings, or key material. Additional collectors must separately
define their sensitivity and completion semantics before being enabled.

## Consequences
The first deep inventory can find many preexisting unmanaged items. Stock
classification, manifest comparison, signature verification and additional
deep collectors are separate planned increments; do not equate all discovered
third-party identifiers with malicious changes. A future native wake hook
should replace best-effort wall-clock gap detection.
