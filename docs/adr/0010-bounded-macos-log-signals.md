# ADR 0010: Bounded, privacy-preserving macOS log signals

- Status: Proposed
- Date: 2026-11-19
- Related: ADR 0002, ADR 0003

## Context
A future local model needs trustworthy, low-volume signals about recurring system faults. Streaming arbitrary macOS unified logs into the local database or model would capture secrets and personal material and could overwhelm laptop resources.

## Decision
Use the built-in `/usr/bin/log show` with a fixed process predicate limited to launchd, trustd, mDNSResponder and configd, a five-minute lookback, a 20-second deadline, a 2 MiB stdout budget and 10,000-record parse bound. Run once at startup and every five minutes in the existing LaunchAgent process. The collection is best effort; errors must not become a successful empty observation. Reject malformed JSON rather than claim coverage.

Use deterministic, allowlisted signal patterns for service crashes/restarts, certificate errors and DNS/network failures. Parse log messages transiently in memory only. Persist **only** process label, signal category, event count, and rounded five-minute UTC collection window to the existing private SQLite database; never store raw messages, timestamps of individual lines, user names, paths, commands or log arguments. Retain at most seven days of these aggregate records. Re-query overlaps are idempotent by taking the maximum window count, not adding counts. This is a low-volume signal rollup, not a complete audit or incident timeline. Collection is not exhaustive, and absence of a signal proves nothing.

Expose `mac-watchdog logs` for manual collection and `mac-watchdog log-report` for a bounded local-only aggregate report. No LLM, network access, remediation or cloud publication is introduced. Local AI may later consume *only* schema-checked aggregates with read-only tools and approval-scoped publication policies consistent with ADR 0003.

## Consequences
No log body is stored or exported. Some useful fault events will be missed by the strict allowlist, log volume cap or OS permissions, by design. Only recorded signal counts should be presented as observations; data gaps and incomplete windows must remain explicit. The launchd user context cannot necessarily read all system logs. Device validation of macOS NDJSON output is required before treating collection as a supported health signal.
