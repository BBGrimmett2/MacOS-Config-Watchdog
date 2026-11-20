# ADR 0007: Explicit, read-only expected-state comparison

- Status: Accepted
- Date: 2026-11-19
- Related: ADR 0002, ADR 0004

## Context
Ansible is the desired-state authority, but its manifest emitter is not yet implemented. The monitor already persists local observed resource metadata. Comparisons must avoid treating missing or incomplete observations as proof of an absent package.

## Decision
Introduce a versioned, strict JSON contract consumed only through an explicit local CLI command (`mac-watchdog compare --manifest <path>`). A manifest declares exactly which inventory categories it manages and resource IDs with optional scalar attributes. Only declared attributes are compared. Undeclared observations within managed categories are marked `unmanaged`; expected resources without a currently present observation are `not_observed`, never definitively `missing`. Matched and attribute-mismatched resources are reported separately. A comparison does not change SQLite, invoke Ansible, submit anything to cloud services, or remediate.

Inputs are schema-checked, limited to 1 MiB, and reject duplicate IDs or categories. No credentials, file contents, arbitrary filesystem paths or user documents are part of the format. Manifest production and coverage/freshness-aware missing-state classification are separate future increments.

## Consequences
Results are local and read-only; unmanaged does not mean malicious. This command establishes the consumer interface for an Ansible-generated manifest while avoiding false removal claims and unsafe automatic remediation.
