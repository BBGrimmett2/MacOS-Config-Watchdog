# ADR 0009: Distinguish Homebrew dependencies from requested formulae

- Status: Accepted
- Date: 2026-11-19
- Related: ADR 0005, ADR 0007, ADR 0008

## Context
Read-only expected-state comparison initially labels every installed formula not explicitly named by Ansible as unmanaged. This incorrectly puts dependency libraries such as `libuv` in the same class as manually requested software. `brew leaves` is not an accurate substitute for installation intent: a user-requested formula may itself be a dependency of another installed formula.

## Decision
Use Homebrew's read-only `brew list --formula --installed-on-request` together with the full formula list. Each formula records `installed_on_request` as a Boolean in local SQLite. The collector fails closed if reported requested packages are not in the installed list, or if any Homebrew invocation fails. In the expected-state comparison, an observed but unlisted formula with `installed_on_request: false` is classified as `dependency`; one requested directly or missing reliable metadata remains `unmanaged`. Expected packages are matched regardless of how installed. The summary adds a dependency count without changing manifest schema version 1, and the operation remains read-only.

## Consequences
Upgrading the collector records one harmless attribute change for each existing observed formula. Homebrew's recorded installation intent can be altered by users and is not proof of trust or irrelevance; it is a local classification hint. No package is uninstalled or remediated. The client can display dependency items separately or collapse them in future UI.
