# Delivery plan

## Phase 1 — Read-only foundation (this branch)
- [x] Project packaging, security guidance, and basic tests
- [x] Local SQLite change history, transaction IDs, versioned JSON export
- [x] Initial macOS application and Homebrew metadata inventory
- [x] Initial FSEvents-based listener and debounce (requires on-device testing)
- [ ] launchd configuration and installation in Ansible-MacOS-Setup (separate PR)
- [x] 30-minute reconciliation while monitor runs (login via launchd pending)\n- [x] Initial, persisted weekly deep scans with receipts, launchd labels, OS build metadata\n- [ ] Native macOS wake notifications (currently best-effort wake-gap detection)
- [ ] Apple-managed/version-aware classification and code-signature verification
- [ ] Manifest comparison\n- [x] Category-aware removal tracking with explicit complete-inventory coverage
- [ ] Retention pruning, log rotation, robust independent health observer

## Phase 2 — Local review
- [x] Opt-in Ollama + Qwen3 8B on-demand aggregate-only advisory (no diagnostic tools)
- [ ] Expanded predefined read-only diagnostic tools after separate security review
- AI-backed review, local draft generation, priority notifications
- Schema-validated outputs; avoid interpreting untrusted content as instructions

## Phase 3 — GitHub workflows
- Deterministic field allowlist and fail-closed sensitive-data validation
- Automatic sanitized issues, stable resource IDs, reopening and deduplication
- PR creation requires approval; closure requires two successful reconciliations

## Phase 4 — Guarded Ansible deployment
- Trusted manifest/revision verification; check/diff before apply
- Automatic low-risk deployment only, approvals for destructive/security changes
- Bounded transient retries; rollback only for roles with verified rollback plan
- Rollback always tracked in a sanitized issue, including rollback failure

## Non-goals for this PR
No autonomous writes to macOS settings, Ansible, or GitHub. No AI-driven shell.
