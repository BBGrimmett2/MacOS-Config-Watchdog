# Delivery plan

## Phase 1 — Read-only foundation (this branch)
- [x] Project packaging, security guidance, and basic tests
- [x] Local SQLite change history, transaction IDs, versioned JSON export
- [x] Initial macOS application and Homebrew metadata inventory
- [ ] FSEvents listener and event debounce
- [ ] launchd configuration and installation in Ansible-MacOS-Setup (separate PR)
- [ ] 30-minute scans, login/wake reconciliation, weekly deep scan
- [ ] Apple-managed/version-aware baseline and receipt/signature classification
- [ ] Manifest comparison and complete category-aware removal tracking
- [ ] Retention pruning, log rotation, robust independent health observer

## Phase 2 — Local review
- Ollama + Qwen3 8B on-demand; predefined read-only diagnostic tools only
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
