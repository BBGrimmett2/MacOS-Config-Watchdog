# ADR 0003: Local AI, publication security and GitHub lifecycle

- Status: Accepted
- Date: 2026-11-17

## Context
AI should explain detected drift and propose Ansible changes while protecting machine-sensitive data, especially because the repository is public.

## Decision
Use strictly local Ollama inference with Qwen3 8B on Apple Silicon (32 GB+ memory). Invoke the model only for meaningful changes. AI investigation is sandboxed, read-only, and restricted to predefined diagnostic tools. No arbitrary shell, secret reads, cloud fallback, or model-initiated machine writes. Model outputs are untrusted and schema validated.

GitHub is the primary actionable-work tracker. Future automation may create sanitized GitHub issues automatically only through a strict per-field publish allowlist and deterministic fail-closed security validation; the system prompt is not itself an enforcement mechanism. Raw evidence stays on the Mac. PR creation requires explicit approval; no AI-originated autonomous merges. Deduplicate issues by stable resource identity; reopen the same issue if the same problem returns. Close automatically only after two consecutive complete successful reconciliation scans verify resolution; incomplete scans do not count.

Notifications are priority based: immediate critical, batched routine, silently stored informational. Keep all local review history in SQLite.

## Consequences
False-positive security blocks are acceptable; no sensitive data may be posted merely because a model judged it safe. GitHub comments, issue reopen actions and PR text must pass the same validator as initial issue creation.
