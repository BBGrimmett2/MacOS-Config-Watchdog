# ADR 0011: Opt-in local-only AI review of anonymous watchdog aggregates

- Status: Proposed
- Date: 2026-11-19
- Related: ADR 0002, ADR 0003, ADR 0010

## Context
The on-device watchdog already collects macOS inventory changes and short-window event signal counts. The next phase should explain meaningful trends without exposing names, paths, raw logs, credentials or device identifiers, and without granting a model any system authority.

## Decision
Ship a separate, **explicitly invoked** `mac-watchdog ai-review` command, never called by the background monitor. Collect only fixed-schema 24-hour aggregates: (allowlisted process, allowlisted signal, count) and (allowlisted inventory category, added/changed/removed count). Read-only SQL produces the input. Do not send resource IDs, filenames, timestamps of individual events, raw messages, manifest contents, diagnostic output or command arguments to the model. If no events or changes exist, return a no-findings response **without invoking a model**, and explicitly state that absence of recorded signals is not proof of good system health.

Use Ollama's `/api/chat` through Python standard-library HTTP to fixed loopback `127.0.0.1:11434`, model `qwen3:8b`; no cloud fallback, model tools, or arbitrary shell. A POSIX main-thread `SIGALRM` deadline bounds the complete request, headers, response body and validation at 30 seconds; if another alarm is active, inference fails closed. Cap request input at 4 KiB, response at 16 KiB and model generation at 128 tokens.

**Model output is not executable prose.** The model selects only `focus` from the currently observed categories (service/certificate/network/inventory) and `confidence` from low/medium/high, via JSON schema and strict membership validation. All displayed explanations and follow-up checks are application-owned fixed strings. Neither severity nor recommendations nor free-form summary come from the model. Severity follows fixed rules: any recorded log fault yields advisory warning; inventory-only changes yield informational; aggregate-only evidence never becomes critical. This remains a descriptive, unverified advisory, not a permission to act.

Maintain best-effort sampling provenance by recording each bounded five-minute log collection's completed status and count (including successful zero-event windows) or failed status, without storing exceptions, raw log lines or identifiers. This is a backwards-compatible additive table in the existing v1 local SQLite schema; older deployed agents can continue reading/writing their original tables, while new agents populate the added coverage table. Each review reports the latest sampling attempt, its status, 24-hour success/failure window counts, and latest inventory scan. Sampling is explicitly partial/unverified even when recent; historical log signals with stale or failed latest sampling are not sent to Ollama.

An initial baseline consisting of additions alone does not invoke inference. Only non-addition inventory changes or recognized fault signals qualify, and no data means no model request. Model output is never persisted, published, used for notifications, executed, or handed to Ansible. The watchdog repo owns the feature; Ansible retains deployment and desired-state authority. This PR does not change the Ansible pin.

A local real-model smoke test is opt-in, using only synthetic observations in a temporary SQLite database; the regular CI test suite uses mocked Ollama HTTP and bounded-response tests. Model availability and device configuration are outside this PR.

## Consequences
Model availability (including RAM cost and installed model size) is the user's responsibility. Requests remain on loopback, but Ollama is a locally running separate process and must be trusted and configured to bind locally. Host-level firewall isolation and other apps' Ollama settings remain outside watchdog control. No model prose is rendered; structured focus and confidence receive strict validation. Reviews summarize aggregate activity and cannot establish root cause, full coverage or safe remediation. No AI response text is copied into reports, so there is no command-language blacklist to maintain. Severity is strictly advisory and not connected to notifications.
