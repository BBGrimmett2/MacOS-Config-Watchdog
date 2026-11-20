# ADR 0011: Opt-in local-only AI review of anonymous watchdog aggregates

- Status: Proposed
- Date: 2026-11-19
- Related: ADR 0002, ADR 0003, ADR 0010

## Context
The on-device watchdog already collects macOS inventory changes and short-window event signal counts. The next phase should explain meaningful trends without exposing names, paths, raw logs, credentials or device identifiers, and without granting a model any system authority.

## Decision
Ship a separate, **explicitly invoked** `mac-watchdog ai-review` command, never called by the background monitor. Collect only fixed-schema 24-hour aggregates: (allowlisted process, allowlisted signal, count) and (allowlisted inventory category, added/changed/removed count). Read-only SQL produces the input. Do not send resource IDs, filenames, timestamps of individual events, raw messages, manifest contents, diagnostic output or command arguments to the model. If no events or changes exist, return a no-findings response **without invoking a model**, and explicitly state that absence of recorded signals is not proof of good system health.

Use Ollama's `/api/chat` through Python standard-library HTTP to **fixed** loopback `127.0.0.1:11434` with model `qwen3:8b`; no configurable destination, cloud fallback, model-driven tools or arbitrary shell execution. Only the user can invoke it. Limit the serialized input to 4 KiB, model response to 16 KiB, request timeout to 30 seconds and generation to 400 tokens. Treat model responses as untrusted: require JSON with exactly severity, summary, recommendations and confidence; enforce closed enums, text length, list bounds and basic control/path/URL text rejection. Do not store responses automatically, publish to GitHub, notify, execute or remediate. Fail closed on missing local model, invalid schema and connection errors.

This is an advisory experiment, not a guaranteed diagnostic or incident responder. A future service/notification or issue-publishing integration needs separate ADRs, stricter deterministic content validation and explicit approval. Ansible retains all installation and configuration authority. This PR does **not** change Ansible's watchdog version pin.

## Consequences
Model availability (including RAM cost and installed model size) is the user's responsibility. Requests remain on loopback, but Ollama is a locally running separate process and must be trusted and configured to bind locally. Host-level firewall isolation and other apps' Ollama settings remain outside watchdog control. Regex output validation is an additional privacy guard, not a complete secret scanner. Reviews summarize aggregate activity and cannot establish root cause, full coverage or safe remediation.
