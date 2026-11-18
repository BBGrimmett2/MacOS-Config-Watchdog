# Architecture Decision Records

ADRs capture decisions that must survive individual chat sessions and agent handoffs.

## Policy
- Add or update an ADR in the same PR as any major architectural, security, persistence, deployment, model, or automation decision.
- Use sequential IDs, context, decision, consequences, and status.
- Never rewrite an accepted ADR to conceal history. Supersede it with a new ADR and link both records.
- Major code changes without an ADR or reference to an existing ADR should not be merged.
- Local code and Ansible integration must conform to these accepted decisions unless a superseding ADR is approved.

## Index
- [0001 — Repository boundary and phased delivery](0001-repository-and-phases.md)
- [0002 — Local scanning, baseline, persistence and reporting](0002-observation-and-state.md)
- [0003 — Local AI and GitHub security boundaries](0003-ai-and-github-security.md)
- [0004 — Guarded deployment, rollback and incident tracking](0004-guarded-deployment.md)
