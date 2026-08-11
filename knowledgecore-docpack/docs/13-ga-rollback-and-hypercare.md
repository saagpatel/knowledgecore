# Pilot Rollback and Hypercare Plan (GA Deferred)

## Scope
Operational response plan for `v0.1.0-pilot.1` while GA remains blocked on Apple signing/notarization prerequisites.

## Release Class
- Class: `Internal pilot`
- Distribution: trusted internal audience only
- GA status: deferred pending credential remediation

## Rollback Triggers
- Any Sev1 incident in pilot workflow.
- Repeatable data integrity fault.
- Determinism regression in Tier 1 outputs.
- Security/privacy issue requiring immediate containment.

## Rollback Actions
1. Stop further pilot distribution immediately.
2. Revoke pilot recommendation in launch channels.
3. Direct users to previous known-good internal build snapshot.
4. Open incident and capture timeline in:
- `~/Projects/knowledgecore/knowledgecore-docpack/docs/16-ga-hypercare-log.md`
5. Run targeted verification command set before any re-issue:
- `cargo test -p kc_core -p kc_extract -p kc_index -p kc_ask -p kc_cli`
- `pnpm lint && pnpm test && pnpm tauri build`
- `cargo run -p kc_cli -- bench run --corpus v1`

## Hypercare Ownership and Windows
- 0-24h: Engineering on-call triage, immediate response SLA.
- 24-72h: Stabilization and residual risk closure.
- Owners:
  - Engineering owner: runtime correctness, determinism, and incident fixes.
  - QA owner: reproduction validation and verification reruns.
  - Release owner: decision logging and communication updates.

## Escalation Policy
- Sev1: immediate stop-ship for pilot updates until closure evidence is recorded.
- Sev2: patch assessment within hypercare window; fix under freeze policy if needed.
- Sev3+: track as post-pilot backlog unless policy escalation is required.

## Exit Criteria (Pilot Hypercare)
- No open Sev1/Sev2 at 72h close.
- Incident logs complete and linked.
- Remaining risks assigned with explicit owners and due dates.
- Closure summary published in:
- `~/Projects/knowledgecore/knowledgecore-docpack/docs/17-project-closeout-report.md`
