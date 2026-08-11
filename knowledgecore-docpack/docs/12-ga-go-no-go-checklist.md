# Launch Go/No-Go Checklist (GA Deferred, Pilot Active)

## Decision Envelope
- Candidate stream: `v0.1.0`
- Decision mode: `Dual-track`
  - GA track: `NO-GO`
  - Pilot track: `GO (internal only)`

## Command Source of Truth
- `~/Projects/knowledgecore/knowledgecore-docpack/AGENTS.md`
- `~/Projects/knowledgecore/knowledgecore-docpack/docs/04-post-dk-ops-and-followup-policy.md`
- `~/Projects/knowledgecore/knowledgecore-docpack/CHECKLIST_VERIFICATION.md`

## Gate Checklist
| Gate | Required for GA | Required for Pilot | Status | Evidence |
|---|---|---|---|---|
| Rust gate (`cargo test -p kc_core -p kc_extract -p kc_index -p kc_ask -p kc_cli`) | Yes | Yes | PASS | `~/Projects/knowledgecore/knowledgecore-docpack/docs/09-ga-validation-evidence.md` |
| Schema/RPC gates | Yes | Yes | PASS | `~/Projects/knowledgecore/knowledgecore-docpack/docs/09-ga-validation-evidence.md` |
| Desktop gate (`pnpm lint && pnpm test && pnpm tauri build`) | Yes | Yes | PASS | `~/Projects/knowledgecore/knowledgecore-docpack/docs/09-ga-validation-evidence.md`, `~/Projects/knowledgecore/knowledgecore-docpack/docs/10-ga-artifact-manifest-v0.1.0.md` |
| Bench run x2 stable checksum | Yes | Yes | PASS | `~/Projects/knowledgecore/knowledgecore-docpack/docs/09-ga-validation-evidence.md` |
| Signed artifacts | Yes | No | FAIL (blocking GA) | `~/Projects/knowledgecore/knowledgecore-docpack/docs/10-ga-artifact-manifest-v0.1.0.md` |
| Notarized + stapled artifacts | Yes | No | FAIL (blocking GA) | `~/Projects/knowledgecore/knowledgecore-docpack/docs/10-ga-artifact-manifest-v0.1.0.md` |

## Stop Conditions (GA)
- Missing Developer ID signing identity.
- Missing notary credentials profile.
- Any unresolved P0/P1.
- Any checksum/signing/notarization mismatch.

## Pilot GO Conditions
- All non-signing functional gates pass.
- Pilot risk disclosure accepted by leadership and engineering owners.
- Controlled audience and internal distribution path documented.
- Rollback and hypercare ownership assigned.

## Signoffs
- Engineering owner:
  - GA: `NO-GO`
  - Pilot: `GO`
- QA owner:
  - GA: `NO-GO`
  - Pilot: `GO`
- Release owner:
  - GA: `NO-GO`
  - Pilot: `GO`

## Decision Summary
- GA release decision: `NO-GO`
- Pilot release decision: `GO (internal only)`
- Formal decision record location:
  - `~/Projects/knowledgecore/knowledgecore-docpack/docs/14-ga-decision-record.md`

## C4 Final Gate Rerun Evidence
| Command | Start (UTC) | End (UTC) | Result | Notes |
|---|---|---|---|---|
| `cargo test -p kc_core -p kc_extract -p kc_index -p kc_ask -p kc_cli` | `2026-02-15T07:19:47Z` | `2026-02-15T07:20:09Z` | PASS | full Rust gate green |
| `pnpm lint && pnpm test && pnpm tauri build` | `2026-02-15T07:20:12Z` | `2026-02-15T07:20:45Z` | PASS | includes macOS bundle outputs |
| `cargo run -p kc_cli -- bench run --corpus v1` | `2026-02-15T07:20:51Z` | `2026-02-15T07:20:51Z` | PASS | `elapsed_ms=13`, `baseline_ms=10`, `checksum=7311227353339408228` |
