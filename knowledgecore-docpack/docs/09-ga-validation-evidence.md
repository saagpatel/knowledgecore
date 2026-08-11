# GA Validation Evidence

## Purpose
Capture reproducible gate execution evidence for GA readiness and closeout signoff.

## Command Source of Truth
- `~/Projects/knowledgecore/knowledgecore-docpack/AGENTS.md`
- `~/Projects/knowledgecore/knowledgecore-docpack/docs/04-post-dk-ops-and-followup-policy.md`
- `~/Projects/knowledgecore/knowledgecore-docpack/CHECKLIST_VERIFICATION.md`

## Execution Context
- Branch: `codex/closeout-c1-full-gate-evidence`
- Execution window (UTC): `2026-02-15T07:05:28Z` to `2026-02-15T07:07:07Z`
- Policy: stop-on-failure, diagnose/fix/rerun before proceeding

## Gate Results
| # | Command | Start (UTC) | End (UTC) | Result |
|---|---|---|---|---|
| 1 | `cargo test -p kc_core -p kc_extract -p kc_index -p kc_ask -p kc_cli` | `2026-02-15T07:05:28Z` | `2026-02-15T07:05:50Z` | PASS |
| 2 | `cargo test -p kc_core -- schema_` | `2026-02-15T07:05:54Z` | `2026-02-15T07:05:56Z` | PASS |
| 3 | `cargo test -p kc_cli -- schema_` | `2026-02-15T07:06:03Z` | `2026-02-15T07:06:05Z` | PASS |
| 4 | `cargo test -p apps_desktop_tauri -- rpc_` | `2026-02-15T07:06:15Z` | `2026-02-15T07:06:26Z` | PASS |
| 5 | `cargo test -p apps_desktop_tauri -- rpc_schema` | `2026-02-15T07:06:32Z` | `2026-02-15T07:06:38Z` | PASS |
| 6 | `pnpm lint && pnpm test && pnpm tauri build` | `2026-02-15T07:06:43Z` | `2026-02-15T07:06:56Z` | PASS |

## Bench Gate (Twice)
| Run | Command | Start (UTC) | End (UTC) | Corpus | elapsed_ms | baseline_ms | checksum | Result |
|---|---|---|---|---|---:|---:|---:|---|
| 1 | `cargo run -p kc_cli -- bench run --corpus v1` | `2026-02-15T07:07:01Z` | `2026-02-15T07:07:02Z` | `v1` | `12` | `10` | `7311227353339408228` | PASS |
| 2 | `cargo run -p kc_cli -- bench run --corpus v1` | `2026-02-15T07:07:06Z` | `2026-02-15T07:07:07Z` | `v1` | `12` | `10` | `7311227353339408228` | PASS |

Bench stability outcome:
- Checksum stability across required repeated runs: PASS (`7311227353339408228` consistent)
- Baseline threshold behavior: PASS (`12ms <= 3 * 10ms`)

## Outcome Summary
- All canonical Rust, schema, RPC, and desktop gates passed.
- Bench closure gate passed twice with stable checksum and expected threshold behavior.
- No remediation reruns were required in this evidence run.
