# Sync Default Strict Auth Rollout Plan - 2026-06-19

## Purpose
Define the path for default strict sync auth without stranding existing sync heads, weakening crypto, changing vault formats, introducing cloud/background sync, or removing the undeclared legacy fallback prematurely.

## Verified Current State
- Declared `author_signature_alg = "ed25519_sync_head_v1"` heads must pass Ed25519 verification and cannot fall back to the legacy BLAKE3-derived compatibility signature.
- Undeclared schema v3 heads still accept the legacy compatibility signature only through explicit compatibility pull while fallback removal remains separately approval-gated.
- `sync auth-readiness` classifies a single target without writes.
- `sync auth-readiness-report` aggregates multiple targets without writes and preserves caller-provided target order.
- `sync auth-strict-check` is a read-only rollout gate that fails with `KC_SYNC_AUTH_STRICT_BLOCKED` if any provided target is not strict-ready.
- `sync pull --strict-auth` and RPC `strict_auth=true` remain explicit strict controls, and omitted pull strictness now defaults to strict behavior.
- Default sync pull now rejects non-strict-ready remote heads before apply.
- Explicit compatibility pull remains available through CLI `--allow-legacy-auth` and RPC `strict_auth=false`.
- Sync push behavior remains compatibility-preserving.
- No cloud sync expansion, background sync, private signing-key backup/recovery, schema migration, or fallback removal is implemented.

## Rollout Principle
Default strict sync auth is active for pull entrypoints, with an explicit compatibility escape hatch retained until fallback removal is separately approved.

The rollout fails closed for default pull behavior while keeping an explicit, temporary compatibility escape hatch until fallback removal is separately approved. Strict defaulting and fallback removal are different decisions.

## Evidence Required Before Approval
1. Operators run `sync auth-readiness-report` across every known sync target set.
2. Operators run `sync auth-strict-check` against the same target sets and record zero `strict_blocked_count`.
3. Any `legacy_schema`, `undeclared_ed25519_compatible`, `undeclared_legacy_fallback`, `unsupported_declared_algorithm`, or `invalid` target is remediated and rechecked.
4. At least one default strict pull succeeds for each active target class intended for normal use.
5. The evidence package records target count, classification counts, strict-ready count, strict-blocked count, invalid count, and whether missing targets were expected.

## Approval Gate
Future expansion or fallback removal requires explicit approval after reviewing the evidence package.

Approval must name:
- Whether any expansion beyond current CLI/core/RPC pull defaults is included.
- Whether file targets, S3 targets, or both are included.
- Whether any temporary compatibility override remains available.
- The rollback command or configuration path.
- The stop condition that prevents proceeding to fallback removal.

## Implementation Sequence
1. Done: strict-readiness classification and multi-target reports.
2. Done: read-only strict-check gate.
3. Done: opt-in strict pull trial flag for CLI and desktop RPC.
4. Done: make pull default to strict for CLI/core/RPC pull entrypoints.
5. Done: keep compatibility override available while fallback removal remains unapproved.
6. Later, after separate approval: remove undeclared legacy fallback acceptance.

## Default-Strict Configuration Boundary
Use explicit pull entrypoint routing and request-level compatibility controls rather than changing low-level verification semantics silently.

The implementation should:
- Keep `ensure_remote_trust_matches` compatibility behavior available for approved fallback windows and explicit compatibility pulls.
- Route default strict behavior through pull entrypoints that can emit `KC_SYNC_AUTH_STRICT_BLOCKED` before apply.
- Avoid modifying sync head schema versions or vault formats.
- Avoid writing to sync targets during readiness or strict-check operations.
- Avoid adding cloud/background sync behavior.

## Compatibility Escape Hatch
Retain a temporary explicit compatibility mode until fallback removal is separately approved.

The escape hatch must:
- Be visible in CLI/RPC request shape or local configuration.
- Emit or return enough context to identify the non-strict-ready target.
- Not downgrade declared Ed25519 heads.
- Not bypass existing trust fingerprint checks.

## Stop Conditions
Stop and do not proceed to fallback removal if any evidence shows:
- `strict_blocked_count > 0`.
- `depends_on_legacy_fallback_count > 0`.
- Any `invalid` or `unsupported_declared_algorithm` target.
- Any target is expected to be present but reports `no_remote_head`.
- Any default strict pull fails for a target intended for production use.
- Any remediation requires private signing-key backup, remote custody, schema migration, or cloud/background sync behavior.

## Verification Expectations
- `cargo fmt --all -- --check`
- `cargo test -p kc_core sync_auth`
- `cargo test -p kc_cli sync`
- `cargo test -p apps_desktop_tauri`
- `cargo test --workspace --exclude apps_desktop_tauri`
- `cargo build -p apps_desktop_tauri`
- `node scripts/audit-rust.mjs`
- `node scripts/dependency-watch.mjs`
- `git diff --check`

## Done Criteria
This lane is complete when default strict pull behavior, evidence requirements, stop conditions, implementation sequence, compatibility escape hatch, and non-goals are documented and verified. Legacy fallback removal remains unimplemented until separately approved.
