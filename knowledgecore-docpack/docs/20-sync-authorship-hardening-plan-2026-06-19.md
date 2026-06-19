# Sync Authorship Hardening Plan - 2026-06-19

## Purpose
Capture the approval-gated implementation contract for fixing sync head authorship without changing vault formats, sync semantics, key custody, or cloud behavior by accident.

## Verified Current Behavior
- `SyncHeadV1` stores `author_device_id`, `author_fingerprint`, `author_signature`, `author_cert_id`, and `author_chain_hash` for schema version 3 heads.
- `sync_signature_payload` canonicalizes public sync fields: `snapshot_id`, `manifest_hash`, `created_at_ms`, device id, fingerprint, certificate id, and chain hash.
- `sign_sync_payload` now uses Ed25519 when encrypted local custody has an unlocked matching device key, or when `KC_SYNC_AUTHOR_SIGNING_KEY_HEX` is provided and matches the verified local author device public key.
- If no unlocked custody key or signing key env var is present, `sign_sync_payload` still emits the legacy 128-character BLAKE3-derived pseudo-signature for compatibility.
- `ensure_remote_trust_matches` now prefers Ed25519 verification against the local trusted-device public key and verified certificate chain, then falls back to the legacy pseudo-signature for existing v3 heads.
- `author_signature_alg = "ed25519_sync_head_v1"` is supported as an optional v3 extension. When present, Ed25519 verification is mandatory and legacy fallback is forbidden; unknown non-empty algorithms are rejected.
- `expected_cert_chain_hash` is also derived from public certificate/device/fingerprint fields.
- Trusted devices store an Ed25519 public key in `trusted_devices.pubkey`; explicit `trust device enroll-signing-key` enrollment now persists the matching private signing seed encrypted in schema v12 `sync_signing_keys`.

## Security Risk
Legacy v3 author signatures still prove deterministic formatting, not authorship. A party that can write a remote sync head and snapshot can recompute the legacy `author_signature` from public fields, so the compatibility fallback must not be treated as production-grade signed sync. Ed25519-authored heads are now verifiable, but full production enforcement still depends on key custody and fallback-removal decisions.

## Design Goal
Remote sync heads should be accepted only when authorship is verified against an approved trust chain and a real Ed25519 signature over a versioned canonical sync payload.

## Required Design Decisions
- Key custody: implemented for local storage/unlock/delete/rotation primitives using encrypted vault-local custody with CLI and desktop RPC surfaces; recovery/fallback-removal policy is captured in `docs/25-sync-signing-key-rotation-recovery-and-fallback-plan-2026-06-19.md`.
- Wire compatibility: `author_signature_alg` is implemented as an optional schema-version-3 extension for read/validation and custody-signed S3 writes.
- Trust source: decide whether remote author certificates must already exist in the local DB, be carried in the signed snapshot, or be verified through another explicit trust-import flow.
- Certificate state: define how expiration, revocation, and provider/session status affect sync acceptance.
- Rollout: define read/write compatibility for existing v1/v2/v3 heads and the exact point at which legacy BLAKE3-derived v3 signatures become hard failures.

## Safest Implementation Slice
1. Done: add test fixtures for a canonical Ed25519 sync signature payload and verification result.
2. Done: add non-migrating verification helpers that reject tampered payloads, unknown keys, malformed signatures, fingerprint mismatches, and chain mismatches.
3. Done: add compatible runtime support that signs with Ed25519 only when an explicit env-provided signing key matches the verified local author device.
4. Done: add optional algorithm parsing and strict declared-Ed25519 acceptance semantics.
5. Done: add initial encrypted local key custody, status/delete surfaces, and declared-algorithm writer emission when the custody key is unlocked.
6. Done: add explicit runtime rotation that enrolls a replacement signing device and retires old local custody while preserving old public trust records.
7. Done: add read-only sync auth readiness reporting that classifies remote heads as declared Ed25519, undeclared Ed25519-compatible, undeclared legacy fallback, legacy schema, missing, or invalid.
8. Remaining: separately approve remote trust import and the point at which undeclared legacy BLAKE3-derived author signatures become hard failures.

## Implementation Checkpoint
- Added a private `kc_core::sync_auth` helper module for future Ed25519 signed-head work.
- Added canonical payload construction with an explicit `signature_alg = "ed25519_sync_head_v1"` domain separator.
- Added Ed25519 verification against the trusted author device public key and verified certificate chain.
- Added tests for canonical payload stability, valid signature verification, tampered payload rejection, wrong-key rejection, malformed signature rejection, malformed public-key rejection, trusted-head verification, tampered-head rejection, and env-key signing.
- Wired compatible runtime acceptance: Ed25519 is preferred for v3 remote heads and legacy BLAKE3-derived signatures remain accepted for existing heads.
- Wired compatible runtime emission: S3 sync emits Ed25519 signatures only when `KC_SYNC_AUTHOR_SIGNING_KEY_HEX` is explicitly provided and matches the verified local author device key; otherwise it keeps legacy emission.
- Wired optional `author_signature_alg` parsing for v3 heads; declared `ed25519_sync_head_v1` heads require Ed25519 success, and unknown algorithms fail closed.
- Added schema v12 `sync_signing_keys` custody storage and CLI/core-service enrollment for encrypted local signing seeds.
- Added CLI/core-service/desktop RPC status and soft-delete surfaces for encrypted local signing-key custody.
- Added CLI/core-service/desktop RPC rotation surfaces that enroll a replacement signing device and mark the old local custody row rotated/deleted.
- Added the rotation/recovery/fallback-removal decision record as `docs/25-sync-signing-key-rotation-recovery-and-fallback-plan-2026-06-19.md`.
- Added read-only `sync auth-readiness` CLI/core-service/desktop RPC reporting for local and URI sync targets; it performs no writes, migrations, fallback removal, cloud expansion, or strict-mode enforcement.
- S3 sync emits declared Ed25519 heads when the custody key is available through the vault unlock/passphrase boundary.
- No cloud behavior, remote trust bootstrapping, background sync, or legacy fallback removal changed in this checkpoint.

## Verification Expectations
- `cargo test -p kc_core --test sync`
- `cargo test -p kc_core --test trust_identity`
- `cargo test -p kc_core --test schema_sync_manifest`
- `cargo test -p kc_core sync_auth`
- `cargo test --workspace --exclude apps_desktop_tauri`
- `cargo test -p apps_desktop_tauri`
- `node scripts/audit-rust.mjs`
- `node scripts/dependency-watch.mjs`

## Approval Gates
- Do not remove the legacy v3 signature fallback, change sync head schema, or change vault storage without explicit design approval.
- Do not extend private-key persistence beyond the encrypted local custody and replacement-device rotation model without explicit recovery design approval.
- Do not introduce background sync, automatic cloud sync, or new remote trust bootstrapping in this lane.
- Do not mark S3 sync or managed identity production-ready until signed-head acceptance, recovery, and resource-limit gates are green.
