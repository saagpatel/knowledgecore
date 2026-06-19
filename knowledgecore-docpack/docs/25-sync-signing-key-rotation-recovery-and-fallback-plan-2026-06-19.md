# Sync Signing Key Rotation, Recovery, and Fallback Plan - 2026-06-19

## Purpose
Define the approval gate and current implementation boundary for moving encrypted sync signing key custody from initial local enrollment/status/delete into replacement-device rotation, recovery policy, and eventual legacy fallback removal without changing vault formats, weakening crypto, introducing cloud custody, or breaking existing sync heads by accident.

## Verified Current State
- Schema v12 `sync_signing_keys` stores one active encrypted signing seed per trusted device id.
- Signing seeds are encrypted with XChaCha20-Poly1305 using a key derived from the vault unlock passphrase boundary.
- `trust device enroll-signing-key` creates a verified trusted device, enrolls its certificate, and stores the encrypted matching Ed25519 seed.
- CLI and desktop RPC expose custody status, soft-delete, and replacement-device rotation controls without returning secret material.
- `trust device signing-key-rotate` and matching desktop RPC rotation create a replacement signing device/certificate, store the new encrypted local seed, and mark the old local custody row rotated/deleted.
- `trust device signing-key-status` and `trust device signing-key-delete` now return explicit re-enrollment guidance when local custody is missing, retired, or deleted; the guidance states private signing keys are not recoverable.
- Custody-signed S3 sync heads emit `author_signature_alg = "ed25519_sync_head_v1"`.
- Undeclared v3 sync heads still accept the legacy BLAKE3-derived compatibility signature.
- No remote private-key custody, background sync, cloud sync expansion, or fallback removal is implemented.

## Rotation Decision
Rotation should create a new authoring identity rather than mutate private key material in place.

- Done: generate a fresh Ed25519 signing seed through the same explicit local enrollment flow.
- Done: create a new trusted device id and device certificate for the rotated authoring key.
- Done: store the new encrypted seed as a new active `sync_signing_keys` row.
- Done: mark the old encrypted seed row with `rotated_at_ms` and `deleted_at_ms` only after the replacement key is enrolled, verified, and stored.
- Done: keep historical trusted device public keys and certificates readable so old declared heads remain verifiable.
- Done: do not overwrite `seed_ciphertext`, `seed_nonce`, `kdf_alg`, or public-key metadata for an existing active row.

## Recovery Decision
Recovery should be local re-enrollment, not private signing-key backup.

- Do not include sync signing private seeds in export bundles, recovery bundles, recovery escrow descriptors, logs, or docs.
- If local signing custody is lost, re-enroll a new local signing device after restoring/opening the vault.
- Preserve old public trust records for historical verification, but treat lost private signing seeds as unrecoverable.
- Recovery UX should say that local signing authority was re-created, not restored from backup.
- Done: CLI/core-service/desktop RPC status/delete surfaces return guidance to re-enroll a replacement local signing device and republish affected sync targets when custody is missing, retired, or deleted.
- Any future private-key backup or remote custody design requires a separate threat model, secret-handling design, fixtures, and explicit approval.

## Fallback Removal Decision
Legacy undeclared v3 signatures can be removed only after compatibility evidence proves existing heads are not stranded.

- Done: add read-only `sync auth-readiness` telemetry/reporting that classifies sync heads as declared Ed25519, undeclared Ed25519-compatible, undeclared legacy fallback, legacy schema, missing, unsupported, or invalid.
- Done: expose a user-visible CLI/core-service/desktop RPC readiness report that lists whether a target still depends on undeclared legacy fallback.
- Done: expose a multi-target CLI rollout report and generated fixture coverage for missing targets, legacy schema heads, declared Ed25519 heads, undeclared Ed25519-compatible heads, undeclared legacy fallback heads, unsupported declared algorithms, and invalid declared heads.
- Done: add read-only `sync auth-strict-check` as an operator/CI gate and strict pull behavior that fails before applying non-strict-ready heads.
- Done: default pull entrypoints now block non-strict-ready heads before apply while preserving explicit compatibility pull.
- Done: document the fallback-removal approval gate, evidence requirements, stop conditions, and compatibility escape hatch in `docs/26-sync-default-strict-auth-rollout-plan-2026-06-19.md`.
- Final removal must fail undeclared legacy fallback heads with a deterministic sync-auth error and clear remediation guidance.

## Safest Implementation Sequence
1. Done: add explicit rotation command/RPC that enrolls a new signing device and soft-deletes the old custody row only after the new key verifies.
2. Done: add a read-only sync auth readiness report for local sync targets; no writes, no migrations, no cloud behavior changes.
3. Done: add CLI/core-service/desktop RPC copy for local re-enrollment recovery when custody is missing, retired, or deleted.
4. Done: add compatibility fixtures for missing targets, legacy schema heads, undeclared v3 heads, declared Ed25519 heads, and invalid/unsupported declared heads.
5. Done: add a read-only strict-check gate for rollout readiness before runtime rejection.
6. Done: add strict pull for rejecting undeclared legacy fallback before apply.
7. Done: make pull default to strict while retaining explicit compatibility pull.
8. Later, after separate approval: remove undeclared legacy fallback acceptance only after compatibility evidence proves existing heads are not stranded.

## Non-Goals
- No private signing-key export.
- No recovery escrow of sync signing seeds.
- No remote/cloud signing-key custody.
- No background sync.
- No automatic trust import.
- No immediate legacy fallback removal.
- No schema v13 migration in this design checkpoint.

## Required Tests Before Runtime Changes
- Done: rotation creates a new trusted device and leaves old public trust records readable.
- Done: rotation rejects missing active old custody before creating replacement material.
- Current implementation wraps replacement device creation, certificate enrollment, new custody storage, and old custody retirement in one transaction so late failures do not commit partial rotation state.
- Done: deleted/lost custody produces clear re-enrollment guidance without silently downgrading declared-head signing or exposing private seed material.
- Recovery re-enrollment can author a new declared Ed25519 head without requiring old private seed material.
- Done: read-only strict-check gate blocks non-strict-ready targets without mutating targets, removing fallback, or changing pull/push behavior.
- Done: opt-in strict pull rejects non-strict-ready remote heads before apply.
- Done: default pull rejects non-strict-ready remote heads before apply while explicit compatibility pull remains available.
- Future fallback-removal strict mode rejects undeclared legacy signatures while preserving declared Ed25519 acceptance.
- Fixtures prove old declared heads remain verifiable after old private custody is deleted.

## Approval Gates
- Runtime rotation is implemented only as replacement-device local custody rotation; changing it to in-place mutation requires explicit approval.
- Any schema migration requires migration tests, rollback/downgrade expectations, and fixture updates.
- Any private signing-key backup, escrow, export, or remote custody requires a separate threat model and explicit approval.
- Legacy fallback removal requires compatibility evidence and explicit rollout approval.
