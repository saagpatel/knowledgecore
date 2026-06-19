# Sync Signing Key Rotation, Recovery, and Fallback Plan - 2026-06-19

## Purpose
Define the approval gate and current implementation boundary for moving encrypted sync signing key custody from initial local enrollment/status/delete into replacement-device rotation, recovery policy, and eventual legacy fallback removal without changing vault formats, weakening crypto, introducing cloud custody, or breaking existing sync heads by accident.

## Verified Current State
- Schema v12 `sync_signing_keys` stores one active encrypted signing seed per trusted device id.
- Signing seeds are encrypted with XChaCha20-Poly1305 using a key derived from the vault unlock passphrase boundary.
- `trust device enroll-signing-key` creates a verified trusted device, enrolls its certificate, and stores the encrypted matching Ed25519 seed.
- CLI and desktop RPC expose custody status, soft-delete, and replacement-device rotation controls without returning secret material.
- `trust device signing-key-rotate` and matching desktop RPC rotation create a replacement signing device/certificate, store the new encrypted local seed, and mark the old local custody row rotated/deleted.
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
- Any future private-key backup or remote custody design requires a separate threat model, secret-handling design, fixtures, and explicit approval.

## Fallback Removal Decision
Legacy undeclared v3 signatures can be removed only after compatibility evidence proves existing heads are not stranded.

- Done: add read-only `sync auth-readiness` telemetry/reporting that classifies sync heads as declared Ed25519, undeclared Ed25519-compatible, undeclared legacy fallback, legacy schema, missing, unsupported, or invalid.
- Done: expose a user-visible CLI/core-service/desktop RPC readiness report that lists whether a target still depends on undeclared legacy fallback.
- Only after that evidence exists, add a separate opt-in enforcement flag or schema-version transition plan.
- Final removal must fail undeclared legacy fallback heads with a deterministic sync-auth error and clear remediation guidance.

## Safest Implementation Sequence
1. Done: add explicit rotation command/RPC that enrolls a new signing device and soft-deletes the old custody row only after the new key verifies.
2. Done: add a read-only sync auth readiness report for local sync targets; no writes, no migrations, no cloud behavior changes.
3. Add UI/CLI copy for local re-enrollment recovery when custody is missing or deleted.
4. Add compatibility fixtures for existing undeclared v3 heads, declared Ed25519 heads, and fallback-removal failure cases.
5. Add opt-in strict mode for rejecting undeclared legacy fallback before making it default.

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
- Deleted/lost custody produces clear locked/missing-key behavior without silently downgrading declared-head signing.
- Recovery re-enrollment can author a new declared Ed25519 head without requiring old private seed material.
- Fallback-removal strict mode rejects undeclared legacy signatures while preserving declared Ed25519 acceptance.
- Fixtures prove old declared heads remain verifiable after old private custody is deleted.

## Approval Gates
- Runtime rotation is implemented only as replacement-device local custody rotation; changing it to in-place mutation requires explicit approval.
- Any schema migration requires migration tests, rollback/downgrade expectations, and fixture updates.
- Any private signing-key backup, escrow, export, or remote custody requires a separate threat model and explicit approval.
- Legacy fallback removal requires compatibility evidence and explicit rollout approval.
