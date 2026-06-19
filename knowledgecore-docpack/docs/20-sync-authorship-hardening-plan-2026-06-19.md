# Sync Authorship Hardening Plan - 2026-06-19

## Purpose
Capture the approval-gated implementation contract for fixing sync head authorship without changing vault formats, sync semantics, key custody, or cloud behavior by accident.

## Verified Current Behavior
- `SyncHeadV1` stores `author_device_id`, `author_fingerprint`, `author_signature`, `author_cert_id`, and `author_chain_hash` for schema version 3 heads.
- `sync_signature_payload` canonicalizes public sync fields: `snapshot_id`, `manifest_hash`, `created_at_ms`, device id, fingerprint, certificate id, and chain hash.
- `sign_sync_payload` does not use Ed25519. It returns a 128-character hex value made from two BLAKE3 hashes over public payload material.
- `ensure_remote_trust_matches` validates v3 `author_signature` by recomputing `sign_sync_payload` from the remote head fields.
- `expected_cert_chain_hash` is also derived from public certificate/device/fingerprint fields.
- Trusted devices store an Ed25519 public key in `trusted_devices.pubkey`, but the generated private signing key is not persisted by the current trust-device flow.

## Security Risk
The current v3 author signature proves deterministic formatting, not authorship. A party that can write a remote sync head and snapshot can recompute the expected `author_signature` from public fields. This does not provide Ed25519 authenticity and must not be treated as production-grade signed sync.

## Design Goal
Remote sync heads should be accepted only when authorship is verified against an approved trust chain and a real Ed25519 signature over a versioned canonical sync payload.

## Required Design Decisions
- Key custody: choose how the local Ed25519 private key is generated, stored, unlocked, rotated, backed up, and deleted.
- Wire compatibility: decide whether to keep schema version 3 with an explicit `author_signature_alg` field or introduce sync head schema version 4.
- Trust source: decide whether remote author certificates must already exist in the local DB, be carried in the signed snapshot, or be verified through another explicit trust-import flow.
- Certificate state: define how expiration, revocation, and provider/session status affect sync acceptance.
- Rollout: define read/write compatibility for existing v1/v2/v3 heads and the exact point at which forged-hash v3 heads become hard failures.

## Safest Implementation Slice
1. Add test fixtures for a canonical Ed25519 sync signature payload and verification result.
2. Add non-migrating verification helpers that accept `(payload, signature, verifying_key)` and reject tampered payloads, unknown keys, malformed signatures, and chain mismatches.
3. Add sync acceptance tests for file and S3-emulated transports that prove forged BLAKE3-derived author signatures are rejected once the new signed-head mode is enabled.
4. Only after design approval, wire the helpers into sync head read/write paths behind an explicit schema/algorithm transition.

## Implementation Checkpoint
- Added a private `kc_core::sync_auth` helper module for future Ed25519 signed-head work.
- Added canonical payload construction with an explicit `signature_alg = "ed25519_sync_head_v1"` domain separator.
- Added Ed25519 verification against a supplied author public key.
- Added tests for canonical payload stability, valid signature verification, tampered payload rejection, wrong-key rejection, malformed signature rejection, and malformed public-key rejection.
- This checkpoint is intentionally non-migrating and not wired into sync head read/write acceptance yet.
- No sync head schema, vault storage, private-key custody, remote trust bootstrapping, or cloud behavior changed in this checkpoint.

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
- Do not change sync head schema, accepted signature semantics, or vault storage without explicit design approval.
- Do not persist private keys until key custody is approved.
- Do not introduce background sync, automatic cloud sync, or new remote trust bootstrapping in this lane.
- Do not mark S3 sync or managed identity production-ready until signed-head acceptance, recovery, and resource-limit gates are green.
