# Sync Key Custody and Algorithm Decision - 2026-06-19

## Purpose
Define the implementation contract for moving sync authorship from compatible Ed25519 support to production-enforced signed heads without changing cloud behavior or removing legacy compatibility by accident.

## Verified Current State
- `SyncHeadV1` currently has `schema_version`, `snapshot_id`, `manifest_hash`, `created_at_ms`, `trust`, `author_device_id`, `author_fingerprint`, `author_signature`, `author_cert_id`, and `author_chain_hash`.
- `author_signature_alg` is now accepted as an optional schema-version-3 extension on read/validation; writers emit it only when an unlocked encrypted custody key signs the sync head.
- `sync_auth::canonical_sync_author_payload_v1` domain-separates Ed25519 payloads with `signature_alg = "ed25519_sync_head_v1"` inside the canonical bytes.
- `verify_sync_head_author_signature_v1` verifies v3 author fields against the trusted device public key and verified certificate chain.
- `ensure_remote_trust_matches` prefers Ed25519 verification, then accepts the legacy BLAKE3-derived signature when Ed25519 verification fails.
- `sign_sync_payload` emits declared Ed25519 when encrypted local custody has an unlocked matching signing key; the env-key bridge still emits undeclared Ed25519 for compatibility, and missing signing keys fall back to the legacy pseudo-signature.
- Trusted devices persist Ed25519 public keys; schema v12 `sync_signing_keys` stores encrypted private signing seeds for explicitly enrolled local signing devices.

## Decision
Adopt an explicit algorithm-signaled sync head transition before removing the legacy fallback.

- Introduce a new signed-head mode using an explicit algorithm signal rather than inferring Ed25519 only from verification success.
- Prefer adding `author_signature_alg` to the sync head metadata over silently changing v3 semantics.
- Keep existing v1/v2/v3 heads readable during the transition.
- Treat legacy BLAKE3-derived v3 signatures as compatibility-only and never as production-grade signed sync.
- Do not extend sync signing private-key persistence beyond the approved local encrypted custody model until rotation, recovery, and fallback-removal behavior is explicitly approved.

## Recommended Key Custody Direction
Use vault-local encrypted key custody rather than environment variables for production signing.

- Done: generate an Ed25519 signing key for the enrolled local device during explicit `trust device enroll-signing-key`.
- Done: encrypt the private signing seed with XChaCha20-Poly1305 using a key derived from the vault unlock passphrase boundary.
- Done: store only encrypted private-key material plus non-secret metadata in schema v12 `sync_signing_keys`.
- Done: keep the trusted device public key as the verification anchor.
- Done: require unlock/passphrase availability before signing declared sync heads; locked custody fails closed rather than silently downgrading.
- Done: expose explicit status and soft-delete surfaces for local encrypted signing-key custody.
- Support explicit rotation by enrolling a new device key/certificate and marking old signing material retired.
- Done: support explicit deletion by retiring encrypted private-key material without deleting historical public trust records needed for verification.

## Schema and Compatibility Contract
- Add an explicit `author_signature_alg` field for newly authored custody-signed Ed25519 heads, with value `ed25519_sync_head_v1`.
- Continue accepting schema-version-3 heads without `author_signature_alg` only through the documented legacy fallback window.
- For heads with `author_signature_alg = "ed25519_sync_head_v1"`, require Ed25519 verification success and do not fall back to the legacy pseudo-signature.
- Reject unknown non-empty `author_signature_alg` values with `KC_TRUST_SIGNATURE_INVALID` or a narrower sync-auth error code.
- The field ships as a schema-version-3 extension for the compatibility window; any later schema-version-4 transition requires separate fixture and migration/compatibility coverage.

## Safest First Implementation Slice
1. Done: add parser/validator support for optional `author_signature_alg` on `SyncHeadV1` without changing writer behavior.
2. Done: add generated fixtures for legacy v3, v3 plus `ed25519_sync_head_v1`, and unknown-algorithm heads.
3. Done: change acceptance semantics only for heads that explicitly declare `ed25519_sync_head_v1`: Ed25519 success required; legacy fallback forbidden.
4. Done: keep env-key signing compatibility heads undeclared while custody-signed heads declare `ed25519_sync_head_v1`.
5. Done: add tests proving unknown algorithms fail, declared Ed25519 rejects tampering, and legacy undeclared v3 remains accepted during the compatibility window.

## Implementation Checkpoint
- `SyncHeadV1` now accepts optional `author_signature_alg` as a v3 extension and omits it from newly written heads.
- The sync head schema validator allows only `ed25519_sync_head_v1` or `null` for `author_signature_alg`.
- Declared `ed25519_sync_head_v1` remote heads require Ed25519 verification success and cannot fall back to the legacy BLAKE3-derived pseudo-signature.
- Unknown non-empty declared algorithms fail with `KC_TRUST_SIGNATURE_INVALID`.
- Undeclared v3 heads still accept the legacy compatibility fallback.
- Schema v12 adds `sync_signing_keys` for encrypted local custody metadata and encrypted signing seeds.
- `trust device enroll-signing-key` creates a verified trusted device, enrolls its certificate, and stores the encrypted matching signing seed without printing secret material.
- `trust device signing-key-status` and `trust device signing-key-delete` expose custody metadata and explicit local soft-delete without printing secret material; desktop RPC mirrors those status/delete surfaces.
- S3 sync uses an unlocked custody key to emit declared Ed25519 heads; if no custody key exists, compatibility behavior is preserved.

## Non-Goals
- No cloud sync expansion.
- No background sync.
- No S3 production-readiness claim.
- No remote/cloud private-key custody.
- No removal of undeclared legacy fallback.
- No removal of the legacy fallback until rollout timing is explicitly approved.

## Approval Gates
- Changing writer behavior beyond custody-signed S3 heads requires explicit approval.
- Extending private signing-key persistence to rotation, backup/recovery, or remote custody requires explicit approval and tests.
- Removing the legacy fallback requires explicit rollout approval and compatibility evidence for existing heads.
- Any vault metadata/schema change requires fixtures, downgrade/rollback expectations, and no private-document ingestion.

## Verification Expectations for the Next Code Lane
- `cargo fmt --all -- --check`
- `cargo test -p kc_core sync_auth`
- `cargo test -p kc_core --test sync`
- `cargo test -p kc_core --test schema_sync_manifest`
- `cargo test --workspace --exclude apps_desktop_tauri`
- `cargo test -p apps_desktop_tauri`
- `node scripts/audit-rust.mjs`
- `node scripts/dependency-watch.mjs`

## Done Criteria
This lane is done when encrypted local custody, custody-signed declared S3 heads, and compatibility fallback preservation are verified, with rotation/recovery and undeclared legacy fallback removal still approval-gated.
