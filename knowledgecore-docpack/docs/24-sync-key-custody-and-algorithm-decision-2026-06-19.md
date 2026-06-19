# Sync Key Custody and Algorithm Decision - 2026-06-19

## Purpose
Define the approval-gated design lane for moving sync authorship from compatible Ed25519 support to production-enforced signed heads without changing vault formats, cloud behavior, or private-key storage by accident.

## Verified Current State
- `SyncHeadV1` currently has `schema_version`, `snapshot_id`, `manifest_hash`, `created_at_ms`, `trust`, `author_device_id`, `author_fingerprint`, `author_signature`, `author_cert_id`, and `author_chain_hash`.
- `author_signature_alg` is now accepted as an optional schema-version-3 extension on read/validation, but writers still omit it.
- `sync_auth::canonical_sync_author_payload_v1` domain-separates Ed25519 payloads with `signature_alg = "ed25519_sync_head_v1"` inside the canonical bytes.
- `verify_sync_head_author_signature_v1` verifies v3 author fields against the trusted device public key and verified certificate chain.
- `ensure_remote_trust_matches` prefers Ed25519 verification, then accepts the legacy BLAKE3-derived signature when Ed25519 verification fails.
- `sign_sync_payload` emits Ed25519 only when `KC_SYNC_AUTHOR_SIGNING_KEY_HEX` is present and its derived public key matches the verified local author device key; otherwise it emits the legacy pseudo-signature.
- Trusted devices persist Ed25519 public keys, but the current local trust-device flow does not persist the corresponding signing private key.

## Decision
Adopt an explicit algorithm-signaled sync head transition before removing the legacy fallback.

- Introduce a new signed-head mode using an explicit algorithm signal rather than inferring Ed25519 only from verification success.
- Prefer adding `author_signature_alg` to the sync head metadata over silently changing v3 semantics.
- Keep existing v1/v2/v3 heads readable during the transition.
- Treat legacy BLAKE3-derived v3 signatures as compatibility-only and never as production-grade signed sync.
- Do not persist sync signing private keys until key custody has a dedicated implementation plan, storage boundary, unlock story, rotation story, and recovery/delete behavior.

## Recommended Key Custody Direction
Use vault-local encrypted key custody rather than environment variables for production signing.

- Generate an Ed25519 signing key for the enrolled local device during an explicit trust/key-enrollment flow.
- Encrypt the private signing seed with a key derived from the already-approved vault unlock boundary or another explicitly approved local secret boundary.
- Store only encrypted private-key material plus non-secret metadata in the vault.
- Keep the trusted device public key as the verification anchor.
- Require unlock before signing sync heads; locked vaults must not sign.
- Support explicit rotation by enrolling a new device key/certificate and marking old signing material retired.
- Support explicit deletion by removing encrypted private-key material without deleting historical public trust records needed for verification.

## Schema and Compatibility Contract
- Add an explicit `author_signature_alg` field for future newly authored Ed25519 heads, with value `ed25519_sync_head_v1`, after writer/key-custody approval.
- Continue accepting schema-version-3 heads without `author_signature_alg` only through the documented legacy fallback window.
- For heads with `author_signature_alg = "ed25519_sync_head_v1"`, require Ed25519 verification success and do not fall back to the legacy pseudo-signature.
- Reject unknown non-empty `author_signature_alg` values with `KC_TRUST_SIGNATURE_INVALID` or a narrower sync-auth error code.
- Decide separately whether the field ships as schema version 3 extension or as schema version 4. Do not implement either path without fixture and migration/compatibility coverage.

## Safest First Implementation Slice
1. Done: add parser/validator support for optional `author_signature_alg` on `SyncHeadV1` without changing writer behavior.
2. Done: add generated fixtures for legacy v3, v3 plus `ed25519_sync_head_v1`, and unknown-algorithm heads.
3. Done: change acceptance semantics only for heads that explicitly declare `ed25519_sync_head_v1`: Ed25519 success required; legacy fallback forbidden.
4. Done: keep writer behavior unchanged until key custody is implemented; env-key signing continues to emit compatibility heads.
5. Done: add tests proving unknown algorithms fail, declared Ed25519 rejects tampering, and legacy undeclared v3 remains accepted during the compatibility window.

## Implementation Checkpoint
- `SyncHeadV1` now accepts optional `author_signature_alg` as a v3 extension and omits it from newly written heads.
- The sync head schema validator allows only `ed25519_sync_head_v1` or `null` for `author_signature_alg`.
- Declared `ed25519_sync_head_v1` remote heads require Ed25519 verification success and cannot fall back to the legacy BLAKE3-derived pseudo-signature.
- Unknown non-empty declared algorithms fail with `KC_TRUST_SIGNATURE_INVALID`.
- Undeclared v3 heads still accept the legacy compatibility fallback.

## Non-Goals
- No cloud sync expansion.
- No background sync.
- No S3 production-readiness claim.
- No private-key persistence in this decision record.
- No vault format migration in this decision record.
- No removal of the legacy fallback until rollout timing is explicitly approved.

## Approval Gates
- Changing writer behavior to emit `author_signature_alg` requires explicit key-custody/writer approval.
- Persisting private signing keys requires explicit key-custody implementation approval and tests for unlock, rotation, backup/recovery, and deletion behavior.
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
This design lane is done when the decision record and optional algorithm enforcement slice are merged, with key persistence and undeclared legacy fallback removal still approval-gated.
