# Local Recovery Kit v2

## Purpose
Define local-only recovery bundle contracts for restoring vault encryption access using a user-held recovery phrase.

## Invariants
- Recovery bundles are generated to a user-selected local directory only.
- Bundle manifests are canonical JSON with deterministic field ordering.
- Recovery verification hard-fails on phrase mismatch or bundle tampering.
- Recovery verification decrypts `key_blob.enc` with the phrase-derived key, validates the deterministic recovery nonce, and rejects undecryptable or empty restored passphrases.
- Recovery artifacts never auto-upload to sync targets.

## Non-goals
- Remote backup escrow.
- Custodial key management.
- Multi-party secret sharing.

## Interface contracts
- Core operations:
  - `recovery_generate_bundle`
  - `recovery_verify_bundle`
  - `recovery_status`
- Bundle layout:
  - `recovery_manifest.json`
  - `key_blob.enc`
- Manifest fields:
  - `schema_version`
  - `vault_id`
  - `created_at_ms`
  - `phrase_checksum`
  - `payload_hash`
  - `escrow` (optional):
    - `provider`
    - `provider_ref`
    - `key_id`
    - `wrapped_at_ms`
- CLI surface:
  - `kc_cli vault recovery generate <vault_path> --output <dir> --passphrase-env KC_VAULT_PASSPHRASE`
  - `kc_cli vault recovery verify <vault_path> --bundle <path> --phrase-env KC_RECOVERY_PHRASE`

## Determinism and version-boundary rules
- Manifest bytes are canonical JSON and hash-stable for fixed inputs.
- Checksum derivation input and encoding are versioned.
- `escrow` descriptor (when present) is serialized in deterministic field order and validated as non-empty string fields plus deterministic timestamp.
- Any change to bundle file names, checksum derivation, or verification semantics requires version boundary review.

## Failure modes and AppError mapping
- `KC_RECOVERY_BUNDLE_INVALID`: bundle missing files, invalid schema, or payload hash mismatch.
- `KC_RECOVERY_PHRASE_INVALID`: phrase checksum mismatch.
- `KC_ENCRYPTION_REQUIRED`: passphrase input missing for generation.
- `KC_RECOVERY_ESCROW_UNAVAILABLE`: escrow provider configured but unavailable.
- `KC_RECOVERY_ESCROW_AUTH_FAILED`: escrow provider authentication failure.
- `KC_RECOVERY_ESCROW_WRITE_FAILED`: escrow descriptor/payload store failure.
- `KC_RECOVERY_ESCROW_RESTORE_FAILED`: escrow payload restore/validation failure.

## Acceptance tests
- Bundle generation emits required files and valid manifest.
- Verify succeeds with correct phrase and fails with `KC_RECOVERY_PHRASE_INVALID` on mismatch.
- Tampered bundle fails with `KC_RECOVERY_BUNDLE_INVALID`.
- Matching-hash forged blobs that cannot decrypt, or whose nonce no longer matches the manifest context, fail with `KC_RECOVERY_BUNDLE_INVALID`.
- Operator restore drill tests must use generated temp vaults only and prove the restored passphrase can unlock/decrypt the generated fixture without persisting secret material.
- Recovery schema validation tests pass.

## Rollout gate and stop conditions
### Rollout gate
- S2 gates pass canonical Rust + desktop + RPC/schema tests.

### Stop conditions
- Any silent verification failure.
- Any runtime path persisting recovery phrase or plaintext secret material in tracked storage.
- Missing schema registry update and tests for recovery contracts.
