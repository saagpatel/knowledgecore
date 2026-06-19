# SQLite Encryption SQLCipher v1

## Purpose
Define DB-at-rest encryption contracts using SQLCipher with vault schema v3 and explicit unlock/migration flows.

See `docs/21-sqlcipher-state-model-plan-2026-06-19.md` for the approval-gated production state model plan. That plan chooses a future `vault.json` v4 `db_encryption.state` boundary, but it is not active runtime behavior until implementation approval, registry updates, schema validation tests, and compatibility coverage land.

## Invariants
- Object-store encryption behavior from v2 remains valid and optional.
- SQLCipher DB encryption is opt-in and versioned.
- `vault_open` supports v1/v2/v3 and normalizes to active internal model.
- Unlock/lock/session behavior is explicit and reported via `AppError.code`.
- Unsupported DB encryption mode or KDF metadata hard-fails before unlock or migration proceeds.
- Migration is idempotent for an already encrypted DB when the supplied passphrase validates.
- Status surfaces may report an inferred SQLCipher lifecycle state for v3 vaults; this is status-only until the v4 state boundary is implemented.

## Non-goals
- External KMS integration.
- Transparent background key recovery.
- Per-table/per-row custom encryption policies.

## Interface contracts
- `vault.json` v3 adds DB encryption metadata block:
  - `db_encryption.enabled: bool`
  - `db_encryption.mode: "sqlcipher_v4"`
  - `db_encryption.kdf.algorithm: "pbkdf2_hmac_sha512"` (SQLCipher default profile)
  - `db_encryption.key_reference: Option<String>`
- CLI:
  - `kc_cli vault db-encrypt status <vault_path>`
  - `kc_cli vault db-encrypt enable <vault_path> --passphrase-env <ENV>`
  - `kc_cli vault db-encrypt migrate <vault_path> --passphrase-env <ENV> --now-ms <ms>`
- RPC:
  - `vault_unlock`
  - `vault_lock`
  - `vault_lock_status`

## Determinism and version-boundary rules
- DB encryption state metadata must serialize deterministically in manifest/report output.
- Migration writes deterministic event payload ordering.
- Any change to schema v3 fields or unlock/session semantics requires version boundary review.

## Failure modes and AppError mapping
- `KC_DB_KEY_INVALID`: provided passphrase/key invalid.
- `KC_DB_LOCKED`: vault DB is encrypted and not unlocked in current session.
- `KC_DB_ENCRYPTION_UNSUPPORTED`: SQLCipher mode/toolchain unsupported.
- `KC_DB_ENCRYPTION_MIGRATION_FAILED`: migration failed.
- Existing generic DB failures remain valid for non-keyed errors.

## Acceptance tests
- v1/v2 vaults open and normalize; v3 vault opens with expected DB metadata.
- Unsupported DB encryption mode and unsupported DB KDF algorithm fail with `KC_DB_ENCRYPTION_UNSUPPORTED`.
- Encrypted DB unlock with valid passphrase succeeds.
- Invalid passphrase fails with `KC_DB_KEY_INVALID`.
- Migration integrity check passes and no active plaintext DB remains.
- Re-running migration on an already encrypted DB returns `already_encrypted` for the valid key and `KC_DB_KEY_INVALID` for a wrong key.
- Successful migration leaves no `.sqlcipher.tmp` or `.pre-sqlcipher.bak` artifact.
- Status-only state derivation covers `disabled_plaintext`, `pending_migration`, `migrated_locked`, `migrated_unlocked`, and `migration_failed_recoverable`.
- Export/verifier schema checks include DB encryption metadata.

## Rollout gate and stop conditions
### Rollout gate
- P1/P2/P3 milestones pass canonical Rust + desktop + schema gates.

### Stop conditions
- Any migration path that leaves ambiguous DB state without deterministic error.
- Any schema-affecting change without registry/test updates.
