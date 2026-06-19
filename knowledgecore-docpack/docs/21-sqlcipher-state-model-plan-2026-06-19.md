# SQLCipher State Model Plan - 2026-06-19

## Purpose
Define the approval-gated state model needed before SQLCipher DB encryption is treated as production-ready across CLI, Tauri RPC, export/verifier, and operator recovery flows.

This is a design note only. It does not change `vault.json`, database bytes, migration behavior, unlock behavior, or any runtime acceptance path.

## Verified Current Behavior
- `vault.json` v3 stores `db_encryption.enabled`, `mode`, `kdf.algorithm`, and `key_reference`.
- New vaults default to `db_encryption.enabled = false`.
- `vault_db_encrypt_enable_service` sets `enabled = true`, ensures `key_reference`, saves `vault.json`, and unlocks with the provided passphrase.
- `vault_db_encrypt_migrate_service` requires `enabled = true`, calls `migrate_db_to_sqlcipher`, unlocks the DB, and appends a deterministic migration event.
- `migrate_db_to_sqlcipher` returns `Migrated` for a plaintext source and `AlreadyEncrypted` only when the source no longer opens as plaintext and the supplied key validates.
- Current tests pin unsupported mode/KDF rejection, valid unlock, wrong-key failure, idempotent already-encrypted detection, and cleanup of `.sqlcipher.tmp` / `.pre-sqlcipher.bak` artifacts after successful migration.

## Risk
The current metadata has only a boolean `enabled`, while the operational lifecycle has multiple states. That is easy to misread:
- `enabled = false` can mean DB encryption has never been requested.
- `enabled = true` can mean encryption was requested but migration is not complete.
- `enabled = true` can also mean the DB is already SQLCipher-encrypted and merely locked.

This ambiguity is manageable for staged development, but not clean enough for production readiness, UI copy, verifier reporting, recovery drills, or support triage.

## Proposed State Model
Future runtime should represent DB encryption as an explicit state machine, not as a boolean-only interpretation.

| State | Meaning | Allowed next actions | Hard failures |
|---|---|---|---|
| `disabled_plaintext` | DB encryption is not enabled and DB is expected to be plaintext. | `enable`, status, export/verify. | `migrate` without enable. |
| `pending_migration` | Encryption metadata is configured but DB bytes are not yet proven SQLCipher-encrypted. | `migrate`, `disable_before_migrate` if explicitly designed, status, repair. | Treating the DB as production-encrypted. |
| `migrated_locked` | DB bytes are SQLCipher-encrypted and no valid session/env passphrase is active. | `unlock`, status, export/verify metadata-only checks. | Opening DB contents without key. |
| `migrated_unlocked` | DB bytes are SQLCipher-encrypted and passphrase/session validation succeeded. | normal DB access, `lock`, status. | Silent downgrade to plaintext. |
| `migration_failed_recoverable` | Migration artifacts or rollback evidence require explicit repair/cleanup before proceeding. | `repair_status`, `repair_abort`, `repair_resume` if approved. | Continuing normal open/migrate without deterministic repair decision. |

## Compatibility Decision
Two implementation routes are plausible and require approval before code:

1. Add `db_encryption.state` to `vault.json`.
   - Likely cleaner for UI/RPC/status surfaces.
   - Requires schema/registry updates, migration/read-compat rules, and fixture coverage.
   - Needs a clear answer on whether this is an additive v3 field or a v4 schema boundary.

2. Keep `vault.json` shape and infer state from metadata plus DB-byte inspection.
   - Avoids schema change.
   - Raises complexity and error-risk in every status/open path.
   - Still requires deterministic tests for ambiguous states and artifact handling.

Recommended design direction: introduce an explicit state field behind a schema/version decision, because operator-facing security state should be declarative and auditable.

## Decision
Use an explicit `db_encryption.state` field in a future `vault.json` v4 boundary.

Rationale:
- The state has security semantics, not just display metadata.
- Treating `enabled = true` as both `pending_migration` and `migrated_*` is too ambiguous for production readiness.
- A v4 boundary is cleaner than adding an optional v3 field whose absence would require every caller to infer safety-critical state.
- Export/verifier, CLI, Tauri RPC, and UI can all report the same declarative state once the boundary is active.

Compatibility contract for future implementation:
- Existing v1/v2/v3 vaults remain readable during the transition.
- v3 vaults with `db_encryption.enabled = false` map to `disabled_plaintext`.
- v3 vaults with `db_encryption.enabled = true` must not be treated as production-encrypted until state derivation proves the DB bytes are SQLCipher-encrypted.
- New v4 writes include `db_encryption.state`.
- No v3-to-v4 rewrite happens implicitly on open.
- Any v4 write path must update `SCHEMA_REGISTRY.md`, schema validation tests, export/verifier expectations, and CLI/RPC status tests.

## Required Runtime Decisions
- Enable may leave a vault in `pending_migration`; production readiness starts only after `migrated_locked` or `migrated_unlocked`.
- Migration remains an explicit command; no automatic DB-byte migration on open.
- Current plaintext DBs with `enabled = true` should surface as `pending_migration` or a migration-required error in future status/open logic, not as fully encrypted.
- Failed migration artifacts should create a repair-required state and likely a new `KC_DB_ENCRYPTION_REPAIR_REQUIRED` error code.
- Export/verifier reports should include explicit DB encryption state in addition to `enabled`.

Still unresolved before runtime implementation:
- Whether `pending_migration` can be explicitly disabled before DB-byte migration, and which audit event records that.
- Exact repair commands and rollback UX for `migration_failed_recoverable`.

## Safest First Implementation Slice
After runtime implementation approval:
1. Add state derivation tests for the five states without changing existing vault bytes. Done in the status-only checkpoint.
2. Add a status-only helper that reports the inferred state and never opens decrypted contents unless a key is already valid. Done in the status-only checkpoint.
3. Wire CLI/RPC status output to the helper. Done for core status, CLI DB-encryption JSON, and Tauri lock-status RPC in the status-only checkpoint.
4. Add v4 schema/registry/tests and persist `db_encryption.state` only after the status-only helper is green. Still pending approval.

## Status-Only Implementation Checkpoint
- Added `DbEncryptionDerivedState` with string values matching the proposed state model.
- Added `derive_db_encryption_state`, which reports state from v3 metadata, DB header inspection, unlock/session/env validation, and migration artifact presence.
- Added coverage for `disabled_plaintext`, `pending_migration`, `migrated_locked`, `migrated_unlocked`, and `migration_failed_recoverable`.
- Added `state` to core DB encryption status and lock status results.
- Added `state` to CLI DB-encryption JSON output and Tauri lock-status RPC output.
- This checkpoint does not persist `db_encryption.state`, rewrite `vault.json`, run a schema migration, or change DB migration behavior.

## Stop Conditions
- Any implementation that silently treats `pending_migration` as fully encrypted.
- Any schema-affecting change without `SCHEMA_REGISTRY.md` and validation tests.
- Any migration path that overwrites or deletes artifacts without deterministic repair/rollback evidence.
- Any UI/RPC wording that implies production encryption before `migrated_locked` or `migrated_unlocked`.

## Verification Expectations
- `cargo test -p kc_core --test db_encryption`
- `cargo test -p kc_core`
- `cargo test --workspace --exclude apps_desktop_tauri`
- `cargo test -p apps_desktop_tauri`
- Export/verifier tests if state appears in manifests or reports.
