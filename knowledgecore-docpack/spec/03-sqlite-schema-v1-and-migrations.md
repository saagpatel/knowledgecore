# SQLite Schema v1 and Migrations

## Purpose
Defines SQLite schema v1 (tables, constraints, indexes) and deterministic migration strategy.

## Invariants
- Tier 1: derived identifiers stored; queries must use explicit ORDER BY.
- Foreign keys ON; migrations sequential and transactional; PRAGMA user_version tracks schema.

## Acceptance Tests
- Migration tests apply from empty DB and validate expected schema.
- Integrity tests validate foreign keys and invariants.

## Migration strategy
- Migrations in `crates/kc_core/migrations/NNNN_*.sql`.
- Apply in order inside a transaction.
- Update `PRAGMA user_version` to latest after apply.

## DDL (v1) core tables
See DDL in docs: this is the authoritative copy.
```sql
-- (Same as in docs/ and earlier; kept in this spec for single-source)
CREATE TABLE IF NOT EXISTS objects (
  object_hash TEXT PRIMARY KEY,
  bytes INTEGER NOT NULL,
  relpath TEXT NOT NULL,
  created_event_id INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS docs (
  doc_id TEXT PRIMARY KEY,
  original_object_hash TEXT NOT NULL REFERENCES objects(object_hash),
  bytes INTEGER NOT NULL,
  mime TEXT NOT NULL,
  source_kind TEXT NOT NULL,
  effective_ts_ms INTEGER NOT NULL,
  ingested_event_id INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS canonical_text (
  doc_id TEXT PRIMARY KEY REFERENCES docs(doc_id),
  canonical_object_hash TEXT NOT NULL REFERENCES objects(object_hash),
  canonical_hash TEXT NOT NULL,
  extractor_name TEXT NOT NULL,
  extractor_version TEXT NOT NULL,
  extractor_flags_json TEXT NOT NULL,
  normalization_version INTEGER NOT NULL,
  toolchain_json TEXT NOT NULL,
  created_event_id INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS chunks (
  chunk_id TEXT PRIMARY KEY,
  doc_id TEXT NOT NULL REFERENCES docs(doc_id),
  ordinal INTEGER NOT NULL,
  start_char INTEGER NOT NULL,
  end_char INTEGER NOT NULL,
  chunking_config_hash TEXT NOT NULL,
  source_kind TEXT NOT NULL,
  UNIQUE(doc_id, chunking_config_hash, ordinal)
);

CREATE TABLE IF NOT EXISTS events (
  event_id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts_ms INTEGER NOT NULL,
  type TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  prev_event_hash TEXT,
  event_hash TEXT NOT NULL
);
```

## FTS5 contract
- `chunks_fts` virtual table defined in spec/07.

## Migration additions (current user_version=12)
- `0002_sync.sql` adds:
  - `sync_state`
  - `sync_snapshots`
- `0003_lineage_overlays.sql` adds:
  - `lineage_overlays`
  - deterministic uniqueness on `(doc_id, from_node_id, to_node_id, relation, evidence)`
- `0004_device_trust.sql` adds:
  - `trusted_devices`
  - `trust_events`
- `0005_lineage_edit_locks.sql` adds:
  - `lineage_edit_locks`
- `0006_trust_identity_v2.sql` adds:
  - `identity_providers`
  - `identity_sessions`
  - `device_certificates`
- `0007_recovery_escrow_v2.sql` adds:
  - `recovery_escrow_configs`
  - `recovery_escrow_events`
- `0008_lineage_rbac_v2.sql` adds:
  - `lineage_roles`
  - `lineage_permissions`
  - `lineage_role_bindings`
  - `lineage_lock_scopes`
- `0009_trust_provider_governance.sql` adds:
  - `trust_providers`
  - `trust_provider_policies`
  - `trust_session_revocations`
- `0010_recovery_escrow_providers_v3.sql` adds:
  - `recovery_escrow_provider_configs`
- `0011_lineage_policy_conditions_v3.sql` adds:
  - `lineage_policies`
  - `lineage_policy_bindings`
  - `lineage_policy_audit`
- `0012_sync_signing_keys.sql` adds:
  - `sync_signing_keys`
  - encrypted Ed25519 signing seed custody metadata keyed by trusted device id

## Error codes
- `KC_DB_OPEN_FAILED`
- `KC_DB_MIGRATION_FAILED`
- `KC_DB_SCHEMA_INCOMPATIBLE`
- `KC_DB_INTEGRITY_FAILED`
