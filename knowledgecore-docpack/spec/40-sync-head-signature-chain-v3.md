# Sync Head Signature Chain v3

## Purpose
Define sync head schema v3 with managed-identity-backed device certificate authorship and deterministic signature-chain validation inputs.

## Invariants
- Sync head write semantics remain deterministic and canonical-json serialized.
- Sync head v2 and v3 are both readable during migration window.
- New writes must emit schema v3 only.
- Merge and pull flows must reject heads that fail identity/certificate verification.

## Non-goals
- Introducing automatic trust acceptance policies.
- Altering snapshot payload determinism from v2.
- Replacing existing conflict artifact semantics.

## Interface contracts
- Sync head v3 fields:
  - `schema_version = 3`
  - `snapshot_id`
  - `manifest_hash`
  - `created_at_ms`
  - `trust` (model, fingerprint, updated_at_ms)
  - `author_device_id`
  - `author_fingerprint`
  - `author_signature`
  - `author_signature_alg` (optional; currently `ed25519_sync_head_v1`)
  - `author_cert_id`
  - `author_chain_hash`
- Validation rules:
  - all required authorship fields present for v3
  - chain hash must match enrolled certificate chain
  - declared `author_signature_alg = "ed25519_sync_head_v1"` must verify against canonical signing payload and must not fall back to legacy signature compatibility
  - unknown non-empty `author_signature_alg` values fail closed
  - undeclared v3 signatures remain compatibility-only during the legacy fallback window

## Sync auth readiness report v1
- `sync auth-readiness` is a read-only inspection surface for one target.
- `sync auth-readiness-report` aggregates multiple target inspections for rollout evidence.
- `sync auth-strict-check` is a read-only rollout gate that exits successfully only when every provided target is strict-ready.
- Pull entrypoints are strict by default and reject non-strict-ready remote heads before snapshot apply.
- CLI `sync pull --allow-legacy-auth` and RPC `strict_auth=false` preserve an explicit temporary compatibility path during the legacy fallback window.
- Per-target classifications:
  - `no_remote_head`
  - `legacy_schema`
  - `declared_ed25519`
  - `undeclared_ed25519_compatible`
  - `undeclared_legacy_fallback`
  - `unsupported_declared_algorithm`
  - `invalid`
- `strict_ready=true` is allowed only for `no_remote_head` and valid `declared_ed25519` heads.
- `depends_on_legacy_fallback=true` is set for legacy schema heads and undeclared legacy fallback heads.
- Aggregate fields are deterministic: `target_count`, `strict_ready_count`, `strict_blocked_count`, `depends_on_legacy_fallback_count`, `invalid_count`, lexical `classification_counts`, and `reports` in caller-provided target order.
- Reports do not include generated timestamps, generated ids, migrations, writes, strict-mode enforcement, fallback removal, or cloud behavior changes.
- The strict check gate does not mutate targets or remove fallback behavior; it returns `KC_SYNC_AUTH_STRICT_BLOCKED` when any target is not strict-ready.
- Default strict pull returns `KC_SYNC_AUTH_STRICT_BLOCKED` before applying a non-strict-ready remote head. Push, readiness, and merge-preview behavior remain unchanged, and explicit compatibility pull remains available until fallback removal is separately approved.

## Determinism and version-boundary rules
- v3 payload canonicalization order is fixed.
- Signature input bytes are canonical-json and stable.
- Custody-signed writes emit `author_signature_alg = "ed25519_sync_head_v1"`; env-key compatibility writes remain undeclared until key-custody rollout is complete.
- Readiness aggregate `classification_counts` ordering is stable because it is emitted from a lexical map, and `reports` ordering is stable because it follows caller input order.
- Any signing input shape changes require schema version bump.
- Any readiness classification, `strict_ready`, fallback-dependency, count, or ordering semantic change requires a readiness report version bump.
- v2 compatibility remains read-only for migration period.

## Failure modes and AppError mapping
- `KC_SYNC_AUTH_FAILED`
- `KC_SYNC_AUTH_STRICT_BLOCKED`
- `KC_TRUST_SIGNATURE_INVALID`
- `KC_TRUST_CERT_CHAIN_INVALID`
- `KC_SYNC_KEY_MISMATCH`

## Acceptance tests
- v3 head write/read round-trip retains byte-stable canonical serialization.
- v2 heads remain readable and mapped correctly.
- Invalid/missing v3 authorship fields fail deterministically.
- Signature mismatch fails with `KC_TRUST_SIGNATURE_INVALID`.
- Generated readiness fixtures cover missing heads, legacy schema heads, declared Ed25519 heads, undeclared Ed25519-compatible heads, undeclared legacy fallback heads, unsupported declared algorithms, invalid declared heads, and aggregate rollout counts.

## Rollout gate and stop conditions
### Rollout gate
- `cargo test -p kc_core -- sync`
- `cargo test -p kc_core -- schema_`
- canonical Rust gate from `knowledgecore-docpack/AGENTS.md`

### Stop conditions
- New writes emit non-v3 schema after migration activation.
- Merge/pull accepts invalid chain or signature.
- Missing schema updates for sync head v3 contracts.
