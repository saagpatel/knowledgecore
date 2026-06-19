# AppError Contract and Taxonomy (v1)

## Purpose
AppError schema v1 and stable error taxonomy; UI branches on code only.

## Invariants
- UI branches on AppError.code only; message is not contract.
- Codes never reused.
- details is JSON-serializable.

## Acceptance Tests
- Serialization round-trips; UI tests branch on code only; all referenced codes present.

## AppError JSON schema (v1)
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "kc://schemas/app-error/v1",
  "type": "object",
  "required": [
    "schema_version",
    "code",
    "category",
    "message",
    "retryable",
    "details"
  ],
  "properties": {
    "schema_version": {
      "const": 1
    },
    "code": {
      "type": "string"
    },
    "category": {
      "type": "string"
    },
    "message": {
      "type": "string"
    },
    "retryable": {
      "type": "boolean"
    },
    "details": {}
  },
  "additionalProperties": false
}
```

## Retryability guidance (v1)
- IO transient: retryable=true
- DB migration/integrity: retryable=false
- Schema validation: retryable=false
- Tool unavailable (PDFium/Tesseract): retryable=true after install/config
- Ask provider unavailable: retryable=true
- Resource policy exceeded: retryable=false unless caller changes explicit limits or input.

## Taxonomy (v1)
- Vault/DB: `KC_VAULT_*`, `KC_DB_*`
  - `KC_DB_KEY_INVALID`
  - `KC_DB_LOCKED`
  - `KC_DB_ENCRYPTION_UNSUPPORTED`
  - `KC_DB_ENCRYPTION_MIGRATION_FAILED`
- Hash/Canon JSON: `KC_HASH_*`, `KC_CANON_JSON_*`
- Ingest: `KC_INGEST_*`, `KC_INBOX_*`, `KC_TIMESTAMP_*`
- Extract: `KC_CANONICAL_*`, `KC_PDFIUM_UNAVAILABLE`, `KC_TESSERACT_UNAVAILABLE`, `KC_OCR_FAILED`
- Chunking: `KC_CHUNK_*`
- Resource policy: `KC_RESOURCE_LIMIT_EXCEEDED`
- Index: `KC_FTS_*`, `KC_VECTOR_*`, `KC_EMBEDDING_*`
- Retrieval: `KC_RETRIEVAL_*`
- Locator/Snippet: `KC_LOCATOR_*`, `KC_SNIPPET_*`
- Export/Verify: `KC_EXPORT_*`, `KC_VERIFY_*`
- Ask/Trace: `KC_ASK_*`, `KC_TRACE_*`
- RPC/Internal: `KC_RPC_*`, `KC_INTERNAL_ERROR`
- Encryption:
  - `KC_ENCRYPTION_KEY_INVALID`
  - `KC_ENCRYPTION_UNSUPPORTED`
  - `KC_ENCRYPTION_REQUIRED`
  - `KC_ENCRYPTION_MIGRATION_FAILED`
- Sync:
  - `KC_SYNC_TARGET_INVALID`
  - `KC_SYNC_TARGET_UNSUPPORTED`
  - `KC_SYNC_STATE_FAILED`
  - `KC_SYNC_CONFLICT`
  - `KC_SYNC_APPLY_FAILED`
  - `KC_SYNC_KEY_MISMATCH`
  - `KC_SYNC_AUTH_FAILED`
  - `KC_SYNC_NETWORK_FAILED`
  - `KC_SYNC_LOCKED`
  - `KC_SYNC_MERGE_NOT_SAFE`
  - `KC_SYNC_MERGE_PRECONDITION_FAILED`
  - `KC_SYNC_MERGE_POLICY_UNSUPPORTED`
  - `KC_SYNC_MERGE_POLICY_V3_UNSUPPORTED`
  - `KC_SYNC_MERGE_POLICY_V3_UNSAFE`
  - `KC_SYNC_MERGE_TRUST_CONFLICT`
  - `KC_SYNC_MERGE_LOCK_CONFLICT`
- Trust:
  - `KC_TRUST_DEVICE_UNVERIFIED`
  - `KC_TRUST_FINGERPRINT_MISMATCH`
  - `KC_TRUST_READ_FAILED`
  - `KC_TRUST_WRITE_FAILED`
  - `KC_TRUST_EVENT_WRITE_FAILED`
- Recovery:
  - `KC_RECOVERY_BUNDLE_INVALID`
  - `KC_RECOVERY_PHRASE_INVALID`
  - `KC_RECOVERY_ESCROW_UNAVAILABLE`
  - `KC_RECOVERY_ESCROW_AUTH_FAILED`
  - `KC_RECOVERY_ESCROW_WRITE_FAILED`
  - `KC_RECOVERY_ESCROW_RESTORE_FAILED`
  - `KC_RECOVERY_ESCROW_PROVIDER_UNSUPPORTED`
  - `KC_RECOVERY_ESCROW_ROTATION_CONFLICT`
- Lineage:
  - `KC_LINEAGE_INVALID_DEPTH`
  - `KC_LINEAGE_DOC_NOT_FOUND`
  - `KC_LINEAGE_QUERY_FAILED`
  - `KC_LINEAGE_PERMISSION_DENIED`
  - `KC_LINEAGE_POLICY_CONDITION_INVALID`
  - `KC_LINEAGE_POLICY_DENY_ENFORCED`
  - `KC_LINEAGE_ROLE_INVALID`
  - `KC_LINEAGE_SCOPE_INVALID`
  - `KC_LINEAGE_LOCK_HELD`
  - `KC_LINEAGE_LOCK_INVALID`
  - `KC_LINEAGE_LOCK_EXPIRED`

## RPC mapping
- RPC responses return either `{ ok: true, data }` or `{ ok: false, error: AppError }` without changing `error.code`.
