# Tauri RPC Surface (v1)

## Purpose
Versioned RPC surface v1, envelope schema, and determinism notes.

## Invariants
- Thin RPC; versioned types; envelope ok/data or ok/error; errors are AppError v1.

## Acceptance Tests
- Round-trip serialization tests; UI types match; desktop gates pass.

         ## Envelope schema (v1)
         ```json
         {
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "kc://schemas/rpc-envelope/v1",
  "oneOf": [
    {
      "type": "object",
      "required": [
        "ok",
        "data"
      ],
      "properties": {
        "ok": {
          "const": true
        },
        "data": {}
      },
      "additionalProperties": false
    },
    {
      "type": "object",
      "required": [
        "ok",
        "error"
      ],
      "properties": {
        "ok": {
          "const": false
        },
        "error": {
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
      },
      "additionalProperties": false
    }
  ]
}
         ```

         ## Methods (v1)
         - vault_init, vault_open
         - vault_lock_status, vault_unlock, vault_lock
         - vault_encryption_status, vault_encryption_enable, vault_encryption_migrate
         - ingest_scan_folder, ingest_inbox_start/stop
         - search_query (includes now_ms param for deterministic tests)
         - locator_resolve
         - export_bundle, verify_bundle
         - ask_question
         - events_list, jobs_list
         - sync_status, sync_push, sync_pull
           - `sync_pull` accepts optional `auto_merge` with supported values `conservative`, `conservative_plus_v2`, `conservative_plus_v3`, and `conservative_plus_v4`
         - sync_merge_preview
           - accepts optional `policy` with supported values `conservative`, `conservative_plus_v2`, `conservative_plus_v3`, and `conservative_plus_v4`
           - `conservative_plus_v2` emits `schema_version=2`; `conservative_plus_v3` emits `schema_version=3`; `conservative_plus_v4` emits `schema_version=4`, each with deterministic `decision_trace`
         - trust_provider_discover (deterministic issuer bootstrap to provider record)
         - trust_policy_set_tenant_template (deterministic canonical tenant claim template)
         - trust_device_signing_key_status, trust_device_signing_key_delete
           - responses may include `recovery_guidance` when local sync signing custody is missing, retired, or deleted; guidance is operator copy only and does not expose private signing material
         - lineage_query
         - lineage_query_v2
         - lineage_overlay_add, lineage_overlay_remove, lineage_overlay_list
         - lineage_lock_acquire, lineage_lock_release, lineage_lock_status
         - lineage_role_grant, lineage_role_revoke, lineage_role_list
         - lineage_policy_add, lineage_policy_bind, lineage_policy_list
           - `condition_json` is caller-provided JSON and core-canonicalized; supported deterministic condition keys are `action`, `doc_id_prefix`, `doc_id_suffix`, and `subject_id_prefix`
         - lineage_lock_acquire_scope

         ### Compatibility note
         - `lineage_query` (v1 response) remains supported during transition.
         - `lineage_query_v2` is the primary method for overlay-aware lineage responses.
         - overlay mutation RPCs require lock-token inputs and lock methods are used to acquire/release per-doc edit leases.
         - governance workflows are core-authoritative; RPC only transports role/policy/lock-scope intent and results.

         ## Determinism note
         - now_ms is passed by caller (UI/tests) to make snapshots deterministic.
