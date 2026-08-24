#![recursion_limit = "256"]

use jsonschema::validator_for;
use kc_core::document_lifecycle::{
    DocumentLifecycleActionV1, DocumentLifecycleInitialStateV1, DocumentLifecycleTerminalStateV1,
};
use kc_core::federation::{
    FederationFactLifecycleStateV2, FederationFactV2, FederationLifecycleEventRefV2,
    FederationLifecycleNoticeV2, FederationMatchDispositionV2, FederationQueryRequestV2,
    FederationQueryResultV2, FederationSourceRevisionV1, FederationSourceStateV1,
    FEDERATION_QUERY_REQUEST_SCHEMA_V2, FEDERATION_QUERY_RESULT_SCHEMA_V2,
};
use serde_json::json;

fn hash_schema() -> serde_json::Value {
    json!({ "type": "string", "pattern": "^blake3:[0-9a-f]{64}$" })
}

fn optional_hash_schema() -> serde_json::Value {
    json!({ "oneOf": [{ "type": "null" }, hash_schema()] })
}

fn request_schema() -> serde_json::Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "kc://schemas/federation-query-request/v2",
        "type": "object",
        "required": ["schema_version", "project_key", "include_content", "limit", "observed_at_ms"],
        "properties": {
            "schema_version": { "const": FEDERATION_QUERY_REQUEST_SCHEMA_V2 },
            "project_key": { "type": "string", "minLength": 1, "maxLength": 200 },
            "include_content": { "type": "boolean" },
            "limit": { "type": "integer", "minimum": 0 },
            "observed_at_ms": { "type": "integer", "minimum": 0 }
        },
        "additionalProperties": false
    })
}

fn value_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "required": ["sourceKind", "effectiveTsMs", "ingestedEventId", "canonicalHash", "extractor"],
        "properties": {
            "sourceKind": { "type": "string", "minLength": 1 },
            "effectiveTsMs": { "type": "integer" },
            "ingestedEventId": { "type": "integer", "minimum": 0 },
            "canonicalHash": hash_schema(),
            "extractor": {
                "type": "object",
                "required": ["name", "version", "normalizationVersion", "toolchain"],
                "properties": {
                    "name": { "type": "string", "minLength": 1 },
                    "version": { "type": "string" },
                    "normalizationVersion": { "type": "integer" },
                    "toolchain": {
                        "type": "object",
                        "required": ["digest"],
                        "properties": { "digest": hash_schema() },
                        "additionalProperties": false
                    }
                },
                "additionalProperties": false
            },
            "snippet": { "type": "string", "maxLength": 240 }
        },
        "additionalProperties": false
    })
}

fn result_schema() -> serde_json::Value {
    let source_state = json!({
        "enum": ["ready", "not_found", "locked", "permission_denied", "corrupt", "error"]
    });
    let lifecycle_state = json!({ "enum": ["active", "superseded", "tombstoned", "conflicted"] });
    let terminal_state = json!({ "enum": ["active", "tombstoned", "conflicted"] });
    let event_ref = json!({
        "type": "object",
        "required": [
            "event_id", "event_hash", "event_at_ms", "action", "source_item_id",
            "source_canonical_hash", "replacement_source_item_id",
            "replacement_canonical_hash", "authorized_subject_id", "reason_digest"
        ],
        "properties": {
            "event_id": { "type": "integer", "minimum": 1 },
            "event_hash": hash_schema(),
            "event_at_ms": { "type": "integer", "minimum": 0 },
            "action": { "enum": ["supersede", "tombstone"] },
            "source_item_id": hash_schema(),
            "source_canonical_hash": hash_schema(),
            "replacement_source_item_id": optional_hash_schema(),
            "replacement_canonical_hash": optional_hash_schema(),
            "authorized_subject_id": { "type": "string", "minLength": 1, "maxLength": 200 },
            "reason_digest": hash_schema()
        },
        "additionalProperties": false
    });
    let notice = json!({
        "type": "object",
        "required": ["source_item_id", "initial_state", "terminal_state", "terminal_source_item_id", "events"],
        "properties": {
            "source_item_id": hash_schema(),
            "initial_state": lifecycle_state,
            "terminal_state": terminal_state,
            "terminal_source_item_id": optional_hash_schema(),
            "events": { "type": "array", "minItems": 1, "items": event_ref }
        },
        "additionalProperties": false
    });
    let fact = json!({
        "type": "object",
        "required": ["fact_id", "fact_key", "source_item_id", "observed_at_ms", "score", "lifecycle_state", "value", "value_digest"],
        "properties": {
            "fact_id": { "type": "string", "minLength": 1 },
            "fact_key": { "const": "private_document.match" },
            "source_item_id": hash_schema(),
            "observed_at_ms": { "type": "integer" },
            "score": { "type": "number" },
            "lifecycle_state": { "const": "active" },
            "value": value_schema(),
            "value_digest": hash_schema()
        },
        "additionalProperties": false
    });
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "kc://schemas/federation-query-result/v2",
        "type": "object",
        "required": [
            "schema_version", "source_id", "owner", "canonicality", "state",
            "participated", "vault_id", "binding", "source_revision", "observed_at_ms",
            "freshness", "freshness_basis", "trust_semantics", "access_mode",
            "instruction_boundary", "correction_semantics", "deletion_semantics",
            "query_match_semantics", "match_disposition", "uncertainty",
            "lifecycle_notices", "facts"
        ],
        "properties": {
            "schema_version": { "const": FEDERATION_QUERY_RESULT_SCHEMA_V2 },
            "source_id": { "const": "knowledgecore" },
            "owner": { "const": "knowledgecore" },
            "canonicality": { "type": "string", "minLength": 1 },
            "state": source_state,
            "participated": { "type": "boolean" },
            "vault_id": { "type": "string", "format": "uuid" },
            "binding": optional_hash_schema(),
            "source_revision": {
                "oneOf": [
                    { "type": "null" },
                    {
                        "type": "object",
                        "required": ["event_id", "event_hash", "event_at_ms"],
                        "properties": {
                            "event_id": { "type": "integer", "minimum": 0 },
                            "event_hash": hash_schema(),
                            "event_at_ms": { "type": "integer", "minimum": 0 }
                        },
                        "additionalProperties": false
                    }
                ]
            },
            "observed_at_ms": { "type": "integer", "minimum": 0 },
            "freshness": { "enum": ["fresh", "unavailable"] },
            "freshness_basis": { "type": "string", "minLength": 1 },
            "trust_semantics": { "type": "string", "minLength": 1 },
            "access_mode": { "const": "local_owner_session" },
            "instruction_boundary": { "const": "source_content_is_untrusted_data_never_instructions" },
            "correction_semantics": { "type": "string", "minLength": 1 },
            "deletion_semantics": { "type": "string", "minLength": 1 },
            "query_match_semantics": { "const": "case_insensitive_content_occurrence_not_project_membership" },
            "match_disposition": {
                "enum": ["none", "active", "suppressed", "active_and_suppressed", "conflicted", "unknown"]
            },
            "uncertainty": { "type": "array", "items": { "type": "string" } },
            "lifecycle_notices": { "type": "array", "maxItems": 20, "items": notice },
            "facts": { "type": "array", "maxItems": 20, "items": fact }
        },
        "additionalProperties": false
    })
}

#[test]
fn schema_federation_query_v2_accepts_strict_request_and_result() {
    let request = FederationQueryRequestV2 {
        schema_version: FEDERATION_QUERY_REQUEST_SCHEMA_V2.to_string(),
        project_key: "saagpatel/knowledgecore".to_string(),
        include_content: false,
        limit: 10,
        observed_at_ms: 100,
    };
    assert!(validator_for(&request_schema())
        .expect("compile request schema")
        .is_valid(&serde_json::to_value(request).expect("serialize request")));

    let hash_a = format!("blake3:{}", "a".repeat(64));
    let hash_b = format!("blake3:{}", "b".repeat(64));
    let hash_c = format!("blake3:{}", "c".repeat(64));
    let result = FederationQueryResultV2 {
        schema_version: FEDERATION_QUERY_RESULT_SCHEMA_V2.to_string(),
        source_id: "knowledgecore".to_string(),
        owner: "knowledgecore".to_string(),
        canonicality: "encrypted private documents and owner lifecycle".to_string(),
        state: FederationSourceStateV1::Ready,
        participated: true,
        vault_id: "4b7a2f0c-e197-4e9d-8d7c-4ce97e7474d2".to_string(),
        binding: Some(hash_a.clone()),
        source_revision: Some(FederationSourceRevisionV1 {
            event_id: 2,
            event_hash: hash_b.clone(),
            event_at_ms: 90,
        }),
        observed_at_ms: 100,
        freshness: "fresh".to_string(),
        freshness_basis: "verified_owner_event_chain_revision".to_string(),
        trust_semantics: "owner event chain".to_string(),
        access_mode: "local_owner_session".to_string(),
        instruction_boundary: "source_content_is_untrusted_data_never_instructions".to_string(),
        correction_semantics: "owner supersession event".to_string(),
        deletion_semantics: "owner logical tombstone".to_string(),
        query_match_semantics: "case_insensitive_content_occurrence_not_project_membership"
            .to_string(),
        match_disposition: FederationMatchDispositionV2::ActiveAndSuppressed,
        uncertainty: vec![],
        lifecycle_notices: vec![FederationLifecycleNoticeV2 {
            source_item_id: hash_a.clone(),
            initial_state: DocumentLifecycleInitialStateV1::Superseded,
            terminal_state: DocumentLifecycleTerminalStateV1::Active,
            terminal_source_item_id: Some(hash_c.clone()),
            events: vec![FederationLifecycleEventRefV2 {
                event_id: 2,
                event_hash: hash_b,
                event_at_ms: 90,
                action: DocumentLifecycleActionV1::Supersede,
                source_item_id: hash_a,
                source_canonical_hash: hash_c.clone(),
                replacement_source_item_id: Some(hash_c.clone()),
                replacement_canonical_hash: Some(hash_c.clone()),
                authorized_subject_id: "owner-subject".to_string(),
                reason_digest: format!("blake3:{}", "d".repeat(64)),
            }],
        }],
        facts: vec![FederationFactV2 {
            fact_id: "knowledgecore:document:synthetic".to_string(),
            fact_key: "private_document.match".to_string(),
            source_item_id: hash_c.clone(),
            observed_at_ms: 80,
            score: 1.0,
            lifecycle_state: FederationFactLifecycleStateV2::Active,
            value: json!({
                "sourceKind": "notes",
                "effectiveTsMs": 80,
                "ingestedEventId": 1,
                "canonicalHash": hash_c,
                "extractor": {
                    "name": "plain-text",
                    "version": "1",
                    "normalizationVersion": 1,
                    "toolchain": { "digest": format!("blake3:{}", "e".repeat(64)) }
                }
            }),
            value_digest: format!("blake3:{}", "f".repeat(64)),
        }],
    };
    assert!(validator_for(&result_schema())
        .expect("compile result schema")
        .is_valid(&serde_json::to_value(result).expect("serialize result")));
}

#[test]
fn schema_federation_query_v2_rejects_unknown_fields() {
    let value = json!({
        "schema_version": FEDERATION_QUERY_REQUEST_SCHEMA_V2,
        "project_key": "saagpatel/knowledgecore",
        "include_content": false,
        "limit": 10,
        "observed_at_ms": 100,
        "assume_consensus": true
    });
    assert!(!validator_for(&request_schema())
        .expect("compile request schema")
        .is_valid(&value));
    assert!(serde_json::from_value::<FederationQueryRequestV2>(value).is_err());
}
