#![recursion_limit = "256"]

use jsonschema::validator_for;
use kc_core::document_lifecycle::{
    DocumentLifecycleActionV1, DocumentLifecycleMutationRequestV1, DocumentLifecyclePayloadV1,
    DOCUMENT_LIFECYCLE_EVENT_SCHEMA, DOCUMENT_LIFECYCLE_REQUEST_SCHEMA,
};
use serde_json::json;

fn document_id_schema() -> serde_json::Value {
    json!({ "type": "string", "pattern": "^blake3:[0-9a-f]{64}$" })
}

fn request_schema() -> serde_json::Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "kc://schemas/document-lifecycle-request/v1",
        "type": "object",
        "required": [
            "schema_version", "action", "doc_id", "replacement_doc_id",
            "subject_id", "reason", "effective_at_ms"
        ],
        "properties": {
            "schema_version": { "const": DOCUMENT_LIFECYCLE_REQUEST_SCHEMA },
            "action": { "enum": ["supersede", "tombstone"] },
            "doc_id": document_id_schema(),
            "replacement_doc_id": {
                "oneOf": [{ "type": "null" }, document_id_schema()]
            },
            "subject_id": { "type": "string", "minLength": 1, "maxLength": 200 },
            "reason": { "type": "string", "minLength": 1, "maxLength": 240 },
            "effective_at_ms": { "type": "integer", "minimum": 0 }
        },
        "additionalProperties": false
    })
}

fn event_schema() -> serde_json::Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "kc://schemas/document-lifecycle-event/v1",
        "type": "object",
        "required": [
            "schema_version", "action", "doc_id", "doc_canonical_hash",
            "replacement_doc_id", "replacement_canonical_hash", "subject_id",
            "reason", "effective_at_ms"
        ],
        "properties": {
            "schema_version": { "const": DOCUMENT_LIFECYCLE_EVENT_SCHEMA },
            "action": { "enum": ["supersede", "tombstone"] },
            "doc_id": document_id_schema(),
            "doc_canonical_hash": document_id_schema(),
            "replacement_doc_id": {
                "oneOf": [{ "type": "null" }, document_id_schema()]
            },
            "replacement_canonical_hash": {
                "oneOf": [{ "type": "null" }, document_id_schema()]
            },
            "subject_id": { "type": "string", "minLength": 1, "maxLength": 200 },
            "reason": { "type": "string", "minLength": 1, "maxLength": 240 },
            "effective_at_ms": { "type": "integer", "minimum": 0 }
        },
        "allOf": [
            {
                "if": { "properties": { "action": { "const": "supersede" } } },
                "then": {
                    "properties": {
                        "replacement_doc_id": document_id_schema(),
                        "replacement_canonical_hash": document_id_schema()
                    }
                }
            },
            {
                "if": { "properties": { "action": { "const": "tombstone" } } },
                "then": {
                    "properties": {
                        "replacement_doc_id": { "type": "null" },
                        "replacement_canonical_hash": { "type": "null" }
                    }
                }
            }
        ],
        "additionalProperties": false
    })
}

#[test]
fn schema_document_lifecycle_accepts_strict_request_and_event() {
    let hash_a = format!("blake3:{}", "a".repeat(64));
    let hash_b = format!("blake3:{}", "b".repeat(64));
    let request = DocumentLifecycleMutationRequestV1 {
        schema_version: DOCUMENT_LIFECYCLE_REQUEST_SCHEMA.to_string(),
        action: DocumentLifecycleActionV1::Supersede,
        doc_id: hash_a.clone(),
        replacement_doc_id: Some(hash_b.clone()),
        subject_id: "owner-subject".to_string(),
        reason: "owner correction".to_string(),
        effective_at_ms: 100,
    };
    assert!(validator_for(&request_schema())
        .expect("compile request schema")
        .is_valid(&serde_json::to_value(request).expect("serialize request")));

    let event = DocumentLifecyclePayloadV1 {
        schema_version: DOCUMENT_LIFECYCLE_EVENT_SCHEMA.to_string(),
        action: DocumentLifecycleActionV1::Supersede,
        doc_id: hash_a.clone(),
        doc_canonical_hash: hash_a,
        replacement_doc_id: Some(hash_b.clone()),
        replacement_canonical_hash: Some(hash_b),
        subject_id: "owner-subject".to_string(),
        reason: "owner correction".to_string(),
        effective_at_ms: 100,
    };
    assert!(validator_for(&event_schema())
        .expect("compile event schema")
        .is_valid(&serde_json::to_value(event).expect("serialize event")));
}

#[test]
fn schema_document_lifecycle_rejects_unknown_and_action_inconsistent_fields() {
    let hash = format!("blake3:{}", "a".repeat(64));
    let unknown = json!({
        "schema_version": DOCUMENT_LIFECYCLE_REQUEST_SCHEMA,
        "action": "tombstone",
        "doc_id": hash,
        "replacement_doc_id": null,
        "subject_id": "owner-subject",
        "reason": "owner deletion",
        "effective_at_ms": 100,
        "physical_delete": true
    });
    assert!(!validator_for(&request_schema())
        .expect("compile request schema")
        .is_valid(&unknown));
    assert!(serde_json::from_value::<DocumentLifecycleMutationRequestV1>(unknown).is_err());

    let invalid_tombstone = json!({
        "schema_version": DOCUMENT_LIFECYCLE_EVENT_SCHEMA,
        "action": "tombstone",
        "doc_id": format!("blake3:{}", "a".repeat(64)),
        "doc_canonical_hash": format!("blake3:{}", "a".repeat(64)),
        "replacement_doc_id": format!("blake3:{}", "b".repeat(64)),
        "replacement_canonical_hash": format!("blake3:{}", "b".repeat(64)),
        "subject_id": "owner-subject",
        "reason": "invalid tombstone",
        "effective_at_ms": 100
    });
    assert!(!validator_for(&event_schema())
        .expect("compile event schema")
        .is_valid(&invalid_tombstone));
}
