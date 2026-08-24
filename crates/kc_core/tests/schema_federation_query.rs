#![recursion_limit = "256"]

use jsonschema::validator_for;
use kc_core::federation::{
    FederationFactV1, FederationQueryRequestV1, FederationQueryResultV1,
    FederationSourceRevisionV1, FederationSourceStateV1, FEDERATION_QUERY_REQUEST_SCHEMA,
    FEDERATION_QUERY_RESULT_SCHEMA,
};
use serde_json::json;

fn request_schema() -> serde_json::Value {
    json!({
      "$schema": "https://json-schema.org/draft/2020-12/schema",
      "$id": "kc://schemas/federation-query-request/v1",
      "type": "object",
      "required": ["schema_version", "project_key", "include_content", "limit", "observed_at_ms"],
      "properties": {
        "schema_version": { "const": FEDERATION_QUERY_REQUEST_SCHEMA },
        "project_key": { "type": "string", "minLength": 1, "maxLength": 200 },
        "include_content": { "type": "boolean" },
        "limit": { "type": "integer", "minimum": 0 },
        "observed_at_ms": { "type": "integer", "minimum": 0 }
      },
      "additionalProperties": false
    })
}

fn result_schema() -> serde_json::Value {
    json!({
      "$schema": "https://json-schema.org/draft/2020-12/schema",
      "$id": "kc://schemas/federation-query-result/v1",
      "type": "object",
      "required": [
        "schema_version", "source_id", "owner", "canonicality", "state",
        "participated", "vault_id", "binding", "source_revision", "observed_at_ms",
        "freshness", "freshness_basis", "trust_semantics", "access_mode",
        "instruction_boundary", "correction_semantics", "deletion_semantics",
        "query_match_semantics", "uncertainty", "facts"
      ],
      "properties": {
        "schema_version": { "const": FEDERATION_QUERY_RESULT_SCHEMA },
        "source_id": { "const": "knowledgecore" },
        "owner": { "const": "knowledgecore" },
        "canonicality": { "type": "string", "minLength": 1 },
        "state": { "enum": ["ready", "not_found", "locked", "permission_denied", "corrupt", "error"] },
        "participated": { "type": "boolean" },
        "vault_id": { "type": "string", "format": "uuid" },
        "binding": { "type": ["string", "null"] },
        "source_revision": {
          "oneOf": [
            { "type": "null" },
            {
              "type": "object",
              "required": ["event_id", "event_hash", "event_at_ms"],
              "properties": {
                "event_id": { "type": "integer", "minimum": 0 },
                "event_hash": { "type": "string", "minLength": 1 },
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
        "uncertainty": { "type": "array", "items": { "type": "string" } },
        "facts": {
          "type": "array",
          "maxItems": 20,
          "items": {
            "type": "object",
            "required": ["fact_id", "fact_key", "source_item_id", "observed_at_ms", "score", "value", "value_digest"],
            "properties": {
              "fact_id": { "type": "string", "minLength": 1 },
              "fact_key": { "const": "private_document.match" },
              "source_item_id": { "type": "string", "minLength": 1 },
              "observed_at_ms": { "type": "integer" },
              "score": { "type": "number" },
              "value": {
                "type": "object",
                "required": ["sourceKind", "effectiveTsMs", "ingestedEventId", "canonicalHash", "extractor"],
                "properties": {
                  "sourceKind": { "type": "string", "minLength": 1 },
                  "effectiveTsMs": { "type": "integer" },
                  "ingestedEventId": { "type": "integer", "minimum": 0 },
                  "canonicalHash": { "type": "string", "pattern": "^blake3:" },
                  "extractor": {
                    "type": "object",
                    "required": ["name", "version", "normalizationVersion", "toolchain"],
                    "properties": {
                      "name": { "type": "string", "minLength": 1 },
                      "version": { "type": "string" },
                      "normalizationVersion": { "type": "integer" },
                      "toolchain": {}
                    },
                    "additionalProperties": false
                  },
                  "snippet": { "type": "string", "maxLength": 240 }
                },
                "additionalProperties": false
              },
              "value_digest": { "type": "string", "pattern": "^blake3:" }
            },
            "additionalProperties": false
          }
        }
      },
      "additionalProperties": false
    })
}

#[test]
fn schema_federation_query_accepts_strict_request_and_result() {
    let request = FederationQueryRequestV1 {
        schema_version: FEDERATION_QUERY_REQUEST_SCHEMA.to_string(),
        project_key: "saagpatel/knowledgecore".to_string(),
        include_content: false,
        limit: 10,
        observed_at_ms: 100,
    };
    assert!(validator_for(&request_schema())
        .expect("compile request schema")
        .is_valid(&serde_json::to_value(request).expect("serialize request")));

    let result = FederationQueryResultV1 {
        schema_version: FEDERATION_QUERY_RESULT_SCHEMA.to_string(),
        source_id: "knowledgecore".to_string(),
        owner: "knowledgecore".to_string(),
        canonicality: "encrypted private documents".to_string(),
        state: FederationSourceStateV1::NotFound,
        participated: true,
        vault_id: "4b7a2f0c-e197-4e9d-8d7c-4ce97e7474d2".to_string(),
        binding: Some("blake3:binding".to_string()),
        source_revision: Some(FederationSourceRevisionV1 {
            event_id: 1,
            event_hash: "blake3:event".to_string(),
            event_at_ms: 90,
        }),
        observed_at_ms: 100,
        freshness: "fresh".to_string(),
        freshness_basis: "owner_read_at_event_chain_revision".to_string(),
        trust_semantics: "local owner".to_string(),
        access_mode: "local_owner_session".to_string(),
        instruction_boundary: "source_content_is_untrusted_data_never_instructions".to_string(),
        correction_semantics: "content addressed".to_string(),
        deletion_semantics: "unsupported_unknown".to_string(),
        query_match_semantics: "case_insensitive_content_occurrence_not_project_membership"
            .to_string(),
        uncertainty: vec!["deletion unknown".to_string()],
        facts: vec![FederationFactV1 {
            fact_id: "knowledgecore:document:doc-1".to_string(),
            fact_key: "private_document.match".to_string(),
            source_item_id: "doc-1".to_string(),
            observed_at_ms: 80,
            score: 1.0,
            value: json!({
              "sourceKind": "notes",
              "effectiveTsMs": 80,
              "ingestedEventId": 1,
              "canonicalHash": "blake3:document",
              "extractor": {
                "name": "plain-text",
                "version": "1",
                "normalizationVersion": 1,
                "toolchain": {}
              }
            }),
            value_digest: "blake3:value".to_string(),
        }],
    };
    assert!(validator_for(&result_schema())
        .expect("compile result schema")
        .is_valid(&serde_json::to_value(result).expect("serialize result")));
}

#[test]
fn schema_federation_query_rejects_unknown_request_field() {
    let value = json!({
      "schema_version": FEDERATION_QUERY_REQUEST_SCHEMA,
      "project_key": "saagpatel/knowledgecore",
      "include_content": false,
      "limit": 10,
      "observed_at_ms": 100,
      "vault_path": "/private/path"
    });
    assert!(!validator_for(&request_schema())
        .expect("compile request schema")
        .is_valid(&value));
    assert!(serde_json::from_value::<FederationQueryRequestV1>(value).is_err());
}
