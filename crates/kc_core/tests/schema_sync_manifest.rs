use jsonschema::validator_for;

fn sync_head_schema() -> serde_json::Value {
    serde_json::json!({
      "$schema": "https://json-schema.org/draft/2020-12/schema",
      "$id": "kc://schemas/sync-head/v3",
      "type": "object",
      "required": ["schema_version", "snapshot_id", "manifest_hash", "created_at_ms"],
      "properties": {
        "schema_version": { "type": "integer", "enum": [1, 2, 3] },
        "snapshot_id": { "type": "string" },
        "manifest_hash": { "type": "string", "pattern": "^blake3:[0-9a-f]{64}$" },
        "created_at_ms": { "type": "integer" },
        "trust": {
          "type": ["object", "null"],
          "required": ["model", "fingerprint", "updated_at_ms"],
          "properties": {
            "model": { "type": "string", "const": "passphrase_v1" },
            "fingerprint": { "type": "string", "pattern": "^blake3:[0-9a-f]{64}$" },
            "updated_at_ms": { "type": "integer" }
          },
          "additionalProperties": false
        },
        "author_device_id": { "type": ["string", "null"] },
        "author_fingerprint": {
          "type": ["string", "null"],
          "pattern": "^[0-9a-f]{8}(:[0-9a-f]{8}){7}$"
        },
        "author_signature": {
          "type": ["string", "null"],
          "pattern": "^[0-9a-f]{128}$"
        },
        "author_signature_alg": {
          "type": ["string", "null"],
          "enum": ["ed25519_sync_head_v1", null]
        },
        "author_cert_id": { "type": ["string", "null"] },
        "author_chain_hash": { "type": ["string", "null"], "pattern": "^blake3:[0-9a-f]{64}$" }
      },
      "allOf": [
        {
          "if": { "properties": { "schema_version": { "enum": [2, 3] } }, "required": ["schema_version"] },
          "then": { "required": ["trust"] }
        },
        {
          "if": { "properties": { "schema_version": { "const": 3 } }, "required": ["schema_version"] },
          "then": {
            "required": [
              "author_device_id",
              "author_fingerprint",
              "author_signature",
              "author_cert_id",
              "author_chain_hash"
            ]
          }
        }
      ],
      "additionalProperties": false
    })
}

fn sync_conflict_schema() -> serde_json::Value {
    serde_json::json!({
      "$schema": "https://json-schema.org/draft/2020-12/schema",
      "$id": "kc://schemas/sync-conflict-artifact/v1",
      "type": "object",
      "required": [
        "schema_version",
        "kind",
        "vault_id",
        "now_ms",
        "local_manifest_hash",
        "remote_head_snapshot_id",
        "remote_head_manifest_hash",
        "seen_remote_snapshot_id"
      ],
      "properties": {
        "schema_version": { "const": 1 },
        "kind": { "type": "string", "const": "sync_conflict" },
        "vault_id": { "type": "string" },
        "now_ms": { "type": "integer" },
        "local_manifest_hash": { "type": "string", "pattern": "^blake3:[0-9a-f]{64}$" },
        "remote_head_snapshot_id": { "type": ["string", "null"] },
        "remote_head_manifest_hash": { "type": ["string", "null"] },
        "seen_remote_snapshot_id": { "type": ["string", "null"] },
        "target": { "type": ["string", "null"] },
        "local_trust_fingerprint": { "type": ["string", "null"], "pattern": "^blake3:[0-9a-f]{64}$" },
        "remote_trust_fingerprint": { "type": ["string", "null"], "pattern": "^blake3:[0-9a-f]{64}$" }
      },
      "additionalProperties": false
    })
}

#[test]
fn schema_sync_head_accepts_valid_payload() {
    let schema = validator_for(&sync_head_schema()).expect("compile sync head schema");
    let payload = serde_json::json!({
      "schema_version": 3,
      "snapshot_id": "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "manifest_hash": "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "created_at_ms": 100,
      "trust": {
        "model": "passphrase_v1",
        "fingerprint": "blake3:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "updated_at_ms": 100
      },
      "author_device_id": "f7ca3e7b-e380-4896-bde1-b2de37789b22",
      "author_fingerprint": "aaaaaaaa:bbbbbbbb:cccccccc:dddddddd:eeeeeeee:ffffffff:11111111:22222222",
      "author_signature": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "author_signature_alg": "ed25519_sync_head_v1",
      "author_cert_id": "4f299112-e7a9-4956-bc63-f24847c110ca",
      "author_chain_hash": "blake3:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    });
    assert!(schema.is_valid(&payload));
}

#[test]
fn schema_sync_head_rejects_unknown_author_signature_algorithm() {
    let schema = validator_for(&sync_head_schema()).expect("compile sync head schema");
    let payload = serde_json::json!({
      "schema_version": 3,
      "snapshot_id": "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "manifest_hash": "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "created_at_ms": 100,
      "trust": {
        "model": "passphrase_v1",
        "fingerprint": "blake3:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "updated_at_ms": 100
      },
      "author_device_id": "f7ca3e7b-e380-4896-bde1-b2de37789b22",
      "author_fingerprint": "aaaaaaaa:bbbbbbbb:cccccccc:dddddddd:eeeeeeee:ffffffff:11111111:22222222",
      "author_signature": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "author_signature_alg": "ed25519_sync_head_v2",
      "author_cert_id": "4f299112-e7a9-4956-bc63-f24847c110ca",
      "author_chain_hash": "blake3:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    });
    assert!(!schema.is_valid(&payload));
}

#[test]
fn schema_sync_head_v2_rejects_missing_trust() {
    let schema = validator_for(&sync_head_schema()).expect("compile sync head schema");
    let invalid = serde_json::json!({
      "schema_version": 2,
      "snapshot_id": "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "manifest_hash": "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "created_at_ms": 100
    });
    assert!(!schema.is_valid(&invalid));
}

#[test]
fn schema_sync_head_v3_rejects_missing_author_chain_fields() {
    let schema = validator_for(&sync_head_schema()).expect("compile sync head schema");
    let invalid = serde_json::json!({
      "schema_version": 3,
      "snapshot_id": "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "manifest_hash": "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "created_at_ms": 100,
      "trust": {
        "model": "passphrase_v1",
        "fingerprint": "blake3:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "updated_at_ms": 100
      },
      "author_device_id": "f7ca3e7b-e380-4896-bde1-b2de37789b22",
      "author_fingerprint": "aaaaaaaa:bbbbbbbb:cccccccc:dddddddd:eeeeeeee:ffffffff:11111111:22222222",
      "author_signature": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    });
    assert!(!schema.is_valid(&invalid));
}

#[test]
fn schema_sync_conflict_rejects_missing_kind() {
    let schema = validator_for(&sync_conflict_schema()).expect("compile sync conflict schema");
    let invalid = serde_json::json!({
      "schema_version": 1,
      "vault_id": "vault-id",
      "now_ms": 100,
      "local_manifest_hash": "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "remote_head_snapshot_id": null,
      "remote_head_manifest_hash": null,
      "seen_remote_snapshot_id": null
    });
    assert!(!schema.is_valid(&invalid));
}
