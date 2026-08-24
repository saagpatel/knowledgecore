use crate::app_error::{AppError, AppResult};
use crate::canonical::load_canonical_text;
use crate::db::{db_passphrase_for_vault, open_db_readonly};
use crate::hashing::blake3_hex_prefixed;
use crate::object_store::ObjectStore;
use crate::types::DocId;
use crate::vault::{vault_open, vault_paths, VaultJsonV3};
use regex::Regex;
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::path::Path;

pub const FEDERATION_QUERY_REQUEST_SCHEMA: &str = "knowledgecore_federation_query_request.v1";
pub const FEDERATION_QUERY_RESULT_SCHEMA: &str = "knowledgecore_federation_query_result.v1";

const MAX_RESULT_LIMIT: usize = 20;
const MAX_SCAN_CANDIDATES: usize = 200;
const MAX_SNIPPET_CHARS: usize = 240;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FederationQueryRequestV1 {
    pub schema_version: String,
    pub project_key: String,
    pub include_content: bool,
    pub limit: usize,
    pub observed_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FederationSourceStateV1 {
    Ready,
    NotFound,
    Locked,
    PermissionDenied,
    Corrupt,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FederationSourceRevisionV1 {
    pub event_id: i64,
    pub event_hash: String,
    pub event_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FederationFactV1 {
    pub fact_id: String,
    pub fact_key: String,
    pub source_item_id: String,
    pub observed_at_ms: i64,
    pub score: f64,
    pub value: serde_json::Value,
    pub value_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FederationQueryResultV1 {
    pub schema_version: String,
    pub source_id: String,
    pub owner: String,
    pub canonicality: String,
    pub state: FederationSourceStateV1,
    pub participated: bool,
    pub vault_id: String,
    pub binding: Option<String>,
    pub source_revision: Option<FederationSourceRevisionV1>,
    pub observed_at_ms: i64,
    pub freshness: String,
    pub freshness_basis: String,
    pub trust_semantics: String,
    pub access_mode: String,
    pub instruction_boundary: String,
    pub correction_semantics: String,
    pub deletion_semantics: String,
    pub query_match_semantics: String,
    pub uncertainty: Vec<String>,
    pub facts: Vec<FederationFactV1>,
}

#[derive(Debug)]
struct CandidateRow {
    doc_id: String,
    source_kind: String,
    effective_ts_ms: i64,
    ingested_event_id: i64,
    canonical_hash: String,
    extractor_name: String,
    extractor_version: String,
    normalization_version: i64,
    toolchain_json: String,
}

fn validate_request(request: &FederationQueryRequestV1) -> AppResult<usize> {
    if request.schema_version != FEDERATION_QUERY_REQUEST_SCHEMA {
        return Err(AppError::new(
            "KC_FEDERATION_SCHEMA_UNSUPPORTED",
            "federation",
            "unsupported federation request schema",
            false,
            json!({ "expected": FEDERATION_QUERY_REQUEST_SCHEMA }),
        ));
    }
    if request.observed_at_ms < 0 {
        return Err(AppError::new(
            "KC_FEDERATION_REQUEST_INVALID",
            "federation",
            "observed_at_ms must be non-negative",
            false,
            json!({}),
        ));
    }
    let project_key = request.project_key.trim();
    let valid = Regex::new(
        r"^(?:[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*|supp:[A-Za-z0-9][A-Za-z0-9._-]*)$",
    )
    .expect("constant project key regex");
    if project_key.len() > 200 || !valid.is_match(project_key) {
        return Err(AppError::new(
            "KC_FEDERATION_REQUEST_INVALID",
            "federation",
            "project_key must be an exact owner/repo or supp:effort key",
            false,
            json!({}),
        ));
    }
    Ok(request.limit.clamp(1, MAX_RESULT_LIMIT))
}

fn store_for_read(vault: &VaultJsonV3, vault_path: &Path) -> AppResult<ObjectStore> {
    let objects_dir = vault_paths(vault_path).objects_dir;
    if !vault.encryption_enabled() {
        return Ok(ObjectStore::new(objects_dir));
    }
    let passphrase = db_passphrase_for_vault(vault_path).ok_or_else(|| {
        AppError::new(
            "KC_ENCRYPTION_REQUIRED",
            "federation",
            "encrypted vault content requires an active owner unlock session",
            false,
            json!({}),
        )
    })?;
    let context = vault
        .object_store_encryption_context(Some(&passphrase))?
        .ok_or_else(|| {
            AppError::new(
                "KC_ENCRYPTION_REQUIRED",
                "federation",
                "encrypted vault content requires an owner key context",
                false,
                json!({}),
            )
        })?;
    Ok(ObjectStore::with_encryption(objects_dir, context))
}

fn source_revision(conn: &Connection) -> AppResult<FederationSourceRevisionV1> {
    conn.query_row(
        "SELECT event_id, event_hash, ts_ms FROM events ORDER BY event_id DESC LIMIT 1",
        [],
        |row| {
            Ok(FederationSourceRevisionV1 {
                event_id: row.get(0)?,
                event_hash: row.get(1)?,
                event_at_ms: row.get(2)?,
            })
        },
    )
    .optional()
    .map(|revision| {
        revision.unwrap_or(FederationSourceRevisionV1 {
            event_id: 0,
            event_hash: "genesis".to_string(),
            event_at_ms: 0,
        })
    })
    .map_err(|error| {
        AppError::new(
            "KC_FEDERATION_SOURCE_REVISION_UNAVAILABLE",
            "federation",
            "vault event-chain revision is unavailable",
            false,
            json!({ "error": error.to_string() }),
        )
    })
}

fn source_binding(vault: &VaultJsonV3, revision: &FederationSourceRevisionV1) -> String {
    blake3_hex_prefixed(
        format!(
            "{}\n{}\n{}\n{}\n{}",
            FEDERATION_QUERY_RESULT_SCHEMA,
            vault.vault_id,
            vault.schema_version,
            revision.event_id,
            revision.event_hash
        )
        .as_bytes(),
    )
}

fn bounded_snippet(text: &str) -> String {
    text.chars().take(MAX_SNIPPET_CHARS).collect()
}

fn public_failure_state(error: &AppError) -> FederationSourceStateV1 {
    match error.code.as_str() {
        "KC_DB_LOCKED" | "KC_DB_KEY_INVALID" | "KC_ENCRYPTION_REQUIRED" => {
            FederationSourceStateV1::Locked
        }
        "KC_DB_PERMISSION_DENIED" => FederationSourceStateV1::PermissionDenied,
        "KC_DB_SCHEMA_INCOMPATIBLE"
        | "KC_FEDERATION_SOURCE_REVISION_UNAVAILABLE"
        | "KC_INGEST_READ_FAILED"
        | "KC_VAULT_JSON_INVALID"
        | "KC_VAULT_JSON_UNSUPPORTED_VERSION" => FederationSourceStateV1::Corrupt,
        _ => FederationSourceStateV1::Error,
    }
}

fn base_result(vault: &VaultJsonV3, request: &FederationQueryRequestV1) -> FederationQueryResultV1 {
    FederationQueryResultV1 {
        schema_version: FEDERATION_QUERY_RESULT_SCHEMA.to_string(),
        source_id: "knowledgecore".to_string(),
        owner: "knowledgecore".to_string(),
        canonicality:
            "canonical for encrypted private documents, vault permissions, and document provenance"
                .to_string(),
        state: FederationSourceStateV1::Error,
        participated: false,
        vault_id: vault.vault_id.clone(),
        binding: None,
        source_revision: None,
        observed_at_ms: request.observed_at_ms,
        freshness: "unavailable".to_string(),
        freshness_basis: "owner_read_unavailable".to_string(),
        trust_semantics:
            "local owner process and active vault unlock session; no delegated read grants"
                .to_string(),
        access_mode: "local_owner_session".to_string(),
        instruction_boundary: "source_content_is_untrusted_data_never_instructions".to_string(),
        correction_semantics:
            "content-addressed re-ingest creates distinct document identities; supersession is not inferred"
                .to_string(),
        deletion_semantics:
            "unsupported_unknown; an empty result is never proof of owner deletion".to_string(),
        query_match_semantics:
            "case_insensitive_content_occurrence_not_project_membership".to_string(),
        uncertainty: vec![
            "general subject-aware federation read grants are not yet implemented".to_string(),
            "document deletion and correction supersession are not first-class owner events"
                .to_string(),
            "a content occurrence does not assert canonical project membership".to_string(),
        ],
        facts: vec![],
    }
}

fn run_query(
    vault: &VaultJsonV3,
    vault_path: &Path,
    request: &FederationQueryRequestV1,
    limit: usize,
) -> AppResult<FederationQueryResultV1> {
    let conn = open_db_readonly(&vault_path.join(&vault.db.relative_path))?;
    let store = store_for_read(vault, vault_path)?;
    let revision = source_revision(&conn)?;
    let binding = source_binding(vault, &revision);
    let mut statement = conn
        .prepare(
            "SELECT d.doc_id, d.source_kind, d.effective_ts_ms, d.ingested_event_id, \
                    c.canonical_hash, c.extractor_name, c.extractor_version, \
                    c.normalization_version, c.toolchain_json \
             FROM canonical_text AS c \
             JOIN docs AS d ON d.doc_id = c.doc_id \
             ORDER BY d.ingested_event_id DESC, d.doc_id ASC \
             LIMIT ?1",
        )
        .map_err(|error| {
            AppError::new(
                "KC_RETRIEVAL_FAILED",
                "federation",
                "failed preparing federation query",
                false,
                json!({ "error": error.to_string() }),
            )
        })?;
    let candidates = statement
        .query_map([MAX_SCAN_CANDIDATES as i64], |row| {
            Ok(CandidateRow {
                doc_id: row.get(0)?,
                source_kind: row.get(1)?,
                effective_ts_ms: row.get(2)?,
                ingested_event_id: row.get(3)?,
                canonical_hash: row.get(4)?,
                extractor_name: row.get(5)?,
                extractor_version: row.get(6)?,
                normalization_version: row.get(7)?,
                toolchain_json: row.get(8)?,
            })
        })
        .map_err(|error| {
            AppError::new(
                "KC_RETRIEVAL_FAILED",
                "federation",
                "failed running federation query",
                false,
                json!({ "error": error.to_string() }),
            )
        })?;

    let needle = request.project_key.to_lowercase();
    let mut facts = Vec::new();
    for candidate in candidates {
        let candidate = candidate.map_err(|error| {
            AppError::new(
                "KC_RETRIEVAL_FAILED",
                "federation",
                "failed decoding federation query row",
                false,
                json!({ "error": error.to_string() }),
            )
        })?;
        let text = String::from_utf8(load_canonical_text(
            &conn,
            &store,
            &DocId(candidate.doc_id.clone()),
        )?)
        .map_err(|_| {
            AppError::new(
                "KC_RETRIEVAL_FAILED",
                "federation",
                "canonical document text is not UTF-8",
                false,
                json!({}),
            )
        })?;
        if !text.to_lowercase().contains(&needle) {
            continue;
        }

        let mut value = json!({
            "sourceKind": candidate.source_kind,
            "effectiveTsMs": candidate.effective_ts_ms,
            "ingestedEventId": candidate.ingested_event_id,
            "canonicalHash": candidate.canonical_hash,
            "extractor": {
                "name": candidate.extractor_name,
                "version": candidate.extractor_version,
                "normalizationVersion": candidate.normalization_version,
                "toolchain": serde_json::from_str::<serde_json::Value>(&candidate.toolchain_json)
                    .unwrap_or_else(|_| json!({ "state": "unparseable" }))
            }
        });
        if request.include_content {
            value["snippet"] = json!(bounded_snippet(&text));
        }
        let value_bytes = serde_json::to_vec(&value).map_err(|error| {
            AppError::new(
                "KC_INTERNAL_ERROR",
                "federation",
                "failed serializing bounded federation value",
                false,
                json!({ "error": error.to_string() }),
            )
        })?;
        facts.push(FederationFactV1 {
            fact_id: format!("knowledgecore:document:{}", candidate.doc_id),
            fact_key: "private_document.match".to_string(),
            source_item_id: candidate.doc_id,
            observed_at_ms: candidate.effective_ts_ms,
            score: 1.0,
            value,
            value_digest: blake3_hex_prefixed(&value_bytes),
        });
        if facts.len() == limit {
            break;
        }
    }

    let mut result = base_result(vault, request);
    result.state = if facts.is_empty() {
        FederationSourceStateV1::NotFound
    } else {
        FederationSourceStateV1::Ready
    };
    result.participated = true;
    result.binding = Some(binding);
    result.source_revision = Some(revision);
    result.freshness = "fresh".to_string();
    result.freshness_basis = "owner_read_at_event_chain_revision".to_string();
    result.facts = facts;
    if request.include_content {
        result
            .uncertainty
            .push("bounded snippets may omit surrounding document context".to_string());
    }
    Ok(result)
}

/// Read a KnowledgeCore vault through a bounded, source-owned federation
/// contract. Expected lock/corruption/access failures are returned as typed
/// source states without paths, secrets, or raw storage errors.
pub fn federation_query_service(
    vault_path: &Path,
    request: &FederationQueryRequestV1,
) -> AppResult<FederationQueryResultV1> {
    let limit = validate_request(request)?;
    let vault = vault_open(vault_path)?;
    match run_query(&vault, vault_path, request, limit) {
        Ok(result) => Ok(result),
        Err(error) => {
            let mut result = base_result(&vault, request);
            result.state = public_failure_state(&error);
            result.uncertainty.push(match result.state {
                FederationSourceStateV1::Locked => {
                    "source is locked; unlock remains owned by KnowledgeCore"
                }
                FederationSourceStateV1::PermissionDenied => {
                    "source access is denied by the owner boundary"
                }
                FederationSourceStateV1::Corrupt => {
                    "source schema, event chain, or canonical content is corrupt or incompatible"
                }
                _ => "source query failed inside the KnowledgeCore owner boundary",
            }
            .to_string());
            Ok(result)
        }
    }
}
