use crate::app_error::{AppError, AppResult};
use crate::events::{append_event, read_verified_event_chain, EventRecord};
use crate::hashing::{blake3_hex_prefixed, validate_blake3_prefixed};
use crate::lineage_policy::ensure_lineage_policy_allows;
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const DOCUMENT_LIFECYCLE_REQUEST_SCHEMA: &str = "knowledgecore_document_lifecycle_request.v1";
pub const DOCUMENT_LIFECYCLE_EVENT_SCHEMA: &str = "knowledgecore_document_lifecycle_event.v1";
pub const DOCUMENT_LIFECYCLE_WRITE_ACTION: &str = "document.lifecycle.write";

const SUPERSEDED_EVENT_TYPE: &str = "document.lifecycle.superseded.v1";
const TOMBSTONED_EVENT_TYPE: &str = "document.lifecycle.tombstoned.v1";
const LIFECYCLE_EVENT_PREFIX: &str = "document.lifecycle.";
const MAX_SUBJECT_CHARS: usize = 200;
const MAX_REASON_CHARS: usize = 240;
const MAX_CHAIN_DEPTH: usize = 100;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DocumentLifecycleActionV1 {
    Supersede,
    Tombstone,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DocumentLifecycleMutationRequestV1 {
    pub schema_version: String,
    pub action: DocumentLifecycleActionV1,
    pub doc_id: String,
    pub replacement_doc_id: Option<String>,
    pub subject_id: String,
    pub reason: String,
    pub effective_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DocumentLifecyclePayloadV1 {
    pub schema_version: String,
    pub action: DocumentLifecycleActionV1,
    pub doc_id: String,
    pub doc_canonical_hash: String,
    pub replacement_doc_id: Option<String>,
    pub replacement_canonical_hash: Option<String>,
    pub subject_id: String,
    pub reason: String,
    pub effective_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DocumentLifecycleEventV1 {
    pub event_id: i64,
    pub event_hash: String,
    pub event_at_ms: i64,
    pub action: DocumentLifecycleActionV1,
    pub doc_id: String,
    pub doc_canonical_hash: String,
    pub replacement_doc_id: Option<String>,
    pub replacement_canonical_hash: Option<String>,
    pub subject_id: String,
    pub reason_digest: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DocumentLifecycleInitialStateV1 {
    Active,
    Superseded,
    Tombstoned,
    Conflicted,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DocumentLifecycleTerminalStateV1 {
    Active,
    Tombstoned,
    Conflicted,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DocumentLifecycleResolutionV1 {
    pub source_doc_id: String,
    pub initial_state: DocumentLifecycleInitialStateV1,
    pub terminal_state: DocumentLifecycleTerminalStateV1,
    pub terminal_doc_id: Option<String>,
    pub events: Vec<DocumentLifecycleEventV1>,
}

fn lifecycle_error(code: &str, message: &str) -> AppError {
    AppError::new(
        code,
        "document_lifecycle",
        message,
        false,
        serde_json::json!({}),
    )
}

fn validate_bounded(value: &str, max_chars: usize) -> bool {
    !value.trim().is_empty() && value.chars().count() <= max_chars
}

fn canonical_hash_for_doc(conn: &Connection, doc_id: &str) -> AppResult<Option<String>> {
    let hash = conn
        .query_row(
            "SELECT canonical_hash FROM canonical_text WHERE doc_id=?1",
            [doc_id],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|_| {
            lifecycle_error(
                "KC_DOCUMENT_LIFECYCLE_LOOKUP_FAILED",
                "failed resolving canonical document identity",
            )
        })?;
    if let Some(value) = &hash {
        validate_blake3_prefixed(value).map_err(|_| {
            lifecycle_error(
                "KC_DOCUMENT_LIFECYCLE_CORRUPT",
                "canonical document hash is invalid",
            )
        })?;
    }
    Ok(hash)
}

fn event_from_record(
    record: &EventRecord,
) -> AppResult<Option<(DocumentLifecyclePayloadV1, DocumentLifecycleEventV1)>> {
    if !record.event_type.starts_with(LIFECYCLE_EVENT_PREFIX) {
        return Ok(None);
    }
    if record.event_type != SUPERSEDED_EVENT_TYPE && record.event_type != TOMBSTONED_EVENT_TYPE {
        return Err(lifecycle_error(
            "KC_DOCUMENT_LIFECYCLE_CORRUPT",
            "owner event chain contains an unsupported document lifecycle event",
        ));
    }
    let payload: DocumentLifecyclePayloadV1 =
        serde_json::from_str(&record.payload_json).map_err(|_| {
            lifecycle_error(
                "KC_DOCUMENT_LIFECYCLE_CORRUPT",
                "document lifecycle payload is malformed",
            )
        })?;
    let expected_type = match payload.action {
        DocumentLifecycleActionV1::Supersede => SUPERSEDED_EVENT_TYPE,
        DocumentLifecycleActionV1::Tombstone => TOMBSTONED_EVENT_TYPE,
    };
    if payload.schema_version != DOCUMENT_LIFECYCLE_EVENT_SCHEMA
        || record.event_type != expected_type
        || payload.effective_at_ms != record.ts_ms
        || validate_blake3_prefixed(&payload.doc_id).is_err()
        || validate_blake3_prefixed(&payload.doc_canonical_hash).is_err()
        || !validate_bounded(&payload.subject_id, MAX_SUBJECT_CHARS)
        || !validate_bounded(&payload.reason, MAX_REASON_CHARS)
    {
        return Err(lifecycle_error(
            "KC_DOCUMENT_LIFECYCLE_CORRUPT",
            "document lifecycle payload violates its owner contract",
        ));
    }
    match payload.action {
        DocumentLifecycleActionV1::Supersede => {
            let Some(replacement_doc_id) = &payload.replacement_doc_id else {
                return Err(lifecycle_error(
                    "KC_DOCUMENT_LIFECYCLE_CORRUPT",
                    "supersession is missing a replacement document",
                ));
            };
            let Some(replacement_hash) = &payload.replacement_canonical_hash else {
                return Err(lifecycle_error(
                    "KC_DOCUMENT_LIFECYCLE_CORRUPT",
                    "supersession is missing a replacement canonical hash",
                ));
            };
            if replacement_doc_id == &payload.doc_id
                || validate_blake3_prefixed(replacement_doc_id).is_err()
                || validate_blake3_prefixed(replacement_hash).is_err()
            {
                return Err(lifecycle_error(
                    "KC_DOCUMENT_LIFECYCLE_CORRUPT",
                    "supersession replacement identity is invalid",
                ));
            }
        }
        DocumentLifecycleActionV1::Tombstone => {
            if payload.replacement_doc_id.is_some() || payload.replacement_canonical_hash.is_some()
            {
                return Err(lifecycle_error(
                    "KC_DOCUMENT_LIFECYCLE_CORRUPT",
                    "tombstone cannot carry a replacement document",
                ));
            }
        }
    }
    let public = DocumentLifecycleEventV1 {
        event_id: record.event_id,
        event_hash: record.event_hash.clone(),
        event_at_ms: record.ts_ms,
        action: payload.action.clone(),
        doc_id: payload.doc_id.clone(),
        doc_canonical_hash: payload.doc_canonical_hash.clone(),
        replacement_doc_id: payload.replacement_doc_id.clone(),
        replacement_canonical_hash: payload.replacement_canonical_hash.clone(),
        subject_id: payload.subject_id.clone(),
        reason_digest: blake3_hex_prefixed(payload.reason.as_bytes()),
    };
    Ok(Some((payload, public)))
}

pub fn load_document_lifecycle_events(
    conn: &Connection,
) -> AppResult<BTreeMap<String, Vec<DocumentLifecycleEventV1>>> {
    let mut by_doc: BTreeMap<String, Vec<DocumentLifecycleEventV1>> = BTreeMap::new();
    for record in read_verified_event_chain(conn)? {
        let Some((payload, event)) = event_from_record(&record)? else {
            continue;
        };
        let Some(current_hash) = canonical_hash_for_doc(conn, &payload.doc_id)? else {
            return Err(lifecycle_error(
                "KC_DOCUMENT_LIFECYCLE_CORRUPT",
                "lifecycle source document is missing",
            ));
        };
        if current_hash != payload.doc_canonical_hash {
            return Err(lifecycle_error(
                "KC_DOCUMENT_LIFECYCLE_CORRUPT",
                "lifecycle source canonical hash changed after the owner event",
            ));
        }
        if let (Some(replacement_doc_id), Some(expected_hash)) = (
            payload.replacement_doc_id.as_deref(),
            payload.replacement_canonical_hash.as_deref(),
        ) {
            let Some(current_replacement_hash) = canonical_hash_for_doc(conn, replacement_doc_id)?
            else {
                return Err(lifecycle_error(
                    "KC_DOCUMENT_LIFECYCLE_CORRUPT",
                    "lifecycle replacement document is missing",
                ));
            };
            if current_replacement_hash != expected_hash {
                return Err(lifecycle_error(
                    "KC_DOCUMENT_LIFECYCLE_CORRUPT",
                    "lifecycle replacement canonical hash changed after the owner event",
                ));
            }
        }
        by_doc.entry(payload.doc_id).or_default().push(event);
    }
    Ok(by_doc)
}

pub fn resolve_document_lifecycle(
    doc_id: &str,
    by_doc: &BTreeMap<String, Vec<DocumentLifecycleEventV1>>,
) -> AppResult<DocumentLifecycleResolutionV1> {
    validate_blake3_prefixed(doc_id).map_err(|_| {
        lifecycle_error(
            "KC_DOCUMENT_LIFECYCLE_REQUEST_INVALID",
            "document lifecycle requires a canonical document identity",
        )
    })?;
    let mut current = doc_id.to_string();
    let mut visited = BTreeSet::new();
    let mut events = Vec::new();
    let mut initial_state = DocumentLifecycleInitialStateV1::Active;

    for depth in 0..=MAX_CHAIN_DEPTH {
        if depth == MAX_CHAIN_DEPTH || !visited.insert(current.clone()) {
            return Err(lifecycle_error(
                "KC_DOCUMENT_LIFECYCLE_CORRUPT",
                "document lifecycle contains a cycle or exceeds its depth bound",
            ));
        }
        let Some(current_events) = by_doc.get(&current) else {
            return Ok(DocumentLifecycleResolutionV1 {
                source_doc_id: doc_id.to_string(),
                initial_state,
                terminal_state: DocumentLifecycleTerminalStateV1::Active,
                terminal_doc_id: Some(current),
                events,
            });
        };
        if current_events.len() != 1 {
            if events.is_empty() {
                initial_state = DocumentLifecycleInitialStateV1::Conflicted;
            }
            events.extend(current_events.iter().cloned());
            return Ok(DocumentLifecycleResolutionV1 {
                source_doc_id: doc_id.to_string(),
                initial_state,
                terminal_state: DocumentLifecycleTerminalStateV1::Conflicted,
                terminal_doc_id: None,
                events,
            });
        }
        let event = current_events[0].clone();
        if events.is_empty() {
            initial_state = match event.action {
                DocumentLifecycleActionV1::Supersede => DocumentLifecycleInitialStateV1::Superseded,
                DocumentLifecycleActionV1::Tombstone => DocumentLifecycleInitialStateV1::Tombstoned,
            };
        }
        events.push(event.clone());
        match event.action {
            DocumentLifecycleActionV1::Supersede => {
                current = event.replacement_doc_id.ok_or_else(|| {
                    lifecycle_error(
                        "KC_DOCUMENT_LIFECYCLE_CORRUPT",
                        "supersession replacement disappeared during resolution",
                    )
                })?;
            }
            DocumentLifecycleActionV1::Tombstone => {
                return Ok(DocumentLifecycleResolutionV1 {
                    source_doc_id: doc_id.to_string(),
                    initial_state,
                    terminal_state: DocumentLifecycleTerminalStateV1::Tombstoned,
                    terminal_doc_id: Some(current),
                    events,
                });
            }
        }
    }
    unreachable!("bounded lifecycle loop returns before exhaustion")
}

fn validate_request(request: &DocumentLifecycleMutationRequestV1) -> AppResult<()> {
    if request.schema_version != DOCUMENT_LIFECYCLE_REQUEST_SCHEMA
        || request.effective_at_ms < 0
        || validate_blake3_prefixed(&request.doc_id).is_err()
        || !validate_bounded(&request.subject_id, MAX_SUBJECT_CHARS)
        || !validate_bounded(&request.reason, MAX_REASON_CHARS)
    {
        return Err(lifecycle_error(
            "KC_DOCUMENT_LIFECYCLE_REQUEST_INVALID",
            "document lifecycle request is invalid",
        ));
    }
    match request.action {
        DocumentLifecycleActionV1::Supersede => {
            let Some(replacement) = &request.replacement_doc_id else {
                return Err(lifecycle_error(
                    "KC_DOCUMENT_LIFECYCLE_REQUEST_INVALID",
                    "supersession requires a replacement document",
                ));
            };
            if replacement == &request.doc_id || validate_blake3_prefixed(replacement).is_err() {
                return Err(lifecycle_error(
                    "KC_DOCUMENT_LIFECYCLE_REQUEST_INVALID",
                    "supersession replacement is invalid",
                ));
            }
        }
        DocumentLifecycleActionV1::Tombstone => {
            if request.replacement_doc_id.is_some() {
                return Err(lifecycle_error(
                    "KC_DOCUMENT_LIFECYCLE_REQUEST_INVALID",
                    "tombstone cannot include a replacement document",
                ));
            }
        }
    }
    Ok(())
}

pub fn append_document_lifecycle_event(
    conn: &Connection,
    request: &DocumentLifecycleMutationRequestV1,
) -> AppResult<DocumentLifecycleEventV1> {
    validate_request(request)?;
    let tx = conn.unchecked_transaction().map_err(|_| {
        lifecycle_error(
            "KC_DOCUMENT_LIFECYCLE_WRITE_FAILED",
            "failed beginning document lifecycle transaction",
        )
    })?;
    if let Err(error) = ensure_lineage_policy_allows(
        &tx,
        &request.subject_id,
        DOCUMENT_LIFECYCLE_WRITE_ACTION,
        Some(&request.doc_id),
        request.effective_at_ms,
    ) {
        tx.commit().map_err(|_| {
            lifecycle_error(
                "KC_DOCUMENT_LIFECYCLE_WRITE_FAILED",
                "failed committing denied lifecycle policy audit",
            )
        })?;
        return Err(error);
    }

    let events_by_doc = load_document_lifecycle_events(&tx)?;
    let source_resolution = resolve_document_lifecycle(&request.doc_id, &events_by_doc)?;
    if source_resolution.initial_state != DocumentLifecycleInitialStateV1::Active {
        return Err(lifecycle_error(
            "KC_DOCUMENT_LIFECYCLE_CONFLICT",
            "document already has a terminal lifecycle transition",
        ));
    }
    let doc_canonical_hash = canonical_hash_for_doc(&tx, &request.doc_id)?.ok_or_else(|| {
        lifecycle_error(
            "KC_DOCUMENT_LIFECYCLE_NOT_FOUND",
            "document lifecycle source does not exist",
        )
    })?;
    let replacement_canonical_hash = match request.replacement_doc_id.as_deref() {
        Some(replacement_doc_id) => {
            let replacement_resolution =
                resolve_document_lifecycle(replacement_doc_id, &events_by_doc)?;
            if replacement_resolution.initial_state != DocumentLifecycleInitialStateV1::Active {
                return Err(lifecycle_error(
                    "KC_DOCUMENT_LIFECYCLE_CONFLICT",
                    "replacement document is not active",
                ));
            }
            Some(
                canonical_hash_for_doc(&tx, replacement_doc_id)?.ok_or_else(|| {
                    lifecycle_error(
                        "KC_DOCUMENT_LIFECYCLE_NOT_FOUND",
                        "replacement document does not exist",
                    )
                })?,
            )
        }
        None => None,
    };

    let payload = DocumentLifecyclePayloadV1 {
        schema_version: DOCUMENT_LIFECYCLE_EVENT_SCHEMA.to_string(),
        action: request.action.clone(),
        doc_id: request.doc_id.clone(),
        doc_canonical_hash: doc_canonical_hash.clone(),
        replacement_doc_id: request.replacement_doc_id.clone(),
        replacement_canonical_hash: replacement_canonical_hash.clone(),
        subject_id: request.subject_id.clone(),
        reason: request.reason.clone(),
        effective_at_ms: request.effective_at_ms,
    };
    let payload_value = serde_json::to_value(&payload).map_err(|_| {
        lifecycle_error(
            "KC_DOCUMENT_LIFECYCLE_WRITE_FAILED",
            "failed serializing document lifecycle event",
        )
    })?;
    let event_type = match request.action {
        DocumentLifecycleActionV1::Supersede => SUPERSEDED_EVENT_TYPE,
        DocumentLifecycleActionV1::Tombstone => TOMBSTONED_EVENT_TYPE,
    };
    let record = append_event(&tx, request.effective_at_ms, event_type, &payload_value)?;
    tx.commit().map_err(|_| {
        lifecycle_error(
            "KC_DOCUMENT_LIFECYCLE_WRITE_FAILED",
            "failed committing document lifecycle event",
        )
    })?;

    Ok(DocumentLifecycleEventV1 {
        event_id: record.event_id,
        event_hash: record.event_hash,
        event_at_ms: record.ts_ms,
        action: request.action.clone(),
        doc_id: request.doc_id.clone(),
        doc_canonical_hash,
        replacement_doc_id: request.replacement_doc_id.clone(),
        replacement_canonical_hash,
        subject_id: request.subject_id.clone(),
        reason_digest: blake3_hex_prefixed(request.reason.as_bytes()),
    })
}
