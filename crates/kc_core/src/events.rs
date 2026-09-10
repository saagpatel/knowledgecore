use crate::app_error::{AppError, AppResult};
use crate::canon_json::to_canonical_bytes;
use crate::hashing::blake3_hex_prefixed;
use rusqlite::{params, Connection};
use serde_json::Value;

#[derive(Debug, Clone)]
pub struct EventRecord {
    pub event_id: i64,
    pub ts_ms: i64,
    pub event_type: String,
    pub payload_json: String,
    pub prev_event_hash: Option<String>,
    pub event_hash: String,
}

pub fn append_event(
    conn: &Connection,
    ts_ms: i64,
    event_type: &str,
    payload: &Value,
) -> AppResult<EventRecord> {
    let prev_event_hash: Option<String> = conn
        .query_row(
            "SELECT event_hash FROM events ORDER BY event_id DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .ok();

    let payload_bytes = to_canonical_bytes(payload)?;
    let payload_json = String::from_utf8(payload_bytes).map_err(|e| {
        AppError::new(
            "KC_DB_INTEGRITY_FAILED",
            "events",
            "payload canonical bytes are not valid utf8",
            false,
            serde_json::json!({ "error": e.to_string() }),
        )
    })?;

    let hash_input = format!(
        "kc.event.v1\n{}\n{}\n{}\n{}",
        ts_ms,
        event_type,
        payload_json,
        prev_event_hash.clone().unwrap_or_default()
    );
    let event_hash = blake3_hex_prefixed(hash_input.as_bytes());

    conn.execute(
        "INSERT INTO events (ts_ms, type, payload_json, prev_event_hash, event_hash) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![ts_ms, event_type, payload_json, prev_event_hash, event_hash],
    )
    .map_err(|e| {
        AppError::new(
            "KC_DB_INTEGRITY_FAILED",
            "events",
            "failed to insert event",
            false,
            serde_json::json!({ "error": e.to_string() }),
        )
    })?;

    let event_id = conn.last_insert_rowid();
    Ok(EventRecord {
        event_id,
        ts_ms,
        event_type: event_type.to_string(),
        payload_json,
        prev_event_hash,
        event_hash,
    })
}
