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

pub fn verify_event_record(record: &EventRecord) -> AppResult<()> {
    let payload: Value = serde_json::from_str(&record.payload_json).map_err(|_| {
        AppError::new(
            "KC_DB_INTEGRITY_FAILED",
            "events",
            "event payload is not valid JSON",
            false,
            serde_json::json!({ "event_id": record.event_id }),
        )
    })?;
    let canonical_payload = String::from_utf8(to_canonical_bytes(&payload)?).map_err(|_| {
        AppError::new(
            "KC_DB_INTEGRITY_FAILED",
            "events",
            "event canonical payload is not valid utf8",
            false,
            serde_json::json!({ "event_id": record.event_id }),
        )
    })?;
    if canonical_payload != record.payload_json {
        return Err(AppError::new(
            "KC_DB_INTEGRITY_FAILED",
            "events",
            "event payload is not canonical",
            false,
            serde_json::json!({ "event_id": record.event_id }),
        ));
    }
    let hash_input = format!(
        "kc.event.v1\n{}\n{}\n{}\n{}",
        record.ts_ms,
        record.event_type,
        record.payload_json,
        record.prev_event_hash.clone().unwrap_or_default()
    );
    if blake3_hex_prefixed(hash_input.as_bytes()) != record.event_hash {
        return Err(AppError::new(
            "KC_DB_INTEGRITY_FAILED",
            "events",
            "event hash does not match its canonical payload",
            false,
            serde_json::json!({ "event_id": record.event_id }),
        ));
    }
    Ok(())
}

pub fn read_verified_event_chain(conn: &Connection) -> AppResult<Vec<EventRecord>> {
    let mut statement = conn
        .prepare(
            "SELECT event_id, ts_ms, type, payload_json, prev_event_hash, event_hash \
             FROM events ORDER BY event_id ASC",
        )
        .map_err(|_| {
            AppError::new(
                "KC_DB_INTEGRITY_FAILED",
                "events",
                "failed preparing owner event-chain verification",
                false,
                serde_json::json!({}),
            )
        })?;
    let rows = statement
        .query_map([], |row| {
            Ok(EventRecord {
                event_id: row.get(0)?,
                ts_ms: row.get(1)?,
                event_type: row.get(2)?,
                payload_json: row.get(3)?,
                prev_event_hash: row.get(4)?,
                event_hash: row.get(5)?,
            })
        })
        .map_err(|_| {
            AppError::new(
                "KC_DB_INTEGRITY_FAILED",
                "events",
                "failed reading owner event chain",
                false,
                serde_json::json!({}),
            )
        })?;

    let mut records = Vec::new();
    let mut expected_prev: Option<String> = None;
    for row in rows {
        let record = row.map_err(|_| {
            AppError::new(
                "KC_DB_INTEGRITY_FAILED",
                "events",
                "failed decoding owner event chain",
                false,
                serde_json::json!({}),
            )
        })?;
        if record.prev_event_hash != expected_prev {
            return Err(AppError::new(
                "KC_DB_INTEGRITY_FAILED",
                "events",
                "owner event-chain link is invalid",
                false,
                serde_json::json!({ "event_id": record.event_id }),
            ));
        }
        verify_event_record(&record)?;
        expected_prev = Some(record.event_hash.clone());
        records.push(record);
    }
    Ok(records)
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
