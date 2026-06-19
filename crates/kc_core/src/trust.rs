use crate::app_error::{AppError, AppResult};
use crate::canon_json::to_canonical_bytes;
use ed25519_dalek::SigningKey;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustedDeviceRecord {
    pub device_id: String,
    pub label: String,
    pub pubkey: String,
    pub fingerprint: String,
    pub verified_at_ms: Option<i64>,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustEventRecord {
    pub event_id: i64,
    pub device_id: String,
    pub action: String,
    pub actor: String,
    pub ts_ms: i64,
    pub details_json: String,
}

fn trust_error(code: &str, message: &str, details: serde_json::Value) -> AppError {
    AppError::new(code, "trust", message, false, details)
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn canonical_json_string(value: serde_json::Value) -> AppResult<String> {
    let bytes = to_canonical_bytes(&value)?;
    String::from_utf8(bytes).map_err(|e| {
        trust_error(
            "KC_INTERNAL_ERROR",
            "failed building canonical trust event JSON",
            serde_json::json!({ "error": e.to_string() }),
        )
    })
}

fn append_trust_event(
    conn: &Connection,
    device_id: &str,
    action: &str,
    actor: &str,
    ts_ms: i64,
    details: serde_json::Value,
) -> AppResult<()> {
    let details_json = canonical_json_string(details)?;
    conn.execute(
        "INSERT INTO trust_events(device_id, action, actor, ts_ms, details_json)
         VALUES(?1, ?2, ?3, ?4, ?5)",
        params![device_id, action, actor, ts_ms, details_json],
    )
    .map_err(|e| {
        trust_error(
            "KC_TRUST_EVENT_WRITE_FAILED",
            "failed writing trust event",
            serde_json::json!({ "error": e.to_string(), "device_id": device_id, "action": action }),
        )
    })?;
    Ok(())
}

fn load_device(conn: &Connection, device_id: &str) -> AppResult<Option<TrustedDeviceRecord>> {
    conn.query_row(
        "SELECT device_id, label, pubkey, fingerprint, verified_at_ms, created_at_ms
         FROM trusted_devices
         WHERE device_id=?1",
        [device_id],
        |row| {
            Ok(TrustedDeviceRecord {
                device_id: row.get(0)?,
                label: row.get(1)?,
                pubkey: row.get(2)?,
                fingerprint: row.get(3)?,
                verified_at_ms: row.get(4)?,
                created_at_ms: row.get(5)?,
            })
        },
    )
    .optional()
    .map_err(|e| {
        trust_error(
            "KC_TRUST_READ_FAILED",
            "failed reading trusted device",
            serde_json::json!({ "error": e.to_string(), "device_id": device_id }),
        )
    })
}

pub fn format_device_fingerprint(pubkey_bytes: &[u8]) -> String {
    let digest = Sha256::digest(pubkey_bytes);
    let hex = bytes_to_hex(&digest);
    let mut groups = Vec::new();
    let mut start = 0usize;
    while start < hex.len() {
        let end = (start + 8).min(hex.len());
        groups.push(hex[start..end].to_string());
        start += 8;
    }
    groups.join(":")
}

pub fn trust_device_init(
    conn: &Connection,
    device_label: &str,
    actor: &str,
    now_ms: i64,
) -> AppResult<TrustedDeviceRecord> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| {
        trust_error(
            "KC_SYNC_AUTH_FAILED",
            "failed generating device keypair entropy",
            serde_json::json!({ "error": e.to_string() }),
        )
    })?;

    let device = trust_device_init_with_seed(conn, device_label, actor, now_ms, &seed);
    seed.fill(0);
    device
}

pub(crate) fn trust_device_init_with_seed(
    conn: &Connection,
    device_label: &str,
    actor: &str,
    now_ms: i64,
    seed: &[u8; 32],
) -> AppResult<TrustedDeviceRecord> {
    let signing_key = SigningKey::from_bytes(seed);
    let verifying_key = signing_key.verifying_key();
    let pubkey_bytes = verifying_key.to_bytes();
    let pubkey_hex = bytes_to_hex(&pubkey_bytes);
    let fingerprint = format_device_fingerprint(&pubkey_bytes);
    let device_id = uuid::Uuid::new_v4().to_string();

    conn.execute(
        "INSERT INTO trusted_devices(device_id, label, pubkey, fingerprint, verified_at_ms, created_at_ms)
         VALUES(?1, ?2, ?3, ?4, NULL, ?5)",
        params![device_id, device_label, pubkey_hex, fingerprint, now_ms],
    )
    .map_err(|e| {
        trust_error(
            "KC_TRUST_WRITE_FAILED",
            "failed creating trusted device",
            serde_json::json!({ "error": e.to_string(), "label": device_label }),
        )
    })?;

    append_trust_event(
        conn,
        &device_id,
        "init",
        actor,
        now_ms,
        serde_json::json!({
            "device_label": device_label,
            "fingerprint": fingerprint
        }),
    )?;

    load_device(conn, &device_id)?.ok_or_else(|| {
        trust_error(
            "KC_TRUST_READ_FAILED",
            "trusted device disappeared after insert",
            serde_json::json!({ "device_id": device_id }),
        )
    })
}

pub fn trust_device_list(conn: &Connection) -> AppResult<Vec<TrustedDeviceRecord>> {
    let mut stmt = conn
        .prepare(
            "SELECT device_id, label, pubkey, fingerprint, verified_at_ms, created_at_ms
             FROM trusted_devices
             ORDER BY created_at_ms ASC, device_id ASC",
        )
        .map_err(|e| {
            trust_error(
                "KC_TRUST_READ_FAILED",
                "failed preparing trusted device list query",
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;
    let rows = stmt
        .query_map([], |row| {
            Ok(TrustedDeviceRecord {
                device_id: row.get(0)?,
                label: row.get(1)?,
                pubkey: row.get(2)?,
                fingerprint: row.get(3)?,
                verified_at_ms: row.get(4)?,
                created_at_ms: row.get(5)?,
            })
        })
        .map_err(|e| {
            trust_error(
                "KC_TRUST_READ_FAILED",
                "failed querying trusted devices",
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;

    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| {
            trust_error(
                "KC_TRUST_READ_FAILED",
                "failed decoding trusted device row",
                serde_json::json!({ "error": e.to_string() }),
            )
        })?);
    }
    Ok(out)
}

pub fn trusted_device_public_key(conn: &Connection, device_id: &str) -> AppResult<String> {
    let Some(device) = load_device(conn, device_id)? else {
        return Err(trust_error(
            "KC_TRUST_DEVICE_UNVERIFIED",
            "device is not present in trust registry",
            serde_json::json!({ "device_id": device_id }),
        ));
    };
    if device.verified_at_ms.is_none() {
        return Err(trust_error(
            "KC_TRUST_DEVICE_UNVERIFIED",
            "device is not verified",
            serde_json::json!({ "device_id": device_id }),
        ));
    }
    Ok(device.pubkey)
}

pub fn trust_device_verify(
    conn: &Connection,
    device_id: &str,
    fingerprint: &str,
    actor: &str,
    now_ms: i64,
) -> AppResult<TrustedDeviceRecord> {
    let Some(existing) = load_device(conn, device_id)? else {
        return Err(trust_error(
            "KC_TRUST_DEVICE_UNVERIFIED",
            "device is not present in trust registry",
            serde_json::json!({ "device_id": device_id }),
        ));
    };

    if existing.fingerprint != fingerprint {
        return Err(trust_error(
            "KC_TRUST_FINGERPRINT_MISMATCH",
            "provided fingerprint did not match trusted device key",
            serde_json::json!({
                "device_id": device_id,
                "expected": existing.fingerprint,
                "actual": fingerprint
            }),
        ));
    }

    conn.execute(
        "UPDATE trusted_devices SET verified_at_ms=?1 WHERE device_id=?2",
        params![now_ms, device_id],
    )
    .map_err(|e| {
        trust_error(
            "KC_TRUST_WRITE_FAILED",
            "failed updating trusted device verification timestamp",
            serde_json::json!({ "error": e.to_string(), "device_id": device_id }),
        )
    })?;

    append_trust_event(
        conn,
        device_id,
        "verify",
        actor,
        now_ms,
        serde_json::json!({
            "fingerprint": fingerprint
        }),
    )?;

    load_device(conn, device_id)?.ok_or_else(|| {
        trust_error(
            "KC_TRUST_READ_FAILED",
            "trusted device disappeared after verification",
            serde_json::json!({ "device_id": device_id }),
        )
    })
}

pub fn trust_events(conn: &Connection) -> AppResult<Vec<TrustEventRecord>> {
    let mut stmt = conn
        .prepare(
            "SELECT event_id, device_id, action, actor, ts_ms, details_json
             FROM trust_events
             ORDER BY event_id ASC",
        )
        .map_err(|e| {
            trust_error(
                "KC_TRUST_READ_FAILED",
                "failed preparing trust events query",
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;
    let rows = stmt
        .query_map([], |row| {
            Ok(TrustEventRecord {
                event_id: row.get(0)?,
                device_id: row.get(1)?,
                action: row.get(2)?,
                actor: row.get(3)?,
                ts_ms: row.get(4)?,
                details_json: row.get(5)?,
            })
        })
        .map_err(|e| {
            trust_error(
                "KC_TRUST_READ_FAILED",
                "failed querying trust events",
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;

    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| {
            trust_error(
                "KC_TRUST_READ_FAILED",
                "failed decoding trust event row",
                serde_json::json!({ "error": e.to_string() }),
            )
        })?);
    }
    Ok(out)
}
