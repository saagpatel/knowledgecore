use crate::app_error::{AppError, AppResult};
use crate::object_store::derive_object_store_key;
use crate::sync_auth::SYNC_AUTHOR_SIGNATURE_ALG_ED25519_V1;
use crate::trust::{format_device_fingerprint, trusted_device_public_key};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use ed25519_dalek::SigningKey;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

const SIGNING_KEY_KDF_ALG: &str = "argon2id_sync_signing_key_v1";
const KDF_MEMORY_KIB: u32 = 65_536;
const KDF_ITERATIONS: u32 = 3;
const KDF_PARALLELISM: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncSigningKeyStatus {
    pub device_id: String,
    pub public_key: String,
    pub signature_alg: String,
    pub key_reference: String,
    pub created_at_ms: i64,
    pub rotated_at_ms: Option<i64>,
    pub deleted_at_ms: Option<i64>,
}

#[derive(Debug)]
struct SyncSigningKeyRow {
    status: SyncSigningKeyStatus,
    seed_ciphertext: String,
    seed_nonce: String,
    kdf_alg: String,
    kdf_salt_id: String,
}

fn custody_error(code: &str, message: &str, details: serde_json::Value) -> AppError {
    AppError::new(code, "sync_key_custody", message, false, details)
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn parse_lower_hex_fixed<const N: usize>(
    value: &str,
    field: &str,
    code: &str,
) -> AppResult<[u8; N]> {
    if value.len() != N * 2
        || !value
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        return Err(custody_error(
            code,
            "hex value has invalid shape",
            serde_json::json!({
                "field": field,
                "expected_hex_chars": N * 2,
                "actual_hex_chars": value.len()
            }),
        ));
    }

    let mut out = [0u8; N];
    for (idx, slot) in out.iter_mut().enumerate() {
        let start = idx * 2;
        *slot = u8::from_str_radix(&value[start..start + 2], 16).map_err(|e| {
            custody_error(
                code,
                "hex value contains invalid byte",
                serde_json::json!({
                    "field": field,
                    "index": idx,
                    "error": e.to_string()
                }),
            )
        })?;
    }
    Ok(out)
}

fn parse_lower_hex_vec(value: &str, field: &str, code: &str) -> AppResult<Vec<u8>> {
    if !value.len().is_multiple_of(2)
        || !value
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        return Err(custody_error(
            code,
            "hex value has invalid shape",
            serde_json::json!({ "field": field, "actual_hex_chars": value.len() }),
        ));
    }
    let mut out = Vec::with_capacity(value.len() / 2);
    for idx in 0..(value.len() / 2) {
        let start = idx * 2;
        out.push(
            u8::from_str_radix(&value[start..start + 2], 16).map_err(|e| {
                custody_error(
                    code,
                    "hex value contains invalid byte",
                    serde_json::json!({
                        "field": field,
                        "index": idx,
                        "error": e.to_string()
                    }),
                )
            })?,
        );
    }
    Ok(out)
}

fn kdf_salt_id(device_id: &str) -> String {
    format!("kc.sync.signing-key.v1:{device_id}")
}

fn key_reference(device_id: &str) -> String {
    format!("sync-signing:{device_id}")
}

fn derive_key(passphrase: &str, salt_id: &str) -> AppResult<[u8; 32]> {
    if passphrase.is_empty() {
        return Err(custody_error(
            "KC_SYNC_SIGNING_KEY_LOCKED",
            "sync signing key passphrase is required",
            serde_json::json!({}),
        ));
    }
    derive_object_store_key(
        passphrase,
        salt_id,
        KDF_MEMORY_KIB,
        KDF_ITERATIONS,
        KDF_PARALLELISM,
    )
}

fn active_row(conn: &Connection, device_id: &str) -> AppResult<Option<SyncSigningKeyRow>> {
    conn.query_row(
        "SELECT device_id, public_key, signature_alg, seed_ciphertext, seed_nonce,
                kdf_alg, kdf_salt_id, key_reference, created_at_ms, rotated_at_ms, deleted_at_ms
         FROM sync_signing_keys
         WHERE device_id=?1 AND deleted_at_ms IS NULL",
        [device_id],
        |row| {
            Ok(SyncSigningKeyRow {
                status: SyncSigningKeyStatus {
                    device_id: row.get(0)?,
                    public_key: row.get(1)?,
                    signature_alg: row.get(2)?,
                    key_reference: row.get(7)?,
                    created_at_ms: row.get(8)?,
                    rotated_at_ms: row.get(9)?,
                    deleted_at_ms: row.get(10)?,
                },
                seed_ciphertext: row.get(3)?,
                seed_nonce: row.get(4)?,
                kdf_alg: row.get(5)?,
                kdf_salt_id: row.get(6)?,
            })
        },
    )
    .optional()
    .map_err(|e| {
        custody_error(
            "KC_SYNC_SIGNING_KEY_READ_FAILED",
            "failed reading sync signing key custody row",
            serde_json::json!({ "error": e.to_string(), "device_id": device_id }),
        )
    })
}

pub fn sync_signing_key_status(
    conn: &Connection,
    device_id: &str,
) -> AppResult<Option<SyncSigningKeyStatus>> {
    Ok(active_row(conn, device_id)?.map(|row| row.status))
}

pub fn store_sync_signing_seed(
    conn: &Connection,
    device_id: &str,
    seed: &[u8; 32],
    passphrase: &str,
    now_ms: i64,
) -> AppResult<SyncSigningKeyStatus> {
    let signing_key = SigningKey::from_bytes(seed);
    let public_key = bytes_to_hex(&signing_key.verifying_key().to_bytes());
    let trusted_public_key = trusted_device_public_key(conn, device_id)?;
    if trusted_public_key != public_key {
        return Err(custody_error(
            "KC_SYNC_SIGNING_KEY_MISMATCH",
            "sync signing seed does not match trusted device public key",
            serde_json::json!({ "device_id": device_id }),
        ));
    }

    if active_row(conn, device_id)?.is_some() {
        return Err(custody_error(
            "KC_SYNC_SIGNING_KEY_EXISTS",
            "sync signing key custody already exists for device",
            serde_json::json!({ "device_id": device_id }),
        ));
    }

    let salt_id = kdf_salt_id(device_id);
    let key = derive_key(passphrase, &salt_id)?;
    let mut nonce = [0u8; 24];
    getrandom::fill(&mut nonce).map_err(|e| {
        custody_error(
            "KC_SYNC_SIGNING_KEY_WRITE_FAILED",
            "failed generating sync signing key nonce",
            serde_json::json!({ "error": e.to_string(), "device_id": device_id }),
        )
    })?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), seed.as_slice())
        .map_err(|e| {
            custody_error(
                "KC_SYNC_SIGNING_KEY_WRITE_FAILED",
                "failed encrypting sync signing seed",
                serde_json::json!({ "error": e.to_string(), "device_id": device_id }),
            )
        })?;

    conn.execute(
        "INSERT INTO sync_signing_keys(
           device_id, public_key, signature_alg, seed_ciphertext, seed_nonce,
           kdf_alg, kdf_salt_id, key_reference, created_at_ms, rotated_at_ms, deleted_at_ms
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL, NULL)",
        params![
            device_id,
            public_key,
            SYNC_AUTHOR_SIGNATURE_ALG_ED25519_V1,
            bytes_to_hex(&ciphertext),
            bytes_to_hex(&nonce),
            SIGNING_KEY_KDF_ALG,
            salt_id,
            key_reference(device_id),
            now_ms
        ],
    )
    .map_err(|e| {
        custody_error(
            "KC_SYNC_SIGNING_KEY_WRITE_FAILED",
            "failed writing sync signing key custody row",
            serde_json::json!({ "error": e.to_string(), "device_id": device_id }),
        )
    })?;

    sync_signing_key_status(conn, device_id)?.ok_or_else(|| {
        custody_error(
            "KC_SYNC_SIGNING_KEY_READ_FAILED",
            "sync signing key custody row disappeared after insert",
            serde_json::json!({ "device_id": device_id }),
        )
    })
}

pub fn load_sync_signing_key(
    conn: &Connection,
    device_id: &str,
    passphrase: Option<&str>,
) -> AppResult<Option<SigningKey>> {
    let Some(row) = active_row(conn, device_id)? else {
        return Ok(None);
    };
    if row.status.signature_alg != SYNC_AUTHOR_SIGNATURE_ALG_ED25519_V1
        || row.kdf_alg != SIGNING_KEY_KDF_ALG
    {
        return Err(custody_error(
            "KC_SYNC_SIGNING_KEY_UNSUPPORTED",
            "sync signing key custody row uses unsupported metadata",
            serde_json::json!({
                "device_id": device_id,
                "signature_alg": row.status.signature_alg,
                "kdf_alg": row.kdf_alg
            }),
        ));
    }
    let passphrase = passphrase.ok_or_else(|| {
        custody_error(
            "KC_SYNC_SIGNING_KEY_LOCKED",
            "sync signing key custody exists but vault passphrase is unavailable",
            serde_json::json!({ "device_id": device_id }),
        )
    })?;
    let key = derive_key(passphrase, &row.kdf_salt_id)?;
    let nonce =
        parse_lower_hex_fixed::<24>(&row.seed_nonce, "seed_nonce", "KC_SYNC_SIGNING_KEY_INVALID")?;
    let ciphertext = parse_lower_hex_vec(
        &row.seed_ciphertext,
        "seed_ciphertext",
        "KC_SYNC_SIGNING_KEY_INVALID",
    )?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    let mut seed_bytes = cipher
        .decrypt(XNonce::from_slice(&nonce), ciphertext.as_slice())
        .map_err(|e| {
            custody_error(
                "KC_SYNC_SIGNING_KEY_LOCKED",
                "failed decrypting sync signing seed",
                serde_json::json!({ "error": e.to_string(), "device_id": device_id }),
            )
        })?;
    if seed_bytes.len() != 32 {
        seed_bytes.fill(0);
        return Err(custody_error(
            "KC_SYNC_SIGNING_KEY_INVALID",
            "decrypted sync signing seed has invalid length",
            serde_json::json!({ "device_id": device_id }),
        ));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);
    seed_bytes.fill(0);
    let signing_key = SigningKey::from_bytes(&seed);
    seed.fill(0);
    let public_key = bytes_to_hex(&signing_key.verifying_key().to_bytes());
    let trusted_public_key = trusted_device_public_key(conn, device_id)?;
    if public_key != row.status.public_key || public_key != trusted_public_key {
        return Err(custody_error(
            "KC_SYNC_SIGNING_KEY_MISMATCH",
            "sync signing seed does not match trusted device public key",
            serde_json::json!({
                "device_id": device_id,
                "fingerprint": format_device_fingerprint(&signing_key.verifying_key().to_bytes())
            }),
        ));
    }
    Ok(Some(signing_key))
}

pub fn delete_sync_signing_key(
    conn: &Connection,
    device_id: &str,
    now_ms: i64,
) -> AppResult<Option<SyncSigningKeyStatus>> {
    let Some(existing) = active_row(conn, device_id)? else {
        return Ok(None);
    };
    conn.execute(
        "UPDATE sync_signing_keys SET deleted_at_ms=?1 WHERE device_id=?2 AND deleted_at_ms IS NULL",
        params![now_ms, device_id],
    )
    .map_err(|e| {
        custody_error(
            "KC_SYNC_SIGNING_KEY_WRITE_FAILED",
            "failed deleting sync signing key custody row",
            serde_json::json!({ "error": e.to_string(), "device_id": device_id }),
        )
    })?;
    Ok(Some(existing.status))
}

pub fn rotate_sync_signing_key(
    conn: &Connection,
    device_id: &str,
    now_ms: i64,
) -> AppResult<Option<SyncSigningKeyStatus>> {
    let Some(existing) = active_row(conn, device_id)? else {
        return Ok(None);
    };
    conn.execute(
        "UPDATE sync_signing_keys
         SET rotated_at_ms=?1, deleted_at_ms=?1
         WHERE device_id=?2 AND deleted_at_ms IS NULL",
        params![now_ms, device_id],
    )
    .map_err(|e| {
        custody_error(
            "KC_SYNC_SIGNING_KEY_WRITE_FAILED",
            "failed rotating sync signing key custody row",
            serde_json::json!({ "error": e.to_string(), "device_id": device_id }),
        )
    })?;
    let mut status = existing.status;
    status.rotated_at_ms = Some(now_ms);
    status.deleted_at_ms = Some(now_ms);
    Ok(Some(status))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::apply_migrations;
    use crate::trust::{trust_device_init_with_seed, trust_device_verify};

    #[test]
    fn sync_signing_seed_round_trips_only_with_passphrase() {
        let conn = Connection::open_in_memory().expect("db");
        apply_migrations(&conn).expect("migrations");
        let seed = [9u8; 32];
        let device =
            trust_device_init_with_seed(&conn, "fixture", "test", 10, &seed).expect("device");
        trust_device_verify(&conn, &device.device_id, &device.fingerprint, "test", 11)
            .expect("verify");

        store_sync_signing_seed(&conn, &device.device_id, &seed, "passphrase", 12).expect("store");
        assert!(load_sync_signing_key(&conn, &device.device_id, None).is_err());
        assert!(load_sync_signing_key(&conn, &device.device_id, Some("wrong")).is_err());
        let loaded = load_sync_signing_key(&conn, &device.device_id, Some("passphrase"))
            .expect("load")
            .expect("key");
        assert_eq!(loaded.to_bytes(), seed);
    }

    #[test]
    fn sync_signing_rotation_marks_active_row_retired() {
        let conn = Connection::open_in_memory().expect("db");
        apply_migrations(&conn).expect("migrations");
        assert!(rotate_sync_signing_key(&conn, "missing-device", 20)
            .expect("missing rotate")
            .is_none());

        let seed = [7u8; 32];
        let device =
            trust_device_init_with_seed(&conn, "fixture", "test", 21, &seed).expect("device");
        trust_device_verify(&conn, &device.device_id, &device.fingerprint, "test", 22)
            .expect("verify");
        store_sync_signing_seed(&conn, &device.device_id, &seed, "passphrase", 23).expect("store");

        let retired = rotate_sync_signing_key(&conn, &device.device_id, 24)
            .expect("rotate")
            .expect("retired");
        assert_eq!(retired.device_id, device.device_id);
        assert_eq!(retired.rotated_at_ms, Some(24));
        assert_eq!(retired.deleted_at_ms, Some(24));
        assert!(sync_signing_key_status(&conn, &device.device_id)
            .expect("status")
            .is_none());
    }
}
