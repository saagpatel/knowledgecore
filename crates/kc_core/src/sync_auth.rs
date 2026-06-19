#![allow(dead_code)]

use crate::app_error::{AppError, AppResult};
use crate::canon_json::to_canonical_bytes;
use crate::sync::SyncHeadV1;
use crate::{trust, trust_identity};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rusqlite::Connection;

pub(crate) const SYNC_AUTHOR_SIGNATURE_ALG_ED25519_V1: &str = "ed25519_sync_head_v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SyncAuthorPayloadV1 {
    pub snapshot_id: String,
    pub manifest_hash: String,
    pub created_at_ms: i64,
    pub author_device_id: String,
    pub author_fingerprint: String,
    pub author_cert_id: String,
    pub author_chain_hash: String,
}

fn sync_auth_error(code: &str, message: &str, details: serde_json::Value) -> AppError {
    AppError::new(code, "sync", message, false, details)
}

pub(crate) fn canonical_sync_author_payload_v1(
    payload: &SyncAuthorPayloadV1,
) -> AppResult<Vec<u8>> {
    to_canonical_bytes(&serde_json::json!({
        "signature_alg": SYNC_AUTHOR_SIGNATURE_ALG_ED25519_V1,
        "snapshot_id": payload.snapshot_id,
        "manifest_hash": payload.manifest_hash,
        "created_at_ms": payload.created_at_ms,
        "author_device_id": payload.author_device_id,
        "author_fingerprint": payload.author_fingerprint,
        "author_cert_id": payload.author_cert_id,
        "author_chain_hash": payload.author_chain_hash
    }))
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
        return Err(sync_auth_error(
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
            sync_auth_error(
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

pub(crate) fn verify_sync_author_signature_v1(
    payload: &[u8],
    signature_hex: &str,
    author_pubkey_hex: &str,
) -> AppResult<()> {
    let signature_bytes = parse_lower_hex_fixed::<64>(
        signature_hex,
        "author_signature",
        "KC_TRUST_SIGNATURE_INVALID",
    )?;
    let pubkey_bytes = parse_lower_hex_fixed::<32>(
        author_pubkey_hex,
        "author_pubkey",
        "KC_TRUST_CERT_CHAIN_INVALID",
    )?;
    let signature = Signature::from_bytes(&signature_bytes);
    let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes).map_err(|e| {
        sync_auth_error(
            "KC_TRUST_CERT_CHAIN_INVALID",
            "author public key is not a valid Ed25519 verifying key",
            serde_json::json!({ "error": e.to_string() }),
        )
    })?;

    verifying_key.verify(payload, &signature).map_err(|e| {
        sync_auth_error(
            "KC_TRUST_SIGNATURE_INVALID",
            "sync author Ed25519 signature verification failed",
            serde_json::json!({ "error": e.to_string() }),
        )
    })
}

pub(crate) fn verify_sync_head_author_signature_v1(
    conn: &Connection,
    head: &SyncHeadV1,
) -> AppResult<()> {
    if head.schema_version < 3 {
        return Ok(());
    }

    let author_device_id =
        required_author_field(head.author_device_id.as_deref(), head, "author_device_id")?;
    let author_fingerprint = required_author_field(
        head.author_fingerprint.as_deref(),
        head,
        "author_fingerprint",
    )?;
    let author_signature =
        required_author_field(head.author_signature.as_deref(), head, "author_signature")?;
    let author_cert_id =
        required_author_field(head.author_cert_id.as_deref(), head, "author_cert_id")?;
    let author_chain_hash =
        required_author_field(head.author_chain_hash.as_deref(), head, "author_chain_hash")?;

    trust_identity::verify_author_chain(conn, author_device_id, author_cert_id, author_chain_hash)
        .map_err(|e| {
            sync_auth_error(
                "KC_TRUST_CERT_CHAIN_INVALID",
                "sync head author certificate chain verification failed",
                serde_json::json!({
                    "source_code": e.code,
                    "source_message": e.message,
                    "snapshot_id": head.snapshot_id,
                    "author_device_id": author_device_id,
                    "author_cert_id": author_cert_id
                }),
            )
        })?;

    let author_pubkey = trust::trusted_device_public_key(conn, author_device_id).map_err(|e| {
        sync_auth_error(
            "KC_TRUST_DEVICE_UNVERIFIED",
            "sync head author device public key is unavailable",
            serde_json::json!({
                "source_code": e.code,
                "source_message": e.message,
                "snapshot_id": head.snapshot_id,
                "author_device_id": author_device_id
            }),
        )
    })?;

    let expected_fingerprint = trust::format_device_fingerprint(&parse_lower_hex_fixed::<32>(
        &author_pubkey,
        "author_pubkey",
        "KC_TRUST_CERT_CHAIN_INVALID",
    )?);
    if expected_fingerprint != author_fingerprint {
        return Err(sync_auth_error(
            "KC_TRUST_FINGERPRINT_MISMATCH",
            "sync head author fingerprint does not match trusted device key",
            serde_json::json!({
                "snapshot_id": head.snapshot_id,
                "author_device_id": author_device_id,
                "expected": expected_fingerprint,
                "actual": author_fingerprint
            }),
        ));
    }

    let payload = canonical_sync_author_payload_v1(&SyncAuthorPayloadV1 {
        snapshot_id: head.snapshot_id.clone(),
        manifest_hash: head.manifest_hash.clone(),
        created_at_ms: head.created_at_ms,
        author_device_id: author_device_id.to_string(),
        author_fingerprint: author_fingerprint.to_string(),
        author_cert_id: author_cert_id.to_string(),
        author_chain_hash: author_chain_hash.to_string(),
    })?;
    verify_sync_author_signature_v1(&payload, author_signature, &author_pubkey)
}

fn required_author_field<'a>(
    value: Option<&'a str>,
    head: &SyncHeadV1,
    field: &str,
) -> AppResult<&'a str> {
    value
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            sync_auth_error(
                "KC_TRUST_SIGNATURE_INVALID",
                "sync head v3 is missing required author signature field",
                serde_json::json!({
                    "snapshot_id": head.snapshot_id,
                    "field": field
                }),
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::apply_migrations;
    use crate::sync::SyncHeadV1;
    use crate::trust::format_device_fingerprint;
    use ed25519_dalek::{Signer, SigningKey};
    use rusqlite::Connection;

    fn bytes_to_hex(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    fn fixture_payload() -> SyncAuthorPayloadV1 {
        SyncAuthorPayloadV1 {
            snapshot_id: "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            manifest_hash:
                "blake3:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    .to_string(),
            created_at_ms: 123456789,
            author_device_id: "device-1".to_string(),
            author_fingerprint:
                "11111111:22222222:33333333:44444444:55555555:66666666:77777777:88888888"
                    .to_string(),
            author_cert_id: "cert-1".to_string(),
            author_chain_hash:
                "blake3:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                    .to_string(),
        }
    }

    fn signing_key(seed_byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed_byte; 32])
    }

    fn trusted_author_conn(key: &SigningKey) -> (Connection, SyncAuthorPayloadV1) {
        let conn = Connection::open_in_memory().expect("open memory db");
        apply_migrations(&conn).expect("migrations");
        let pubkey_hex = bytes_to_hex(&key.verifying_key().to_bytes());
        let fingerprint = format_device_fingerprint(&key.verifying_key().to_bytes());
        let payload = fixture_payload();

        conn.execute(
            "INSERT INTO trusted_devices(device_id, label, pubkey, fingerprint, verified_at_ms, created_at_ms)
             VALUES(?1, 'fixture', ?2, ?3, 10, 9)",
            rusqlite::params![payload.author_device_id, pubkey_hex, fingerprint],
        )
        .expect("insert trusted device");
        conn.execute(
            "INSERT INTO identity_providers(provider_id, issuer, audience, enabled, created_at_ms)
             VALUES('default', 'https://default.oidc.knowledgecore.local', 'kc-desktop:default', 1, 10)",
            [],
        )
        .expect("insert identity provider");
        conn.execute(
            "INSERT INTO device_certificates(
               cert_id, device_id, provider_id, subject, cert_chain_hash, issued_at_ms, expires_at_ms, verified_at_ms, created_at_ms
             )
             VALUES(?1, ?2, 'default', 'sub:sync-author', ?3, 11, 3600011, 12, 11)",
            rusqlite::params![
                payload.author_cert_id,
                payload.author_device_id,
                payload.author_chain_hash
            ],
        )
        .expect("insert device certificate");
        (conn, payload)
    }

    fn head_for_payload(payload: &SyncAuthorPayloadV1, signature_hex: String) -> SyncHeadV1 {
        SyncHeadV1 {
            schema_version: 3,
            snapshot_id: payload.snapshot_id.clone(),
            manifest_hash: payload.manifest_hash.clone(),
            created_at_ms: payload.created_at_ms,
            trust: None,
            author_device_id: Some(payload.author_device_id.clone()),
            author_fingerprint: Some(payload.author_fingerprint.clone()),
            author_signature: Some(signature_hex),
            author_signature_alg: None,
            author_cert_id: Some(payload.author_cert_id.clone()),
            author_chain_hash: Some(payload.author_chain_hash.clone()),
        }
    }

    #[test]
    fn sync_author_payload_v1_is_canonical_and_domain_separated() {
        let bytes = canonical_sync_author_payload_v1(&fixture_payload()).expect("payload");
        let expected = concat!(
            "{\"author_cert_id\":\"cert-1\",",
            "\"author_chain_hash\":\"blake3:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\",",
            "\"author_device_id\":\"device-1\",",
            "\"author_fingerprint\":\"11111111:22222222:33333333:44444444:55555555:66666666:77777777:88888888\",",
            "\"created_at_ms\":123456789,",
            "\"manifest_hash\":\"blake3:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",",
            "\"signature_alg\":\"ed25519_sync_head_v1\",",
            "\"snapshot_id\":\"blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}"
        );
        assert_eq!(String::from_utf8(bytes).expect("utf8"), expected);
    }

    #[test]
    fn sync_author_signature_v1_verifies_ed25519_signature() {
        let key = signing_key(7);
        let payload = canonical_sync_author_payload_v1(&fixture_payload()).expect("payload");
        let signature = key.sign(&payload);
        let signature_hex = bytes_to_hex(&signature.to_bytes());
        let pubkey_hex = bytes_to_hex(&key.verifying_key().to_bytes());

        verify_sync_author_signature_v1(&payload, &signature_hex, &pubkey_hex)
            .expect("signature should verify");
    }

    #[test]
    fn sync_author_signature_v1_rejects_tampered_payload() {
        let key = signing_key(7);
        let payload = canonical_sync_author_payload_v1(&fixture_payload()).expect("payload");
        let signature = key.sign(&payload);
        let signature_hex = bytes_to_hex(&signature.to_bytes());
        let pubkey_hex = bytes_to_hex(&key.verifying_key().to_bytes());
        let mut tampered = payload.clone();
        tampered.extend_from_slice(b"\n");

        let err = verify_sync_author_signature_v1(&tampered, &signature_hex, &pubkey_hex)
            .expect_err("tampered payload must fail");
        assert_eq!(err.code, "KC_TRUST_SIGNATURE_INVALID");
    }

    #[test]
    fn sync_author_signature_v1_rejects_wrong_key() {
        let key = signing_key(7);
        let wrong_key = signing_key(9);
        let payload = canonical_sync_author_payload_v1(&fixture_payload()).expect("payload");
        let signature = key.sign(&payload);
        let signature_hex = bytes_to_hex(&signature.to_bytes());
        let wrong_pubkey_hex = bytes_to_hex(&wrong_key.verifying_key().to_bytes());

        let err = verify_sync_author_signature_v1(&payload, &signature_hex, &wrong_pubkey_hex)
            .expect_err("wrong key must fail");
        assert_eq!(err.code, "KC_TRUST_SIGNATURE_INVALID");
    }

    #[test]
    fn sync_author_signature_v1_rejects_malformed_signature_hex() {
        let key = signing_key(7);
        let payload = canonical_sync_author_payload_v1(&fixture_payload()).expect("payload");
        let pubkey_hex = bytes_to_hex(&key.verifying_key().to_bytes());

        let err = verify_sync_author_signature_v1(&payload, "abcd", &pubkey_hex)
            .expect_err("short signature must fail");
        assert_eq!(err.code, "KC_TRUST_SIGNATURE_INVALID");
    }

    #[test]
    fn sync_author_signature_v1_rejects_malformed_pubkey_hex() {
        let key = signing_key(7);
        let payload = canonical_sync_author_payload_v1(&fixture_payload()).expect("payload");
        let signature = key.sign(&payload);
        let signature_hex = bytes_to_hex(&signature.to_bytes());

        let err = verify_sync_author_signature_v1(&payload, &signature_hex, "abcd")
            .expect_err("short pubkey must fail");
        assert_eq!(err.code, "KC_TRUST_CERT_CHAIN_INVALID");
    }

    #[test]
    fn sync_head_author_signature_v1_verifies_against_trusted_device_key() {
        let key = signing_key(7);
        let (conn, mut payload) = trusted_author_conn(&key);
        payload.author_fingerprint = format_device_fingerprint(&key.verifying_key().to_bytes());
        let payload_bytes = canonical_sync_author_payload_v1(&payload).expect("payload");
        let signature = key.sign(&payload_bytes);
        let head = head_for_payload(&payload, bytes_to_hex(&signature.to_bytes()));

        verify_sync_head_author_signature_v1(&conn, &head).expect("head signature should verify");
    }

    #[test]
    fn sync_head_author_signature_v1_rejects_tampered_head_payload() {
        let key = signing_key(7);
        let (conn, mut payload) = trusted_author_conn(&key);
        payload.author_fingerprint = format_device_fingerprint(&key.verifying_key().to_bytes());
        let payload_bytes = canonical_sync_author_payload_v1(&payload).expect("payload");
        let signature = key.sign(&payload_bytes);
        let mut head = head_for_payload(&payload, bytes_to_hex(&signature.to_bytes()));
        head.manifest_hash =
            "blake3:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_string();

        let err = verify_sync_head_author_signature_v1(&conn, &head)
            .expect_err("tampered head must fail");
        assert_eq!(err.code, "KC_TRUST_SIGNATURE_INVALID");
    }
}
