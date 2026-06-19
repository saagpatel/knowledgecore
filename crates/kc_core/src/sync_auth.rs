#![allow(dead_code)]

use crate::app_error::{AppError, AppResult};
use crate::canon_json::to_canonical_bytes;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

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

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

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
}
