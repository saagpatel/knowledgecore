use crate::app_error::{AppError, AppResult};
use crate::canon_json::to_canonical_bytes;
use crate::hashing::blake3_hex_prefixed;
use crate::recovery_escrow::{validate_escrow_descriptor, RecoveryEscrowDescriptorV2};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

const RECOVERY_MAGIC: &[u8; 4] = b"KCR1";
const RECOVERY_NONCE_LEN: usize = 24;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoveryManifestV2 {
    pub schema_version: i64,
    pub vault_id: String,
    pub created_at_ms: i64,
    pub phrase_checksum: String,
    pub payload_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub escrow: Option<RecoveryEscrowDescriptorV2>,
}

// Alias kept for compatibility with existing crate references.
pub type RecoveryManifestV1 = RecoveryManifestV2;

#[derive(Debug, Clone, Deserialize)]
struct RecoveryManifestLegacyV1 {
    pub schema_version: i64,
    pub vault_id: String,
    pub created_at_ms: i64,
    pub phrase_checksum: String,
    pub payload_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryBundleGenerateResult {
    pub bundle_path: PathBuf,
    pub manifest: RecoveryManifestV2,
    pub recovery_phrase: String,
}

fn recovery_error(code: &str, message: &str, details: serde_json::Value) -> AppError {
    AppError::new(code, "recovery", message, false, details)
}

fn normalize_phrase(phrase: &str) -> String {
    phrase.trim().to_ascii_lowercase()
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn recovery_phrase_key(vault_id: &str, phrase: &str) -> [u8; 32] {
    let normalized = normalize_phrase(phrase);
    let material = format!("kc.recovery.phrase.v1\n{}\n{}", vault_id, normalized);
    let digest = Sha256::digest(material.as_bytes());
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);
    key
}

fn recovery_nonce(vault_id: &str, created_at_ms: i64) -> [u8; RECOVERY_NONCE_LEN] {
    let material = format!("kc.recovery.nonce.v1\n{}\n{}", vault_id, created_at_ms);
    let digest = blake3::hash(material.as_bytes());
    let mut nonce = [0u8; RECOVERY_NONCE_LEN];
    nonce.copy_from_slice(&digest.as_bytes()[0..RECOVERY_NONCE_LEN]);
    nonce
}

fn phrase_checksum(vault_id: &str, phrase: &str) -> String {
    let normalized = normalize_phrase(phrase);
    blake3_hex_prefixed(format!("kc.recovery.checksum.v1\n{}\n{}", vault_id, normalized).as_bytes())
}

fn random_phrase() -> AppResult<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|e| {
        recovery_error(
            "KC_RECOVERY_BUNDLE_INVALID",
            "failed generating recovery phrase entropy",
            serde_json::json!({ "error": e.to_string() }),
        )
    })?;
    let hex = bytes_to_hex(&bytes);
    Ok(format!(
        "{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..16],
        &hex[16..24],
        &hex[24..32]
    ))
}

fn build_blob(
    vault_id: &str,
    created_at_ms: i64,
    passphrase: &str,
    phrase: &str,
) -> AppResult<Vec<u8>> {
    let key = recovery_phrase_key(vault_id, phrase);
    let nonce = recovery_nonce(vault_id, created_at_ms);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), passphrase.as_bytes())
        .map_err(|e| {
            recovery_error(
                "KC_RECOVERY_BUNDLE_INVALID",
                "failed encrypting recovery key blob",
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;
    let mut blob = Vec::with_capacity(RECOVERY_MAGIC.len() + RECOVERY_NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(RECOVERY_MAGIC);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

fn decrypt_recovery_blob(
    vault_id: &str,
    created_at_ms: i64,
    phrase: &str,
    blob: &[u8],
    blob_path: &Path,
) -> AppResult<Vec<u8>> {
    if !blob.starts_with(RECOVERY_MAGIC) || blob.len() <= RECOVERY_MAGIC.len() + RECOVERY_NONCE_LEN
    {
        return Err(recovery_error(
            "KC_RECOVERY_BUNDLE_INVALID",
            "recovery key blob has invalid format",
            serde_json::json!({ "path": blob_path, "len": blob.len() }),
        ));
    }

    let nonce = &blob[RECOVERY_MAGIC.len()..RECOVERY_MAGIC.len() + RECOVERY_NONCE_LEN];
    let expected_nonce = recovery_nonce(vault_id, created_at_ms);
    if nonce != expected_nonce {
        return Err(recovery_error(
            "KC_RECOVERY_BUNDLE_INVALID",
            "recovery key blob nonce does not match manifest",
            serde_json::json!({ "path": blob_path }),
        ));
    }

    let ciphertext = &blob[RECOVERY_MAGIC.len() + RECOVERY_NONCE_LEN..];
    let key = recovery_phrase_key(vault_id, phrase);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    let plaintext = cipher
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .map_err(|e| {
            recovery_error(
                "KC_RECOVERY_BUNDLE_INVALID",
                "failed decrypting recovery key blob",
                serde_json::json!({ "error": e.to_string(), "path": blob_path }),
            )
        })?;

    if plaintext.is_empty() {
        return Err(recovery_error(
            "KC_RECOVERY_BUNDLE_INVALID",
            "recovery key blob decrypted to empty passphrase",
            serde_json::json!({ "path": blob_path }),
        ));
    }

    Ok(plaintext)
}

pub fn generate_recovery_bundle(
    vault_id: &str,
    output_dir: &Path,
    passphrase: &str,
    created_at_ms: i64,
) -> AppResult<RecoveryBundleGenerateResult> {
    generate_recovery_bundle_with_escrow(vault_id, output_dir, passphrase, created_at_ms, None)
}

pub fn generate_recovery_bundle_with_escrow(
    vault_id: &str,
    output_dir: &Path,
    passphrase: &str,
    created_at_ms: i64,
    escrow: Option<RecoveryEscrowDescriptorV2>,
) -> AppResult<RecoveryBundleGenerateResult> {
    if passphrase.is_empty() {
        return Err(recovery_error(
            "KC_ENCRYPTION_REQUIRED",
            "passphrase is required for recovery bundle generation",
            serde_json::json!({}),
        ));
    }
    if let Some(desc) = &escrow {
        validate_escrow_descriptor(desc)?;
    }

    let phrase = random_phrase()?;
    let blob = build_blob(vault_id, created_at_ms, passphrase, &phrase)?;
    let payload_hash = blake3_hex_prefixed(&blob);
    let checksum = phrase_checksum(vault_id, &phrase);

    let bundle_path = output_dir.join(format!("recovery_{}_{}", vault_id, created_at_ms));
    fs::create_dir_all(&bundle_path).map_err(|e| {
        recovery_error(
            "KC_RECOVERY_BUNDLE_INVALID",
            "failed creating recovery bundle directory",
            serde_json::json!({ "error": e.to_string(), "path": bundle_path }),
        )
    })?;

    let blob_path = bundle_path.join("key_blob.enc");
    fs::write(&blob_path, &blob).map_err(|e| {
        recovery_error(
            "KC_RECOVERY_BUNDLE_INVALID",
            "failed writing recovery key blob",
            serde_json::json!({ "error": e.to_string(), "path": blob_path }),
        )
    })?;

    let manifest = RecoveryManifestV2 {
        schema_version: 2,
        vault_id: vault_id.to_string(),
        created_at_ms,
        phrase_checksum: checksum,
        payload_hash,
        escrow,
    };
    let manifest_bytes = to_canonical_bytes(&serde_json::to_value(&manifest).map_err(|e| {
        recovery_error(
            "KC_RECOVERY_BUNDLE_INVALID",
            "failed serializing recovery manifest",
            serde_json::json!({ "error": e.to_string() }),
        )
    })?)?;
    let manifest_path = bundle_path.join("recovery_manifest.json");
    fs::write(&manifest_path, manifest_bytes).map_err(|e| {
        recovery_error(
            "KC_RECOVERY_BUNDLE_INVALID",
            "failed writing recovery manifest",
            serde_json::json!({ "error": e.to_string(), "path": manifest_path }),
        )
    })?;

    Ok(RecoveryBundleGenerateResult {
        bundle_path,
        manifest,
        recovery_phrase: phrase,
    })
}

fn parse_recovery_manifest(
    manifest_bytes: &[u8],
    manifest_path: &Path,
) -> AppResult<RecoveryManifestV2> {
    let raw_value: serde_json::Value = serde_json::from_slice(manifest_bytes).map_err(|e| {
        recovery_error(
            "KC_RECOVERY_BUNDLE_INVALID",
            "failed parsing recovery manifest json",
            serde_json::json!({ "error": e.to_string(), "path": manifest_path }),
        )
    })?;

    let schema_version = raw_value
        .get("schema_version")
        .and_then(|x| x.as_i64())
        .ok_or_else(|| {
            recovery_error(
                "KC_RECOVERY_BUNDLE_INVALID",
                "recovery manifest is missing schema_version",
                serde_json::json!({ "path": manifest_path }),
            )
        })?;

    match schema_version {
        2 => {
            let parsed: RecoveryManifestV2 = serde_json::from_value(raw_value).map_err(|e| {
                recovery_error(
                    "KC_RECOVERY_BUNDLE_INVALID",
                    "failed parsing v2 recovery manifest",
                    serde_json::json!({ "error": e.to_string(), "path": manifest_path }),
                )
            })?;
            if let Some(desc) = &parsed.escrow {
                validate_escrow_descriptor(desc)?;
            }
            Ok(parsed)
        }
        1 => {
            let parsed: RecoveryManifestLegacyV1 =
                serde_json::from_value(raw_value).map_err(|e| {
                    recovery_error(
                        "KC_RECOVERY_BUNDLE_INVALID",
                        "failed parsing v1 recovery manifest",
                        serde_json::json!({ "error": e.to_string(), "path": manifest_path }),
                    )
                })?;
            Ok(RecoveryManifestV2 {
                schema_version: parsed.schema_version,
                vault_id: parsed.vault_id,
                created_at_ms: parsed.created_at_ms,
                phrase_checksum: parsed.phrase_checksum,
                payload_hash: parsed.payload_hash,
                escrow: None,
            })
        }
        other => Err(recovery_error(
            "KC_RECOVERY_BUNDLE_INVALID",
            "unsupported recovery manifest schema version",
            serde_json::json!({
                "expected": [1, 2],
                "actual": other,
                "path": manifest_path
            }),
        )),
    }
}

pub fn read_recovery_manifest(bundle_path: &Path) -> AppResult<RecoveryManifestV2> {
    let manifest_path = bundle_path.join("recovery_manifest.json");
    let manifest_bytes = fs::read(&manifest_path).map_err(|e| {
        recovery_error(
            "KC_RECOVERY_BUNDLE_INVALID",
            "failed reading recovery manifest",
            serde_json::json!({ "error": e.to_string(), "path": manifest_path }),
        )
    })?;
    parse_recovery_manifest(&manifest_bytes, &manifest_path)
}

pub fn write_recovery_manifest(bundle_path: &Path, manifest: &RecoveryManifestV2) -> AppResult<()> {
    let manifest_bytes = to_canonical_bytes(&serde_json::to_value(manifest).map_err(|e| {
        recovery_error(
            "KC_RECOVERY_BUNDLE_INVALID",
            "failed serializing recovery manifest",
            serde_json::json!({ "error": e.to_string() }),
        )
    })?)?;
    let manifest_path = bundle_path.join("recovery_manifest.json");
    fs::write(&manifest_path, manifest_bytes).map_err(|e| {
        recovery_error(
            "KC_RECOVERY_BUNDLE_INVALID",
            "failed writing recovery manifest",
            serde_json::json!({ "error": e.to_string(), "path": manifest_path }),
        )
    })
}

pub fn verify_recovery_bundle(
    expected_vault_id: &str,
    bundle_path: &Path,
    phrase: &str,
) -> AppResult<RecoveryManifestV2> {
    let manifest = read_recovery_manifest(bundle_path)?;

    if manifest.vault_id != expected_vault_id {
        return Err(recovery_error(
            "KC_RECOVERY_BUNDLE_INVALID",
            "recovery bundle vault_id mismatch",
            serde_json::json!({
                "expected": expected_vault_id,
                "actual": manifest.vault_id
            }),
        ));
    }

    let blob_path = bundle_path.join("key_blob.enc");
    let blob = fs::read(&blob_path).map_err(|e| {
        recovery_error(
            "KC_RECOVERY_BUNDLE_INVALID",
            "failed reading recovery key blob",
            serde_json::json!({ "error": e.to_string(), "path": blob_path }),
        )
    })?;

    let actual_hash = blake3_hex_prefixed(&blob);
    if actual_hash != manifest.payload_hash {
        return Err(recovery_error(
            "KC_RECOVERY_BUNDLE_INVALID",
            "recovery key blob hash mismatch",
            serde_json::json!({
                "expected": manifest.payload_hash,
                "actual": actual_hash
            }),
        ));
    }

    let expected_checksum = phrase_checksum(expected_vault_id, phrase);
    if expected_checksum != manifest.phrase_checksum {
        return Err(recovery_error(
            "KC_RECOVERY_PHRASE_INVALID",
            "recovery phrase checksum mismatch",
            serde_json::json!({
                "expected": manifest.phrase_checksum,
                "actual": expected_checksum
            }),
        ));
    }

    decrypt_recovery_blob(
        expected_vault_id,
        manifest.created_at_ms,
        phrase,
        &blob,
        &blob_path,
    )?;

    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_db;
    use crate::object_store::{ObjectStore, ObjectStoreEncryptionContext};

    #[test]
    fn recovery_blob_decrypts_to_original_passphrase() {
        let blob = build_blob(
            "vault-id",
            100,
            "vault-passphrase",
            "00112233-44556677-8899aabb-ccddeeff",
        )
        .expect("build blob");

        let restored = decrypt_recovery_blob(
            "vault-id",
            100,
            "00112233-44556677-8899aabb-ccddeeff",
            &blob,
            Path::new("key_blob.enc"),
        )
        .expect("decrypt blob");

        assert_eq!(restored, b"vault-passphrase");
    }

    #[test]
    fn recovery_restore_drill_unlocks_generated_encrypted_fixture() {
        let root = tempfile::tempdir().expect("tempdir");
        let db_path = root.path().join("db/knowledge.sqlite");
        let conn = open_db(&db_path).expect("open db");
        let objects_dir = root.path().join("store/objects");
        let vault_id = "vault-drill";
        let vault_passphrase = "vault-passphrase-for-generated-drill";
        let key_reference = format!("vault:{vault_id}");

        let key = crate::object_store::derive_object_store_key(
            vault_passphrase,
            "vault-kdf-salt-v1",
            4096,
            2,
            1,
        )
        .expect("derive fixture key");
        let encrypted_store = ObjectStore::with_encryption(
            objects_dir.clone(),
            ObjectStoreEncryptionContext {
                key,
                key_reference: key_reference.clone(),
            },
        );
        let payload = b"generated recovery drill payload";
        let hash = encrypted_store
            .put_bytes(&conn, payload, 1)
            .expect("write encrypted fixture object");

        let generated = generate_recovery_bundle(
            vault_id,
            &root.path().join("recovery-out"),
            vault_passphrase,
            100,
        )
        .expect("generate recovery bundle");
        let verified =
            verify_recovery_bundle(vault_id, &generated.bundle_path, &generated.recovery_phrase)
                .expect("verify recovery bundle");
        assert_eq!(verified, generated.manifest);

        let blob = fs::read(generated.bundle_path.join("key_blob.enc")).expect("read key blob");
        let restored = decrypt_recovery_blob(
            vault_id,
            generated.manifest.created_at_ms,
            &generated.recovery_phrase,
            &blob,
            &generated.bundle_path.join("key_blob.enc"),
        )
        .expect("restore passphrase from recovery bundle");
        assert_eq!(restored, vault_passphrase.as_bytes());

        let restored_passphrase =
            String::from_utf8(restored).expect("restored passphrase is utf8 fixture");
        let restored_key = crate::object_store::derive_object_store_key(
            &restored_passphrase,
            "vault-kdf-salt-v1",
            4096,
            2,
            1,
        )
        .expect("derive restored fixture key");
        let restored_store = ObjectStore::with_encryption(
            objects_dir,
            ObjectStoreEncryptionContext {
                key: restored_key,
                key_reference,
            },
        );

        assert_eq!(
            restored_store
                .get_bytes(&hash)
                .expect("restored passphrase decrypts object"),
            payload
        );
    }
}
