use crate::app_error::{AppError, AppResult};
use crate::canonical::load_canonical_text;
use crate::db::{
    db_is_unlocked, db_lock, db_unlock, derive_db_encryption_state, migrate_db_to_sqlcipher,
    open_db, DbMigrationOutcome,
};
use crate::document_lifecycle::{
    append_document_lifecycle_event, DocumentLifecycleEventV1, DocumentLifecycleMutationRequestV1,
};
use crate::events::append_event;
use crate::hashing::blake3_hex_prefixed;
use crate::ingest::{ingest_bytes_with_limits, validate_scan_folder_files, IngestBytesReq};
use crate::lineage_governance::{
    lineage_lock_acquire_scope, lineage_role_grant, lineage_role_list, lineage_role_revoke,
    LineageRoleBindingV2, LineageScopeLockLeaseV2,
};
use crate::lineage_policy::{
    lineage_policy_add, lineage_policy_bind, lineage_policy_list, LineagePolicyBindingV3,
    LineagePolicyV3,
};
use crate::locator::{resolve_locator_strict, LocatorV1};
use crate::object_store::{is_encrypted_payload, ObjectStore};
use crate::recovery::{
    generate_recovery_bundle, read_recovery_manifest, verify_recovery_bundle,
    write_recovery_manifest, RecoveryManifestV2,
};
use crate::recovery_escrow::{
    provider_priority, supported_provider_ids, RecoveryEscrowProvider, RecoveryEscrowReadRequest,
    RecoveryEscrowWriteRequest,
};
use crate::recovery_escrow_aws::{AwsRecoveryEscrowConfig, AwsRecoveryEscrowProvider};
use crate::recovery_escrow_azure::{AzureRecoveryEscrowConfig, AzureRecoveryEscrowProvider};
use crate::recovery_escrow_gcp::{GcpRecoveryEscrowConfig, GcpRecoveryEscrowProvider};
use crate::recovery_escrow_hsm::{HsmRecoveryEscrowConfig, HsmRecoveryEscrowProvider};
use crate::recovery_escrow_local::LocalRecoveryEscrowProvider;
use crate::recovery_escrow_private_kms::{
    PrivateKmsRecoveryEscrowConfig, PrivateKmsRecoveryEscrowProvider,
};
use crate::resource_limits::{ingest_single_file_limits, scan_folder_limits};
use crate::sync_key_custody::{
    delete_sync_signing_key, rotate_sync_signing_key, store_sync_signing_seed,
    sync_signing_key_status, SyncSigningKeyStatus,
};
use crate::trust::{
    trust_device_init, trust_device_init_with_seed, trust_device_list, trust_device_verify,
    TrustedDeviceRecord,
};
use crate::trust_identity::{
    discover_identity_provider, trust_device_enroll, trust_device_verify_chain,
    trust_identity_complete, trust_identity_start, trust_provider_add, trust_provider_disable,
    trust_provider_list, DeviceCertificateRecord, IdentityProviderRecord, IdentitySessionRecord,
    IdentityStartResult,
};
use crate::trust_policy::{
    trust_provider_policy_set, trust_provider_policy_set_tenant_template, TrustProviderPolicyV1,
};
use crate::types::{DocId, ObjectHash};
use crate::vault::{vault_init, vault_open, vault_paths, vault_save};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

static ACTIVE_JOBS: OnceLock<Mutex<BTreeSet<String>>> = OnceLock::new();

#[derive(Debug, Clone)]
pub struct VaultSummary {
    pub vault_id: String,
    pub vault_slug: String,
}

#[derive(Debug, Clone)]
pub struct SearchHit {
    pub doc_id: String,
    pub score: f64,
    pub snippet: String,
}

#[derive(Debug, Clone)]
pub struct EventItem {
    pub event_id: i64,
    pub ts_ms: i64,
    pub event_type: String,
}

#[derive(Debug, Clone)]
pub struct IngestInboxStartResult {
    pub job_id: String,
    pub doc_id: String,
}

#[derive(Debug, Clone)]
pub struct VaultEncryptionStatus {
    pub enabled: bool,
    pub mode: String,
    pub key_reference: Option<String>,
    pub kdf_algorithm: String,
    pub objects_total: i64,
    pub objects_encrypted: i64,
}

#[derive(Debug, Clone)]
pub struct VaultEncryptionMigrateResult {
    pub status: VaultEncryptionStatus,
    pub migrated_objects: i64,
    pub already_encrypted_objects: i64,
    pub event_id: i64,
}

#[derive(Debug, Clone)]
pub struct VaultRecoveryStatus {
    pub vault_id: String,
    pub encryption_enabled: bool,
    pub last_bundle_path: Option<String>,
}

#[derive(Debug, Clone)]
pub struct VaultRecoveryGenerateResult {
    pub bundle_path: PathBuf,
    pub recovery_phrase: String,
    pub manifest: RecoveryManifestV2,
}

#[derive(Debug, Clone)]
pub struct VaultRecoveryVerifyResult {
    pub manifest: RecoveryManifestV2,
}

#[derive(Debug, Clone)]
pub struct VaultRecoveryEscrowStatus {
    pub enabled: bool,
    pub provider: String,
    pub provider_available: bool,
    pub updated_at_ms: Option<i64>,
    pub details_json: String,
}

#[derive(Debug, Clone)]
pub struct VaultRecoveryEscrowProviderItem {
    pub provider: String,
    pub priority: i64,
    pub config_ref: String,
    pub enabled: bool,
    pub provider_available: bool,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone)]
pub struct VaultRecoveryEscrowRotateAllItem {
    pub provider: String,
    pub bundle_path: PathBuf,
    pub recovery_phrase: String,
    pub manifest: RecoveryManifestV2,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone)]
pub struct VaultRecoveryEscrowRotateAllResult {
    pub rotated: Vec<VaultRecoveryEscrowRotateAllItem>,
}

#[derive(Debug, Clone)]
pub struct VaultRecoveryEscrowRotateResult {
    pub status: VaultRecoveryEscrowStatus,
    pub bundle_path: PathBuf,
    pub recovery_phrase: String,
    pub manifest: RecoveryManifestV2,
}

#[derive(Debug, Clone)]
pub struct VaultRecoveryEscrowRestoreResult {
    pub status: VaultRecoveryEscrowStatus,
    pub bundle_path: PathBuf,
    pub restored_bytes: i64,
    pub manifest: RecoveryManifestV2,
}

#[derive(Debug, Clone)]
pub struct VaultDbLockStatus {
    pub db_encryption_enabled: bool,
    pub unlocked: bool,
    pub mode: String,
    pub key_reference: Option<String>,
    pub state: String,
}

#[derive(Debug, Clone)]
pub struct VaultDbEncryptStatus {
    pub enabled: bool,
    pub mode: String,
    pub key_reference: Option<String>,
    pub unlocked: bool,
    pub state: String,
}

#[derive(Debug, Clone)]
pub struct VaultDbEncryptMigrateResult {
    pub status: VaultDbEncryptStatus,
    pub outcome: String,
    pub event_id: i64,
}

#[derive(Debug, Clone)]
pub struct TrustDeviceEnrollResult {
    pub device: TrustedDeviceRecord,
    pub certificate: DeviceCertificateRecord,
}

#[derive(Debug, Clone)]
pub struct TrustDeviceEnrollSigningKeyResult {
    pub device: TrustedDeviceRecord,
    pub certificate: DeviceCertificateRecord,
    pub signing_key: SyncSigningKeyStatus,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct SyncSigningKeyRecoveryGuidance {
    pub reason: String,
    pub summary: String,
    pub command: String,
    pub private_key_recoverable: bool,
}

#[derive(Debug, Clone)]
pub struct TrustDeviceSigningKeyStatusResult {
    pub signing_key: Option<SyncSigningKeyStatus>,
    pub recovery_guidance: Option<SyncSigningKeyRecoveryGuidance>,
}

#[derive(Debug, Clone)]
pub struct TrustDeviceSigningKeyDeleteResult {
    pub deleted: bool,
    pub signing_key: Option<SyncSigningKeyStatus>,
    pub recovery_guidance: Option<SyncSigningKeyRecoveryGuidance>,
}

#[derive(Debug, Clone)]
pub struct TrustDeviceSigningKeyRotateResult {
    pub old_signing_key: SyncSigningKeyStatus,
    pub device: TrustedDeviceRecord,
    pub certificate: DeviceCertificateRecord,
    pub signing_key: SyncSigningKeyStatus,
}

struct SyncSigningSeed([u8; 32]);

impl Drop for SyncSigningSeed {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

fn jobs_set() -> &'static Mutex<BTreeSet<String>> {
    ACTIVE_JOBS.get_or_init(|| Mutex::new(BTreeSet::new()))
}

fn recovery_state_file(vault_path: &Path) -> PathBuf {
    vault_path.join(".kc_recovery_last_path")
}

fn write_recovery_state_file(vault_path: &Path, bundle_path: &Path) -> AppResult<()> {
    fs::write(
        recovery_state_file(vault_path),
        bundle_path.display().to_string(),
    )
    .map_err(|e| {
        AppError::new(
            "KC_RECOVERY_BUNDLE_INVALID",
            "recovery",
            "failed writing recovery state marker",
            false,
            serde_json::json!({ "error": e.to_string(), "vault_path": vault_path }),
        )
    })
}

fn read_recovery_state_file(vault_path: &Path) -> Option<String> {
    let path = recovery_state_file(vault_path);
    let Ok(value) = fs::read_to_string(path) else {
        return None;
    };
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[derive(Debug, Clone)]
struct RecoveryEscrowConfigRow {
    provider_id: String,
    enabled: bool,
    descriptor_json: String,
    updated_at_ms: i64,
}

#[derive(Debug, Clone)]
struct RecoveryEscrowProviderConfigRowV3 {
    provider_id: String,
    provider_priority: i64,
    config_ref: String,
    enabled: bool,
    updated_at_ms: i64,
}

fn read_recovery_escrow_config(
    conn: &rusqlite::Connection,
) -> AppResult<Option<RecoveryEscrowConfigRow>> {
    let mut stmt = conn
        .prepare(
            "SELECT provider_id, enabled, descriptor_json, updated_at_ms
             FROM recovery_escrow_configs
             ORDER BY updated_at_ms DESC, provider_id DESC
             LIMIT 1",
        )
        .map_err(|e| {
            AppError::new(
                "KC_RECOVERY_ESCROW_UNAVAILABLE",
                "recovery",
                "failed preparing escrow config query",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;
    let mut rows = stmt.query([]).map_err(|e| {
        AppError::new(
            "KC_RECOVERY_ESCROW_UNAVAILABLE",
            "recovery",
            "failed querying escrow config",
            false,
            serde_json::json!({ "error": e.to_string() }),
        )
    })?;
    let Some(row) = rows.next().map_err(|e| {
        AppError::new(
            "KC_RECOVERY_ESCROW_UNAVAILABLE",
            "recovery",
            "failed reading escrow config row",
            false,
            serde_json::json!({ "error": e.to_string() }),
        )
    })?
    else {
        return Ok(None);
    };

    Ok(Some(RecoveryEscrowConfigRow {
        provider_id: row.get::<_, String>(0).map_err(|e| {
            AppError::new(
                "KC_RECOVERY_ESCROW_UNAVAILABLE",
                "recovery",
                "failed decoding escrow provider_id",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?,
        enabled: row.get::<_, i64>(1).map(|v| v != 0).map_err(|e| {
            AppError::new(
                "KC_RECOVERY_ESCROW_UNAVAILABLE",
                "recovery",
                "failed decoding escrow enabled flag",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?,
        descriptor_json: row.get::<_, String>(2).map_err(|e| {
            AppError::new(
                "KC_RECOVERY_ESCROW_UNAVAILABLE",
                "recovery",
                "failed decoding escrow descriptor_json",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?,
        updated_at_ms: row.get::<_, i64>(3).map_err(|e| {
            AppError::new(
                "KC_RECOVERY_ESCROW_UNAVAILABLE",
                "recovery",
                "failed decoding escrow updated_at_ms",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?,
    }))
}

fn upsert_recovery_escrow_config(
    conn: &rusqlite::Connection,
    provider_id: &str,
    enabled: bool,
    descriptor_json: &str,
    updated_at_ms: i64,
) -> AppResult<()> {
    conn.execute(
        "INSERT INTO recovery_escrow_configs (provider_id, enabled, descriptor_json, updated_at_ms)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(provider_id)
         DO UPDATE SET
           enabled = excluded.enabled,
           descriptor_json = excluded.descriptor_json,
           updated_at_ms = excluded.updated_at_ms",
        rusqlite::params![
            provider_id,
            if enabled { 1 } else { 0 },
            descriptor_json,
            updated_at_ms
        ],
    )
    .map_err(|e| {
        AppError::new(
            "KC_RECOVERY_ESCROW_WRITE_FAILED",
            "recovery",
            "failed upserting recovery escrow config",
            false,
            serde_json::json!({ "error": e.to_string(), "provider": provider_id }),
        )
    })?;
    Ok(())
}

fn upsert_recovery_escrow_provider_config_v3(
    conn: &rusqlite::Connection,
    provider_id: &str,
    config_ref: &str,
    enabled: bool,
    updated_at_ms: i64,
) -> AppResult<()> {
    let normalized_provider_id = provider_id.trim().to_ascii_lowercase();
    let priority = provider_priority(&normalized_provider_id);
    conn.execute(
        "INSERT INTO recovery_escrow_provider_configs(
            provider_id,
            provider_priority,
            config_ref,
            enabled,
            updated_at_ms
         )
         VALUES(
           ?1,
           ?2,
           ?3,
           ?4,
           ?5
         )
         ON CONFLICT(provider_id)
         DO UPDATE SET
           provider_priority = excluded.provider_priority,
           config_ref = excluded.config_ref,
           enabled = excluded.enabled,
           updated_at_ms = excluded.updated_at_ms",
        rusqlite::params![
            normalized_provider_id,
            priority,
            config_ref,
            if enabled { 1 } else { 0 },
            updated_at_ms
        ],
    )
    .map_err(|e| {
        AppError::new(
            "KC_RECOVERY_ESCROW_WRITE_FAILED",
            "recovery",
            "failed upserting v3 recovery escrow provider config",
            false,
            serde_json::json!({ "error": e.to_string(), "provider": normalized_provider_id }),
        )
    })?;
    Ok(())
}

fn list_recovery_escrow_provider_configs_v3(
    conn: &rusqlite::Connection,
) -> AppResult<Vec<RecoveryEscrowProviderConfigRowV3>> {
    let mut stmt = conn
        .prepare(
            "SELECT provider_id, provider_priority, config_ref, enabled, updated_at_ms
             FROM recovery_escrow_provider_configs
             ORDER BY provider_priority ASC, provider_id ASC",
        )
        .map_err(|e| {
            AppError::new(
                "KC_RECOVERY_ESCROW_UNAVAILABLE",
                "recovery",
                "failed preparing v3 recovery escrow provider config query",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;
    let rows = stmt
        .query_map([], |row| {
            Ok(RecoveryEscrowProviderConfigRowV3 {
                provider_id: row.get(0)?,
                provider_priority: row.get(1)?,
                config_ref: row.get(2)?,
                enabled: row.get::<_, i64>(3)? != 0,
                updated_at_ms: row.get(4)?,
            })
        })
        .map_err(|e| {
            AppError::new(
                "KC_RECOVERY_ESCROW_UNAVAILABLE",
                "recovery",
                "failed querying v3 recovery escrow provider configs",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| {
            AppError::new(
                "KC_RECOVERY_ESCROW_UNAVAILABLE",
                "recovery",
                "failed decoding v3 recovery escrow provider config row",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?);
    }
    Ok(out)
}

fn append_recovery_escrow_event(
    conn: &rusqlite::Connection,
    provider_id: &str,
    action: &str,
    ts_ms: i64,
    details: &serde_json::Value,
) -> AppResult<()> {
    let details_json = serde_json::to_string(details).map_err(|e| {
        AppError::new(
            "KC_RECOVERY_ESCROW_WRITE_FAILED",
            "recovery",
            "failed serializing recovery escrow event details",
            false,
            serde_json::json!({ "error": e.to_string(), "provider": provider_id, "action": action }),
        )
    })?;
    conn.execute(
        "INSERT INTO recovery_escrow_events (provider_id, action, ts_ms, details_json)
         VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![provider_id, action, ts_ms, details_json],
    )
    .map_err(|e| {
        AppError::new(
            "KC_RECOVERY_ESCROW_WRITE_FAILED",
            "recovery",
            "failed appending recovery escrow event",
            false,
            serde_json::json!({ "error": e.to_string(), "provider": provider_id, "action": action }),
        )
    })?;
    Ok(())
}

fn resolve_recovery_escrow_provider(
    provider_id: &str,
    vault_path: &Path,
    vault_id: &str,
) -> AppResult<Box<dyn RecoveryEscrowProvider>> {
    let normalized_provider_id = provider_id.trim().to_ascii_lowercase();
    match normalized_provider_id.as_str() {
        "aws" => {
            let region = std::env::var("KC_RECOVERY_ESCROW_AWS_REGION")
                .ok()
                .filter(|v| !v.trim().is_empty())
                .unwrap_or_else(|| "us-east-1".to_string());
            let kms_key_id = std::env::var("KC_RECOVERY_ESCROW_AWS_KMS_KEY_ID")
                .ok()
                .filter(|v| !v.trim().is_empty())
                .unwrap_or_default();
            let secret_prefix = std::env::var("KC_RECOVERY_ESCROW_AWS_SECRET_PREFIX")
                .ok()
                .filter(|v| !v.trim().is_empty())
                .unwrap_or_else(|| format!("kc/recovery/{vault_id}"));
            Ok(Box::new(AwsRecoveryEscrowProvider::new(
                AwsRecoveryEscrowConfig {
                    region,
                    kms_key_id,
                    secret_prefix,
                },
            )))
        }
        "gcp" => {
            let project_id = std::env::var("KC_RECOVERY_ESCROW_GCP_PROJECT_ID")
                .ok()
                .filter(|v| !v.trim().is_empty())
                .unwrap_or_else(|| "kc-local".to_string());
            let location = std::env::var("KC_RECOVERY_ESCROW_GCP_LOCATION")
                .ok()
                .filter(|v| !v.trim().is_empty())
                .unwrap_or_else(|| "global".to_string());
            let key_ring = std::env::var("KC_RECOVERY_ESCROW_GCP_KEY_RING")
                .ok()
                .filter(|v| !v.trim().is_empty())
                .unwrap_or_else(|| "knowledgecore".to_string());
            let key_name = std::env::var("KC_RECOVERY_ESCROW_GCP_KEY_NAME")
                .ok()
                .filter(|v| !v.trim().is_empty())
                .unwrap_or_else(|| "recovery".to_string());
            let secret_prefix = std::env::var("KC_RECOVERY_ESCROW_GCP_SECRET_PREFIX")
                .ok()
                .filter(|v| !v.trim().is_empty())
                .unwrap_or_else(|| format!("kc/recovery/{vault_id}"));
            Ok(Box::new(GcpRecoveryEscrowProvider::new(
                GcpRecoveryEscrowConfig {
                    project_id,
                    location,
                    key_ring,
                    key_name,
                    secret_prefix,
                },
            )))
        }
        "azure" => {
            let key_vault_url = std::env::var("KC_RECOVERY_ESCROW_AZURE_KEY_VAULT_URL")
                .ok()
                .filter(|v| !v.trim().is_empty())
                .unwrap_or_else(|| "https://knowledgecore-local.vault.azure.net".to_string());
            let key_name = std::env::var("KC_RECOVERY_ESCROW_AZURE_KEY_NAME")
                .ok()
                .filter(|v| !v.trim().is_empty())
                .unwrap_or_else(|| "recovery".to_string());
            let secret_prefix = std::env::var("KC_RECOVERY_ESCROW_AZURE_SECRET_PREFIX")
                .ok()
                .filter(|v| !v.trim().is_empty())
                .unwrap_or_else(|| format!("kc/recovery/{vault_id}"));
            Ok(Box::new(AzureRecoveryEscrowProvider::new(
                AzureRecoveryEscrowConfig {
                    key_vault_url,
                    key_name,
                    secret_prefix,
                },
            )))
        }
        "hsm" => {
            let cluster = std::env::var("KC_RECOVERY_ESCROW_HSM_CLUSTER")
                .ok()
                .filter(|v| !v.trim().is_empty())
                .unwrap_or_else(|| "kc-local-hsm".to_string());
            let key_slot = std::env::var("KC_RECOVERY_ESCROW_HSM_KEY_SLOT")
                .ok()
                .filter(|v| !v.trim().is_empty())
                .unwrap_or_else(|| "slot-0".to_string());
            let secret_prefix = std::env::var("KC_RECOVERY_ESCROW_HSM_SECRET_PREFIX")
                .ok()
                .filter(|v| !v.trim().is_empty())
                .unwrap_or_else(|| format!("kc/recovery/{vault_id}"));
            Ok(Box::new(HsmRecoveryEscrowProvider::new(
                HsmRecoveryEscrowConfig {
                    cluster,
                    key_slot,
                    secret_prefix,
                },
            )))
        }
        "private_kms" => {
            let endpoint = std::env::var("KC_RECOVERY_ESCROW_PRIVATE_KMS_ENDPOINT")
                .ok()
                .filter(|v| !v.trim().is_empty())
                .unwrap_or_else(|| "https://private-kms.local".to_string());
            let key_alias = std::env::var("KC_RECOVERY_ESCROW_PRIVATE_KMS_KEY_ALIAS")
                .ok()
                .filter(|v| !v.trim().is_empty())
                .unwrap_or_else(|| "recovery".to_string());
            let tenant = std::env::var("KC_RECOVERY_ESCROW_PRIVATE_KMS_TENANT")
                .ok()
                .filter(|v| !v.trim().is_empty())
                .unwrap_or_else(|| "default".to_string());
            let secret_prefix = std::env::var("KC_RECOVERY_ESCROW_PRIVATE_KMS_SECRET_PREFIX")
                .ok()
                .filter(|v| !v.trim().is_empty())
                .unwrap_or_else(|| format!("kc/recovery/{vault_id}"));
            Ok(Box::new(PrivateKmsRecoveryEscrowProvider::new(
                PrivateKmsRecoveryEscrowConfig {
                    endpoint,
                    key_alias,
                    tenant,
                    secret_prefix,
                },
            )))
        }
        "local" => Ok(Box::new(LocalRecoveryEscrowProvider::new(
            vault_path.join("recovery-escrow-local"),
        ))),
        _ => Err(AppError::new(
            "KC_RECOVERY_ESCROW_PROVIDER_UNSUPPORTED",
            "recovery",
            "unsupported recovery escrow provider",
            false,
            serde_json::json!({
                "provider": normalized_provider_id,
                "supported": supported_provider_ids()
            }),
        )),
    }
}

fn recovery_escrow_status_from_config(
    vault_path: &Path,
    vault_id: &str,
    config: Option<RecoveryEscrowConfigRow>,
) -> AppResult<VaultRecoveryEscrowStatus> {
    let Some(config) = config else {
        return Ok(VaultRecoveryEscrowStatus {
            enabled: false,
            provider: "none".to_string(),
            provider_available: false,
            updated_at_ms: None,
            details_json: "{}".to_string(),
        });
    };
    let provider = resolve_recovery_escrow_provider(&config.provider_id, vault_path, vault_id)?;
    let status = provider.status()?;
    Ok(VaultRecoveryEscrowStatus {
        enabled: config.enabled,
        provider: config.provider_id,
        provider_available: status.available,
        updated_at_ms: Some(config.updated_at_ms),
        details_json: config.descriptor_json,
    })
}

fn recovery_escrow_provider_item_from_row(
    vault_path: &Path,
    vault_id: &str,
    row: &RecoveryEscrowProviderConfigRowV3,
) -> AppResult<VaultRecoveryEscrowProviderItem> {
    let provider = resolve_recovery_escrow_provider(&row.provider_id, vault_path, vault_id)?;
    let status = provider.status()?;
    Ok(VaultRecoveryEscrowProviderItem {
        provider: row.provider_id.clone(),
        priority: row.provider_priority,
        config_ref: row.config_ref.clone(),
        enabled: row.enabled,
        provider_available: status.available,
        updated_at_ms: row.updated_at_ms,
    })
}

fn mime_for_path(path: &Path) -> String {
    match path
        .extension()
        .and_then(|x| x.to_str())
        .unwrap_or_default()
    {
        "md" => "text/markdown".to_string(),
        "html" | "htm" => "text/html".to_string(),
        "pdf" => "application/pdf".to_string(),
        "txt" => "text/plain".to_string(),
        _ => "application/octet-stream".to_string(),
    }
}

fn object_store_without_passphrase(
    vault: &crate::vault::VaultJsonV2,
    vault_path: &Path,
) -> AppResult<ObjectStore> {
    if vault.encryption_enabled() {
        return Err(AppError::new(
            "KC_ENCRYPTION_REQUIRED",
            "encryption",
            "vault is encrypted; provide passphrase-enabled command path",
            false,
            serde_json::json!({
                "vault_path": vault_path,
                "hint": "use vault encrypt migrate/status flows"
            }),
        ));
    }
    Ok(ObjectStore::new(vault_paths(vault_path).objects_dir))
}

pub fn vault_init_service(vault_path: &Path, vault_slug: &str, now_ms: i64) -> AppResult<String> {
    let vault = vault_init(vault_path, vault_slug, now_ms)?;
    Ok(vault.vault_id)
}

pub fn vault_open_service(vault_path: &Path) -> AppResult<VaultSummary> {
    let vault = vault_open(vault_path)?;
    Ok(VaultSummary {
        vault_id: vault.vault_id,
        vault_slug: vault.vault_slug,
    })
}

pub fn document_lifecycle_mutate_service(
    vault_path: &Path,
    request: &DocumentLifecycleMutationRequestV1,
) -> AppResult<DocumentLifecycleEventV1> {
    let vault = vault_open(vault_path)?;
    let conn = open_db(&vault_path.join(vault.db.relative_path))?;
    append_document_lifecycle_event(&conn, request)
}

pub fn ingest_scan_folder_service(
    vault_path: &Path,
    scan_root: &Path,
    source_kind: &str,
    now_ms: i64,
) -> AppResult<i64> {
    let vault = vault_open(vault_path)?;
    let conn = open_db(&vault_path.join(vault.db.relative_path.clone()))?;
    let store = object_store_without_passphrase(&vault, vault_path)?;

    let mut files: Vec<PathBuf> = walkdir::WalkDir::new(scan_root)
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .map(|e| e.path().to_path_buf())
        .collect();
    files.sort();
    validate_scan_folder_files(scan_root, &files, scan_folder_limits())?;

    let mut ingested = 0i64;
    for path in files {
        let bytes = fs::read(&path).map_err(|e| {
            AppError::new(
                "KC_INGEST_FAILED",
                "ingest",
                "failed reading scan file",
                true,
                serde_json::json!({ "error": e.to_string(), "path": path }),
            )
        })?;
        ingest_bytes_with_limits(
            &conn,
            &store,
            IngestBytesReq {
                bytes: &bytes,
                mime: &mime_for_path(&path),
                source_kind,
                effective_ts_ms: now_ms,
                source_path: Some(&path.to_string_lossy()),
                now_ms,
            },
            ingest_single_file_limits(),
        )?;
        ingested += 1;
    }

    Ok(ingested)
}

pub fn ingest_inbox_start_service(
    vault_path: &Path,
    file_path: &Path,
    source_kind: &str,
    now_ms: i64,
) -> AppResult<IngestInboxStartResult> {
    let vault = vault_open(vault_path)?;
    let conn = open_db(&vault_path.join(vault.db.relative_path.clone()))?;
    let store = object_store_without_passphrase(&vault, vault_path)?;

    let bytes = fs::read(file_path).map_err(|e| {
        AppError::new(
            "KC_INGEST_FAILED",
            "ingest",
            "failed reading inbox file",
            true,
            serde_json::json!({ "error": e.to_string(), "path": file_path }),
        )
    })?;

    let out = ingest_bytes_with_limits(
        &conn,
        &store,
        IngestBytesReq {
            bytes: &bytes,
            mime: &mime_for_path(file_path),
            source_kind,
            effective_ts_ms: now_ms,
            source_path: Some(&file_path.to_string_lossy()),
            now_ms,
        },
        ingest_single_file_limits(),
    )?;

    let job_id = format!(
        "inbox:{}",
        blake3_hex_prefixed(format!("{}\n{}", out.doc_id.0, now_ms).as_bytes())
    );
    let mut jobs = jobs_set().lock().map_err(|_| {
        AppError::new(
            "KC_INTERNAL_ERROR",
            "jobs",
            "failed acquiring active jobs lock",
            true,
            serde_json::json!({}),
        )
    })?;
    jobs.insert(job_id.clone());

    Ok(IngestInboxStartResult {
        job_id,
        doc_id: out.doc_id.0,
    })
}

pub fn ingest_inbox_stop_service(job_id: &str) -> AppResult<bool> {
    let mut jobs = jobs_set().lock().map_err(|_| {
        AppError::new(
            "KC_INTERNAL_ERROR",
            "jobs",
            "failed acquiring active jobs lock",
            true,
            serde_json::json!({}),
        )
    })?;
    Ok(jobs.remove(job_id))
}

pub fn search_query_service(
    vault_path: &Path,
    query: &str,
    _now_ms: i64,
    limit: usize,
) -> AppResult<Vec<SearchHit>> {
    let vault = vault_open(vault_path)?;
    let conn = open_db(&vault_path.join(vault.db.relative_path.clone()))?;
    let store = object_store_without_passphrase(&vault, vault_path)?;
    let mut stmt = conn
        .prepare(
            "SELECT doc_id FROM canonical_text ORDER BY created_event_id DESC, doc_id ASC LIMIT ?1",
        )
        .map_err(|e| {
            AppError::new(
                "KC_RETRIEVAL_FAILED",
                "search",
                "failed preparing search query",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;
    let rows = stmt
        .query_map([limit as i64], |row| row.get::<_, String>(0))
        .map_err(|e| {
            AppError::new(
                "KC_RETRIEVAL_FAILED",
                "search",
                "failed running search query",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;

    let query_lower = query.to_lowercase();
    let mut hits = Vec::new();
    for row in rows {
        let doc_id = row.map_err(|e| {
            AppError::new(
                "KC_RETRIEVAL_FAILED",
                "search",
                "failed reading search row",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;
        let text = String::from_utf8(load_canonical_text(&conn, &store, &DocId(doc_id.clone()))?)
            .unwrap_or_default();
        if text.to_lowercase().contains(&query_lower) {
            hits.push(SearchHit {
                doc_id,
                score: 1.0,
                snippet: text.chars().take(120).collect(),
            });
        }
    }
    Ok(hits)
}

pub fn locator_resolve_service(vault_path: &Path, locator: &LocatorV1) -> AppResult<String> {
    let vault = vault_open(vault_path)?;
    let conn = open_db(&vault_path.join(vault.db.relative_path.clone()))?;
    let store = object_store_without_passphrase(&vault, vault_path)?;
    resolve_locator_strict(&conn, &store, locator)
}

pub fn export_bundle_service(
    vault_path: &Path,
    export_dir: &Path,
    include_vectors: bool,
    now_ms: i64,
) -> AppResult<PathBuf> {
    crate::export::export_bundle(
        vault_path,
        export_dir,
        &crate::export::ExportOptions {
            include_vectors,
            as_zip: false,
        },
        now_ms,
    )
}

pub fn events_list_service(vault_path: &Path, limit: i64) -> AppResult<Vec<EventItem>> {
    let vault = vault_open(vault_path)?;
    let conn = open_db(&vault_path.join(vault.db.relative_path))?;
    let mut stmt = conn
        .prepare("SELECT event_id, ts_ms, type FROM events ORDER BY event_id DESC LIMIT ?1")
        .map_err(|e| {
            AppError::new(
                "KC_DB_INTEGRITY_FAILED",
                "events",
                "failed preparing events query",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;
    let rows = stmt
        .query_map([limit.max(1)], |row| {
            Ok(EventItem {
                event_id: row.get(0)?,
                ts_ms: row.get(1)?,
                event_type: row.get(2)?,
            })
        })
        .map_err(|e| {
            AppError::new(
                "KC_DB_INTEGRITY_FAILED",
                "events",
                "failed querying events",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;

    let mut events = Vec::new();
    for row in rows {
        events.push(row.map_err(|e| {
            AppError::new(
                "KC_DB_INTEGRITY_FAILED",
                "events",
                "failed decoding event row",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?);
    }
    Ok(events)
}

pub fn jobs_list_service(_vault_path: &Path) -> AppResult<Vec<String>> {
    let jobs = jobs_set().lock().map_err(|_| {
        AppError::new(
            "KC_INTERNAL_ERROR",
            "jobs",
            "failed acquiring active jobs lock",
            true,
            serde_json::json!({}),
        )
    })?;
    Ok(jobs.iter().cloned().collect())
}

pub fn sync_status_service(
    vault_path: &Path,
    target_uri: &str,
) -> AppResult<crate::sync::SyncStatusV1> {
    let vault = vault_open(vault_path)?;
    let conn = open_db(&vault_path.join(vault.db.relative_path))?;
    crate::sync::sync_status_target(&conn, target_uri)
}

pub fn sync_auth_readiness_service(
    vault_path: &Path,
    target_uri: &str,
) -> AppResult<crate::sync::SyncAuthReadinessReportV1> {
    let vault = vault_open(vault_path)?;
    let conn = open_db(&vault_path.join(vault.db.relative_path))?;
    crate::sync::sync_auth_readiness_target(&conn, target_uri)
}

pub fn sync_push_service(
    vault_path: &Path,
    target_uri: &str,
    now_ms: i64,
) -> AppResult<crate::sync::SyncPushResultV1> {
    let vault = vault_open(vault_path)?;
    let conn = open_db(&vault_path.join(vault.db.relative_path))?;
    crate::sync::sync_push_target(&conn, vault_path, target_uri, now_ms)
}

pub fn sync_pull_service(
    vault_path: &Path,
    target_uri: &str,
    now_ms: i64,
    auto_merge_mode: Option<&str>,
    strict_auth: bool,
) -> AppResult<crate::sync::SyncPullResultV1> {
    let vault = vault_open(vault_path)?;
    let conn = open_db(&vault_path.join(vault.db.relative_path))?;
    crate::sync::sync_pull_target_with_mode(
        &conn,
        vault_path,
        target_uri,
        now_ms,
        auto_merge_mode,
        strict_auth,
    )
}

pub fn sync_merge_preview_service(
    vault_path: &Path,
    target_uri: &str,
    policy: Option<&str>,
    now_ms: i64,
) -> AppResult<crate::sync::SyncMergePreviewResultV1> {
    let vault = vault_open(vault_path)?;
    let conn = open_db(&vault_path.join(vault.db.relative_path))?;
    crate::sync::sync_merge_preview_target_with_policy(
        &conn, vault_path, target_uri, policy, now_ms,
    )
}

pub fn trust_identity_start_service(
    vault_path: &Path,
    provider_id: &str,
    now_ms: i64,
) -> AppResult<IdentityStartResult> {
    let vault = vault_open(vault_path)?;
    let conn = open_db(&vault_path.join(vault.db.relative_path))?;
    trust_identity_start(&conn, provider_id, now_ms)
}

pub fn trust_identity_complete_service(
    vault_path: &Path,
    provider_id: &str,
    auth_code: &str,
    now_ms: i64,
) -> AppResult<IdentitySessionRecord> {
    let vault = vault_open(vault_path)?;
    let conn = open_db(&vault_path.join(vault.db.relative_path))?;
    trust_identity_complete(&conn, provider_id, auth_code, now_ms)
}

pub fn trust_device_enroll_service(
    vault_path: &Path,
    device_label: &str,
    now_ms: i64,
) -> AppResult<TrustDeviceEnrollResult> {
    let vault = vault_open(vault_path)?;
    let conn = open_db(&vault_path.join(vault.db.relative_path))?;

    let created = trust_device_init(&conn, device_label, "trust_device_enroll", now_ms)?;
    let verified = trust_device_verify(
        &conn,
        &created.device_id,
        &created.fingerprint,
        "trust_device_enroll",
        now_ms + 1,
    )?;
    let certificate = trust_device_enroll(&conn, "default", &verified.device_id, now_ms + 2)?;

    Ok(TrustDeviceEnrollResult {
        device: verified,
        certificate,
    })
}

pub fn trust_device_enroll_signing_key_service(
    vault_path: &Path,
    device_label: &str,
    passphrase: &str,
    now_ms: i64,
) -> AppResult<TrustDeviceEnrollSigningKeyResult> {
    ensure_passphrase_not_empty(passphrase)?;
    let vault = vault_open(vault_path)?;
    let conn = open_db(&vault_path.join(vault.db.relative_path))?;

    let mut seed = SyncSigningSeed([0u8; 32]);
    getrandom::fill(&mut seed.0).map_err(|e| {
        AppError::new(
            "KC_SYNC_SIGNING_KEY_WRITE_FAILED",
            "sync_key_custody",
            "failed generating sync signing key seed",
            false,
            serde_json::json!({ "error": e.to_string() }),
        )
    })?;
    let created = trust_device_init_with_seed(
        &conn,
        device_label,
        "trust_device_enroll_signing_key",
        now_ms,
        &seed.0,
    )?;
    let verified = trust_device_verify(
        &conn,
        &created.device_id,
        &created.fingerprint,
        "trust_device_enroll_signing_key",
        now_ms + 1,
    )?;
    let certificate = trust_device_enroll(&conn, "default", &verified.device_id, now_ms + 2)?;
    let signing_key =
        store_sync_signing_seed(&conn, &verified.device_id, &seed.0, passphrase, now_ms + 3)?;

    Ok(TrustDeviceEnrollSigningKeyResult {
        device: verified,
        certificate,
        signing_key,
    })
}

pub fn trust_device_verify_chain_service(
    vault_path: &Path,
    device_id: &str,
    now_ms: i64,
) -> AppResult<DeviceCertificateRecord> {
    let vault = vault_open(vault_path)?;
    let conn = open_db(&vault_path.join(vault.db.relative_path))?;
    trust_device_verify_chain(&conn, device_id, now_ms)
}

fn sync_signing_key_recovery_guidance(
    device_id: &str,
    reason: &str,
) -> SyncSigningKeyRecoveryGuidance {
    SyncSigningKeyRecoveryGuidance {
        reason: reason.to_string(),
        summary: "local sync signing private-key custody is not recoverable; re-enroll a new local signing device after restoring or opening the vault".to_string(),
        command: format!(
            "trust device enroll-signing-key <vault_path> --device-label replacement-for-{device_id} --passphrase-env <env_var>; then republish affected sync targets"
        ),
        private_key_recoverable: false,
    }
}

pub fn trust_device_signing_key_status_service(
    vault_path: &Path,
    device_id: &str,
) -> AppResult<TrustDeviceSigningKeyStatusResult> {
    let vault = vault_open(vault_path)?;
    let conn = open_db(&vault_path.join(vault.db.relative_path))?;
    let signing_key = sync_signing_key_status(&conn, device_id)?;
    let recovery_guidance = signing_key
        .is_none()
        .then(|| sync_signing_key_recovery_guidance(device_id, "missing_or_retired"));
    Ok(TrustDeviceSigningKeyStatusResult {
        signing_key,
        recovery_guidance,
    })
}

pub fn trust_device_signing_key_delete_service(
    vault_path: &Path,
    device_id: &str,
    now_ms: i64,
) -> AppResult<TrustDeviceSigningKeyDeleteResult> {
    let vault = vault_open(vault_path)?;
    let conn = open_db(&vault_path.join(vault.db.relative_path))?;
    let signing_key = delete_sync_signing_key(&conn, device_id, now_ms)?;
    Ok(TrustDeviceSigningKeyDeleteResult {
        deleted: signing_key.is_some(),
        signing_key,
        recovery_guidance: Some(sync_signing_key_recovery_guidance(
            device_id,
            "deleted_or_missing",
        )),
    })
}

pub fn trust_device_signing_key_rotate_service(
    vault_path: &Path,
    old_device_id: &str,
    new_device_label: &str,
    passphrase: &str,
    now_ms: i64,
) -> AppResult<TrustDeviceSigningKeyRotateResult> {
    ensure_passphrase_not_empty(passphrase)?;
    let vault = vault_open(vault_path)?;
    let conn = open_db(&vault_path.join(vault.db.relative_path))?;

    if sync_signing_key_status(&conn, old_device_id)?.is_none() {
        return Err(AppError::new(
            "KC_SYNC_SIGNING_KEY_NOT_FOUND",
            "sync_key_custody",
            "active sync signing key custody row is required for rotation",
            false,
            serde_json::json!({ "device_id": old_device_id }),
        ));
    }

    let mut seed = SyncSigningSeed([0u8; 32]);
    getrandom::fill(&mut seed.0).map_err(|e| {
        AppError::new(
            "KC_SYNC_SIGNING_KEY_WRITE_FAILED",
            "sync_key_custody",
            "failed generating replacement sync signing key seed",
            false,
            serde_json::json!({ "error": e.to_string() }),
        )
    })?;
    let tx = conn.unchecked_transaction().map_err(|e| {
        AppError::new(
            "KC_SYNC_SIGNING_KEY_WRITE_FAILED",
            "sync_key_custody",
            "failed beginning sync signing key rotation transaction",
            false,
            serde_json::json!({ "error": e.to_string(), "device_id": old_device_id }),
        )
    })?;
    let created = trust_device_init_with_seed(
        &tx,
        new_device_label,
        "trust_device_signing_key_rotate",
        now_ms,
        &seed.0,
    )?;
    let verified = trust_device_verify(
        &tx,
        &created.device_id,
        &created.fingerprint,
        "trust_device_signing_key_rotate",
        now_ms + 1,
    )?;
    let certificate = trust_device_enroll(&tx, "default", &verified.device_id, now_ms + 2)?;
    let signing_key =
        store_sync_signing_seed(&tx, &verified.device_id, &seed.0, passphrase, now_ms + 3)?;
    let old_signing_key =
        rotate_sync_signing_key(&tx, old_device_id, now_ms + 4)?.ok_or_else(|| {
            AppError::new(
                "KC_SYNC_SIGNING_KEY_NOT_FOUND",
                "sync_key_custody",
                "sync signing key custody row disappeared during rotation",
                false,
                serde_json::json!({ "device_id": old_device_id }),
            )
        })?;
    tx.commit().map_err(|e| {
        AppError::new(
            "KC_SYNC_SIGNING_KEY_WRITE_FAILED",
            "sync_key_custody",
            "failed committing sync signing key rotation transaction",
            false,
            serde_json::json!({ "error": e.to_string(), "device_id": old_device_id }),
        )
    })?;

    Ok(TrustDeviceSigningKeyRotateResult {
        old_signing_key,
        device: verified,
        certificate,
        signing_key,
    })
}

pub fn trust_device_list_service(vault_path: &Path) -> AppResult<Vec<TrustedDeviceRecord>> {
    let vault = vault_open(vault_path)?;
    let conn = open_db(&vault_path.join(vault.db.relative_path))?;
    trust_device_list(&conn)
}

pub fn trust_provider_add_service(
    vault_path: &Path,
    provider_id: &str,
    issuer: &str,
    audience: &str,
    jwks_url: &str,
    now_ms: i64,
) -> AppResult<IdentityProviderRecord> {
    let vault = vault_open(vault_path)?;
    let conn = open_db(&vault_path.join(vault.db.relative_path))?;
    trust_provider_add(&conn, provider_id, issuer, audience, jwks_url, now_ms)
}

pub fn trust_provider_disable_service(
    vault_path: &Path,
    provider_id: &str,
    now_ms: i64,
) -> AppResult<IdentityProviderRecord> {
    let vault = vault_open(vault_path)?;
    let conn = open_db(&vault_path.join(vault.db.relative_path))?;
    trust_provider_disable(&conn, provider_id, now_ms)
}

pub fn trust_provider_list_service(vault_path: &Path) -> AppResult<Vec<IdentityProviderRecord>> {
    let vault = vault_open(vault_path)?;
    let conn = open_db(&vault_path.join(vault.db.relative_path))?;
    trust_provider_list(&conn)
}

pub fn trust_provider_discover_service(
    vault_path: &Path,
    issuer: &str,
    now_ms: i64,
) -> AppResult<IdentityProviderRecord> {
    let vault = vault_open(vault_path)?;
    let conn = open_db(&vault_path.join(vault.db.relative_path))?;
    discover_identity_provider(&conn, issuer, now_ms)
}

pub fn trust_provider_policy_set_service(
    vault_path: &Path,
    provider_id: &str,
    max_clock_skew_ms: i64,
    require_claims_json: &str,
    now_ms: i64,
) -> AppResult<TrustProviderPolicyV1> {
    let vault = vault_open(vault_path)?;
    let conn = open_db(&vault_path.join(vault.db.relative_path))?;
    trust_provider_policy_set(
        &conn,
        provider_id,
        max_clock_skew_ms,
        require_claims_json,
        now_ms,
    )
}

pub fn trust_provider_policy_set_tenant_template_service(
    vault_path: &Path,
    provider_ref: &str,
    tenant_id: &str,
    now_ms: i64,
) -> AppResult<TrustProviderPolicyV1> {
    let vault = vault_open(vault_path)?;
    let conn = open_db(&vault_path.join(vault.db.relative_path))?;

    let provider = if provider_ref.starts_with("https://") || provider_ref.starts_with("http://") {
        discover_identity_provider(&conn, provider_ref, now_ms)?
    } else {
        let providers = trust_provider_list(&conn)?;
        providers
            .into_iter()
            .find(|item| item.provider_id == provider_ref)
            .ok_or_else(|| {
                AppError::new(
                    "KC_TRUST_OIDC_PROVIDER_UNAVAILABLE",
                    "trust_identity",
                    "identity provider is not registered",
                    false,
                    serde_json::json!({ "provider_id": provider_ref }),
                )
            })?
    };

    trust_provider_policy_set_tenant_template(
        &conn,
        &provider.provider_id,
        &provider.issuer,
        &provider.audience,
        tenant_id,
        now_ms,
    )
}

pub fn lineage_query_service(
    vault_path: &Path,
    seed_doc_id: &str,
    depth: i64,
    now_ms: i64,
) -> AppResult<crate::lineage::LineageQueryResV1> {
    let vault = vault_open(vault_path)?;
    let conn = open_db(&vault_path.join(vault.db.relative_path))?;
    crate::lineage::query_lineage(&conn, seed_doc_id, depth, now_ms)
}

pub fn lineage_query_v2_service(
    vault_path: &Path,
    seed_doc_id: &str,
    depth: i64,
    now_ms: i64,
) -> AppResult<crate::lineage::LineageQueryResV2> {
    let vault = vault_open(vault_path)?;
    let conn = open_db(&vault_path.join(vault.db.relative_path))?;
    crate::lineage::query_lineage_v2(&conn, seed_doc_id, depth, now_ms)
}

pub struct LineageOverlayAddServiceReq<'a> {
    pub doc_id: &'a str,
    pub from_node_id: &'a str,
    pub to_node_id: &'a str,
    pub relation: &'a str,
    pub evidence: &'a str,
    pub lock_token: &'a str,
    pub created_at_ms: i64,
    pub created_by: Option<&'a str>,
}

pub fn lineage_overlay_add_service(
    vault_path: &Path,
    req: LineageOverlayAddServiceReq<'_>,
) -> AppResult<crate::lineage::LineageOverlayEntryV1> {
    let vault = vault_open(vault_path)?;
    let conn = open_db(&vault_path.join(vault.db.relative_path))?;
    crate::lineage::lineage_overlay_add(
        &conn,
        crate::lineage::LineageOverlayAddReq {
            doc_id: req.doc_id,
            from_node_id: req.from_node_id,
            to_node_id: req.to_node_id,
            relation: req.relation,
            evidence: req.evidence,
            lock_token: req.lock_token,
            created_at_ms: req.created_at_ms,
            created_by: req.created_by.unwrap_or("overlay"),
        },
    )
}

pub fn lineage_overlay_remove_service(
    vault_path: &Path,
    overlay_id: &str,
    lock_token: &str,
    now_ms: i64,
) -> AppResult<()> {
    let vault = vault_open(vault_path)?;
    let conn = open_db(&vault_path.join(vault.db.relative_path))?;
    crate::lineage::lineage_overlay_remove(&conn, overlay_id, lock_token, now_ms)
}

pub fn lineage_overlay_list_service(
    vault_path: &Path,
    doc_id: &str,
) -> AppResult<Vec<crate::lineage::LineageOverlayEntryV1>> {
    let vault = vault_open(vault_path)?;
    let conn = open_db(&vault_path.join(vault.db.relative_path))?;
    crate::lineage::lineage_overlay_list(&conn, doc_id)
}

pub fn lineage_lock_acquire_service(
    vault_path: &Path,
    doc_id: &str,
    owner: &str,
    now_ms: i64,
) -> AppResult<crate::lineage::LineageLockLeaseV1> {
    let vault = vault_open(vault_path)?;
    let conn = open_db(&vault_path.join(vault.db.relative_path))?;
    crate::lineage::lineage_lock_acquire(&conn, doc_id, owner, now_ms)
}

pub fn lineage_lock_release_service(vault_path: &Path, doc_id: &str, token: &str) -> AppResult<()> {
    let vault = vault_open(vault_path)?;
    let conn = open_db(&vault_path.join(vault.db.relative_path))?;
    crate::lineage::lineage_lock_release(&conn, doc_id, token)
}

pub fn lineage_lock_status_service(
    vault_path: &Path,
    doc_id: &str,
    now_ms: i64,
) -> AppResult<crate::lineage::LineageLockStatusV1> {
    let vault = vault_open(vault_path)?;
    let conn = open_db(&vault_path.join(vault.db.relative_path))?;
    crate::lineage::lineage_lock_status(&conn, doc_id, now_ms)
}

pub fn lineage_role_grant_service(
    vault_path: &Path,
    subject_id: &str,
    role_name: &str,
    granted_by: &str,
    now_ms: i64,
) -> AppResult<LineageRoleBindingV2> {
    let vault = vault_open(vault_path)?;
    let conn = open_db(&vault_path.join(vault.db.relative_path))?;
    lineage_role_grant(&conn, subject_id, role_name, granted_by, now_ms)
}

pub fn lineage_role_revoke_service(
    vault_path: &Path,
    subject_id: &str,
    role_name: &str,
) -> AppResult<()> {
    let vault = vault_open(vault_path)?;
    let conn = open_db(&vault_path.join(vault.db.relative_path))?;
    lineage_role_revoke(&conn, subject_id, role_name)
}

pub fn lineage_role_list_service(vault_path: &Path) -> AppResult<Vec<LineageRoleBindingV2>> {
    let vault = vault_open(vault_path)?;
    let conn = open_db(&vault_path.join(vault.db.relative_path))?;
    lineage_role_list(&conn)
}

pub fn lineage_lock_acquire_scope_service(
    vault_path: &Path,
    scope_kind: &str,
    scope_value: &str,
    owner: &str,
    now_ms: i64,
) -> AppResult<LineageScopeLockLeaseV2> {
    let vault = vault_open(vault_path)?;
    let conn = open_db(&vault_path.join(vault.db.relative_path))?;
    lineage_lock_acquire_scope(&conn, scope_kind, scope_value, owner, now_ms)
}

pub fn lineage_policy_add_service(
    vault_path: &Path,
    policy_name: &str,
    effect: &str,
    condition_json: &str,
    created_by: &str,
    now_ms: i64,
) -> AppResult<LineagePolicyV3> {
    let vault = vault_open(vault_path)?;
    let conn = open_db(&vault_path.join(vault.db.relative_path))?;
    lineage_policy_add(
        &conn,
        policy_name,
        effect,
        condition_json,
        created_by,
        now_ms,
    )
}

pub fn lineage_policy_bind_service(
    vault_path: &Path,
    subject_id: &str,
    policy_name: &str,
    bound_by: &str,
    now_ms: i64,
) -> AppResult<LineagePolicyBindingV3> {
    let vault = vault_open(vault_path)?;
    let conn = open_db(&vault_path.join(vault.db.relative_path))?;
    lineage_policy_bind(&conn, subject_id, policy_name, bound_by, now_ms)
}

pub fn lineage_policy_list_service(vault_path: &Path) -> AppResult<Vec<LineagePolicyBindingV3>> {
    let vault = vault_open(vault_path)?;
    let conn = open_db(&vault_path.join(vault.db.relative_path))?;
    lineage_policy_list(&conn)
}

fn load_object_hashes(conn: &rusqlite::Connection) -> AppResult<Vec<ObjectHash>> {
    let mut stmt = conn
        .prepare("SELECT object_hash FROM objects ORDER BY object_hash ASC")
        .map_err(|e| {
            AppError::new(
                "KC_DB_INTEGRITY_FAILED",
                "encryption",
                "failed preparing object hash query",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|e| {
            AppError::new(
                "KC_DB_INTEGRITY_FAILED",
                "encryption",
                "failed querying object hashes",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;

    let mut hashes = Vec::new();
    for row in rows {
        hashes.push(ObjectHash(row.map_err(|e| {
            AppError::new(
                "KC_DB_INTEGRITY_FAILED",
                "encryption",
                "failed reading object hash row",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?));
    }
    Ok(hashes)
}

fn encryption_status_for_vault(
    vault_path: &Path,
    vault: &crate::vault::VaultJsonV2,
) -> AppResult<VaultEncryptionStatus> {
    let conn = open_db(&vault_path.join(vault.db.relative_path.clone()))?;
    let hashes = load_object_hashes(&conn)?;
    let store = ObjectStore::new(vault_paths(vault_path).objects_dir);
    let mut encrypted = 0i64;
    for hash in &hashes {
        let raw = store.raw_bytes(hash)?;
        if is_encrypted_payload(&raw) {
            encrypted += 1;
        }
    }

    Ok(VaultEncryptionStatus {
        enabled: vault.encryption.enabled,
        mode: vault.encryption.mode.clone(),
        key_reference: vault.encryption.key_reference.clone(),
        kdf_algorithm: vault.encryption.kdf.algorithm.clone(),
        objects_total: hashes.len() as i64,
        objects_encrypted: encrypted,
    })
}

pub fn vault_encryption_status_service(vault_path: &Path) -> AppResult<VaultEncryptionStatus> {
    let vault = vault_open(vault_path)?;
    encryption_status_for_vault(vault_path, &vault)
}

pub fn vault_encryption_enable_service(
    vault_path: &Path,
    passphrase: &str,
) -> AppResult<VaultEncryptionStatus> {
    let mut vault = vault_open(vault_path)?;
    if !vault.encryption.enabled {
        vault.encryption.enabled = true;
        if vault.encryption.key_reference.is_none() {
            vault.encryption.key_reference = Some(format!("vault:{}", vault.vault_id));
        }
    }
    let _ctx = vault.object_store_encryption_context(Some(passphrase))?;
    vault_save(vault_path, &vault)?;
    encryption_status_for_vault(vault_path, &vault)
}

pub fn vault_encryption_migrate_service(
    vault_path: &Path,
    passphrase: &str,
    now_ms: i64,
) -> AppResult<VaultEncryptionMigrateResult> {
    let vault = vault_open(vault_path)?;
    if !vault.encryption.enabled {
        return Err(AppError::new(
            "KC_ENCRYPTION_REQUIRED",
            "encryption",
            "vault encryption must be enabled before migrate",
            false,
            serde_json::json!({ "vault_path": vault_path }),
        ));
    }
    let enc_ctx = vault
        .object_store_encryption_context(Some(passphrase))?
        .ok_or_else(|| {
            AppError::new(
                "KC_ENCRYPTION_REQUIRED",
                "encryption",
                "encryption context unavailable",
                false,
                serde_json::json!({}),
            )
        })?;

    let conn = open_db(&vault_path.join(vault.db.relative_path.clone()))?;
    let hashes = load_object_hashes(&conn)?;
    let plain_store = ObjectStore::new(vault_paths(vault_path).objects_dir.clone());
    let encrypted_store =
        ObjectStore::with_encryption(vault_paths(vault_path).objects_dir, enc_ctx);

    let mut migrated = 0i64;
    let mut already_encrypted = 0i64;
    for hash in hashes {
        let raw = plain_store.raw_bytes(&hash)?;
        if is_encrypted_payload(&raw) {
            let _ = encrypted_store.get_bytes(&hash)?;
            already_encrypted += 1;
            continue;
        }

        let plaintext = plain_store.get_bytes(&hash)?;
        encrypted_store.rewrite_plaintext_for_hash(&hash, &plaintext)?;
        migrated += 1;
    }

    let event = append_event(
        &conn,
        now_ms,
        "vault.encryption.migrate",
        &serde_json::json!({
            "migrated_objects": migrated,
            "already_encrypted_objects": already_encrypted,
            "mode": vault.encryption.mode,
            "kdf_algorithm": vault.encryption.kdf.algorithm,
        }),
    )
    .map_err(|e| {
        AppError::new(
            "KC_ENCRYPTION_MIGRATION_FAILED",
            "encryption",
            "failed appending migration event",
            false,
            serde_json::json!({ "error": e.code, "message": e.message }),
        )
    })?;

    let status = encryption_status_for_vault(vault_path, &vault)?;
    Ok(VaultEncryptionMigrateResult {
        status,
        migrated_objects: migrated,
        already_encrypted_objects: already_encrypted,
        event_id: event.event_id,
    })
}

pub fn vault_recovery_status_service(vault_path: &Path) -> AppResult<VaultRecoveryStatus> {
    let vault = vault_open(vault_path)?;
    Ok(VaultRecoveryStatus {
        vault_id: vault.vault_id,
        encryption_enabled: vault.encryption.enabled,
        last_bundle_path: read_recovery_state_file(vault_path),
    })
}

pub fn vault_recovery_generate_service(
    vault_path: &Path,
    output_dir: &Path,
    passphrase: &str,
    now_ms: i64,
) -> AppResult<VaultRecoveryGenerateResult> {
    let vault = vault_open(vault_path)?;
    let generated = generate_recovery_bundle(&vault.vault_id, output_dir, passphrase, now_ms)?;
    write_recovery_state_file(vault_path, &generated.bundle_path)?;
    Ok(VaultRecoveryGenerateResult {
        bundle_path: generated.bundle_path,
        recovery_phrase: generated.recovery_phrase,
        manifest: generated.manifest,
    })
}

pub fn vault_recovery_verify_service(
    vault_path: &Path,
    bundle_path: &Path,
    phrase: &str,
) -> AppResult<VaultRecoveryVerifyResult> {
    let vault = vault_open(vault_path)?;
    let manifest = verify_recovery_bundle(&vault.vault_id, bundle_path, phrase)?;
    Ok(VaultRecoveryVerifyResult { manifest })
}

pub fn vault_recovery_escrow_status_service(
    vault_path: &Path,
) -> AppResult<VaultRecoveryEscrowStatus> {
    let vault = vault_open(vault_path)?;
    let conn = open_db(&vault_path.join(vault.db.relative_path.clone()))?;
    let config = read_recovery_escrow_config(&conn)?;
    recovery_escrow_status_from_config(vault_path, &vault.vault_id, config)
}

pub fn vault_recovery_escrow_enable_service(
    vault_path: &Path,
    provider_id: &str,
    now_ms: i64,
) -> AppResult<VaultRecoveryEscrowStatus> {
    let vault = vault_open(vault_path)?;
    let conn = open_db(&vault_path.join(vault.db.relative_path.clone()))?;
    let provider = resolve_recovery_escrow_provider(provider_id, vault_path, &vault.vault_id)?;
    let provider_status = provider.status()?;
    if !provider_status.configured {
        return Err(AppError::new(
            "KC_RECOVERY_ESCROW_AUTH_FAILED",
            "recovery",
            "recovery escrow provider is not configured",
            false,
            serde_json::json!({ "provider": provider_id, "details": provider_status.details_json }),
        ));
    }

    let descriptor_json = serde_json::to_string(&serde_json::json!({
        "provider_status": {
            "configured": provider_status.configured,
            "available": provider_status.available,
            "details_json": provider_status.details_json,
        }
    }))
    .map_err(|e| {
        AppError::new(
            "KC_RECOVERY_ESCROW_WRITE_FAILED",
            "recovery",
            "failed serializing escrow config descriptor",
            false,
            serde_json::json!({ "error": e.to_string(), "provider": provider_id }),
        )
    })?;
    upsert_recovery_escrow_config(&conn, provider_id, true, &descriptor_json, now_ms)?;
    append_recovery_escrow_event(
        &conn,
        provider_id,
        "enable",
        now_ms,
        &serde_json::json!({
            "available": provider_status.available,
            "configured": provider_status.configured
        }),
    )?;
    vault_recovery_escrow_status_service(vault_path)
}

pub fn vault_recovery_escrow_provider_add_service(
    vault_path: &Path,
    provider_id: &str,
    config_ref: &str,
    now_ms: i64,
) -> AppResult<VaultRecoveryEscrowProviderItem> {
    if config_ref.trim().is_empty() {
        return Err(AppError::new(
            "KC_RECOVERY_ESCROW_WRITE_FAILED",
            "recovery",
            "config_ref is required",
            false,
            serde_json::json!({ "provider": provider_id }),
        ));
    }

    let vault = vault_open(vault_path)?;
    let conn = open_db(&vault_path.join(vault.db.relative_path.clone()))?;
    let provider = resolve_recovery_escrow_provider(provider_id, vault_path, &vault.vault_id)?;
    let provider_status = provider.status()?;
    if !provider_status.configured {
        return Err(AppError::new(
            "KC_RECOVERY_ESCROW_AUTH_FAILED",
            "recovery",
            "recovery escrow provider is not configured",
            false,
            serde_json::json!({ "provider": provider_id, "details": provider_status.details_json }),
        ));
    }

    upsert_recovery_escrow_provider_config_v3(&conn, provider_id, config_ref, true, now_ms)?;
    // Keep existing v2 config table in sync for compatibility surfaces.
    upsert_recovery_escrow_config(
        &conn,
        provider_id,
        true,
        &serde_json::to_string(&serde_json::json!({
            "config_ref": config_ref
        }))
        .map_err(|e| {
            AppError::new(
                "KC_RECOVERY_ESCROW_WRITE_FAILED",
                "recovery",
                "failed serializing recovery escrow provider config_ref",
                false,
                serde_json::json!({ "error": e.to_string(), "provider": provider_id }),
            )
        })?,
        now_ms,
    )?;
    append_recovery_escrow_event(
        &conn,
        provider_id,
        "provider_add",
        now_ms,
        &serde_json::json!({
            "config_ref": config_ref,
            "available": provider_status.available
        }),
    )?;

    let mut items = vault_recovery_escrow_provider_list_service(vault_path)?;
    items.retain(|item| item.provider == provider_id);
    items.into_iter().next().ok_or_else(|| {
        AppError::new(
            "KC_RECOVERY_ESCROW_WRITE_FAILED",
            "recovery",
            "provider config missing after add",
            false,
            serde_json::json!({ "provider": provider_id }),
        )
    })
}

pub fn vault_recovery_escrow_provider_list_service(
    vault_path: &Path,
) -> AppResult<Vec<VaultRecoveryEscrowProviderItem>> {
    let vault = vault_open(vault_path)?;
    let conn = open_db(&vault_path.join(vault.db.relative_path.clone()))?;
    let rows = list_recovery_escrow_provider_configs_v3(&conn)?;
    let mut out = Vec::new();
    for row in rows {
        out.push(recovery_escrow_provider_item_from_row(
            vault_path,
            &vault.vault_id,
            &row,
        )?);
    }
    Ok(out)
}

pub fn vault_recovery_escrow_rotate_all_service(
    vault_path: &Path,
    passphrase: &str,
    now_ms: i64,
) -> AppResult<VaultRecoveryEscrowRotateAllResult> {
    if passphrase.trim().is_empty() {
        return Err(AppError::new(
            "KC_ENCRYPTION_REQUIRED",
            "recovery",
            "passphrase is required for escrow rotate-all",
            false,
            serde_json::json!({}),
        ));
    }

    let vault = vault_open(vault_path)?;
    let conn = open_db(&vault_path.join(vault.db.relative_path.clone()))?;
    let providers = list_recovery_escrow_provider_configs_v3(&conn)?
        .into_iter()
        .filter(|row| row.enabled)
        .collect::<Vec<_>>();
    if providers.is_empty() {
        return Err(AppError::new(
            "KC_RECOVERY_ESCROW_ROTATION_CONFLICT",
            "recovery",
            "no enabled escrow providers configured for rotate-all",
            false,
            serde_json::json!({}),
        ));
    }

    let output_root = vault_path.join("recovery-escrow-bundles");
    let mut rotated = Vec::new();
    for (idx, provider_cfg) in providers.into_iter().enumerate() {
        let provider_now_ms = now_ms + idx as i64;
        let provider = resolve_recovery_escrow_provider(
            &provider_cfg.provider_id,
            vault_path,
            &vault.vault_id,
        )?;
        let provider_status = provider.status()?;
        if !provider_status.available {
            return Err(AppError::new(
                "KC_RECOVERY_ESCROW_ROTATION_CONFLICT",
                "recovery",
                "escrow provider unavailable during rotate-all",
                false,
                serde_json::json!({
                    "provider": provider_cfg.provider_id,
                    "details": provider_status.details_json
                }),
            ));
        }

        let provider_output = output_root.join(&provider_cfg.provider_id);
        let generated = generate_recovery_bundle(
            &vault.vault_id,
            &provider_output,
            passphrase,
            provider_now_ms,
        )?;
        let blob_path = generated.bundle_path.join("key_blob.enc");
        let key_blob = fs::read(&blob_path).map_err(|e| {
            AppError::new(
                "KC_RECOVERY_ESCROW_WRITE_FAILED",
                "recovery",
                "failed reading generated recovery key blob for rotate-all",
                false,
                serde_json::json!({ "error": e.to_string(), "path": blob_path }),
            )
        })?;
        let descriptor = provider.write(RecoveryEscrowWriteRequest {
            vault_id: &vault.vault_id,
            payload_hash: &generated.manifest.payload_hash,
            key_blob: &key_blob,
            now_ms: provider_now_ms,
        })?;
        let mut manifest = generated.manifest.clone();
        manifest.escrow = Some(descriptor.clone());
        write_recovery_manifest(&generated.bundle_path, &manifest)?;

        let descriptor_json = serde_json::to_string(&descriptor).map_err(|e| {
            AppError::new(
                "KC_RECOVERY_ESCROW_WRITE_FAILED",
                "recovery",
                "failed serializing rotate-all descriptor",
                false,
                serde_json::json!({ "error": e.to_string(), "provider": provider_cfg.provider_id }),
            )
        })?;
        upsert_recovery_escrow_config(
            &conn,
            &provider_cfg.provider_id,
            true,
            &descriptor_json,
            provider_now_ms,
        )?;
        upsert_recovery_escrow_provider_config_v3(
            &conn,
            &provider_cfg.provider_id,
            &provider_cfg.config_ref,
            true,
            provider_now_ms,
        )?;
        append_recovery_escrow_event(
            &conn,
            &provider_cfg.provider_id,
            "rotate_all",
            provider_now_ms,
            &serde_json::json!({
                "bundle_path": generated.bundle_path,
                "payload_hash": manifest.payload_hash
            }),
        )?;
        write_recovery_state_file(vault_path, &generated.bundle_path)?;

        rotated.push(VaultRecoveryEscrowRotateAllItem {
            provider: provider_cfg.provider_id,
            bundle_path: generated.bundle_path,
            recovery_phrase: generated.recovery_phrase,
            manifest,
            updated_at_ms: provider_now_ms,
        });
    }

    Ok(VaultRecoveryEscrowRotateAllResult { rotated })
}

pub fn vault_recovery_escrow_rotate_service(
    vault_path: &Path,
    passphrase: &str,
    now_ms: i64,
) -> AppResult<VaultRecoveryEscrowRotateResult> {
    if passphrase.is_empty() {
        return Err(AppError::new(
            "KC_ENCRYPTION_REQUIRED",
            "recovery",
            "passphrase is required for escrow rotation",
            false,
            serde_json::json!({}),
        ));
    }
    let vault = vault_open(vault_path)?;
    let conn = open_db(&vault_path.join(vault.db.relative_path.clone()))?;
    let config = read_recovery_escrow_config(&conn)?.ok_or_else(|| {
        AppError::new(
            "KC_RECOVERY_ESCROW_UNAVAILABLE",
            "recovery",
            "recovery escrow provider is not enabled",
            false,
            serde_json::json!({}),
        )
    })?;
    if !config.enabled {
        return Err(AppError::new(
            "KC_RECOVERY_ESCROW_UNAVAILABLE",
            "recovery",
            "recovery escrow provider is disabled",
            false,
            serde_json::json!({ "provider": config.provider_id }),
        ));
    }
    let provider =
        resolve_recovery_escrow_provider(&config.provider_id, vault_path, &vault.vault_id)?;
    let provider_status = provider.status()?;
    if !provider_status.available {
        return Err(AppError::new(
            "KC_RECOVERY_ESCROW_UNAVAILABLE",
            "recovery",
            "recovery escrow provider is unavailable",
            false,
            serde_json::json!({ "provider": config.provider_id, "details": provider_status.details_json }),
        ));
    }

    let output_dir = vault_path.join("recovery-escrow-bundles");
    let generated = generate_recovery_bundle(&vault.vault_id, &output_dir, passphrase, now_ms)?;
    let blob_path = generated.bundle_path.join("key_blob.enc");
    let blob = fs::read(&blob_path).map_err(|e| {
        AppError::new(
            "KC_RECOVERY_ESCROW_WRITE_FAILED",
            "recovery",
            "failed reading generated recovery key blob for escrow write",
            false,
            serde_json::json!({ "error": e.to_string(), "path": blob_path }),
        )
    })?;
    let descriptor = provider.write(RecoveryEscrowWriteRequest {
        vault_id: &vault.vault_id,
        payload_hash: &generated.manifest.payload_hash,
        key_blob: &blob,
        now_ms,
    })?;
    let mut manifest = generated.manifest.clone();
    manifest.escrow = Some(descriptor);
    write_recovery_manifest(&generated.bundle_path, &manifest)?;
    write_recovery_state_file(vault_path, &generated.bundle_path)?;

    let descriptor_json = serde_json::to_string(&serde_json::json!({
        "provider_status": {
            "configured": provider_status.configured,
            "available": provider_status.available,
            "details_json": provider_status.details_json,
        },
        "last_rotate_manifest_payload_hash": manifest.payload_hash
    }))
    .map_err(|e| {
        AppError::new(
            "KC_RECOVERY_ESCROW_WRITE_FAILED",
            "recovery",
            "failed serializing escrow rotation descriptor",
            false,
            serde_json::json!({ "error": e.to_string(), "provider": config.provider_id }),
        )
    })?;
    upsert_recovery_escrow_config(&conn, &config.provider_id, true, &descriptor_json, now_ms)?;
    append_recovery_escrow_event(
        &conn,
        &config.provider_id,
        "rotate",
        now_ms,
        &serde_json::json!({
            "bundle_path": generated.bundle_path,
            "payload_hash": manifest.payload_hash
        }),
    )?;

    let status = vault_recovery_escrow_status_service(vault_path)?;
    Ok(VaultRecoveryEscrowRotateResult {
        status,
        bundle_path: generated.bundle_path,
        recovery_phrase: generated.recovery_phrase,
        manifest,
    })
}

pub fn vault_recovery_escrow_restore_service(
    vault_path: &Path,
    bundle_path: &Path,
    now_ms: i64,
) -> AppResult<VaultRecoveryEscrowRestoreResult> {
    let vault = vault_open(vault_path)?;
    let conn = open_db(&vault_path.join(vault.db.relative_path.clone()))?;
    let config = read_recovery_escrow_config(&conn)?.ok_or_else(|| {
        AppError::new(
            "KC_RECOVERY_ESCROW_UNAVAILABLE",
            "recovery",
            "recovery escrow provider is not enabled",
            false,
            serde_json::json!({}),
        )
    })?;
    if !config.enabled {
        return Err(AppError::new(
            "KC_RECOVERY_ESCROW_UNAVAILABLE",
            "recovery",
            "recovery escrow provider is disabled",
            false,
            serde_json::json!({ "provider": config.provider_id }),
        ));
    }

    let manifest = read_recovery_manifest(bundle_path)?;
    let descriptor = manifest.escrow.clone().ok_or_else(|| {
        AppError::new(
            "KC_RECOVERY_ESCROW_RESTORE_FAILED",
            "recovery",
            "recovery manifest has no escrow descriptor",
            false,
            serde_json::json!({ "bundle_path": bundle_path }),
        )
    })?;
    let provider =
        resolve_recovery_escrow_provider(&descriptor.provider, vault_path, &vault.vault_id)?;
    let bytes = provider.read(RecoveryEscrowReadRequest {
        descriptor: &descriptor,
        expected_payload_hash: &manifest.payload_hash,
    })?;

    let blob_path = bundle_path.join("key_blob.enc");
    fs::write(&blob_path, &bytes).map_err(|e| {
        AppError::new(
            "KC_RECOVERY_ESCROW_RESTORE_FAILED",
            "recovery",
            "failed writing restored escrow payload to bundle",
            false,
            serde_json::json!({ "error": e.to_string(), "path": blob_path }),
        )
    })?;

    append_recovery_escrow_event(
        &conn,
        &config.provider_id,
        "restore",
        now_ms,
        &serde_json::json!({
            "bundle_path": bundle_path,
            "payload_hash": manifest.payload_hash
        }),
    )?;

    let status = vault_recovery_escrow_status_service(vault_path)?;
    Ok(VaultRecoveryEscrowRestoreResult {
        status,
        bundle_path: bundle_path.to_path_buf(),
        restored_bytes: bytes.len() as i64,
        manifest,
    })
}

fn db_lock_status_for_vault(
    vault_path: &Path,
    vault: &crate::vault::VaultJsonV2,
) -> AppResult<VaultDbLockStatus> {
    let db_path = vault_path.join(vault.db.relative_path.clone());
    let state = derive_db_encryption_state(vault_path, &db_path, vault.db_encryption.enabled)?;
    let unlocked = if vault.db_encryption.enabled {
        db_is_unlocked(vault_path)
            || std::env::var("KC_VAULT_DB_PASSPHRASE").is_ok()
            || std::env::var("KC_VAULT_PASSPHRASE").is_ok()
    } else {
        true
    };
    Ok(VaultDbLockStatus {
        db_encryption_enabled: vault.db_encryption.enabled,
        unlocked,
        mode: vault.db_encryption.mode.clone(),
        key_reference: vault.db_encryption.key_reference.clone(),
        state: state.as_str().to_string(),
    })
}

fn db_encrypt_status_for_vault(
    vault_path: &Path,
    vault: &crate::vault::VaultJsonV2,
) -> AppResult<VaultDbEncryptStatus> {
    let lock_status = db_lock_status_for_vault(vault_path, vault)?;
    Ok(VaultDbEncryptStatus {
        enabled: vault.db_encryption.enabled,
        mode: vault.db_encryption.mode.clone(),
        key_reference: vault.db_encryption.key_reference.clone(),
        unlocked: lock_status.unlocked,
        state: lock_status.state,
    })
}

fn ensure_passphrase_not_empty(passphrase: &str) -> AppResult<()> {
    if passphrase.is_empty() {
        return Err(AppError::new(
            "KC_DB_KEY_INVALID",
            "db",
            "db passphrase must not be empty",
            false,
            serde_json::json!({}),
        ));
    }
    Ok(())
}

pub fn vault_lock_status_service(vault_path: &Path) -> AppResult<VaultDbLockStatus> {
    let vault = vault_open(vault_path)?;
    db_lock_status_for_vault(vault_path, &vault)
}

pub fn vault_unlock_service(vault_path: &Path, passphrase: &str) -> AppResult<VaultDbLockStatus> {
    ensure_passphrase_not_empty(passphrase)?;
    let vault = vault_open(vault_path)?;
    if !vault.db_encryption.enabled {
        return db_lock_status_for_vault(vault_path, &vault);
    }
    let db_path = vault_path.join(vault.db.relative_path.clone());
    db_unlock(vault_path, &db_path, passphrase)?;
    db_lock_status_for_vault(vault_path, &vault)
}

pub fn vault_lock_service(vault_path: &Path) -> AppResult<VaultDbLockStatus> {
    let vault = vault_open(vault_path)?;
    db_lock(vault_path)?;
    db_lock_status_for_vault(vault_path, &vault)
}

pub fn vault_db_encrypt_status_service(vault_path: &Path) -> AppResult<VaultDbEncryptStatus> {
    let vault = vault_open(vault_path)?;
    db_encrypt_status_for_vault(vault_path, &vault)
}

pub fn vault_db_encrypt_enable_service(
    vault_path: &Path,
    passphrase: &str,
) -> AppResult<VaultDbEncryptStatus> {
    ensure_passphrase_not_empty(passphrase)?;
    let mut vault = vault_open(vault_path)?;
    if !vault.db_encryption.enabled {
        vault.db_encryption.enabled = true;
        if vault.db_encryption.key_reference.is_none() {
            vault.db_encryption.key_reference = Some(format!("vaultdb:{}", vault.vault_id));
        }
        vault_save(vault_path, &vault)?;
    }
    let db_path = vault_path.join(vault.db.relative_path.clone());
    db_unlock(vault_path, &db_path, passphrase)?;
    db_encrypt_status_for_vault(vault_path, &vault)
}

pub fn vault_db_encrypt_migrate_service(
    vault_path: &Path,
    passphrase: &str,
    now_ms: i64,
) -> AppResult<VaultDbEncryptMigrateResult> {
    ensure_passphrase_not_empty(passphrase)?;
    let vault = vault_open(vault_path)?;
    if !vault.db_encryption.enabled {
        return Err(AppError::new(
            "KC_DB_LOCKED",
            "db",
            "db encryption must be enabled before migrate",
            false,
            serde_json::json!({ "vault_path": vault_path }),
        ));
    }
    let db_path = vault_path.join(vault.db.relative_path.clone());
    let migration_outcome = migrate_db_to_sqlcipher(&db_path, passphrase)?;
    db_unlock(vault_path, &db_path, passphrase)?;
    let conn = open_db(&db_path)?;
    let event = append_event(
        &conn,
        now_ms,
        "vault.db_encryption.migrate",
        &serde_json::json!({
            "outcome": match migration_outcome {
                DbMigrationOutcome::Migrated => "migrated",
                DbMigrationOutcome::AlreadyEncrypted => "already_encrypted",
            },
            "mode": vault.db_encryption.mode,
            "kdf_algorithm": vault.db_encryption.kdf.algorithm,
        }),
    )
    .map_err(|e| {
        AppError::new(
            "KC_DB_ENCRYPTION_MIGRATION_FAILED",
            "db",
            "failed appending db encryption migration event",
            false,
            serde_json::json!({ "error": e.code, "message": e.message }),
        )
    })?;
    Ok(VaultDbEncryptMigrateResult {
        status: db_encrypt_status_for_vault(vault_path, &vault)?,
        outcome: match migration_outcome {
            DbMigrationOutcome::Migrated => "migrated".to_string(),
            DbMigrationOutcome::AlreadyEncrypted => "already_encrypted".to_string(),
        },
        event_id: event.event_id,
    })
}

pub fn rpc_health_snapshot_service(vault_path: &Path) -> AppResult<serde_json::Value> {
    let vault = vault_open(vault_path)?;
    let conn = open_db(&vault_path.join(vault.db.relative_path.clone()))?;
    let db_bytes = fs::read(vault_path.join(vault.db.relative_path)).map_err(|e| {
        AppError::new(
            "KC_RPC_FAILED",
            "rpc",
            "failed reading db for health snapshot",
            false,
            serde_json::json!({ "error": e.to_string() }),
        )
    })?;
    let event_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
        .unwrap_or(0);
    Ok(serde_json::json!({
        "vaultId": vault.vault_id,
        "dbHash": blake3_hex_prefixed(&db_bytes),
        "eventCount": event_count
    }))
}
