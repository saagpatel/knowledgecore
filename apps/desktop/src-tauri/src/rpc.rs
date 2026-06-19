use kc_ask::{AskRequest, AskService, RetrievedOnlyAskService};
use kc_cli::verifier::verify_bundle;
use kc_core::app_error::AppError;
use kc_core::locator::LocatorV1;
use kc_core::rpc_service;
use serde::de::Error as DeError;
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone, PartialEq)]
pub enum RpcResponse<T> {
    Ok { data: T },
    Err { error: AppError },
}

impl<T> RpcResponse<T> {
    pub fn ok(data: T) -> Self {
        Self::Ok { data }
    }

    pub fn err(error: AppError) -> Self {
        Self::Err { error }
    }
}

impl<T: Serialize> Serialize for RpcResponse<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(2))?;
        match self {
            RpcResponse::Ok { data } => {
                map.serialize_entry("ok", &true)?;
                map.serialize_entry("data", data)?;
            }
            RpcResponse::Err { error } => {
                map.serialize_entry("ok", &false)?;
                map.serialize_entry("error", error)?;
            }
        }
        map.end()
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RpcOkWire<T> {
    ok: bool,
    data: T,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RpcErrWire {
    ok: bool,
    error: AppError,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RpcWire<T> {
    Ok(RpcOkWire<T>),
    Err(RpcErrWire),
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for RpcResponse<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match RpcWire::<T>::deserialize(deserializer)? {
            RpcWire::Ok(wire) => {
                if !wire.ok {
                    return Err(D::Error::custom("rpc ok response must set ok=true"));
                }
                Ok(RpcResponse::Ok { data: wire.data })
            }
            RpcWire::Err(wire) => {
                if wire.ok {
                    return Err(D::Error::custom("rpc error response must set ok=false"));
                }
                Ok(RpcResponse::Err { error: wire.error })
            }
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultInitReq {
    pub vault_path: String,
    pub vault_slug: String,
    pub now_ms: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultInitRes {
    pub vault_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultOpenReq {
    pub vault_path: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultOpenRes {
    pub vault_id: String,
    pub vault_slug: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustIdentityStartReq {
    pub vault_path: String,
    pub provider: String,
    pub now_ms: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrustIdentityStartRes {
    pub provider_id: String,
    pub state: String,
    pub authorization_url: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustIdentityCompleteReq {
    pub vault_path: String,
    pub provider: String,
    pub code: String,
    pub now_ms: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrustIdentityCompleteRes {
    pub session_id: String,
    pub provider_id: String,
    pub subject: String,
    pub expires_at_ms: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustDeviceEnrollReq {
    pub vault_path: String,
    pub device_label: String,
    pub now_ms: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrustDeviceEnrollRes {
    pub device_id: String,
    pub label: String,
    pub fingerprint: String,
    pub cert_id: String,
    pub cert_chain_hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustDeviceEnrollSigningKeyReq {
    pub vault_path: String,
    pub device_label: String,
    pub passphrase: String,
    pub now_ms: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrustDeviceSigningKeyRes {
    pub device_id: String,
    pub public_key: String,
    pub signature_alg: String,
    pub key_reference: String,
    pub created_at_ms: i64,
    pub rotated_at_ms: Option<i64>,
    pub deleted_at_ms: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrustDeviceEnrollSigningKeyRes {
    pub device_id: String,
    pub label: String,
    pub fingerprint: String,
    pub cert_id: String,
    pub cert_chain_hash: String,
    pub signing_key: TrustDeviceSigningKeyRes,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustDeviceVerifyChainReq {
    pub vault_path: String,
    pub device_id: String,
    pub now_ms: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrustDeviceVerifyChainRes {
    pub cert_id: String,
    pub device_id: String,
    pub provider_id: String,
    pub subject: String,
    pub cert_chain_hash: String,
    pub verified_at_ms: Option<i64>,
    pub expires_at_ms: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustDeviceListReq {
    pub vault_path: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrustDeviceListItemRes {
    pub device_id: String,
    pub label: String,
    pub fingerprint: String,
    pub verified_at_ms: Option<i64>,
    pub created_at_ms: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrustDeviceListRes {
    pub devices: Vec<TrustDeviceListItemRes>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustDeviceSigningKeyStatusReq {
    pub vault_path: String,
    pub device_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrustDeviceSigningKeyStatusRes {
    pub signing_key: Option<TrustDeviceSigningKeyRes>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustDeviceSigningKeyDeleteReq {
    pub vault_path: String,
    pub device_id: String,
    pub now_ms: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrustDeviceSigningKeyDeleteRes {
    pub deleted: bool,
    pub signing_key: Option<TrustDeviceSigningKeyRes>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustDeviceSigningKeyRotateReq {
    pub vault_path: String,
    pub old_device_id: String,
    pub new_device_label: String,
    pub passphrase: String,
    pub now_ms: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrustDeviceSigningKeyRotateRes {
    pub old_signing_key: TrustDeviceSigningKeyRes,
    pub device_id: String,
    pub label: String,
    pub fingerprint: String,
    pub cert_id: String,
    pub cert_chain_hash: String,
    pub signing_key: TrustDeviceSigningKeyRes,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustProviderAddReq {
    pub vault_path: String,
    pub provider_id: String,
    pub issuer: String,
    pub aud: String,
    pub jwks: String,
    pub now_ms: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrustProviderRes {
    pub provider_id: String,
    pub issuer: String,
    pub audience: String,
    pub jwks_url: String,
    pub enabled: bool,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustProviderDisableReq {
    pub vault_path: String,
    pub provider_id: String,
    pub now_ms: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustProviderListReq {
    pub vault_path: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustProviderDiscoverReq {
    pub vault_path: String,
    pub issuer: String,
    pub now_ms: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrustProviderListRes {
    pub providers: Vec<TrustProviderRes>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustPolicySetReq {
    pub vault_path: String,
    pub provider_id: String,
    pub max_clock_skew_ms: i64,
    pub require_claims_json: String,
    pub now_ms: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustPolicySetTenantTemplateReq {
    pub vault_path: String,
    pub provider: String,
    pub tenant_id: String,
    pub now_ms: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrustPolicySetRes {
    pub provider_id: String,
    pub max_clock_skew_ms: i64,
    pub require_claims_json: String,
    pub updated_at_ms: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultLockStatusReq {
    pub vault_path: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VaultLockStatusRes {
    pub db_encryption_enabled: bool,
    pub unlocked: bool,
    pub mode: String,
    pub key_reference: Option<String>,
    pub state: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultUnlockReq {
    pub vault_path: String,
    pub passphrase: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultUnlockRes {
    pub status: VaultLockStatusRes,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultLockReq {
    pub vault_path: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultLockRes {
    pub status: VaultLockStatusRes,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultEncryptionStatusReq {
    pub vault_path: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VaultEncryptionStatusRes {
    pub enabled: bool,
    pub mode: String,
    pub key_reference: Option<String>,
    pub kdf_algorithm: String,
    pub objects_total: i64,
    pub objects_encrypted: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultEncryptionEnableReq {
    pub vault_path: String,
    pub passphrase: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultEncryptionEnableRes {
    pub status: VaultEncryptionStatusRes,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultEncryptionMigrateReq {
    pub vault_path: String,
    pub passphrase: String,
    pub now_ms: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultEncryptionMigrateRes {
    pub status: VaultEncryptionStatusRes,
    pub migrated_objects: i64,
    pub already_encrypted_objects: i64,
    pub event_id: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultRecoveryStatusReq {
    pub vault_path: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultRecoveryStatusRes {
    pub vault_id: String,
    pub encryption_enabled: bool,
    pub last_bundle_path: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultRecoveryGenerateReq {
    pub vault_path: String,
    pub output_dir: String,
    pub passphrase: String,
    pub now_ms: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RecoveryManifestRes {
    pub schema_version: i64,
    pub vault_id: String,
    pub created_at_ms: i64,
    pub phrase_checksum: String,
    pub payload_hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultRecoveryGenerateRes {
    pub bundle_path: String,
    pub recovery_phrase: String,
    pub manifest: RecoveryManifestRes,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultRecoveryVerifyReq {
    pub vault_path: String,
    pub bundle_path: String,
    pub recovery_phrase: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultRecoveryVerifyRes {
    pub manifest: RecoveryManifestRes,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultRecoveryEscrowStatusReq {
    pub vault_path: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultRecoveryEscrowStatusRes {
    pub enabled: bool,
    pub provider: String,
    pub provider_available: bool,
    pub updated_at_ms: Option<i64>,
    pub details_json: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultRecoveryEscrowEnableReq {
    pub vault_path: String,
    pub provider: String,
    pub now_ms: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultRecoveryEscrowEnableRes {
    pub status: VaultRecoveryEscrowStatusRes,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultRecoveryEscrowRotateReq {
    pub vault_path: String,
    pub passphrase: String,
    pub now_ms: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultRecoveryEscrowRotateRes {
    pub status: VaultRecoveryEscrowStatusRes,
    pub bundle_path: String,
    pub recovery_phrase: String,
    pub manifest: RecoveryManifestRes,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultRecoveryEscrowRestoreReq {
    pub vault_path: String,
    pub bundle_path: String,
    pub now_ms: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultRecoveryEscrowRestoreRes {
    pub status: VaultRecoveryEscrowStatusRes,
    pub bundle_path: String,
    pub restored_bytes: i64,
    pub manifest: RecoveryManifestRes,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultRecoveryEscrowProviderAddReq {
    pub vault_path: String,
    pub provider: String,
    pub config_ref: String,
    pub now_ms: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultRecoveryEscrowProviderListReq {
    pub vault_path: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultRecoveryEscrowProviderItemRes {
    pub provider: String,
    pub priority: i64,
    pub config_ref: String,
    pub enabled: bool,
    pub provider_available: bool,
    pub updated_at_ms: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultRecoveryEscrowProviderAddRes {
    pub provider: VaultRecoveryEscrowProviderItemRes,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultRecoveryEscrowProviderListRes {
    pub providers: Vec<VaultRecoveryEscrowProviderItemRes>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultRecoveryEscrowRotateAllReq {
    pub vault_path: String,
    pub passphrase: String,
    pub now_ms: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultRecoveryEscrowRotateAllItemRes {
    pub provider: String,
    pub bundle_path: String,
    pub recovery_phrase: String,
    pub manifest: RecoveryManifestRes,
    pub updated_at_ms: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultRecoveryEscrowRotateAllRes {
    pub rotated: Vec<VaultRecoveryEscrowRotateAllItemRes>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngestScanFolderReq {
    pub vault_path: String,
    pub scan_root: String,
    pub source_kind: String,
    pub now_ms: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IngestScanFolderRes {
    pub ingested: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngestInboxStartReq {
    pub vault_path: String,
    pub file_path: String,
    pub source_kind: String,
    pub now_ms: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IngestInboxStartRes {
    pub job_id: String,
    pub doc_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngestInboxStopReq {
    pub vault_path: String,
    pub job_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IngestInboxStopRes {
    pub stopped: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchQueryReq {
    pub vault_path: String,
    pub query: String,
    pub now_ms: i64,
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SearchHit {
    pub doc_id: String,
    pub score: f64,
    pub snippet: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SearchQueryRes {
    pub hits: Vec<SearchHit>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocatorResolveReq {
    pub vault_path: String,
    pub locator: LocatorV1,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LocatorResolveRes {
    pub text: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportBundleReq {
    pub vault_path: String,
    pub export_dir: String,
    pub include_vectors: bool,
    pub now_ms: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExportBundleRes {
    pub bundle_path: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyBundleReq {
    pub bundle_path: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyBundleRes {
    pub exit_code: i64,
    pub report: kc_cli::verifier::VerifyReportV1,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AskQuestionReq {
    pub vault_path: String,
    pub question: String,
    pub now_ms: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AskQuestionRes {
    pub answer_text: String,
    pub trace_path: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventsListReq {
    pub vault_path: String,
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EventItem {
    pub event_id: i64,
    pub ts_ms: i64,
    pub event_type: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EventsListRes {
    pub events: Vec<EventItem>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobsListReq {
    pub vault_path: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JobsListRes {
    pub jobs: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncStatusReq {
    pub vault_path: String,
    pub target_path: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SyncHeadRes {
    pub schema_version: i64,
    pub snapshot_id: String,
    pub manifest_hash: String,
    pub created_at_ms: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SyncStatusRes {
    pub target_path: String,
    pub remote_head: Option<SyncHeadRes>,
    pub seen_remote_snapshot_id: Option<String>,
    pub last_applied_manifest_hash: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncAuthReadinessReq {
    pub vault_path: String,
    pub target_path: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SyncAuthReadinessRes {
    pub report_version: i64,
    pub target_path: String,
    pub classification: String,
    pub strict_ready: bool,
    pub depends_on_legacy_fallback: bool,
    pub remediation: Option<String>,
    pub remote_head: Option<SyncHeadRes>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncPushReq {
    pub vault_path: String,
    pub target_path: String,
    pub now_ms: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SyncPushRes {
    pub snapshot_id: String,
    pub manifest_hash: String,
    pub remote_head: SyncHeadRes,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncPullReq {
    pub vault_path: String,
    pub target_path: String,
    #[serde(default)]
    pub auto_merge: Option<String>,
    pub now_ms: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SyncPullRes {
    pub snapshot_id: String,
    pub manifest_hash: String,
    pub remote_head: SyncHeadRes,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncMergePreviewReq {
    pub vault_path: String,
    pub target_path: String,
    #[serde(default)]
    pub policy: Option<String>,
    pub now_ms: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SyncMergeChangeSetRes {
    pub object_hashes: Vec<String>,
    pub lineage_overlay_ids: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SyncMergePreviewReportRes {
    pub schema_version: i64,
    pub merge_policy: String,
    pub safe: bool,
    pub generated_at_ms: i64,
    pub local: SyncMergeChangeSetRes,
    pub remote: SyncMergeChangeSetRes,
    pub overlap: SyncMergeChangeSetRes,
    pub reasons: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_trace: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SyncMergePreviewRes {
    pub target_path: String,
    pub seen_remote_snapshot_id: Option<String>,
    pub remote_snapshot_id: String,
    pub report: SyncMergePreviewReportRes,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LineageQueryReq {
    pub vault_path: String,
    pub seed_doc_id: String,
    pub depth: i64,
    pub now_ms: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LineageNodeRes {
    pub node_id: String,
    pub kind: String,
    pub label: String,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LineageEdgeRes {
    pub from_node_id: String,
    pub to_node_id: String,
    pub relation: String,
    pub evidence: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LineageQueryRes {
    pub schema_version: i64,
    pub seed_doc_id: String,
    pub depth: i64,
    pub generated_at_ms: i64,
    pub nodes: Vec<LineageNodeRes>,
    pub edges: Vec<LineageEdgeRes>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LineageQueryV2Req {
    pub vault_path: String,
    pub seed_doc_id: String,
    pub depth: i64,
    pub now_ms: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LineageEdgeV2Res {
    pub from_node_id: String,
    pub to_node_id: String,
    pub relation: String,
    pub evidence: String,
    pub origin: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LineageQueryV2Res {
    pub schema_version: i64,
    pub seed_doc_id: String,
    pub depth: i64,
    pub generated_at_ms: i64,
    pub nodes: Vec<LineageNodeRes>,
    pub edges: Vec<LineageEdgeV2Res>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LineageOverlayEntryRes {
    pub overlay_id: String,
    pub doc_id: String,
    pub from_node_id: String,
    pub to_node_id: String,
    pub relation: String,
    pub evidence: String,
    pub created_at_ms: i64,
    pub created_by: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LineageOverlayAddReq {
    pub vault_path: String,
    pub doc_id: String,
    pub from_node_id: String,
    pub to_node_id: String,
    pub relation: String,
    pub evidence: String,
    pub lock_token: String,
    pub created_at_ms: i64,
    pub created_by: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LineageOverlayAddRes {
    pub overlay: LineageOverlayEntryRes,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LineageOverlayRemoveReq {
    pub vault_path: String,
    pub overlay_id: String,
    pub lock_token: String,
    pub now_ms: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LineageOverlayRemoveRes {
    pub removed_overlay_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LineageOverlayListReq {
    pub vault_path: String,
    pub doc_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LineageOverlayListRes {
    pub overlays: Vec<LineageOverlayEntryRes>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LineageLockAcquireReq {
    pub vault_path: String,
    pub doc_id: String,
    pub owner: String,
    pub now_ms: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LineageLockLeaseRes {
    pub doc_id: String,
    pub owner: String,
    pub token: String,
    pub acquired_at_ms: i64,
    pub expires_at_ms: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LineageLockAcquireRes {
    pub lease: LineageLockLeaseRes,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LineageLockReleaseReq {
    pub vault_path: String,
    pub doc_id: String,
    pub token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LineageLockReleaseRes {
    pub released: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LineageLockStatusReq {
    pub vault_path: String,
    pub doc_id: String,
    pub now_ms: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LineageLockStatusRes {
    pub doc_id: String,
    pub held: bool,
    pub owner: Option<String>,
    pub acquired_at_ms: Option<i64>,
    pub expires_at_ms: Option<i64>,
    pub expired: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LineageRoleGrantReq {
    pub vault_path: String,
    pub subject: String,
    pub role: String,
    #[serde(default)]
    pub granted_by: Option<String>,
    pub now_ms: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LineageRoleBindingRes {
    pub subject_id: String,
    pub role_name: String,
    pub role_rank: i64,
    pub granted_by: String,
    pub granted_at_ms: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LineageRoleGrantRes {
    pub binding: LineageRoleBindingRes,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LineageRoleRevokeReq {
    pub vault_path: String,
    pub subject: String,
    pub role: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LineageRoleRevokeRes {
    pub revoked: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LineageRoleListReq {
    pub vault_path: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LineageRoleListRes {
    pub bindings: Vec<LineageRoleBindingRes>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LineagePolicyAddReq {
    pub vault_path: String,
    pub name: String,
    pub effect: String,
    pub condition_json: String,
    #[serde(default)]
    pub created_by: Option<String>,
    pub now_ms: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LineagePolicyRes {
    pub policy_id: String,
    pub policy_name: String,
    pub effect: String,
    pub priority: i64,
    pub condition_json: String,
    pub created_by: String,
    pub created_at_ms: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LineagePolicyAddRes {
    pub policy: LineagePolicyRes,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LineagePolicyBindReq {
    pub vault_path: String,
    pub subject: String,
    pub policy: String,
    #[serde(default)]
    pub bound_by: Option<String>,
    pub now_ms: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LineagePolicyBindingRes {
    pub subject_id: String,
    pub policy_id: String,
    pub policy_name: String,
    pub effect: String,
    pub priority: i64,
    pub condition_json: String,
    pub bound_by: String,
    pub bound_at_ms: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LineagePolicyBindRes {
    pub binding: LineagePolicyBindingRes,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LineagePolicyListReq {
    pub vault_path: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LineagePolicyListRes {
    pub bindings: Vec<LineagePolicyBindingRes>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LineageLockAcquireScopeReq {
    pub vault_path: String,
    pub scope_kind: String,
    pub scope_value: String,
    pub owner: String,
    pub now_ms: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LineageScopeLockLeaseRes {
    pub scope_kind: String,
    pub scope_value: String,
    pub owner: String,
    pub token: String,
    pub acquired_at_ms: i64,
    pub expires_at_ms: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LineageLockAcquireScopeRes {
    pub lease: LineageScopeLockLeaseRes,
}

pub fn vault_init_rpc(req: VaultInitReq) -> RpcResponse<VaultInitRes> {
    match rpc_service::vault_init_service(
        std::path::Path::new(&req.vault_path),
        &req.vault_slug,
        req.now_ms,
    ) {
        Ok(vault_id) => RpcResponse::ok(VaultInitRes { vault_id }),
        Err(error) => RpcResponse::err(error),
    }
}

pub fn vault_open_rpc(req: VaultOpenReq) -> RpcResponse<VaultOpenRes> {
    match rpc_service::vault_open_service(std::path::Path::new(&req.vault_path)) {
        Ok(vault) => RpcResponse::ok(VaultOpenRes {
            vault_id: vault.vault_id,
            vault_slug: vault.vault_slug,
        }),
        Err(error) => RpcResponse::err(error),
    }
}

fn map_trust_provider(
    provider: kc_core::trust_identity::IdentityProviderRecord,
) -> TrustProviderRes {
    TrustProviderRes {
        provider_id: provider.provider_id,
        issuer: provider.issuer,
        audience: provider.audience,
        jwks_url: provider.jwks_url,
        enabled: provider.enabled,
        created_at_ms: provider.created_at_ms,
        updated_at_ms: provider.updated_at_ms,
    }
}

pub fn trust_identity_start_rpc(req: TrustIdentityStartReq) -> RpcResponse<TrustIdentityStartRes> {
    match rpc_service::trust_identity_start_service(
        std::path::Path::new(&req.vault_path),
        &req.provider,
        req.now_ms,
    ) {
        Ok(out) => RpcResponse::ok(TrustIdentityStartRes {
            provider_id: out.provider_id,
            state: out.state,
            authorization_url: out.authorization_url,
        }),
        Err(error) => RpcResponse::err(error),
    }
}

pub fn trust_identity_complete_rpc(
    req: TrustIdentityCompleteReq,
) -> RpcResponse<TrustIdentityCompleteRes> {
    match rpc_service::trust_identity_complete_service(
        std::path::Path::new(&req.vault_path),
        &req.provider,
        &req.code,
        req.now_ms,
    ) {
        Ok(out) => RpcResponse::ok(TrustIdentityCompleteRes {
            session_id: out.session_id,
            provider_id: out.provider_id,
            subject: out.subject,
            expires_at_ms: out.expires_at_ms,
        }),
        Err(error) => RpcResponse::err(error),
    }
}

pub fn trust_device_enroll_rpc(req: TrustDeviceEnrollReq) -> RpcResponse<TrustDeviceEnrollRes> {
    match rpc_service::trust_device_enroll_service(
        std::path::Path::new(&req.vault_path),
        &req.device_label,
        req.now_ms,
    ) {
        Ok(out) => RpcResponse::ok(TrustDeviceEnrollRes {
            device_id: out.device.device_id,
            label: out.device.label,
            fingerprint: out.device.fingerprint,
            cert_id: out.certificate.cert_id,
            cert_chain_hash: out.certificate.cert_chain_hash,
        }),
        Err(error) => RpcResponse::err(error),
    }
}

fn signing_key_res(
    status: kc_core::sync_key_custody::SyncSigningKeyStatus,
) -> TrustDeviceSigningKeyRes {
    TrustDeviceSigningKeyRes {
        device_id: status.device_id,
        public_key: status.public_key,
        signature_alg: status.signature_alg,
        key_reference: status.key_reference,
        created_at_ms: status.created_at_ms,
        rotated_at_ms: status.rotated_at_ms,
        deleted_at_ms: status.deleted_at_ms,
    }
}

pub fn trust_device_enroll_signing_key_rpc(
    req: TrustDeviceEnrollSigningKeyReq,
) -> RpcResponse<TrustDeviceEnrollSigningKeyRes> {
    match rpc_service::trust_device_enroll_signing_key_service(
        std::path::Path::new(&req.vault_path),
        &req.device_label,
        &req.passphrase,
        req.now_ms,
    ) {
        Ok(out) => RpcResponse::ok(TrustDeviceEnrollSigningKeyRes {
            device_id: out.device.device_id,
            label: out.device.label,
            fingerprint: out.device.fingerprint,
            cert_id: out.certificate.cert_id,
            cert_chain_hash: out.certificate.cert_chain_hash,
            signing_key: signing_key_res(out.signing_key),
        }),
        Err(error) => RpcResponse::err(error),
    }
}

pub fn trust_device_verify_chain_rpc(
    req: TrustDeviceVerifyChainReq,
) -> RpcResponse<TrustDeviceVerifyChainRes> {
    match rpc_service::trust_device_verify_chain_service(
        std::path::Path::new(&req.vault_path),
        &req.device_id,
        req.now_ms,
    ) {
        Ok(out) => RpcResponse::ok(TrustDeviceVerifyChainRes {
            cert_id: out.cert_id,
            device_id: out.device_id,
            provider_id: out.provider_id,
            subject: out.subject,
            cert_chain_hash: out.cert_chain_hash,
            verified_at_ms: out.verified_at_ms,
            expires_at_ms: out.expires_at_ms,
        }),
        Err(error) => RpcResponse::err(error),
    }
}

pub fn trust_device_list_rpc(req: TrustDeviceListReq) -> RpcResponse<TrustDeviceListRes> {
    match rpc_service::trust_device_list_service(std::path::Path::new(&req.vault_path)) {
        Ok(devices) => RpcResponse::ok(TrustDeviceListRes {
            devices: devices
                .into_iter()
                .map(|d| TrustDeviceListItemRes {
                    device_id: d.device_id,
                    label: d.label,
                    fingerprint: d.fingerprint,
                    verified_at_ms: d.verified_at_ms,
                    created_at_ms: d.created_at_ms,
                })
                .collect(),
        }),
        Err(error) => RpcResponse::err(error),
    }
}

pub fn trust_device_signing_key_status_rpc(
    req: TrustDeviceSigningKeyStatusReq,
) -> RpcResponse<TrustDeviceSigningKeyStatusRes> {
    match rpc_service::trust_device_signing_key_status_service(
        std::path::Path::new(&req.vault_path),
        &req.device_id,
    ) {
        Ok(signing_key) => RpcResponse::ok(TrustDeviceSigningKeyStatusRes {
            signing_key: signing_key.map(signing_key_res),
        }),
        Err(error) => RpcResponse::err(error),
    }
}

pub fn trust_device_signing_key_delete_rpc(
    req: TrustDeviceSigningKeyDeleteReq,
) -> RpcResponse<TrustDeviceSigningKeyDeleteRes> {
    match rpc_service::trust_device_signing_key_delete_service(
        std::path::Path::new(&req.vault_path),
        &req.device_id,
        req.now_ms,
    ) {
        Ok(out) => RpcResponse::ok(TrustDeviceSigningKeyDeleteRes {
            deleted: out.deleted,
            signing_key: out.signing_key.map(signing_key_res),
        }),
        Err(error) => RpcResponse::err(error),
    }
}

pub fn trust_device_signing_key_rotate_rpc(
    req: TrustDeviceSigningKeyRotateReq,
) -> RpcResponse<TrustDeviceSigningKeyRotateRes> {
    match rpc_service::trust_device_signing_key_rotate_service(
        std::path::Path::new(&req.vault_path),
        &req.old_device_id,
        &req.new_device_label,
        &req.passphrase,
        req.now_ms,
    ) {
        Ok(out) => RpcResponse::ok(TrustDeviceSigningKeyRotateRes {
            old_signing_key: signing_key_res(out.old_signing_key),
            device_id: out.device.device_id,
            label: out.device.label,
            fingerprint: out.device.fingerprint,
            cert_id: out.certificate.cert_id,
            cert_chain_hash: out.certificate.cert_chain_hash,
            signing_key: signing_key_res(out.signing_key),
        }),
        Err(error) => RpcResponse::err(error),
    }
}

pub fn trust_provider_add_rpc(req: TrustProviderAddReq) -> RpcResponse<TrustProviderRes> {
    match rpc_service::trust_provider_add_service(
        std::path::Path::new(&req.vault_path),
        &req.provider_id,
        &req.issuer,
        &req.aud,
        &req.jwks,
        req.now_ms,
    ) {
        Ok(provider) => RpcResponse::ok(map_trust_provider(provider)),
        Err(error) => RpcResponse::err(error),
    }
}

pub fn trust_provider_disable_rpc(req: TrustProviderDisableReq) -> RpcResponse<TrustProviderRes> {
    match rpc_service::trust_provider_disable_service(
        std::path::Path::new(&req.vault_path),
        &req.provider_id,
        req.now_ms,
    ) {
        Ok(provider) => RpcResponse::ok(map_trust_provider(provider)),
        Err(error) => RpcResponse::err(error),
    }
}

pub fn trust_provider_list_rpc(req: TrustProviderListReq) -> RpcResponse<TrustProviderListRes> {
    match rpc_service::trust_provider_list_service(std::path::Path::new(&req.vault_path)) {
        Ok(providers) => RpcResponse::ok(TrustProviderListRes {
            providers: providers.into_iter().map(map_trust_provider).collect(),
        }),
        Err(error) => RpcResponse::err(error),
    }
}

pub fn trust_provider_discover_rpc(req: TrustProviderDiscoverReq) -> RpcResponse<TrustProviderRes> {
    match rpc_service::trust_provider_discover_service(
        std::path::Path::new(&req.vault_path),
        &req.issuer,
        req.now_ms,
    ) {
        Ok(provider) => RpcResponse::ok(map_trust_provider(provider)),
        Err(error) => RpcResponse::err(error),
    }
}

pub fn trust_policy_set_rpc(req: TrustPolicySetReq) -> RpcResponse<TrustPolicySetRes> {
    match rpc_service::trust_provider_policy_set_service(
        std::path::Path::new(&req.vault_path),
        &req.provider_id,
        req.max_clock_skew_ms,
        &req.require_claims_json,
        req.now_ms,
    ) {
        Ok(policy) => RpcResponse::ok(TrustPolicySetRes {
            provider_id: policy.provider_id,
            max_clock_skew_ms: policy.max_clock_skew_ms,
            require_claims_json: policy.require_claims_json,
            updated_at_ms: policy.updated_at_ms,
        }),
        Err(error) => RpcResponse::err(error),
    }
}

pub fn trust_policy_set_tenant_template_rpc(
    req: TrustPolicySetTenantTemplateReq,
) -> RpcResponse<TrustPolicySetRes> {
    match rpc_service::trust_provider_policy_set_tenant_template_service(
        std::path::Path::new(&req.vault_path),
        &req.provider,
        &req.tenant_id,
        req.now_ms,
    ) {
        Ok(policy) => RpcResponse::ok(TrustPolicySetRes {
            provider_id: policy.provider_id,
            max_clock_skew_ms: policy.max_clock_skew_ms,
            require_claims_json: policy.require_claims_json,
            updated_at_ms: policy.updated_at_ms,
        }),
        Err(error) => RpcResponse::err(error),
    }
}

fn map_encryption_status(
    status: kc_core::rpc_service::VaultEncryptionStatus,
) -> VaultEncryptionStatusRes {
    VaultEncryptionStatusRes {
        enabled: status.enabled,
        mode: status.mode,
        key_reference: status.key_reference,
        kdf_algorithm: status.kdf_algorithm,
        objects_total: status.objects_total,
        objects_encrypted: status.objects_encrypted,
    }
}

fn map_recovery_manifest(manifest: kc_core::recovery::RecoveryManifestV2) -> RecoveryManifestRes {
    RecoveryManifestRes {
        schema_version: manifest.schema_version,
        vault_id: manifest.vault_id,
        created_at_ms: manifest.created_at_ms,
        phrase_checksum: manifest.phrase_checksum,
        payload_hash: manifest.payload_hash,
    }
}

fn map_recovery_escrow_status(
    status: kc_core::rpc_service::VaultRecoveryEscrowStatus,
) -> VaultRecoveryEscrowStatusRes {
    VaultRecoveryEscrowStatusRes {
        enabled: status.enabled,
        provider: status.provider,
        provider_available: status.provider_available,
        updated_at_ms: status.updated_at_ms,
        details_json: status.details_json,
    }
}

fn map_recovery_escrow_provider_item(
    item: kc_core::rpc_service::VaultRecoveryEscrowProviderItem,
) -> VaultRecoveryEscrowProviderItemRes {
    VaultRecoveryEscrowProviderItemRes {
        provider: item.provider,
        priority: item.priority,
        config_ref: item.config_ref,
        enabled: item.enabled,
        provider_available: item.provider_available,
        updated_at_ms: item.updated_at_ms,
    }
}

fn map_lock_status(status: kc_core::rpc_service::VaultDbLockStatus) -> VaultLockStatusRes {
    VaultLockStatusRes {
        db_encryption_enabled: status.db_encryption_enabled,
        unlocked: status.unlocked,
        mode: status.mode,
        key_reference: status.key_reference,
        state: status.state,
    }
}

pub fn vault_encryption_status_rpc(
    req: VaultEncryptionStatusReq,
) -> RpcResponse<VaultEncryptionStatusRes> {
    match rpc_service::vault_encryption_status_service(std::path::Path::new(&req.vault_path)) {
        Ok(status) => RpcResponse::ok(map_encryption_status(status)),
        Err(error) => RpcResponse::err(error),
    }
}

pub fn vault_lock_status_rpc(req: VaultLockStatusReq) -> RpcResponse<VaultLockStatusRes> {
    match rpc_service::vault_lock_status_service(std::path::Path::new(&req.vault_path)) {
        Ok(status) => RpcResponse::ok(map_lock_status(status)),
        Err(error) => RpcResponse::err(error),
    }
}

pub fn vault_unlock_rpc(req: VaultUnlockReq) -> RpcResponse<VaultUnlockRes> {
    match rpc_service::vault_unlock_service(std::path::Path::new(&req.vault_path), &req.passphrase)
    {
        Ok(status) => RpcResponse::ok(VaultUnlockRes {
            status: map_lock_status(status),
        }),
        Err(error) => RpcResponse::err(error),
    }
}

pub fn vault_lock_rpc(req: VaultLockReq) -> RpcResponse<VaultLockRes> {
    match rpc_service::vault_lock_service(std::path::Path::new(&req.vault_path)) {
        Ok(status) => RpcResponse::ok(VaultLockRes {
            status: map_lock_status(status),
        }),
        Err(error) => RpcResponse::err(error),
    }
}

pub fn vault_encryption_enable_rpc(
    req: VaultEncryptionEnableReq,
) -> RpcResponse<VaultEncryptionEnableRes> {
    match rpc_service::vault_encryption_enable_service(
        std::path::Path::new(&req.vault_path),
        &req.passphrase,
    ) {
        Ok(status) => RpcResponse::ok(VaultEncryptionEnableRes {
            status: map_encryption_status(status),
        }),
        Err(error) => RpcResponse::err(error),
    }
}

pub fn vault_encryption_migrate_rpc(
    req: VaultEncryptionMigrateReq,
) -> RpcResponse<VaultEncryptionMigrateRes> {
    match rpc_service::vault_encryption_migrate_service(
        std::path::Path::new(&req.vault_path),
        &req.passphrase,
        req.now_ms,
    ) {
        Ok(out) => RpcResponse::ok(VaultEncryptionMigrateRes {
            status: map_encryption_status(out.status),
            migrated_objects: out.migrated_objects,
            already_encrypted_objects: out.already_encrypted_objects,
            event_id: out.event_id,
        }),
        Err(error) => RpcResponse::err(error),
    }
}

pub fn vault_recovery_status_rpc(
    req: VaultRecoveryStatusReq,
) -> RpcResponse<VaultRecoveryStatusRes> {
    match rpc_service::vault_recovery_status_service(std::path::Path::new(&req.vault_path)) {
        Ok(status) => RpcResponse::ok(VaultRecoveryStatusRes {
            vault_id: status.vault_id,
            encryption_enabled: status.encryption_enabled,
            last_bundle_path: status.last_bundle_path,
        }),
        Err(error) => RpcResponse::err(error),
    }
}

pub fn vault_recovery_generate_rpc(
    req: VaultRecoveryGenerateReq,
) -> RpcResponse<VaultRecoveryGenerateRes> {
    match rpc_service::vault_recovery_generate_service(
        std::path::Path::new(&req.vault_path),
        std::path::Path::new(&req.output_dir),
        &req.passphrase,
        req.now_ms,
    ) {
        Ok(out) => RpcResponse::ok(VaultRecoveryGenerateRes {
            bundle_path: out.bundle_path.display().to_string(),
            recovery_phrase: out.recovery_phrase,
            manifest: map_recovery_manifest(out.manifest),
        }),
        Err(error) => RpcResponse::err(error),
    }
}

pub fn vault_recovery_verify_rpc(
    req: VaultRecoveryVerifyReq,
) -> RpcResponse<VaultRecoveryVerifyRes> {
    match rpc_service::vault_recovery_verify_service(
        std::path::Path::new(&req.vault_path),
        std::path::Path::new(&req.bundle_path),
        &req.recovery_phrase,
    ) {
        Ok(out) => RpcResponse::ok(VaultRecoveryVerifyRes {
            manifest: map_recovery_manifest(out.manifest),
        }),
        Err(error) => RpcResponse::err(error),
    }
}

pub fn vault_recovery_escrow_status_rpc(
    req: VaultRecoveryEscrowStatusReq,
) -> RpcResponse<VaultRecoveryEscrowStatusRes> {
    match rpc_service::vault_recovery_escrow_status_service(std::path::Path::new(&req.vault_path)) {
        Ok(status) => RpcResponse::ok(map_recovery_escrow_status(status)),
        Err(error) => RpcResponse::err(error),
    }
}

pub fn vault_recovery_escrow_enable_rpc(
    req: VaultRecoveryEscrowEnableReq,
) -> RpcResponse<VaultRecoveryEscrowEnableRes> {
    match rpc_service::vault_recovery_escrow_enable_service(
        std::path::Path::new(&req.vault_path),
        &req.provider,
        req.now_ms,
    ) {
        Ok(status) => RpcResponse::ok(VaultRecoveryEscrowEnableRes {
            status: map_recovery_escrow_status(status),
        }),
        Err(error) => RpcResponse::err(error),
    }
}

pub fn vault_recovery_escrow_rotate_rpc(
    req: VaultRecoveryEscrowRotateReq,
) -> RpcResponse<VaultRecoveryEscrowRotateRes> {
    match rpc_service::vault_recovery_escrow_rotate_service(
        std::path::Path::new(&req.vault_path),
        &req.passphrase,
        req.now_ms,
    ) {
        Ok(out) => RpcResponse::ok(VaultRecoveryEscrowRotateRes {
            status: map_recovery_escrow_status(out.status),
            bundle_path: out.bundle_path.display().to_string(),
            recovery_phrase: out.recovery_phrase,
            manifest: map_recovery_manifest(out.manifest),
        }),
        Err(error) => RpcResponse::err(error),
    }
}

pub fn vault_recovery_escrow_restore_rpc(
    req: VaultRecoveryEscrowRestoreReq,
) -> RpcResponse<VaultRecoveryEscrowRestoreRes> {
    match rpc_service::vault_recovery_escrow_restore_service(
        std::path::Path::new(&req.vault_path),
        std::path::Path::new(&req.bundle_path),
        req.now_ms,
    ) {
        Ok(out) => RpcResponse::ok(VaultRecoveryEscrowRestoreRes {
            status: map_recovery_escrow_status(out.status),
            bundle_path: out.bundle_path.display().to_string(),
            restored_bytes: out.restored_bytes,
            manifest: map_recovery_manifest(out.manifest),
        }),
        Err(error) => RpcResponse::err(error),
    }
}

pub fn vault_recovery_escrow_provider_add_rpc(
    req: VaultRecoveryEscrowProviderAddReq,
) -> RpcResponse<VaultRecoveryEscrowProviderAddRes> {
    match rpc_service::vault_recovery_escrow_provider_add_service(
        std::path::Path::new(&req.vault_path),
        &req.provider,
        &req.config_ref,
        req.now_ms,
    ) {
        Ok(provider) => RpcResponse::ok(VaultRecoveryEscrowProviderAddRes {
            provider: map_recovery_escrow_provider_item(provider),
        }),
        Err(error) => RpcResponse::err(error),
    }
}

pub fn vault_recovery_escrow_provider_list_rpc(
    req: VaultRecoveryEscrowProviderListReq,
) -> RpcResponse<VaultRecoveryEscrowProviderListRes> {
    match rpc_service::vault_recovery_escrow_provider_list_service(std::path::Path::new(
        &req.vault_path,
    )) {
        Ok(providers) => RpcResponse::ok(VaultRecoveryEscrowProviderListRes {
            providers: providers
                .into_iter()
                .map(map_recovery_escrow_provider_item)
                .collect(),
        }),
        Err(error) => RpcResponse::err(error),
    }
}

pub fn vault_recovery_escrow_rotate_all_rpc(
    req: VaultRecoveryEscrowRotateAllReq,
) -> RpcResponse<VaultRecoveryEscrowRotateAllRes> {
    match rpc_service::vault_recovery_escrow_rotate_all_service(
        std::path::Path::new(&req.vault_path),
        &req.passphrase,
        req.now_ms,
    ) {
        Ok(out) => RpcResponse::ok(VaultRecoveryEscrowRotateAllRes {
            rotated: out
                .rotated
                .into_iter()
                .map(|item| VaultRecoveryEscrowRotateAllItemRes {
                    provider: item.provider,
                    bundle_path: item.bundle_path.display().to_string(),
                    recovery_phrase: item.recovery_phrase,
                    manifest: map_recovery_manifest(item.manifest),
                    updated_at_ms: item.updated_at_ms,
                })
                .collect(),
        }),
        Err(error) => RpcResponse::err(error),
    }
}

pub fn ingest_scan_folder_rpc(req: IngestScanFolderReq) -> RpcResponse<IngestScanFolderRes> {
    match rpc_service::ingest_scan_folder_service(
        std::path::Path::new(&req.vault_path),
        std::path::Path::new(&req.scan_root),
        &req.source_kind,
        req.now_ms,
    ) {
        Ok(ingested) => RpcResponse::ok(IngestScanFolderRes { ingested }),
        Err(error) => RpcResponse::err(error),
    }
}

pub fn ingest_inbox_start_rpc(req: IngestInboxStartReq) -> RpcResponse<IngestInboxStartRes> {
    match rpc_service::ingest_inbox_start_service(
        std::path::Path::new(&req.vault_path),
        std::path::Path::new(&req.file_path),
        &req.source_kind,
        req.now_ms,
    ) {
        Ok(out) => RpcResponse::ok(IngestInboxStartRes {
            job_id: out.job_id,
            doc_id: out.doc_id,
        }),
        Err(error) => RpcResponse::err(error),
    }
}

pub fn ingest_inbox_stop_rpc(req: IngestInboxStopReq) -> RpcResponse<IngestInboxStopRes> {
    let _ = req.vault_path;
    match rpc_service::ingest_inbox_stop_service(&req.job_id) {
        Ok(stopped) => RpcResponse::ok(IngestInboxStopRes { stopped }),
        Err(error) => RpcResponse::err(error),
    }
}

pub fn search_query_rpc(req: SearchQueryReq) -> RpcResponse<SearchQueryRes> {
    match rpc_service::search_query_service(
        std::path::Path::new(&req.vault_path),
        &req.query,
        req.now_ms,
        req.limit.unwrap_or(20),
    ) {
        Ok(hits) => RpcResponse::ok(SearchQueryRes {
            hits: hits
                .into_iter()
                .map(|h| SearchHit {
                    doc_id: h.doc_id,
                    score: h.score,
                    snippet: h.snippet,
                })
                .collect(),
        }),
        Err(error) => RpcResponse::err(error),
    }
}

pub fn locator_resolve_rpc(req: LocatorResolveReq) -> RpcResponse<LocatorResolveRes> {
    match rpc_service::locator_resolve_service(std::path::Path::new(&req.vault_path), &req.locator)
    {
        Ok(text) => RpcResponse::ok(LocatorResolveRes { text }),
        Err(error) => RpcResponse::err(error),
    }
}

pub fn export_bundle_rpc(req: ExportBundleReq) -> RpcResponse<ExportBundleRes> {
    match rpc_service::export_bundle_service(
        std::path::Path::new(&req.vault_path),
        std::path::Path::new(&req.export_dir),
        req.include_vectors,
        req.now_ms,
    ) {
        Ok(path) => RpcResponse::ok(ExportBundleRes {
            bundle_path: path.display().to_string(),
        }),
        Err(error) => RpcResponse::err(error),
    }
}

pub fn verify_bundle_rpc(req: VerifyBundleReq) -> RpcResponse<VerifyBundleRes> {
    match verify_bundle(std::path::Path::new(&req.bundle_path)) {
        Ok((exit_code, report)) => RpcResponse::ok(VerifyBundleRes { exit_code, report }),
        Err(error) => RpcResponse::err(error),
    }
}

pub fn ask_question_rpc(req: AskQuestionReq) -> RpcResponse<AskQuestionRes> {
    let service = RetrievedOnlyAskService::default();
    match service.ask(AskRequest {
        vault_path: std::path::PathBuf::from(&req.vault_path),
        question: req.question,
        now_ms: req.now_ms,
    }) {
        Ok(out) => RpcResponse::ok(AskQuestionRes {
            answer_text: out.answer_text,
            trace_path: out.trace_path.display().to_string(),
        }),
        Err(error) => RpcResponse::err(error),
    }
}

pub fn events_list_rpc(req: EventsListReq) -> RpcResponse<EventsListRes> {
    match rpc_service::events_list_service(
        std::path::Path::new(&req.vault_path),
        req.limit.unwrap_or(50),
    ) {
        Ok(events) => RpcResponse::ok(EventsListRes {
            events: events
                .into_iter()
                .map(|e| EventItem {
                    event_id: e.event_id,
                    ts_ms: e.ts_ms,
                    event_type: e.event_type,
                })
                .collect(),
        }),
        Err(error) => RpcResponse::err(error),
    }
}

pub fn jobs_list_rpc(req: JobsListReq) -> RpcResponse<JobsListRes> {
    match rpc_service::jobs_list_service(std::path::Path::new(&req.vault_path)) {
        Ok(jobs) => RpcResponse::ok(JobsListRes { jobs }),
        Err(error) => RpcResponse::err(error),
    }
}

fn map_sync_head(head: kc_core::sync::SyncHeadV1) -> SyncHeadRes {
    SyncHeadRes {
        schema_version: head.schema_version,
        snapshot_id: head.snapshot_id,
        manifest_hash: head.manifest_hash,
        created_at_ms: head.created_at_ms,
    }
}

fn map_sync_merge_change_set(
    set: kc_core::sync_merge::SyncMergeChangeSetV1,
) -> SyncMergeChangeSetRes {
    SyncMergeChangeSetRes {
        object_hashes: set.object_hashes,
        lineage_overlay_ids: set.lineage_overlay_ids,
    }
}

fn map_sync_merge_preview_report(
    report: kc_core::sync_merge::SyncMergePreviewReportV1,
) -> SyncMergePreviewReportRes {
    SyncMergePreviewReportRes {
        schema_version: report.schema_version,
        merge_policy: report.merge_policy,
        safe: report.safe,
        generated_at_ms: report.generated_at_ms,
        local: map_sync_merge_change_set(report.local),
        remote: map_sync_merge_change_set(report.remote),
        overlap: map_sync_merge_change_set(report.overlap),
        reasons: report.reasons,
        decision_trace: report.decision_trace,
    }
}

pub fn sync_status_rpc(req: SyncStatusReq) -> RpcResponse<SyncStatusRes> {
    match rpc_service::sync_status_service(std::path::Path::new(&req.vault_path), &req.target_path)
    {
        Ok(status) => RpcResponse::ok(SyncStatusRes {
            target_path: status.target_path,
            remote_head: status.remote_head.map(map_sync_head),
            seen_remote_snapshot_id: status.seen_remote_snapshot_id,
            last_applied_manifest_hash: status.last_applied_manifest_hash,
        }),
        Err(error) => RpcResponse::err(error),
    }
}

fn sync_auth_readiness_classification_name(
    classification: kc_core::sync::SyncAuthReadinessClassification,
) -> String {
    match classification {
        kc_core::sync::SyncAuthReadinessClassification::NoRemoteHead => "no_remote_head",
        kc_core::sync::SyncAuthReadinessClassification::LegacySchema => "legacy_schema",
        kc_core::sync::SyncAuthReadinessClassification::DeclaredEd25519 => "declared_ed25519",
        kc_core::sync::SyncAuthReadinessClassification::UndeclaredEd25519Compatible => {
            "undeclared_ed25519_compatible"
        }
        kc_core::sync::SyncAuthReadinessClassification::UndeclaredLegacyFallback => {
            "undeclared_legacy_fallback"
        }
        kc_core::sync::SyncAuthReadinessClassification::UnsupportedDeclaredAlgorithm => {
            "unsupported_declared_algorithm"
        }
        kc_core::sync::SyncAuthReadinessClassification::Invalid => "invalid",
    }
    .to_string()
}

pub fn sync_auth_readiness_rpc(req: SyncAuthReadinessReq) -> RpcResponse<SyncAuthReadinessRes> {
    match rpc_service::sync_auth_readiness_service(
        std::path::Path::new(&req.vault_path),
        &req.target_path,
    ) {
        Ok(report) => RpcResponse::ok(SyncAuthReadinessRes {
            report_version: report.report_version,
            target_path: report.target_path,
            classification: sync_auth_readiness_classification_name(report.classification),
            strict_ready: report.strict_ready,
            depends_on_legacy_fallback: report.depends_on_legacy_fallback,
            remediation: report.remediation,
            remote_head: report.remote_head.map(map_sync_head),
            error_code: report.error_code,
            error_message: report.error_message,
        }),
        Err(error) => RpcResponse::err(error),
    }
}

pub fn sync_push_rpc(req: SyncPushReq) -> RpcResponse<SyncPushRes> {
    match rpc_service::sync_push_service(
        std::path::Path::new(&req.vault_path),
        &req.target_path,
        req.now_ms,
    ) {
        Ok(out) => RpcResponse::ok(SyncPushRes {
            snapshot_id: out.snapshot_id,
            manifest_hash: out.manifest_hash,
            remote_head: map_sync_head(out.remote_head),
        }),
        Err(error) => RpcResponse::err(error),
    }
}

pub fn sync_pull_rpc(req: SyncPullReq) -> RpcResponse<SyncPullRes> {
    match rpc_service::sync_pull_service(
        std::path::Path::new(&req.vault_path),
        &req.target_path,
        req.now_ms,
        req.auto_merge.as_deref(),
    ) {
        Ok(out) => RpcResponse::ok(SyncPullRes {
            snapshot_id: out.snapshot_id,
            manifest_hash: out.manifest_hash,
            remote_head: map_sync_head(out.remote_head),
        }),
        Err(error) => RpcResponse::err(error),
    }
}

pub fn sync_merge_preview_rpc(req: SyncMergePreviewReq) -> RpcResponse<SyncMergePreviewRes> {
    match rpc_service::sync_merge_preview_service(
        std::path::Path::new(&req.vault_path),
        &req.target_path,
        req.policy.as_deref(),
        req.now_ms,
    ) {
        Ok(out) => RpcResponse::ok(SyncMergePreviewRes {
            target_path: out.target_path,
            seen_remote_snapshot_id: out.seen_remote_snapshot_id,
            remote_snapshot_id: out.remote_snapshot_id,
            report: map_sync_merge_preview_report(out.report),
        }),
        Err(error) => RpcResponse::err(error),
    }
}

pub fn lineage_query_rpc(req: LineageQueryReq) -> RpcResponse<LineageQueryRes> {
    match rpc_service::lineage_query_service(
        std::path::Path::new(&req.vault_path),
        &req.seed_doc_id,
        req.depth,
        req.now_ms,
    ) {
        Ok(res) => RpcResponse::ok(LineageQueryRes {
            schema_version: res.schema_version,
            seed_doc_id: res.seed_doc_id,
            depth: res.depth,
            generated_at_ms: res.generated_at_ms,
            nodes: res
                .nodes
                .into_iter()
                .map(|n| LineageNodeRes {
                    node_id: n.node_id,
                    kind: n.kind,
                    label: n.label,
                    metadata: n.metadata,
                })
                .collect(),
            edges: res
                .edges
                .into_iter()
                .map(|e| LineageEdgeRes {
                    from_node_id: e.from_node_id,
                    to_node_id: e.to_node_id,
                    relation: e.relation,
                    evidence: e.evidence,
                })
                .collect(),
        }),
        Err(error) => RpcResponse::err(error),
    }
}

fn map_lineage_overlay_entry(
    entry: kc_core::lineage::LineageOverlayEntryV1,
) -> LineageOverlayEntryRes {
    LineageOverlayEntryRes {
        overlay_id: entry.overlay_id,
        doc_id: entry.doc_id,
        from_node_id: entry.from_node_id,
        to_node_id: entry.to_node_id,
        relation: entry.relation,
        evidence: entry.evidence,
        created_at_ms: entry.created_at_ms,
        created_by: entry.created_by,
    }
}

fn map_lineage_lock_lease(lease: kc_core::lineage::LineageLockLeaseV1) -> LineageLockLeaseRes {
    LineageLockLeaseRes {
        doc_id: lease.doc_id,
        owner: lease.owner,
        token: lease.token,
        acquired_at_ms: lease.acquired_at_ms,
        expires_at_ms: lease.expires_at_ms,
    }
}

fn map_lineage_lock_status(status: kc_core::lineage::LineageLockStatusV1) -> LineageLockStatusRes {
    LineageLockStatusRes {
        doc_id: status.doc_id,
        held: status.held,
        owner: status.owner,
        acquired_at_ms: status.acquired_at_ms,
        expires_at_ms: status.expires_at_ms,
        expired: status.expired,
    }
}

fn map_lineage_role_binding(
    binding: kc_core::lineage_governance::LineageRoleBindingV2,
) -> LineageRoleBindingRes {
    LineageRoleBindingRes {
        subject_id: binding.subject_id,
        role_name: binding.role_name,
        role_rank: binding.role_rank,
        granted_by: binding.granted_by,
        granted_at_ms: binding.granted_at_ms,
    }
}

fn map_lineage_policy(policy: kc_core::lineage_policy::LineagePolicyV3) -> LineagePolicyRes {
    LineagePolicyRes {
        policy_id: policy.policy_id,
        policy_name: policy.policy_name,
        effect: policy.effect,
        priority: policy.priority,
        condition_json: policy.condition_json,
        created_by: policy.created_by,
        created_at_ms: policy.created_at_ms,
    }
}

fn map_lineage_policy_binding(
    binding: kc_core::lineage_policy::LineagePolicyBindingV3,
) -> LineagePolicyBindingRes {
    LineagePolicyBindingRes {
        subject_id: binding.subject_id,
        policy_id: binding.policy_id,
        policy_name: binding.policy_name,
        effect: binding.effect,
        priority: binding.priority,
        condition_json: binding.condition_json,
        bound_by: binding.bound_by,
        bound_at_ms: binding.bound_at_ms,
    }
}

fn map_lineage_scope_lock_lease(
    lease: kc_core::lineage_governance::LineageScopeLockLeaseV2,
) -> LineageScopeLockLeaseRes {
    LineageScopeLockLeaseRes {
        scope_kind: lease.scope_kind,
        scope_value: lease.scope_value,
        owner: lease.owner,
        token: lease.token,
        acquired_at_ms: lease.acquired_at_ms,
        expires_at_ms: lease.expires_at_ms,
    }
}

pub fn lineage_query_v2_rpc(req: LineageQueryV2Req) -> RpcResponse<LineageQueryV2Res> {
    match rpc_service::lineage_query_v2_service(
        std::path::Path::new(&req.vault_path),
        &req.seed_doc_id,
        req.depth,
        req.now_ms,
    ) {
        Ok(res) => RpcResponse::ok(LineageQueryV2Res {
            schema_version: res.schema_version,
            seed_doc_id: res.seed_doc_id,
            depth: res.depth,
            generated_at_ms: res.generated_at_ms,
            nodes: res
                .nodes
                .into_iter()
                .map(|n| LineageNodeRes {
                    node_id: n.node_id,
                    kind: n.kind,
                    label: n.label,
                    metadata: n.metadata,
                })
                .collect(),
            edges: res
                .edges
                .into_iter()
                .map(|e| LineageEdgeV2Res {
                    from_node_id: e.from_node_id,
                    to_node_id: e.to_node_id,
                    relation: e.relation,
                    evidence: e.evidence,
                    origin: e.origin,
                })
                .collect(),
        }),
        Err(error) => RpcResponse::err(error),
    }
}

pub fn lineage_overlay_add_rpc(req: LineageOverlayAddReq) -> RpcResponse<LineageOverlayAddRes> {
    match rpc_service::lineage_overlay_add_service(
        std::path::Path::new(&req.vault_path),
        rpc_service::LineageOverlayAddServiceReq {
            doc_id: &req.doc_id,
            from_node_id: &req.from_node_id,
            to_node_id: &req.to_node_id,
            relation: &req.relation,
            evidence: &req.evidence,
            lock_token: &req.lock_token,
            created_at_ms: req.created_at_ms,
            created_by: req.created_by.as_deref(),
        },
    ) {
        Ok(overlay) => RpcResponse::ok(LineageOverlayAddRes {
            overlay: map_lineage_overlay_entry(overlay),
        }),
        Err(error) => RpcResponse::err(error),
    }
}

pub fn lineage_overlay_remove_rpc(
    req: LineageOverlayRemoveReq,
) -> RpcResponse<LineageOverlayRemoveRes> {
    match rpc_service::lineage_overlay_remove_service(
        std::path::Path::new(&req.vault_path),
        &req.overlay_id,
        &req.lock_token,
        req.now_ms,
    ) {
        Ok(()) => RpcResponse::ok(LineageOverlayRemoveRes {
            removed_overlay_id: req.overlay_id,
        }),
        Err(error) => RpcResponse::err(error),
    }
}

pub fn lineage_overlay_list_rpc(req: LineageOverlayListReq) -> RpcResponse<LineageOverlayListRes> {
    match rpc_service::lineage_overlay_list_service(
        std::path::Path::new(&req.vault_path),
        &req.doc_id,
    ) {
        Ok(overlays) => RpcResponse::ok(LineageOverlayListRes {
            overlays: overlays
                .into_iter()
                .map(map_lineage_overlay_entry)
                .collect(),
        }),
        Err(error) => RpcResponse::err(error),
    }
}

pub fn lineage_lock_acquire_rpc(req: LineageLockAcquireReq) -> RpcResponse<LineageLockAcquireRes> {
    match rpc_service::lineage_lock_acquire_service(
        std::path::Path::new(&req.vault_path),
        &req.doc_id,
        &req.owner,
        req.now_ms,
    ) {
        Ok(lease) => RpcResponse::ok(LineageLockAcquireRes {
            lease: map_lineage_lock_lease(lease),
        }),
        Err(error) => RpcResponse::err(error),
    }
}

pub fn lineage_lock_release_rpc(req: LineageLockReleaseReq) -> RpcResponse<LineageLockReleaseRes> {
    match rpc_service::lineage_lock_release_service(
        std::path::Path::new(&req.vault_path),
        &req.doc_id,
        &req.token,
    ) {
        Ok(()) => RpcResponse::ok(LineageLockReleaseRes { released: true }),
        Err(error) => RpcResponse::err(error),
    }
}

pub fn lineage_lock_status_rpc(req: LineageLockStatusReq) -> RpcResponse<LineageLockStatusRes> {
    match rpc_service::lineage_lock_status_service(
        std::path::Path::new(&req.vault_path),
        &req.doc_id,
        req.now_ms,
    ) {
        Ok(status) => RpcResponse::ok(map_lineage_lock_status(status)),
        Err(error) => RpcResponse::err(error),
    }
}

pub fn lineage_role_grant_rpc(req: LineageRoleGrantReq) -> RpcResponse<LineageRoleGrantRes> {
    match rpc_service::lineage_role_grant_service(
        std::path::Path::new(&req.vault_path),
        &req.subject,
        &req.role,
        req.granted_by.as_deref().unwrap_or("rpc"),
        req.now_ms,
    ) {
        Ok(binding) => RpcResponse::ok(LineageRoleGrantRes {
            binding: map_lineage_role_binding(binding),
        }),
        Err(error) => RpcResponse::err(error),
    }
}

pub fn lineage_role_revoke_rpc(req: LineageRoleRevokeReq) -> RpcResponse<LineageRoleRevokeRes> {
    match rpc_service::lineage_role_revoke_service(
        std::path::Path::new(&req.vault_path),
        &req.subject,
        &req.role,
    ) {
        Ok(()) => RpcResponse::ok(LineageRoleRevokeRes { revoked: true }),
        Err(error) => RpcResponse::err(error),
    }
}

pub fn lineage_role_list_rpc(req: LineageRoleListReq) -> RpcResponse<LineageRoleListRes> {
    match rpc_service::lineage_role_list_service(std::path::Path::new(&req.vault_path)) {
        Ok(bindings) => RpcResponse::ok(LineageRoleListRes {
            bindings: bindings.into_iter().map(map_lineage_role_binding).collect(),
        }),
        Err(error) => RpcResponse::err(error),
    }
}

pub fn lineage_policy_add_rpc(req: LineagePolicyAddReq) -> RpcResponse<LineagePolicyAddRes> {
    match rpc_service::lineage_policy_add_service(
        std::path::Path::new(&req.vault_path),
        &req.name,
        &req.effect,
        &req.condition_json,
        req.created_by.as_deref().unwrap_or("rpc"),
        req.now_ms,
    ) {
        Ok(policy) => RpcResponse::ok(LineagePolicyAddRes {
            policy: map_lineage_policy(policy),
        }),
        Err(error) => RpcResponse::err(error),
    }
}

pub fn lineage_policy_bind_rpc(req: LineagePolicyBindReq) -> RpcResponse<LineagePolicyBindRes> {
    match rpc_service::lineage_policy_bind_service(
        std::path::Path::new(&req.vault_path),
        &req.subject,
        &req.policy,
        req.bound_by.as_deref().unwrap_or("rpc"),
        req.now_ms,
    ) {
        Ok(binding) => RpcResponse::ok(LineagePolicyBindRes {
            binding: map_lineage_policy_binding(binding),
        }),
        Err(error) => RpcResponse::err(error),
    }
}

pub fn lineage_policy_list_rpc(req: LineagePolicyListReq) -> RpcResponse<LineagePolicyListRes> {
    match rpc_service::lineage_policy_list_service(std::path::Path::new(&req.vault_path)) {
        Ok(bindings) => RpcResponse::ok(LineagePolicyListRes {
            bindings: bindings
                .into_iter()
                .map(map_lineage_policy_binding)
                .collect(),
        }),
        Err(error) => RpcResponse::err(error),
    }
}

pub fn lineage_lock_acquire_scope_rpc(
    req: LineageLockAcquireScopeReq,
) -> RpcResponse<LineageLockAcquireScopeRes> {
    match rpc_service::lineage_lock_acquire_scope_service(
        std::path::Path::new(&req.vault_path),
        &req.scope_kind,
        &req.scope_value,
        &req.owner,
        req.now_ms,
    ) {
        Ok(lease) => RpcResponse::ok(LineageLockAcquireScopeRes {
            lease: map_lineage_scope_lock_lease(lease),
        }),
        Err(error) => RpcResponse::err(error),
    }
}

#[allow(dead_code)]
pub fn rpc_health_snapshot(vault_path: &str) -> RpcResponse<serde_json::Value> {
    match rpc_service::rpc_health_snapshot_service(std::path::Path::new(vault_path)) {
        Ok(data) => RpcResponse::ok(data),
        Err(error) => RpcResponse::err(error),
    }
}
