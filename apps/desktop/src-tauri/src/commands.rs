use crate::rpc;

#[tauri::command]
pub fn vault_init(req: rpc::VaultInitReq) -> rpc::RpcResponse<rpc::VaultInitRes> {
    rpc::vault_init_rpc(req)
}

#[tauri::command]
pub fn vault_open(req: rpc::VaultOpenReq) -> rpc::RpcResponse<rpc::VaultOpenRes> {
    rpc::vault_open_rpc(req)
}

#[tauri::command]
pub fn trust_identity_start(
    req: rpc::TrustIdentityStartReq,
) -> rpc::RpcResponse<rpc::TrustIdentityStartRes> {
    rpc::trust_identity_start_rpc(req)
}

#[tauri::command]
pub fn trust_identity_complete(
    req: rpc::TrustIdentityCompleteReq,
) -> rpc::RpcResponse<rpc::TrustIdentityCompleteRes> {
    rpc::trust_identity_complete_rpc(req)
}

#[tauri::command]
pub fn trust_device_enroll(
    req: rpc::TrustDeviceEnrollReq,
) -> rpc::RpcResponse<rpc::TrustDeviceEnrollRes> {
    rpc::trust_device_enroll_rpc(req)
}

#[tauri::command]
pub fn trust_device_enroll_signing_key(
    req: rpc::TrustDeviceEnrollSigningKeyReq,
) -> rpc::RpcResponse<rpc::TrustDeviceEnrollSigningKeyRes> {
    rpc::trust_device_enroll_signing_key_rpc(req)
}

#[tauri::command]
pub fn trust_device_verify_chain(
    req: rpc::TrustDeviceVerifyChainReq,
) -> rpc::RpcResponse<rpc::TrustDeviceVerifyChainRes> {
    rpc::trust_device_verify_chain_rpc(req)
}

#[tauri::command]
pub fn trust_device_list(
    req: rpc::TrustDeviceListReq,
) -> rpc::RpcResponse<rpc::TrustDeviceListRes> {
    rpc::trust_device_list_rpc(req)
}

#[tauri::command]
pub fn trust_device_signing_key_status(
    req: rpc::TrustDeviceSigningKeyStatusReq,
) -> rpc::RpcResponse<rpc::TrustDeviceSigningKeyStatusRes> {
    rpc::trust_device_signing_key_status_rpc(req)
}

#[tauri::command]
pub fn trust_device_signing_key_delete(
    req: rpc::TrustDeviceSigningKeyDeleteReq,
) -> rpc::RpcResponse<rpc::TrustDeviceSigningKeyDeleteRes> {
    rpc::trust_device_signing_key_delete_rpc(req)
}

#[tauri::command]
pub fn trust_device_signing_key_rotate(
    req: rpc::TrustDeviceSigningKeyRotateReq,
) -> rpc::RpcResponse<rpc::TrustDeviceSigningKeyRotateRes> {
    rpc::trust_device_signing_key_rotate_rpc(req)
}

#[tauri::command]
pub fn trust_provider_add(
    req: rpc::TrustProviderAddReq,
) -> rpc::RpcResponse<rpc::TrustProviderRes> {
    rpc::trust_provider_add_rpc(req)
}

#[tauri::command]
pub fn trust_provider_disable(
    req: rpc::TrustProviderDisableReq,
) -> rpc::RpcResponse<rpc::TrustProviderRes> {
    rpc::trust_provider_disable_rpc(req)
}

#[tauri::command]
pub fn trust_provider_list(
    req: rpc::TrustProviderListReq,
) -> rpc::RpcResponse<rpc::TrustProviderListRes> {
    rpc::trust_provider_list_rpc(req)
}

#[tauri::command]
pub fn trust_provider_discover(
    req: rpc::TrustProviderDiscoverReq,
) -> rpc::RpcResponse<rpc::TrustProviderRes> {
    rpc::trust_provider_discover_rpc(req)
}

#[tauri::command]
pub fn trust_policy_set(req: rpc::TrustPolicySetReq) -> rpc::RpcResponse<rpc::TrustPolicySetRes> {
    rpc::trust_policy_set_rpc(req)
}

#[tauri::command]
pub fn trust_policy_set_tenant_template(
    req: rpc::TrustPolicySetTenantTemplateReq,
) -> rpc::RpcResponse<rpc::TrustPolicySetRes> {
    rpc::trust_policy_set_tenant_template_rpc(req)
}

#[tauri::command]
pub fn vault_lock_status(
    req: rpc::VaultLockStatusReq,
) -> rpc::RpcResponse<rpc::VaultLockStatusRes> {
    rpc::vault_lock_status_rpc(req)
}

#[tauri::command]
pub fn vault_unlock(req: rpc::VaultUnlockReq) -> rpc::RpcResponse<rpc::VaultUnlockRes> {
    rpc::vault_unlock_rpc(req)
}

#[tauri::command]
pub fn vault_lock(req: rpc::VaultLockReq) -> rpc::RpcResponse<rpc::VaultLockRes> {
    rpc::vault_lock_rpc(req)
}

#[tauri::command]
pub fn vault_encryption_status(
    req: rpc::VaultEncryptionStatusReq,
) -> rpc::RpcResponse<rpc::VaultEncryptionStatusRes> {
    rpc::vault_encryption_status_rpc(req)
}

#[tauri::command]
pub fn vault_encryption_enable(
    req: rpc::VaultEncryptionEnableReq,
) -> rpc::RpcResponse<rpc::VaultEncryptionEnableRes> {
    rpc::vault_encryption_enable_rpc(req)
}

#[tauri::command]
pub fn vault_encryption_migrate(
    req: rpc::VaultEncryptionMigrateReq,
) -> rpc::RpcResponse<rpc::VaultEncryptionMigrateRes> {
    rpc::vault_encryption_migrate_rpc(req)
}

#[tauri::command]
pub fn vault_recovery_status(
    req: rpc::VaultRecoveryStatusReq,
) -> rpc::RpcResponse<rpc::VaultRecoveryStatusRes> {
    rpc::vault_recovery_status_rpc(req)
}

#[tauri::command]
pub fn vault_recovery_generate(
    req: rpc::VaultRecoveryGenerateReq,
) -> rpc::RpcResponse<rpc::VaultRecoveryGenerateRes> {
    rpc::vault_recovery_generate_rpc(req)
}

#[tauri::command]
pub fn vault_recovery_verify(
    req: rpc::VaultRecoveryVerifyReq,
) -> rpc::RpcResponse<rpc::VaultRecoveryVerifyRes> {
    rpc::vault_recovery_verify_rpc(req)
}

#[tauri::command]
pub fn vault_recovery_escrow_status(
    req: rpc::VaultRecoveryEscrowStatusReq,
) -> rpc::RpcResponse<rpc::VaultRecoveryEscrowStatusRes> {
    rpc::vault_recovery_escrow_status_rpc(req)
}

#[tauri::command]
pub fn vault_recovery_escrow_enable(
    req: rpc::VaultRecoveryEscrowEnableReq,
) -> rpc::RpcResponse<rpc::VaultRecoveryEscrowEnableRes> {
    rpc::vault_recovery_escrow_enable_rpc(req)
}

#[tauri::command]
pub fn vault_recovery_escrow_rotate(
    req: rpc::VaultRecoveryEscrowRotateReq,
) -> rpc::RpcResponse<rpc::VaultRecoveryEscrowRotateRes> {
    rpc::vault_recovery_escrow_rotate_rpc(req)
}

#[tauri::command]
pub fn vault_recovery_escrow_restore(
    req: rpc::VaultRecoveryEscrowRestoreReq,
) -> rpc::RpcResponse<rpc::VaultRecoveryEscrowRestoreRes> {
    rpc::vault_recovery_escrow_restore_rpc(req)
}

#[tauri::command]
pub fn vault_recovery_escrow_provider_add(
    req: rpc::VaultRecoveryEscrowProviderAddReq,
) -> rpc::RpcResponse<rpc::VaultRecoveryEscrowProviderAddRes> {
    rpc::vault_recovery_escrow_provider_add_rpc(req)
}

#[tauri::command]
pub fn vault_recovery_escrow_provider_list(
    req: rpc::VaultRecoveryEscrowProviderListReq,
) -> rpc::RpcResponse<rpc::VaultRecoveryEscrowProviderListRes> {
    rpc::vault_recovery_escrow_provider_list_rpc(req)
}

#[tauri::command]
pub fn vault_recovery_escrow_rotate_all(
    req: rpc::VaultRecoveryEscrowRotateAllReq,
) -> rpc::RpcResponse<rpc::VaultRecoveryEscrowRotateAllRes> {
    rpc::vault_recovery_escrow_rotate_all_rpc(req)
}

#[tauri::command]
pub fn ingest_scan_folder(
    req: rpc::IngestScanFolderReq,
) -> rpc::RpcResponse<rpc::IngestScanFolderRes> {
    rpc::ingest_scan_folder_rpc(req)
}

#[tauri::command]
pub fn ingest_inbox_start(
    req: rpc::IngestInboxStartReq,
) -> rpc::RpcResponse<rpc::IngestInboxStartRes> {
    rpc::ingest_inbox_start_rpc(req)
}

#[tauri::command]
pub fn ingest_inbox_stop(
    req: rpc::IngestInboxStopReq,
) -> rpc::RpcResponse<rpc::IngestInboxStopRes> {
    rpc::ingest_inbox_stop_rpc(req)
}

#[tauri::command]
pub fn search_query(req: rpc::SearchQueryReq) -> rpc::RpcResponse<rpc::SearchQueryRes> {
    rpc::search_query_rpc(req)
}

#[tauri::command]
pub fn locator_resolve(req: rpc::LocatorResolveReq) -> rpc::RpcResponse<rpc::LocatorResolveRes> {
    rpc::locator_resolve_rpc(req)
}

#[tauri::command]
pub fn export_bundle(req: rpc::ExportBundleReq) -> rpc::RpcResponse<rpc::ExportBundleRes> {
    rpc::export_bundle_rpc(req)
}

#[tauri::command]
pub fn verify_bundle(req: rpc::VerifyBundleReq) -> rpc::RpcResponse<rpc::VerifyBundleRes> {
    rpc::verify_bundle_rpc(req)
}

#[tauri::command]
pub fn ask_question(req: rpc::AskQuestionReq) -> rpc::RpcResponse<rpc::AskQuestionRes> {
    rpc::ask_question_rpc(req)
}

#[tauri::command]
pub fn events_list(req: rpc::EventsListReq) -> rpc::RpcResponse<rpc::EventsListRes> {
    rpc::events_list_rpc(req)
}

#[tauri::command]
pub fn jobs_list(req: rpc::JobsListReq) -> rpc::RpcResponse<rpc::JobsListRes> {
    rpc::jobs_list_rpc(req)
}

#[tauri::command]
pub fn sync_status(req: rpc::SyncStatusReq) -> rpc::RpcResponse<rpc::SyncStatusRes> {
    rpc::sync_status_rpc(req)
}

#[tauri::command]
pub fn sync_push(req: rpc::SyncPushReq) -> rpc::RpcResponse<rpc::SyncPushRes> {
    rpc::sync_push_rpc(req)
}

#[tauri::command]
pub fn sync_pull(req: rpc::SyncPullReq) -> rpc::RpcResponse<rpc::SyncPullRes> {
    rpc::sync_pull_rpc(req)
}

#[tauri::command]
pub fn sync_merge_preview(
    req: rpc::SyncMergePreviewReq,
) -> rpc::RpcResponse<rpc::SyncMergePreviewRes> {
    rpc::sync_merge_preview_rpc(req)
}

#[tauri::command]
pub fn lineage_query(req: rpc::LineageQueryReq) -> rpc::RpcResponse<rpc::LineageQueryRes> {
    rpc::lineage_query_rpc(req)
}

#[tauri::command]
pub fn lineage_query_v2(req: rpc::LineageQueryV2Req) -> rpc::RpcResponse<rpc::LineageQueryV2Res> {
    rpc::lineage_query_v2_rpc(req)
}

#[tauri::command]
pub fn lineage_overlay_add(
    req: rpc::LineageOverlayAddReq,
) -> rpc::RpcResponse<rpc::LineageOverlayAddRes> {
    rpc::lineage_overlay_add_rpc(req)
}

#[tauri::command]
pub fn lineage_overlay_remove(
    req: rpc::LineageOverlayRemoveReq,
) -> rpc::RpcResponse<rpc::LineageOverlayRemoveRes> {
    rpc::lineage_overlay_remove_rpc(req)
}

#[tauri::command]
pub fn lineage_overlay_list(
    req: rpc::LineageOverlayListReq,
) -> rpc::RpcResponse<rpc::LineageOverlayListRes> {
    rpc::lineage_overlay_list_rpc(req)
}

#[tauri::command]
pub fn lineage_lock_acquire(
    req: rpc::LineageLockAcquireReq,
) -> rpc::RpcResponse<rpc::LineageLockAcquireRes> {
    rpc::lineage_lock_acquire_rpc(req)
}

#[tauri::command]
pub fn lineage_lock_release(
    req: rpc::LineageLockReleaseReq,
) -> rpc::RpcResponse<rpc::LineageLockReleaseRes> {
    rpc::lineage_lock_release_rpc(req)
}

#[tauri::command]
pub fn lineage_lock_status(
    req: rpc::LineageLockStatusReq,
) -> rpc::RpcResponse<rpc::LineageLockStatusRes> {
    rpc::lineage_lock_status_rpc(req)
}

#[tauri::command]
pub fn lineage_role_grant(
    req: rpc::LineageRoleGrantReq,
) -> rpc::RpcResponse<rpc::LineageRoleGrantRes> {
    rpc::lineage_role_grant_rpc(req)
}

#[tauri::command]
pub fn lineage_role_revoke(
    req: rpc::LineageRoleRevokeReq,
) -> rpc::RpcResponse<rpc::LineageRoleRevokeRes> {
    rpc::lineage_role_revoke_rpc(req)
}

#[tauri::command]
pub fn lineage_role_list(
    req: rpc::LineageRoleListReq,
) -> rpc::RpcResponse<rpc::LineageRoleListRes> {
    rpc::lineage_role_list_rpc(req)
}

#[tauri::command]
pub fn lineage_policy_add(
    req: rpc::LineagePolicyAddReq,
) -> rpc::RpcResponse<rpc::LineagePolicyAddRes> {
    rpc::lineage_policy_add_rpc(req)
}

#[tauri::command]
pub fn lineage_policy_bind(
    req: rpc::LineagePolicyBindReq,
) -> rpc::RpcResponse<rpc::LineagePolicyBindRes> {
    rpc::lineage_policy_bind_rpc(req)
}

#[tauri::command]
pub fn lineage_policy_list(
    req: rpc::LineagePolicyListReq,
) -> rpc::RpcResponse<rpc::LineagePolicyListRes> {
    rpc::lineage_policy_list_rpc(req)
}

#[tauri::command]
pub fn lineage_lock_acquire_scope(
    req: rpc::LineageLockAcquireScopeReq,
) -> rpc::RpcResponse<rpc::LineageLockAcquireScopeRes> {
    rpc::lineage_lock_acquire_scope_rpc(req)
}
