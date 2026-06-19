use apps_desktop_tauri::rpc::{
    AskQuestionReq, LineageLockAcquireReq, LineageLockAcquireScopeReq, LineageLockReleaseReq,
    LineageLockStatusReq, LineageOverlayAddReq, LineageOverlayListReq, LineageOverlayRemoveReq,
    LineagePolicyAddReq, LineagePolicyBindReq, LineagePolicyListReq, LineageQueryReq,
    LineageQueryV2Req, LineageRoleGrantReq, LineageRoleListReq, LineageRoleRevokeReq,
    SearchQueryReq, SyncMergePreviewReq, SyncPullReq, SyncPushReq, SyncStatusReq,
    TrustDeviceEnrollReq, TrustDeviceEnrollSigningKeyReq, TrustDeviceListReq,
    TrustDeviceSigningKeyDeleteReq, TrustDeviceSigningKeyRotateReq, TrustDeviceSigningKeyStatusReq,
    TrustDeviceVerifyChainReq, TrustIdentityCompleteReq, TrustIdentityStartReq, TrustPolicySetReq,
    TrustPolicySetTenantTemplateReq, TrustProviderAddReq, TrustProviderDisableReq,
    TrustProviderDiscoverReq, TrustProviderListReq, VaultEncryptionEnableReq,
    VaultEncryptionMigrateReq, VaultEncryptionStatusReq, VaultInitReq, VaultLockReq,
    VaultLockStatusReq, VaultRecoveryEscrowEnableReq, VaultRecoveryEscrowProviderAddReq,
    VaultRecoveryEscrowProviderListReq, VaultRecoveryEscrowRestoreReq,
    VaultRecoveryEscrowRotateAllReq, VaultRecoveryEscrowRotateReq, VaultRecoveryEscrowStatusReq,
    VaultRecoveryGenerateReq, VaultRecoveryStatusReq, VaultRecoveryVerifyReq, VaultUnlockReq,
};

#[test]
fn rpc_schema_requires_now_ms_on_deterministic_requests() {
    let missing_vault_now = serde_json::json!({
        "vault_path": "/tmp/vault",
        "vault_slug": "demo"
    });
    let missing_search_now = serde_json::json!({
        "vault_path": "/tmp/vault",
        "query": "foo"
    });
    let missing_ask_now = serde_json::json!({
        "vault_path": "/tmp/vault",
        "question": "What happened?"
    });

    assert!(serde_json::from_value::<VaultInitReq>(missing_vault_now).is_err());
    assert!(serde_json::from_value::<SearchQueryReq>(missing_search_now).is_err());
    assert!(serde_json::from_value::<AskQuestionReq>(missing_ask_now).is_err());
}

#[test]
fn rpc_schema_rejects_unknown_fields() {
    let req = serde_json::json!({
        "vault_path": "/tmp/vault",
        "query": "foo",
        "now_ms": 123,
        "extra": "nope"
    });
    assert!(serde_json::from_value::<SearchQueryReq>(req).is_err());

    let invalid_status = serde_json::json!({
        "vault_path": "/tmp/vault",
        "extra": "nope"
    });
    assert!(serde_json::from_value::<VaultEncryptionStatusReq>(invalid_status).is_err());

    let invalid_enable = serde_json::json!({
        "vault_path": "/tmp/vault",
        "passphrase": "secret",
        "extra": "nope"
    });
    assert!(serde_json::from_value::<VaultEncryptionEnableReq>(invalid_enable).is_err());

    let invalid_unlock = serde_json::json!({
        "vault_path": "/tmp/vault",
        "passphrase": "secret",
        "extra": "nope"
    });
    assert!(serde_json::from_value::<VaultUnlockReq>(invalid_unlock).is_err());

    let invalid_lock = serde_json::json!({
        "vault_path": "/tmp/vault",
        "extra": "nope"
    });
    assert!(serde_json::from_value::<VaultLockReq>(invalid_lock).is_err());
}

#[test]
fn rpc_schema_requires_now_ms_for_encryption_migrate() {
    let missing_now = serde_json::json!({
        "vault_path": "/tmp/vault",
        "passphrase": "secret"
    });
    assert!(serde_json::from_value::<VaultEncryptionMigrateReq>(missing_now).is_err());

    let missing_sync_now = serde_json::json!({
        "vault_path": "/tmp/vault",
        "target_path": "/tmp/target"
    });
    assert!(serde_json::from_value::<SyncPushReq>(missing_sync_now.clone()).is_err());
    assert!(serde_json::from_value::<SyncPullReq>(missing_sync_now).is_err());
}

#[test]
fn rpc_schema_requires_now_ms_for_recovery_generate() {
    let missing_now = serde_json::json!({
        "vault_path": "/tmp/vault",
        "output_dir": "/tmp/out",
        "passphrase": "secret"
    });
    assert!(serde_json::from_value::<VaultRecoveryGenerateReq>(missing_now).is_err());

    let missing_enable_now = serde_json::json!({
        "vault_path": "/tmp/vault",
        "provider": "aws"
    });
    assert!(serde_json::from_value::<VaultRecoveryEscrowEnableReq>(missing_enable_now).is_err());

    let missing_rotate_now = serde_json::json!({
        "vault_path": "/tmp/vault",
        "passphrase": "secret"
    });
    assert!(serde_json::from_value::<VaultRecoveryEscrowRotateReq>(missing_rotate_now).is_err());

    let missing_restore_now = serde_json::json!({
        "vault_path": "/tmp/vault",
        "bundle_path": "/tmp/out/recovery"
    });
    assert!(serde_json::from_value::<VaultRecoveryEscrowRestoreReq>(missing_restore_now).is_err());
}

#[test]
fn rpc_schema_recovery_requests_validate_shapes() {
    let status = serde_json::json!({
        "vault_path": "/tmp/vault"
    });
    assert!(serde_json::from_value::<VaultRecoveryStatusReq>(status).is_ok());

    let generate = serde_json::json!({
        "vault_path": "/tmp/vault",
        "output_dir": "/tmp/out",
        "passphrase": "secret",
        "now_ms": 123
    });
    assert!(serde_json::from_value::<VaultRecoveryGenerateReq>(generate).is_ok());

    let verify = serde_json::json!({
        "vault_path": "/tmp/vault",
        "bundle_path": "/tmp/out/recovery",
        "recovery_phrase": "abcd-efgh"
    });
    assert!(serde_json::from_value::<VaultRecoveryVerifyReq>(verify).is_ok());

    let escrow_status = serde_json::json!({
        "vault_path": "/tmp/vault"
    });
    assert!(serde_json::from_value::<VaultRecoveryEscrowStatusReq>(escrow_status).is_ok());

    let escrow_enable = serde_json::json!({
        "vault_path": "/tmp/vault",
        "provider": "aws",
        "now_ms": 100
    });
    assert!(serde_json::from_value::<VaultRecoveryEscrowEnableReq>(escrow_enable).is_ok());

    let escrow_rotate = serde_json::json!({
        "vault_path": "/tmp/vault",
        "passphrase": "secret",
        "now_ms": 101
    });
    assert!(serde_json::from_value::<VaultRecoveryEscrowRotateReq>(escrow_rotate).is_ok());

    let escrow_restore = serde_json::json!({
        "vault_path": "/tmp/vault",
        "bundle_path": "/tmp/out/recovery",
        "now_ms": 102
    });
    assert!(serde_json::from_value::<VaultRecoveryEscrowRestoreReq>(escrow_restore).is_ok());

    let escrow_provider_add = serde_json::json!({
        "vault_path": "/tmp/vault",
        "provider": "aws",
        "config_ref": "kms://alias/kc",
        "now_ms": 103
    });
    assert!(
        serde_json::from_value::<VaultRecoveryEscrowProviderAddReq>(escrow_provider_add).is_ok()
    );

    let escrow_provider_list = serde_json::json!({
        "vault_path": "/tmp/vault"
    });
    assert!(
        serde_json::from_value::<VaultRecoveryEscrowProviderListReq>(escrow_provider_list).is_ok()
    );

    let escrow_rotate_all = serde_json::json!({
        "vault_path": "/tmp/vault",
        "passphrase": "secret",
        "now_ms": 104
    });
    assert!(serde_json::from_value::<VaultRecoveryEscrowRotateAllReq>(escrow_rotate_all).is_ok());
}

#[test]
fn rpc_schema_recovery_rejects_unknown_fields() {
    let invalid = serde_json::json!({
        "vault_path": "/tmp/vault",
        "extra": "nope"
    });
    assert!(serde_json::from_value::<VaultRecoveryStatusReq>(invalid).is_err());

    let invalid_escrow = serde_json::json!({
        "vault_path": "/tmp/vault",
        "provider": "aws",
        "now_ms": 100,
        "extra": "nope"
    });
    assert!(serde_json::from_value::<VaultRecoveryEscrowEnableReq>(invalid_escrow).is_err());

    let invalid_provider_add = serde_json::json!({
        "vault_path": "/tmp/vault",
        "provider": "aws",
        "config_ref": "kms://alias/kc",
        "extra": "nope"
    });
    assert!(
        serde_json::from_value::<VaultRecoveryEscrowProviderAddReq>(invalid_provider_add).is_err()
    );
}

#[test]
fn rpc_schema_sync_rejects_unknown_fields() {
    let invalid_status = serde_json::json!({
        "vault_path": "/tmp/vault",
        "target_path": "/tmp/target",
        "extra": "nope"
    });
    assert!(serde_json::from_value::<SyncStatusReq>(invalid_status).is_err());
}

#[test]
fn rpc_schema_sync_accepts_uri_targets() {
    let status = serde_json::json!({
        "vault_path": "/tmp/vault",
        "target_path": "s3://demo-bucket/kc"
    });
    assert!(serde_json::from_value::<SyncStatusReq>(status).is_ok());

    let push = serde_json::json!({
        "vault_path": "/tmp/vault",
        "target_path": "s3://demo-bucket/kc",
        "now_ms": 123
    });
    assert!(serde_json::from_value::<SyncPushReq>(push.clone()).is_ok());
    assert!(serde_json::from_value::<SyncPullReq>(push).is_ok());

    let pull_with_merge = serde_json::json!({
        "vault_path": "/tmp/vault",
        "target_path": "s3://demo-bucket/kc",
        "auto_merge": "conservative",
        "now_ms": 124
    });
    assert!(serde_json::from_value::<SyncPullReq>(pull_with_merge).is_ok());

    let pull_with_merge_v2 = serde_json::json!({
        "vault_path": "/tmp/vault",
        "target_path": "s3://demo-bucket/kc",
        "auto_merge": "conservative_plus_v2",
        "now_ms": 125
    });
    assert!(serde_json::from_value::<SyncPullReq>(pull_with_merge_v2).is_ok());

    let pull_with_merge_v3 = serde_json::json!({
        "vault_path": "/tmp/vault",
        "target_path": "s3://demo-bucket/kc",
        "auto_merge": "conservative_plus_v3",
        "now_ms": 126
    });
    assert!(serde_json::from_value::<SyncPullReq>(pull_with_merge_v3).is_ok());

    let pull_with_merge_v4 = serde_json::json!({
        "vault_path": "/tmp/vault",
        "target_path": "s3://demo-bucket/kc",
        "auto_merge": "conservative_plus_v4",
        "now_ms": 127
    });
    assert!(serde_json::from_value::<SyncPullReq>(pull_with_merge_v4).is_ok());
}

#[test]
fn rpc_schema_sync_merge_preview_requires_now_ms() {
    let missing_now = serde_json::json!({
        "vault_path": "/tmp/vault",
        "target_path": "s3://demo-bucket/kc"
    });
    assert!(serde_json::from_value::<SyncMergePreviewReq>(missing_now).is_err());

    let valid = serde_json::json!({
        "vault_path": "/tmp/vault",
        "target_path": "s3://demo-bucket/kc",
        "policy": "conservative_plus_v2",
        "now_ms": 123
    });
    assert!(serde_json::from_value::<SyncMergePreviewReq>(valid).is_ok());

    let valid_v3 = serde_json::json!({
        "vault_path": "/tmp/vault",
        "target_path": "s3://demo-bucket/kc",
        "policy": "conservative_plus_v3",
        "now_ms": 124
    });
    assert!(serde_json::from_value::<SyncMergePreviewReq>(valid_v3).is_ok());

    let valid_v4 = serde_json::json!({
        "vault_path": "/tmp/vault",
        "target_path": "s3://demo-bucket/kc",
        "policy": "conservative_plus_v4",
        "now_ms": 125
    });
    assert!(serde_json::from_value::<SyncMergePreviewReq>(valid_v4).is_ok());
}

#[test]
fn rpc_schema_lock_requests_validate_shapes() {
    let lock_status = serde_json::json!({
        "vault_path": "/tmp/vault"
    });
    assert!(serde_json::from_value::<VaultLockStatusReq>(lock_status).is_ok());

    let unlock = serde_json::json!({
        "vault_path": "/tmp/vault",
        "passphrase": "secret"
    });
    assert!(serde_json::from_value::<VaultUnlockReq>(unlock).is_ok());
}

#[test]
fn rpc_schema_trust_identity_requests_validate_shapes() {
    let start = serde_json::json!({
        "vault_path": "/tmp/vault",
        "provider": "default",
        "now_ms": 100
    });
    assert!(serde_json::from_value::<TrustIdentityStartReq>(start).is_ok());

    let complete = serde_json::json!({
        "vault_path": "/tmp/vault",
        "provider": "default",
        "code": "auth-code",
        "now_ms": 101
    });
    assert!(serde_json::from_value::<TrustIdentityCompleteReq>(complete).is_ok());
}

#[test]
fn rpc_schema_trust_identity_requires_now_ms() {
    let missing_now_start = serde_json::json!({
        "vault_path": "/tmp/vault",
        "provider": "default"
    });
    assert!(serde_json::from_value::<TrustIdentityStartReq>(missing_now_start).is_err());

    let missing_now_complete = serde_json::json!({
        "vault_path": "/tmp/vault",
        "provider": "default",
        "code": "auth-code"
    });
    assert!(serde_json::from_value::<TrustIdentityCompleteReq>(missing_now_complete).is_err());
}

#[test]
fn rpc_schema_trust_device_requests_validate_shapes() {
    let enroll = serde_json::json!({
        "vault_path": "/tmp/vault",
        "device_label": "desktop",
        "now_ms": 102
    });
    assert!(serde_json::from_value::<TrustDeviceEnrollReq>(enroll).is_ok());

    let verify_chain = serde_json::json!({
        "vault_path": "/tmp/vault",
        "device_id": "device-1",
        "now_ms": 103
    });
    assert!(serde_json::from_value::<TrustDeviceVerifyChainReq>(verify_chain).is_ok());

    let enroll_signing_key = serde_json::json!({
        "vault_path": "/tmp/vault",
        "device_label": "desktop",
        "passphrase": "secret",
        "now_ms": 104
    });
    assert!(serde_json::from_value::<TrustDeviceEnrollSigningKeyReq>(enroll_signing_key).is_ok());

    let signing_key_status = serde_json::json!({
        "vault_path": "/tmp/vault",
        "device_id": "device-1"
    });
    assert!(serde_json::from_value::<TrustDeviceSigningKeyStatusReq>(signing_key_status).is_ok());

    let signing_key_delete = serde_json::json!({
        "vault_path": "/tmp/vault",
        "device_id": "device-1",
        "now_ms": 105
    });
    assert!(serde_json::from_value::<TrustDeviceSigningKeyDeleteReq>(signing_key_delete).is_ok());

    let signing_key_rotate = serde_json::json!({
        "vault_path": "/tmp/vault",
        "old_device_id": "device-1",
        "new_device_label": "desktop-rotated",
        "passphrase": "secret",
        "now_ms": 106
    });
    assert!(serde_json::from_value::<TrustDeviceSigningKeyRotateReq>(signing_key_rotate).is_ok());

    let list = serde_json::json!({
        "vault_path": "/tmp/vault"
    });
    assert!(serde_json::from_value::<TrustDeviceListReq>(list).is_ok());
}

#[test]
fn rpc_schema_trust_device_rejects_unknown_fields() {
    let invalid = serde_json::json!({
        "vault_path": "/tmp/vault",
        "device_label": "desktop",
        "now_ms": 102,
        "extra": "nope"
    });
    assert!(serde_json::from_value::<TrustDeviceEnrollReq>(invalid).is_err());

    let invalid_rotate = serde_json::json!({
        "vault_path": "/tmp/vault",
        "old_device_id": "device-1",
        "new_device_label": "desktop-rotated",
        "passphrase": "secret",
        "extra": "nope"
    });
    assert!(serde_json::from_value::<TrustDeviceSigningKeyRotateReq>(invalid_rotate).is_err());
}

#[test]
fn rpc_schema_trust_provider_requests_validate_shapes() {
    let add = serde_json::json!({
        "vault_path": "/tmp/vault",
        "provider_id": "corp",
        "issuer": "https://corp.example/oidc",
        "aud": "kc-desktop:corp",
        "jwks": "https://corp.example/oidc/jwks",
        "now_ms": 200
    });
    assert!(serde_json::from_value::<TrustProviderAddReq>(add).is_ok());

    let disable = serde_json::json!({
        "vault_path": "/tmp/vault",
        "provider_id": "corp",
        "now_ms": 201
    });
    assert!(serde_json::from_value::<TrustProviderDisableReq>(disable).is_ok());

    let list = serde_json::json!({
        "vault_path": "/tmp/vault"
    });
    assert!(serde_json::from_value::<TrustProviderListReq>(list).is_ok());

    let discover = serde_json::json!({
        "vault_path": "/tmp/vault",
        "issuer": "https://corp.example/oidc",
        "now_ms": 201
    });
    assert!(serde_json::from_value::<TrustProviderDiscoverReq>(discover).is_ok());

    let policy_set = serde_json::json!({
        "vault_path": "/tmp/vault",
        "provider_id": "corp",
        "max_clock_skew_ms": 5000,
        "require_claims_json": "{\"aud\":\"kc-desktop:corp\",\"iss\":\"https://corp.example/oidc\"}",
        "now_ms": 202
    });
    assert!(serde_json::from_value::<TrustPolicySetReq>(policy_set).is_ok());

    let policy_template = serde_json::json!({
        "vault_path": "/tmp/vault",
        "provider": "https://corp.example/oidc",
        "tenant_id": "tenant-a",
        "now_ms": 203
    });
    assert!(serde_json::from_value::<TrustPolicySetTenantTemplateReq>(policy_template).is_ok());
}

#[test]
fn rpc_schema_trust_provider_rejects_unknown_fields_and_missing_now_ms() {
    let missing_now = serde_json::json!({
        "vault_path": "/tmp/vault",
        "provider_id": "corp",
        "issuer": "https://corp.example/oidc",
        "aud": "kc-desktop:corp",
        "jwks": "https://corp.example/oidc/jwks"
    });
    assert!(serde_json::from_value::<TrustProviderAddReq>(missing_now).is_err());

    let extra_field = serde_json::json!({
        "vault_path": "/tmp/vault",
        "provider_id": "corp",
        "now_ms": 1,
        "extra": "nope"
    });
    assert!(serde_json::from_value::<TrustProviderDisableReq>(extra_field).is_err());

    let bad_policy = serde_json::json!({
        "vault_path": "/tmp/vault",
        "provider_id": "corp",
        "max_clock_skew_ms": 5000,
        "require_claims_json": "{}",
        "now_ms": 202,
        "extra": "nope"
    });
    assert!(serde_json::from_value::<TrustPolicySetReq>(bad_policy).is_err());

    let missing_tenant_template_now = serde_json::json!({
        "vault_path": "/tmp/vault",
        "provider": "corp",
        "tenant_id": "tenant-a"
    });
    assert!(
        serde_json::from_value::<TrustPolicySetTenantTemplateReq>(missing_tenant_template_now)
            .is_err()
    );
}

#[test]
fn rpc_schema_requires_now_ms_for_lineage_query() {
    let missing_now = serde_json::json!({
        "vault_path": "/tmp/vault",
        "seed_doc_id": "doc-1",
        "depth": 1
    });
    assert!(serde_json::from_value::<LineageQueryReq>(missing_now).is_err());
}

#[test]
fn rpc_schema_lineage_rejects_unknown_fields() {
    let invalid = serde_json::json!({
        "vault_path": "/tmp/vault",
        "seed_doc_id": "doc-1",
        "depth": 1,
        "now_ms": 123,
        "extra": "nope"
    });
    assert!(serde_json::from_value::<LineageQueryReq>(invalid).is_err());
}

#[test]
fn rpc_schema_requires_now_ms_for_lineage_query_v2() {
    let missing_now = serde_json::json!({
        "vault_path": "/tmp/vault",
        "seed_doc_id": "doc-1",
        "depth": 1
    });
    assert!(serde_json::from_value::<LineageQueryV2Req>(missing_now).is_err());
}

#[test]
fn rpc_schema_lineage_overlay_add_requires_created_at_ms() {
    let missing_created_at = serde_json::json!({
        "vault_path": "/tmp/vault",
        "doc_id": "doc-1",
        "from_node_id": "doc:doc-1",
        "to_node_id": "chunk:c1",
        "relation": "supports",
        "evidence": "manual",
        "lock_token": "blake3:token"
    });
    assert!(serde_json::from_value::<LineageOverlayAddReq>(missing_created_at).is_err());
}

#[test]
fn rpc_schema_lineage_overlay_add_requires_lock_token() {
    let missing_lock_token = serde_json::json!({
        "vault_path": "/tmp/vault",
        "doc_id": "doc-1",
        "from_node_id": "doc:doc-1",
        "to_node_id": "chunk:c1",
        "relation": "supports",
        "evidence": "manual",
        "created_at_ms": 123
    });
    assert!(serde_json::from_value::<LineageOverlayAddReq>(missing_lock_token).is_err());
}

#[test]
fn rpc_schema_lineage_overlay_requests_validate_shapes() {
    let add = serde_json::json!({
        "vault_path": "/tmp/vault",
        "doc_id": "doc-1",
        "from_node_id": "doc:doc-1",
        "to_node_id": "chunk:c1",
        "relation": "supports",
        "evidence": "manual",
        "lock_token": "blake3:token",
        "created_at_ms": 123,
        "created_by": "user"
    });
    assert!(serde_json::from_value::<LineageOverlayAddReq>(add).is_ok());

    let list = serde_json::json!({
        "vault_path": "/tmp/vault",
        "doc_id": "doc-1"
    });
    assert!(serde_json::from_value::<LineageOverlayListReq>(list).is_ok());

    let remove = serde_json::json!({
        "vault_path": "/tmp/vault",
        "overlay_id": "blake3:abcd",
        "lock_token": "blake3:token",
        "now_ms": 124
    });
    assert!(serde_json::from_value::<LineageOverlayRemoveReq>(remove).is_ok());
}

#[test]
fn rpc_schema_lineage_overlay_rejects_unknown_fields() {
    let invalid = serde_json::json!({
        "vault_path": "/tmp/vault",
        "overlay_id": "blake3:abcd",
        "lock_token": "blake3:token",
        "now_ms": 124,
        "extra": "nope"
    });
    assert!(serde_json::from_value::<LineageOverlayRemoveReq>(invalid).is_err());
}

#[test]
fn rpc_schema_lineage_lock_requests_validate_shapes() {
    let acquire = serde_json::json!({
        "vault_path": "/tmp/vault",
        "doc_id": "doc-1",
        "owner": "desktop",
        "now_ms": 100
    });
    assert!(serde_json::from_value::<LineageLockAcquireReq>(acquire).is_ok());

    let status = serde_json::json!({
        "vault_path": "/tmp/vault",
        "doc_id": "doc-1",
        "now_ms": 101
    });
    assert!(serde_json::from_value::<LineageLockStatusReq>(status).is_ok());

    let release = serde_json::json!({
        "vault_path": "/tmp/vault",
        "doc_id": "doc-1",
        "token": "blake3:token"
    });
    assert!(serde_json::from_value::<LineageLockReleaseReq>(release).is_ok());
}

#[test]
fn rpc_schema_lineage_lock_rejects_unknown_fields() {
    let invalid = serde_json::json!({
        "vault_path": "/tmp/vault",
        "doc_id": "doc-1",
        "owner": "desktop",
        "now_ms": 100,
        "extra": "nope"
    });
    assert!(serde_json::from_value::<LineageLockAcquireReq>(invalid).is_err());
}

#[test]
fn rpc_schema_lineage_role_requests_validate_shapes() {
    let grant = serde_json::json!({
        "vault_path": "/tmp/vault",
        "subject": "user-a",
        "role": "editor",
        "granted_by": "desktop",
        "now_ms": 200
    });
    assert!(serde_json::from_value::<LineageRoleGrantReq>(grant).is_ok());

    let list = serde_json::json!({
        "vault_path": "/tmp/vault"
    });
    assert!(serde_json::from_value::<LineageRoleListReq>(list).is_ok());

    let revoke = serde_json::json!({
        "vault_path": "/tmp/vault",
        "subject": "user-a",
        "role": "editor"
    });
    assert!(serde_json::from_value::<LineageRoleRevokeReq>(revoke).is_ok());
}

#[test]
fn rpc_schema_lineage_role_rejects_unknown_fields() {
    let invalid = serde_json::json!({
        "vault_path": "/tmp/vault",
        "subject": "user-a",
        "role": "editor",
        "now_ms": 200,
        "extra": "nope"
    });
    assert!(serde_json::from_value::<LineageRoleGrantReq>(invalid).is_err());
}

#[test]
fn rpc_schema_lineage_lock_acquire_scope_requires_fields() {
    let missing_scope = serde_json::json!({
        "vault_path": "/tmp/vault",
        "scope_value": "doc-1",
        "owner": "desktop",
        "now_ms": 100
    });
    assert!(serde_json::from_value::<LineageLockAcquireScopeReq>(missing_scope).is_err());

    let valid = serde_json::json!({
        "vault_path": "/tmp/vault",
        "scope_kind": "doc",
        "scope_value": "doc-1",
        "owner": "desktop",
        "now_ms": 100
    });
    assert!(serde_json::from_value::<LineageLockAcquireScopeReq>(valid).is_ok());
}

#[test]
fn rpc_schema_lineage_policy_requests_validate_shapes() {
    let add = serde_json::json!({
        "vault_path": "/tmp/vault",
        "name": "allow-overlay",
        "effect": "allow",
        "condition_json": "{\"action\":\"lineage.overlay.write\",\"doc_id_suffix\":\"_release\",\"subject_id_prefix\":\"desktop-\"}",
        "created_by": "desktop",
        "now_ms": 300
    });
    assert!(serde_json::from_value::<LineagePolicyAddReq>(add).is_ok());

    let bind = serde_json::json!({
        "vault_path": "/tmp/vault",
        "subject": "user-a",
        "policy": "allow-overlay",
        "bound_by": "desktop",
        "now_ms": 301
    });
    assert!(serde_json::from_value::<LineagePolicyBindReq>(bind).is_ok());

    let list = serde_json::json!({
        "vault_path": "/tmp/vault"
    });
    assert!(serde_json::from_value::<LineagePolicyListReq>(list).is_ok());
}

#[test]
fn rpc_schema_lineage_policy_rejects_invalid_shapes() {
    let missing_now = serde_json::json!({
        "vault_path": "/tmp/vault",
        "name": "allow-overlay",
        "effect": "allow",
        "condition_json": "{}"
    });
    assert!(serde_json::from_value::<LineagePolicyAddReq>(missing_now).is_err());

    let invalid_bind = serde_json::json!({
        "vault_path": "/tmp/vault",
        "subject": "user-a",
        "policy": "allow-overlay",
        "now_ms": 301,
        "extra": "nope"
    });
    assert!(serde_json::from_value::<LineagePolicyBindReq>(invalid_bind).is_err());
}
