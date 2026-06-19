use apps_desktop_tauri::commands;
use apps_desktop_tauri::rpc::{
    ingest_inbox_start_rpc, ingest_inbox_stop_rpc, jobs_list_rpc, lineage_lock_acquire_rpc,
    lineage_lock_acquire_scope_rpc, lineage_lock_release_rpc, lineage_lock_status_rpc,
    lineage_overlay_add_rpc, lineage_overlay_list_rpc, lineage_overlay_remove_rpc,
    lineage_policy_add_rpc, lineage_policy_bind_rpc, lineage_policy_list_rpc, lineage_query_rpc,
    lineage_query_v2_rpc, lineage_role_grant_rpc, lineage_role_list_rpc, lineage_role_revoke_rpc,
    sync_auth_readiness_rpc, sync_merge_preview_rpc, sync_pull_rpc, sync_push_rpc, sync_status_rpc,
    trust_device_enroll_rpc, trust_device_enroll_signing_key_rpc, trust_device_list_rpc,
    trust_device_signing_key_delete_rpc, trust_device_signing_key_rotate_rpc,
    trust_device_signing_key_status_rpc, trust_device_verify_chain_rpc,
    trust_identity_complete_rpc, trust_identity_start_rpc, trust_policy_set_tenant_template_rpc,
    trust_provider_discover_rpc, vault_encryption_enable_rpc, vault_encryption_migrate_rpc,
    vault_encryption_status_rpc, vault_init_rpc, vault_lock_rpc, vault_lock_status_rpc,
    vault_open_rpc, vault_recovery_escrow_enable_rpc, vault_recovery_escrow_provider_add_rpc,
    vault_recovery_escrow_provider_list_rpc, vault_recovery_escrow_restore_rpc,
    vault_recovery_escrow_rotate_all_rpc, vault_recovery_escrow_rotate_rpc,
    vault_recovery_escrow_status_rpc, vault_recovery_generate_rpc, vault_recovery_status_rpc,
    vault_recovery_verify_rpc, vault_unlock_rpc, IngestInboxStartReq, IngestInboxStopReq,
    JobsListReq, LineageLockAcquireReq, LineageLockAcquireScopeReq, LineageLockReleaseReq,
    LineageLockStatusReq, LineageOverlayAddReq, LineageOverlayListReq, LineageOverlayRemoveReq,
    LineagePolicyAddReq, LineagePolicyBindReq, LineagePolicyListReq, LineageQueryReq,
    LineageQueryV2Req, LineageRoleGrantReq, LineageRoleListReq, LineageRoleRevokeReq, RpcResponse,
    SyncAuthReadinessReq, SyncMergePreviewReq, SyncPullReq, SyncPushReq, SyncStatusReq,
    TrustDeviceEnrollReq, TrustDeviceEnrollSigningKeyReq, TrustDeviceListReq,
    TrustDeviceSigningKeyDeleteReq, TrustDeviceSigningKeyRotateReq, TrustDeviceSigningKeyStatusReq,
    TrustDeviceVerifyChainReq, TrustIdentityCompleteReq, TrustIdentityStartReq,
    TrustPolicySetTenantTemplateReq, TrustProviderDiscoverReq, VaultEncryptionEnableReq,
    VaultEncryptionMigrateReq, VaultEncryptionStatusReq, VaultInitReq, VaultLockReq,
    VaultLockStatusReq, VaultOpenReq, VaultRecoveryEscrowEnableReq,
    VaultRecoveryEscrowProviderAddReq, VaultRecoveryEscrowProviderListReq,
    VaultRecoveryEscrowRestoreReq, VaultRecoveryEscrowRotateAllReq, VaultRecoveryEscrowRotateReq,
    VaultRecoveryEscrowStatusReq, VaultRecoveryGenerateReq, VaultRecoveryStatusReq,
    VaultRecoveryVerifyReq, VaultUnlockReq,
};
use kc_core::app_error::AppError;
use std::sync::{Mutex, OnceLock};

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[test]
fn rpc_envelope_success_shape() {
    let root = tempfile::tempdir().expect("tempdir").keep();
    let response = vault_init_rpc(VaultInitReq {
        vault_path: root.to_string_lossy().to_string(),
        vault_slug: "demo".to_string(),
        now_ms: 1,
    });

    match response {
        RpcResponse::Ok { ref data } => {
            assert!(!data.vault_id.is_empty());
        }
        RpcResponse::Err { .. } => panic!("expected success response"),
    }

    let serialized = serde_json::to_value(&response).expect("serialize rpc");
    assert_eq!(serialized.get("ok").and_then(|v| v.as_bool()), Some(true));
    assert!(serialized.get("data").is_some());
    assert!(serialized.get("error").is_none());
}

#[test]
fn rpc_envelope_error_shape() {
    let error = AppError::new("KC_RPC_FAIL", "rpc", "failed", true, serde_json::json!({}));
    let response: RpcResponse<()> = RpcResponse::err(error.clone());

    let serialized = serde_json::to_value(&response).expect("serialize rpc");
    assert_eq!(serialized.get("ok").and_then(|v| v.as_bool()), Some(false));
    assert!(serialized.get("data").is_none());
    assert_eq!(
        serialized
            .get("error")
            .and_then(|v| v.get("code"))
            .and_then(|v| v.as_str()),
        Some(error.code.as_str())
    );

    let round_trip: RpcResponse<()> = serde_json::from_value(serialized).expect("deserialize rpc");
    match round_trip {
        RpcResponse::Err { error: e } => assert_eq!(e.code, "KC_RPC_FAIL"),
        RpcResponse::Ok { .. } => panic!("expected error response"),
    }
}

#[test]
fn rpc_vault_open_and_jobs_list() {
    let root = tempfile::tempdir().expect("tempdir").keep();
    let init = vault_init_rpc(VaultInitReq {
        vault_path: root.to_string_lossy().to_string(),
        vault_slug: "demo".to_string(),
        now_ms: 1,
    });
    match init {
        RpcResponse::Ok { .. } => {}
        RpcResponse::Err { error } => panic!("vault init failed: {}", error.code),
    }

    let opened = vault_open_rpc(VaultOpenReq {
        vault_path: root.to_string_lossy().to_string(),
    });
    match opened {
        RpcResponse::Ok { data } => assert_eq!(data.vault_slug, "demo"),
        RpcResponse::Err { error } => panic!("vault open failed: {}", error.code),
    }

    let jobs = jobs_list_rpc(JobsListReq {
        vault_path: root.to_string_lossy().to_string(),
    });
    match jobs {
        RpcResponse::Ok { data } => assert!(data.jobs.is_empty()),
        RpcResponse::Err { error } => panic!("jobs list failed: {}", error.code),
    }
}

#[test]
fn rpc_trust_identity_and_device_workflow_round_trip() {
    let root = tempfile::tempdir().expect("tempdir").keep();

    let init = vault_init_rpc(VaultInitReq {
        vault_path: root.to_string_lossy().to_string(),
        vault_slug: "demo".to_string(),
        now_ms: 1,
    });
    match init {
        RpcResponse::Ok { .. } => {}
        RpcResponse::Err { error } => panic!("vault init failed: {}", error.code),
    }

    let started = trust_identity_start_rpc(TrustIdentityStartReq {
        vault_path: root.to_string_lossy().to_string(),
        provider: "default".to_string(),
        now_ms: 2,
    });
    match started {
        RpcResponse::Ok { data } => {
            assert_eq!(data.provider_id, "default");
            assert!(data.authorization_url.contains("state="));
        }
        RpcResponse::Err { error } => panic!("trust identity start failed: {}", error.code),
    }

    let completed = trust_identity_complete_rpc(TrustIdentityCompleteReq {
        vault_path: root.to_string_lossy().to_string(),
        provider: "default".to_string(),
        code: "sub:alice@example.com".to_string(),
        now_ms: 3,
    });
    match completed {
        RpcResponse::Ok { data } => {
            assert_eq!(data.provider_id, "default");
            assert_eq!(data.subject, "alice@example.com");
        }
        RpcResponse::Err { error } => panic!("trust identity complete failed: {}", error.code),
    }

    let enrolled = trust_device_enroll_rpc(TrustDeviceEnrollReq {
        vault_path: root.to_string_lossy().to_string(),
        device_label: "desktop".to_string(),
        now_ms: 4,
    });
    let device_id = match enrolled {
        RpcResponse::Ok { data } => {
            assert_eq!(data.label, "desktop");
            data.device_id
        }
        RpcResponse::Err { error } => panic!("trust device enroll failed: {}", error.code),
    };

    let verified = trust_device_verify_chain_rpc(TrustDeviceVerifyChainReq {
        vault_path: root.to_string_lossy().to_string(),
        device_id: device_id.clone(),
        now_ms: 5,
    });
    match verified {
        RpcResponse::Ok { data } => assert_eq!(data.device_id, device_id),
        RpcResponse::Err { error } => panic!("trust device verify-chain failed: {}", error.code),
    }

    let listed = trust_device_list_rpc(TrustDeviceListReq {
        vault_path: root.to_string_lossy().to_string(),
    });
    match listed {
        RpcResponse::Ok { data } => assert!(data.devices.iter().any(|d| d.device_id == device_id)),
        RpcResponse::Err { error } => panic!("trust device list failed: {}", error.code),
    }
}

#[test]
fn rpc_trust_device_signing_key_custody_round_trip() {
    let root = tempfile::tempdir().expect("tempdir").keep();
    let vault_path = root.to_string_lossy().to_string();

    match vault_init_rpc(VaultInitReq {
        vault_path: vault_path.clone(),
        vault_slug: "demo".to_string(),
        now_ms: 1,
    }) {
        RpcResponse::Ok { .. } => {}
        RpcResponse::Err { error } => panic!("vault init failed: {}", error.code),
    }

    match trust_identity_start_rpc(TrustIdentityStartReq {
        vault_path: vault_path.clone(),
        provider: "default".to_string(),
        now_ms: 2,
    }) {
        RpcResponse::Ok { .. } => {}
        RpcResponse::Err { error } => panic!("trust identity start failed: {}", error.code),
    }
    match trust_identity_complete_rpc(TrustIdentityCompleteReq {
        vault_path: vault_path.clone(),
        provider: "default".to_string(),
        code: "sub:alice@example.com".to_string(),
        now_ms: 3,
    }) {
        RpcResponse::Ok { .. } => {}
        RpcResponse::Err { error } => panic!("trust identity complete failed: {}", error.code),
    }

    let enrolled = trust_device_enroll_signing_key_rpc(TrustDeviceEnrollSigningKeyReq {
        vault_path: vault_path.clone(),
        device_label: "desktop".to_string(),
        passphrase: "custody-passphrase".to_string(),
        now_ms: 4,
    });
    let device_id = match enrolled {
        RpcResponse::Ok { data } => {
            assert_eq!(data.label, "desktop");
            assert_eq!(data.signing_key.signature_alg, "ed25519_sync_head_v1");
            assert!(data.signing_key.key_reference.starts_with("sync-signing:"));
            data.device_id
        }
        RpcResponse::Err { error } => {
            panic!("trust device enroll signing key failed: {}", error.code)
        }
    };

    match trust_device_signing_key_status_rpc(TrustDeviceSigningKeyStatusReq {
        vault_path: vault_path.clone(),
        device_id: device_id.clone(),
    }) {
        RpcResponse::Ok { data } => {
            let signing_key = data.signing_key.expect("signing key status");
            assert_eq!(signing_key.device_id, device_id);
            assert_eq!(signing_key.deleted_at_ms, None);
            assert!(data.recovery_guidance.is_none());
        }
        RpcResponse::Err { error } => panic!("signing key status failed: {}", error.code),
    }

    let rotated = trust_device_signing_key_rotate_rpc(TrustDeviceSigningKeyRotateReq {
        vault_path: vault_path.clone(),
        old_device_id: device_id.clone(),
        new_device_label: "desktop-rotated".to_string(),
        passphrase: "custody-passphrase".to_string(),
        now_ms: 5,
    });
    let new_device_id = match rotated {
        RpcResponse::Ok { data } => {
            assert_eq!(data.label, "desktop-rotated");
            assert_ne!(data.device_id, device_id);
            assert_eq!(data.old_signing_key.device_id, device_id);
            assert_eq!(data.old_signing_key.rotated_at_ms, Some(9));
            assert_eq!(data.old_signing_key.deleted_at_ms, Some(9));
            assert_eq!(data.signing_key.device_id, data.device_id);
            data.device_id
        }
        RpcResponse::Err { error } => panic!("signing key rotate failed: {}", error.code),
    };

    match trust_device_signing_key_status_rpc(TrustDeviceSigningKeyStatusReq {
        vault_path: vault_path.clone(),
        device_id: device_id.clone(),
    }) {
        RpcResponse::Ok { data } => {
            assert!(data.signing_key.is_none());
            let guidance = data.recovery_guidance.expect("old recovery guidance");
            assert_eq!(guidance.reason, "missing_or_retired");
            assert!(!guidance.private_key_recoverable);
            assert!(guidance
                .summary
                .contains("re-enroll a new local signing device"));
            assert!(guidance.command.contains("enroll-signing-key"));
        }
        RpcResponse::Err { error } => {
            panic!("old signing key status after rotate failed: {}", error.code)
        }
    }

    match trust_device_list_rpc(TrustDeviceListReq {
        vault_path: vault_path.clone(),
    }) {
        RpcResponse::Ok { data } => {
            assert!(data.devices.iter().any(|d| d.device_id == device_id));
            assert!(data.devices.iter().any(|d| d.device_id == new_device_id));
        }
        RpcResponse::Err { error } => {
            panic!("trust device list after rotate failed: {}", error.code)
        }
    }

    match trust_device_signing_key_delete_rpc(TrustDeviceSigningKeyDeleteReq {
        vault_path: vault_path.clone(),
        device_id: new_device_id.clone(),
        now_ms: 10,
    }) {
        RpcResponse::Ok { data } => {
            assert!(data.deleted);
            assert_eq!(
                data.signing_key.expect("deleted signing key").device_id,
                new_device_id
            );
            let guidance = data.recovery_guidance.expect("delete recovery guidance");
            assert_eq!(guidance.reason, "deleted_or_missing");
            assert!(!guidance.private_key_recoverable);
            assert!(guidance.command.contains("enroll-signing-key"));
            assert!(guidance.command.contains("republish affected sync targets"));
        }
        RpcResponse::Err { error } => panic!("signing key delete failed: {}", error.code),
    }

    match trust_device_signing_key_status_rpc(TrustDeviceSigningKeyStatusReq {
        vault_path,
        device_id: new_device_id,
    }) {
        RpcResponse::Ok { data } => {
            assert!(data.signing_key.is_none());
            assert!(data
                .recovery_guidance
                .expect("deleted recovery guidance")
                .summary
                .contains("not recoverable"));
        }
        RpcResponse::Err { error } => {
            panic!("signing key status after delete failed: {}", error.code)
        }
    }
}

#[test]
fn rpc_trust_provider_discovery_and_tenant_template_round_trip() {
    let root = tempfile::tempdir().expect("tempdir").keep();
    let vault_path = root.to_string_lossy().to_string();

    let init = vault_init_rpc(VaultInitReq {
        vault_path: vault_path.clone(),
        vault_slug: "demo".to_string(),
        now_ms: 1,
    });
    match init {
        RpcResponse::Ok { .. } => {}
        RpcResponse::Err { error } => panic!("vault init failed: {}", error.code),
    }

    let discovered = trust_provider_discover_rpc(TrustProviderDiscoverReq {
        vault_path: vault_path.clone(),
        issuer: "https://tenant.example/oidc".to_string(),
        now_ms: 2,
    });
    let provider_id = match discovered {
        RpcResponse::Ok { data } => {
            assert!(data.provider_id.starts_with("auto-"));
            assert_eq!(data.issuer, "https://tenant.example/oidc");
            data.provider_id
        }
        RpcResponse::Err { error } => panic!("provider discover failed: {}", error.code),
    };

    let policy = trust_policy_set_tenant_template_rpc(TrustPolicySetTenantTemplateReq {
        vault_path,
        provider: "https://tenant.example/oidc".to_string(),
        tenant_id: "Tenant-A".to_string(),
        now_ms: 3,
    });
    match policy {
        RpcResponse::Ok { data } => {
            assert_eq!(data.provider_id, provider_id);
            assert_eq!(data.max_clock_skew_ms, 5_000);
            assert!(data.require_claims_json.contains("\"tenant\":\"tenant-a\""));
        }
        RpcResponse::Err { error } => panic!("tenant template set failed: {}", error.code),
    }
}

#[test]
fn rpc_vault_lock_status_unlock_and_lock_round_trip() {
    let root = tempfile::tempdir().expect("tempdir").keep();

    let init = vault_init_rpc(VaultInitReq {
        vault_path: root.to_string_lossy().to_string(),
        vault_slug: "demo".to_string(),
        now_ms: 1,
    });
    match init {
        RpcResponse::Ok { .. } => {}
        RpcResponse::Err { error } => panic!("vault init failed: {}", error.code),
    }

    let status_before = vault_lock_status_rpc(VaultLockStatusReq {
        vault_path: root.to_string_lossy().to_string(),
    });
    match status_before {
        RpcResponse::Ok { data } => {
            assert!(!data.db_encryption_enabled);
            assert!(data.unlocked);
            assert_eq!(data.state, "disabled_plaintext");
        }
        RpcResponse::Err { error } => panic!("lock status failed: {}", error.code),
    }

    let unlocked = vault_unlock_rpc(VaultUnlockReq {
        vault_path: root.to_string_lossy().to_string(),
        passphrase: "test-passphrase".to_string(),
    });
    match unlocked {
        RpcResponse::Ok { data } => assert!(data.status.unlocked),
        RpcResponse::Err { error } => panic!("unlock failed: {}", error.code),
    }

    let locked = vault_lock_rpc(VaultLockReq {
        vault_path: root.to_string_lossy().to_string(),
    });
    match locked {
        RpcResponse::Ok { data } => assert!(data.status.unlocked),
        RpcResponse::Err { error } => panic!("lock failed: {}", error.code),
    }
}

#[test]
fn rpc_vault_encryption_status_enable_and_migrate() {
    let root = tempfile::tempdir().expect("tempdir").keep();
    let input = root.join("note.txt");
    std::fs::write(&input, b"hello").expect("write input");

    let init = vault_init_rpc(VaultInitReq {
        vault_path: root.to_string_lossy().to_string(),
        vault_slug: "demo".to_string(),
        now_ms: 1,
    });
    match init {
        RpcResponse::Ok { .. } => {}
        RpcResponse::Err { error } => panic!("vault init failed: {}", error.code),
    }

    let started = ingest_inbox_start_rpc(IngestInboxStartReq {
        vault_path: root.to_string_lossy().to_string(),
        file_path: input.to_string_lossy().to_string(),
        source_kind: "notes".to_string(),
        now_ms: 2,
    });
    match started {
        RpcResponse::Ok { .. } => {}
        RpcResponse::Err { error } => panic!("inbox start failed: {}", error.code),
    }

    let status_before = vault_encryption_status_rpc(VaultEncryptionStatusReq {
        vault_path: root.to_string_lossy().to_string(),
    });
    match status_before {
        RpcResponse::Ok { data } => {
            assert!(!data.enabled);
            assert_eq!(data.objects_total, 1);
            assert_eq!(data.objects_encrypted, 0);
        }
        RpcResponse::Err { error } => panic!("status failed: {}", error.code),
    }

    let enabled = vault_encryption_enable_rpc(VaultEncryptionEnableReq {
        vault_path: root.to_string_lossy().to_string(),
        passphrase: "test-passphrase".to_string(),
    });
    match enabled {
        RpcResponse::Ok { data } => assert!(data.status.enabled),
        RpcResponse::Err { error } => panic!("enable failed: {}", error.code),
    }

    let migrated = vault_encryption_migrate_rpc(VaultEncryptionMigrateReq {
        vault_path: root.to_string_lossy().to_string(),
        passphrase: "test-passphrase".to_string(),
        now_ms: 3,
    });
    match migrated {
        RpcResponse::Ok { data } => {
            assert_eq!(data.migrated_objects, 1);
            assert_eq!(data.status.objects_encrypted, 1);
        }
        RpcResponse::Err { error } => panic!("migrate failed: {}", error.code),
    }
}

#[test]
fn rpc_vault_recovery_status_generate_and_verify() {
    let root = tempfile::tempdir().expect("tempdir").keep();
    let output = root.join("recovery-output");

    let init = vault_init_rpc(VaultInitReq {
        vault_path: root.to_string_lossy().to_string(),
        vault_slug: "demo".to_string(),
        now_ms: 1,
    });
    match init {
        RpcResponse::Ok { .. } => {}
        RpcResponse::Err { error } => panic!("vault init failed: {}", error.code),
    }

    let status_before = vault_recovery_status_rpc(VaultRecoveryStatusReq {
        vault_path: root.to_string_lossy().to_string(),
    });
    match status_before {
        RpcResponse::Ok { data } => {
            assert!(data.last_bundle_path.is_none());
        }
        RpcResponse::Err { error } => panic!("recovery status failed: {}", error.code),
    }

    let generated = vault_recovery_generate_rpc(VaultRecoveryGenerateReq {
        vault_path: root.to_string_lossy().to_string(),
        output_dir: output.to_string_lossy().to_string(),
        passphrase: "vault-passphrase".to_string(),
        now_ms: 100,
    });
    let (bundle_path, phrase) = match generated {
        RpcResponse::Ok { data } => {
            assert_eq!(data.manifest.schema_version, 2);
            (data.bundle_path, data.recovery_phrase)
        }
        RpcResponse::Err { error } => panic!("recovery generate failed: {}", error.code),
    };

    let verified = vault_recovery_verify_rpc(VaultRecoveryVerifyReq {
        vault_path: root.to_string_lossy().to_string(),
        bundle_path,
        recovery_phrase: phrase,
    });
    match verified {
        RpcResponse::Ok { data } => assert_eq!(data.manifest.schema_version, 2),
        RpcResponse::Err { error } => panic!("recovery verify failed: {}", error.code),
    }
}

#[test]
fn rpc_vault_recovery_escrow_enable_rotate_restore_round_trip() {
    let _guard = env_lock().lock().expect("env lock");
    let root = tempfile::tempdir().expect("tempdir").keep();
    let emu = root.join("escrow-emulation");
    std::fs::create_dir_all(&emu).expect("create emulation dir");
    std::env::set_var(
        "KC_RECOVERY_ESCROW_AWS_EMULATE_DIR",
        emu.to_string_lossy().to_string(),
    );
    std::env::set_var("KC_RECOVERY_ESCROW_AWS_KMS_KEY_ID", "alias/kc-test");

    let init = vault_init_rpc(VaultInitReq {
        vault_path: root.to_string_lossy().to_string(),
        vault_slug: "demo".to_string(),
        now_ms: 1,
    });
    match init {
        RpcResponse::Ok { .. } => {}
        RpcResponse::Err { error } => panic!("vault init failed: {}", error.code),
    }

    let status_before = vault_recovery_escrow_status_rpc(VaultRecoveryEscrowStatusReq {
        vault_path: root.to_string_lossy().to_string(),
    });
    match status_before {
        RpcResponse::Ok { data } => {
            assert!(!data.enabled);
            assert_eq!(data.provider, "none");
        }
        RpcResponse::Err { error } => panic!("escrow status failed: {}", error.code),
    }

    let enabled = vault_recovery_escrow_enable_rpc(VaultRecoveryEscrowEnableReq {
        vault_path: root.to_string_lossy().to_string(),
        provider: "aws".to_string(),
        now_ms: 2,
    });
    match enabled {
        RpcResponse::Ok { data } => {
            assert!(data.status.enabled);
            assert_eq!(data.status.provider, "aws");
        }
        RpcResponse::Err { error } => panic!("escrow enable failed: {}", error.code),
    }

    let provider_added =
        vault_recovery_escrow_provider_add_rpc(VaultRecoveryEscrowProviderAddReq {
            vault_path: root.to_string_lossy().to_string(),
            provider: "aws".to_string(),
            config_ref: "kms://alias/kc-test".to_string(),
            now_ms: 2,
        });
    match provider_added {
        RpcResponse::Ok { data } => {
            assert_eq!(data.provider.provider, "aws");
            assert!(data.provider.enabled);
        }
        RpcResponse::Err { error } => panic!("escrow provider add failed: {}", error.code),
    }

    let providers = vault_recovery_escrow_provider_list_rpc(VaultRecoveryEscrowProviderListReq {
        vault_path: root.to_string_lossy().to_string(),
    });
    match providers {
        RpcResponse::Ok { data } => {
            assert!(data.providers.iter().any(|item| item.provider == "aws"));
        }
        RpcResponse::Err { error } => panic!("escrow provider list failed: {}", error.code),
    }

    let rotated = vault_recovery_escrow_rotate_rpc(VaultRecoveryEscrowRotateReq {
        vault_path: root.to_string_lossy().to_string(),
        passphrase: "vault-passphrase".to_string(),
        now_ms: 3,
    });
    let bundle_path = match rotated {
        RpcResponse::Ok { data } => {
            assert_eq!(data.manifest.schema_version, 2);
            data.bundle_path
        }
        RpcResponse::Err { error } => panic!("escrow rotate failed: {}", error.code),
    };

    let restored = vault_recovery_escrow_restore_rpc(VaultRecoveryEscrowRestoreReq {
        vault_path: root.to_string_lossy().to_string(),
        bundle_path,
        now_ms: 4,
    });
    match restored {
        RpcResponse::Ok { data } => {
            assert_eq!(data.status.provider, "aws");
            assert!(data.restored_bytes > 0);
        }
        RpcResponse::Err { error } => panic!("escrow restore failed: {}", error.code),
    }

    let rotated_all = vault_recovery_escrow_rotate_all_rpc(VaultRecoveryEscrowRotateAllReq {
        vault_path: root.to_string_lossy().to_string(),
        passphrase: "vault-passphrase".to_string(),
        now_ms: 5,
    });
    match rotated_all {
        RpcResponse::Ok { data } => {
            assert!(!data.rotated.is_empty());
            assert_eq!(data.rotated[0].provider, "aws");
        }
        RpcResponse::Err { error } => panic!("escrow rotate-all failed: {}", error.code),
    }

    std::env::remove_var("KC_RECOVERY_ESCROW_AWS_EMULATE_DIR");
    std::env::remove_var("KC_RECOVERY_ESCROW_AWS_KMS_KEY_ID");
}

#[test]
fn rpc_sync_status_and_push() {
    let root = tempfile::tempdir().expect("tempdir").keep();
    let sync_target = root.join("sync-target");
    let input = root.join("note-sync.txt");
    std::fs::write(&input, b"hello sync").expect("write input");

    let init = vault_init_rpc(VaultInitReq {
        vault_path: root.to_string_lossy().to_string(),
        vault_slug: "demo".to_string(),
        now_ms: 1,
    });
    match init {
        RpcResponse::Ok { .. } => {}
        RpcResponse::Err { error } => panic!("vault init failed: {}", error.code),
    }

    let started = ingest_inbox_start_rpc(IngestInboxStartReq {
        vault_path: root.to_string_lossy().to_string(),
        file_path: input.to_string_lossy().to_string(),
        source_kind: "notes".to_string(),
        now_ms: 2,
    });
    match started {
        RpcResponse::Ok { .. } => {}
        RpcResponse::Err { error } => panic!("ingest failed: {}", error.code),
    }

    let status_before = sync_status_rpc(SyncStatusReq {
        vault_path: root.to_string_lossy().to_string(),
        target_path: sync_target.to_string_lossy().to_string(),
    });
    match status_before {
        RpcResponse::Ok { data } => assert!(data.remote_head.is_none()),
        RpcResponse::Err { error } => panic!("sync status failed: {}", error.code),
    }

    let readiness_before = sync_auth_readiness_rpc(SyncAuthReadinessReq {
        vault_path: root.to_string_lossy().to_string(),
        target_path: sync_target.to_string_lossy().to_string(),
    });
    match readiness_before {
        RpcResponse::Ok { data } => {
            assert_eq!(data.classification, "no_remote_head");
            assert!(data.strict_ready);
            assert!(!data.depends_on_legacy_fallback);
            assert!(data.remote_head.is_none());
        }
        RpcResponse::Err { error } => panic!("sync auth readiness failed: {}", error.code),
    }

    let pushed = sync_push_rpc(SyncPushReq {
        vault_path: root.to_string_lossy().to_string(),
        target_path: sync_target.to_string_lossy().to_string(),
        now_ms: 3,
    });
    match pushed {
        RpcResponse::Ok { data } => assert!(!data.snapshot_id.is_empty()),
        RpcResponse::Err { error } => panic!("sync push failed: {}", error.code),
    }

    let readiness_after = sync_auth_readiness_rpc(SyncAuthReadinessReq {
        vault_path: root.to_string_lossy().to_string(),
        target_path: sync_target.to_string_lossy().to_string(),
    });
    match readiness_after {
        RpcResponse::Ok { data } => {
            assert_eq!(data.classification, "legacy_schema");
            assert!(!data.strict_ready);
            assert!(data.depends_on_legacy_fallback);
            assert!(data.remote_head.is_some());
        }
        RpcResponse::Err { error } => panic!("sync auth readiness failed: {}", error.code),
    }
}

#[test]
fn rpc_sync_supports_s3_uri_targets_via_emulation() {
    let _guard = env_lock().lock().expect("env lock");
    let root = tempfile::tempdir().expect("tempdir").keep();
    let pull_root = tempfile::tempdir().expect("pull tempdir").keep();
    let emulated_s3 = root.join("emulated-s3");
    std::env::set_var(
        "KC_SYNC_S3_EMULATE_ROOT",
        emulated_s3.to_string_lossy().as_ref(),
    );
    std::env::set_var("KC_VAULT_PASSPHRASE", "rpc-sync-passphrase");

    let input = root.join("note-sync-s3.txt");
    std::fs::write(&input, b"hello sync s3").expect("write input");

    let init = vault_init_rpc(VaultInitReq {
        vault_path: root.to_string_lossy().to_string(),
        vault_slug: "demo".to_string(),
        now_ms: 1,
    });
    match init {
        RpcResponse::Ok { .. } => {}
        RpcResponse::Err { error } => panic!("vault init failed: {}", error.code),
    }

    let pull_init = vault_init_rpc(VaultInitReq {
        vault_path: pull_root.to_string_lossy().to_string(),
        vault_slug: "pull-demo".to_string(),
        now_ms: 1,
    });
    match pull_init {
        RpcResponse::Ok { .. } => {}
        RpcResponse::Err { error } => panic!("pull vault init failed: {}", error.code),
    }

    let started = ingest_inbox_start_rpc(IngestInboxStartReq {
        vault_path: root.to_string_lossy().to_string(),
        file_path: input.to_string_lossy().to_string(),
        source_kind: "notes".to_string(),
        now_ms: 2,
    });
    match started {
        RpcResponse::Ok { .. } => {}
        RpcResponse::Err { error } => panic!("ingest failed: {}", error.code),
    }

    match trust_identity_start_rpc(TrustIdentityStartReq {
        vault_path: root.to_string_lossy().to_string(),
        provider: "default".to_string(),
        now_ms: 3,
    }) {
        RpcResponse::Ok { .. } => {}
        RpcResponse::Err { error } => panic!("trust identity start failed: {}", error.code),
    }
    match trust_identity_complete_rpc(TrustIdentityCompleteReq {
        vault_path: root.to_string_lossy().to_string(),
        provider: "default".to_string(),
        code: "sub:sync@example.com".to_string(),
        now_ms: 4,
    }) {
        RpcResponse::Ok { .. } => {}
        RpcResponse::Err { error } => panic!("trust identity complete failed: {}", error.code),
    }
    let enrolled = trust_device_enroll_rpc(TrustDeviceEnrollReq {
        vault_path: root.to_string_lossy().to_string(),
        device_label: "sync-source".to_string(),
        now_ms: 5,
    });
    let source_device_id = match enrolled {
        RpcResponse::Ok { data } => data.device_id,
        RpcResponse::Err { error } => panic!("trust device enroll failed: {}", error.code),
    };
    match trust_device_verify_chain_rpc(TrustDeviceVerifyChainReq {
        vault_path: root.to_string_lossy().to_string(),
        device_id: source_device_id,
        now_ms: 6,
    }) {
        RpcResponse::Ok { .. } => {}
        RpcResponse::Err { error } => panic!("trust device verify-chain failed: {}", error.code),
    }

    let target_uri = "s3://demo-bucket/kc";
    let pushed = sync_push_rpc(SyncPushReq {
        vault_path: root.to_string_lossy().to_string(),
        target_path: target_uri.to_string(),
        now_ms: 7,
    });
    let pushed_snapshot_id = match pushed {
        RpcResponse::Ok { data } => data.snapshot_id,
        RpcResponse::Err { error } => panic!("sync push failed: {}", error.code),
    };

    let status = sync_status_rpc(SyncStatusReq {
        vault_path: root.to_string_lossy().to_string(),
        target_path: target_uri.to_string(),
    });
    match status {
        RpcResponse::Ok { data } => {
            assert_eq!(data.target_path, target_uri);
            assert_eq!(
                data.remote_head.map(|h| h.snapshot_id),
                Some(pushed_snapshot_id.clone())
            );
        }
        RpcResponse::Err { error } => panic!("sync status failed: {}", error.code),
    }

    let pulled = sync_pull_rpc(SyncPullReq {
        vault_path: pull_root.to_string_lossy().to_string(),
        target_path: target_uri.to_string(),
        auto_merge: Some("conservative".to_string()),
        strict_auth: false,
        now_ms: 4,
    });
    match pulled {
        RpcResponse::Ok { data } => assert_eq!(data.snapshot_id, pushed_snapshot_id),
        RpcResponse::Err { error } => panic!("sync pull failed: {}", error.code),
    }

    let preview = sync_merge_preview_rpc(SyncMergePreviewReq {
        vault_path: root.to_string_lossy().to_string(),
        target_path: target_uri.to_string(),
        policy: Some("conservative_plus_v2".to_string()),
        now_ms: 5,
    });
    match preview {
        RpcResponse::Ok { data } => {
            assert_eq!(data.target_path, target_uri);
            assert_eq!(data.report.merge_policy, "conservative_plus_v2");
            assert_eq!(data.report.schema_version, 2);
            assert!(data
                .report
                .decision_trace
                .as_ref()
                .is_some_and(|trace| !trace.is_empty()));
        }
        RpcResponse::Err { error } => panic!("sync merge preview failed: {}", error.code),
    }

    let preview_v4 = sync_merge_preview_rpc(SyncMergePreviewReq {
        vault_path: root.to_string_lossy().to_string(),
        target_path: target_uri.to_string(),
        policy: Some("conservative_plus_v4".to_string()),
        now_ms: 6,
    });
    match preview_v4 {
        RpcResponse::Ok { data } => {
            assert_eq!(data.report.merge_policy, "conservative_plus_v4");
            assert_eq!(data.report.schema_version, 4);
            assert!(data
                .report
                .decision_trace
                .as_ref()
                .is_some_and(|trace| !trace.is_empty()));
        }
        RpcResponse::Err { error } => panic!("sync merge preview v4 failed: {}", error.code),
    }

    std::env::remove_var("KC_VAULT_PASSPHRASE");
    std::env::remove_var("KC_SYNC_S3_EMULATE_ROOT");
}

#[test]
fn rpc_lineage_query_is_deterministic_and_sorted() {
    let root = tempfile::tempdir().expect("tempdir").keep();
    let input = root.join("note-lineage.txt");
    std::fs::write(&input, b"lineage seed").expect("write input");

    let init = vault_init_rpc(VaultInitReq {
        vault_path: root.to_string_lossy().to_string(),
        vault_slug: "demo".to_string(),
        now_ms: 1,
    });
    match init {
        RpcResponse::Ok { .. } => {}
        RpcResponse::Err { error } => panic!("vault init failed: {}", error.code),
    }

    let started = ingest_inbox_start_rpc(IngestInboxStartReq {
        vault_path: root.to_string_lossy().to_string(),
        file_path: input.to_string_lossy().to_string(),
        source_kind: "notes".to_string(),
        now_ms: 2,
    });
    let seed_doc_id = match started {
        RpcResponse::Ok { data } => data.doc_id,
        RpcResponse::Err { error } => panic!("ingest failed: {}", error.code),
    };

    let req = LineageQueryReq {
        vault_path: root.to_string_lossy().to_string(),
        seed_doc_id,
        depth: 2,
        now_ms: 3,
    };
    let res_a = lineage_query_rpc(req);
    let req_b = LineageQueryReq {
        vault_path: root.to_string_lossy().to_string(),
        seed_doc_id: match &res_a {
            RpcResponse::Ok { data } => data.seed_doc_id.clone(),
            RpcResponse::Err { .. } => "missing".to_string(),
        },
        depth: 2,
        now_ms: 3,
    };
    let res_b = lineage_query_rpc(req_b);
    assert_eq!(
        serde_json::to_value(&res_a).expect("serialize a"),
        serde_json::to_value(&res_b).expect("serialize b")
    );

    match res_a {
        RpcResponse::Ok { data } => {
            let node_keys: Vec<(String, String)> = data
                .nodes
                .iter()
                .map(|n| (n.kind.clone(), n.node_id.clone()))
                .collect();
            let mut sorted_node_keys = node_keys.clone();
            sorted_node_keys.sort();
            assert_eq!(node_keys, sorted_node_keys);

            let edge_keys: Vec<(String, String, String)> = data
                .edges
                .iter()
                .map(|e| {
                    (
                        e.from_node_id.clone(),
                        e.to_node_id.clone(),
                        e.relation.clone(),
                    )
                })
                .collect();
            let mut sorted_edge_keys = edge_keys.clone();
            sorted_edge_keys.sort();
            assert_eq!(edge_keys, sorted_edge_keys);
        }
        RpcResponse::Err { error } => panic!("lineage query failed: {}", error.code),
    }
}

#[test]
fn rpc_lineage_v2_overlay_round_trip_is_deterministic() {
    let root = tempfile::tempdir().expect("tempdir").keep();
    let input = root.join("note-lineage-v2.txt");
    std::fs::write(&input, b"lineage seed v2").expect("write input");

    let init = vault_init_rpc(VaultInitReq {
        vault_path: root.to_string_lossy().to_string(),
        vault_slug: "demo".to_string(),
        now_ms: 1,
    });
    match init {
        RpcResponse::Ok { .. } => {}
        RpcResponse::Err { error } => panic!("vault init failed: {}", error.code),
    }

    let started = ingest_inbox_start_rpc(IngestInboxStartReq {
        vault_path: root.to_string_lossy().to_string(),
        file_path: input.to_string_lossy().to_string(),
        source_kind: "notes".to_string(),
        now_ms: 2,
    });
    let seed_doc_id = match started {
        RpcResponse::Ok { data } => data.doc_id,
        RpcResponse::Err { error } => panic!("ingest failed: {}", error.code),
    };

    let granted = lineage_role_grant_rpc(LineageRoleGrantReq {
        vault_path: root.to_string_lossy().to_string(),
        subject: "desktop-test".to_string(),
        role: "editor".to_string(),
        granted_by: Some("rpc-test".to_string()),
        now_ms: 3,
    });
    match granted {
        RpcResponse::Ok { data } => {
            assert_eq!(data.binding.subject_id, "desktop-test");
            assert_eq!(data.binding.role_name, "editor");
        }
        RpcResponse::Err { error } => panic!("lineage role grant failed: {}", error.code),
    }

    let condition_json = format!(
        "{{\"subject_id_prefix\":\"desktop-\",\"doc_id_suffix\":\"{}\",\"action\":\"lineage.overlay.write\"}}",
        seed_doc_id
    );
    let policy_added = lineage_policy_add_rpc(LineagePolicyAddReq {
        vault_path: root.to_string_lossy().to_string(),
        name: "allow-overlay".to_string(),
        effect: "allow".to_string(),
        condition_json,
        created_by: Some("rpc-test".to_string()),
        now_ms: 3,
    });
    match policy_added {
        RpcResponse::Ok { data } => {
            assert_eq!(data.policy.policy_name, "allow-overlay");
            assert_eq!(data.policy.effect, "allow");
            assert_eq!(
                data.policy.condition_json,
                format!(
                    "{{\"action\":\"lineage.overlay.write\",\"doc_id_suffix\":\"{}\",\"subject_id_prefix\":\"desktop-\"}}",
                    seed_doc_id
                )
            );
        }
        RpcResponse::Err { error } => panic!("lineage policy add failed: {}", error.code),
    }

    match lineage_policy_bind_rpc(LineagePolicyBindReq {
        vault_path: root.to_string_lossy().to_string(),
        subject: "desktop-test".to_string(),
        policy: "allow-overlay".to_string(),
        bound_by: Some("rpc-test".to_string()),
        now_ms: 3,
    }) {
        RpcResponse::Ok { data } => {
            assert_eq!(data.binding.subject_id, "desktop-test");
            assert_eq!(data.binding.policy_name, "allow-overlay");
        }
        RpcResponse::Err { error } => panic!("lineage policy bind failed: {}", error.code),
    }

    match lineage_policy_list_rpc(LineagePolicyListReq {
        vault_path: root.to_string_lossy().to_string(),
    }) {
        RpcResponse::Ok { data } => {
            assert!(data
                .bindings
                .iter()
                .any(|binding| binding.policy_name == "allow-overlay"));
        }
        RpcResponse::Err { error } => panic!("lineage policy list failed: {}", error.code),
    }

    let acquired = lineage_lock_acquire_rpc(LineageLockAcquireReq {
        vault_path: root.to_string_lossy().to_string(),
        doc_id: seed_doc_id.clone(),
        owner: "desktop-test".to_string(),
        now_ms: 4,
    });
    let lock_token = match acquired {
        RpcResponse::Ok { data } => data.lease.token,
        RpcResponse::Err { error } => panic!("lineage lock acquire failed: {}", error.code),
    };

    let lock_status = lineage_lock_status_rpc(LineageLockStatusReq {
        vault_path: root.to_string_lossy().to_string(),
        doc_id: seed_doc_id.clone(),
        now_ms: 5,
    });
    match lock_status {
        RpcResponse::Ok { data } => {
            assert!(data.held);
            assert_eq!(data.owner.as_deref(), Some("desktop-test"));
        }
        RpcResponse::Err { error } => panic!("lineage lock status failed: {}", error.code),
    }

    let added = lineage_overlay_add_rpc(LineageOverlayAddReq {
        vault_path: root.to_string_lossy().to_string(),
        doc_id: seed_doc_id.clone(),
        from_node_id: format!("doc:{seed_doc_id}"),
        to_node_id: "note:overlay-1".to_string(),
        relation: "supports".to_string(),
        evidence: "manual".to_string(),
        lock_token: lock_token.clone(),
        created_at_ms: 6,
        created_by: Some("desktop-test".to_string()),
    });
    let overlay_id = match added {
        RpcResponse::Ok { data } => {
            assert_eq!(data.overlay.doc_id, seed_doc_id);
            data.overlay.overlay_id
        }
        RpcResponse::Err { error } => panic!("overlay add failed: {}", error.code),
    };

    let listed = lineage_overlay_list_rpc(LineageOverlayListReq {
        vault_path: root.to_string_lossy().to_string(),
        doc_id: seed_doc_id.clone(),
    });
    match listed {
        RpcResponse::Ok { data } => {
            assert_eq!(data.overlays.len(), 1);
            assert_eq!(data.overlays[0].overlay_id, overlay_id);
        }
        RpcResponse::Err { error } => panic!("overlay list failed: {}", error.code),
    }

    let req = LineageQueryV2Req {
        vault_path: root.to_string_lossy().to_string(),
        seed_doc_id: seed_doc_id.clone(),
        depth: 2,
        now_ms: 7,
    };
    let res_a = lineage_query_v2_rpc(req);
    let res_b = lineage_query_v2_rpc(LineageQueryV2Req {
        vault_path: root.to_string_lossy().to_string(),
        seed_doc_id: seed_doc_id.clone(),
        depth: 2,
        now_ms: 7,
    });
    assert_eq!(
        serde_json::to_value(&res_a).expect("serialize lineage a"),
        serde_json::to_value(&res_b).expect("serialize lineage b")
    );

    match res_a {
        RpcResponse::Ok { data } => {
            let has_overlay_edge = data.edges.iter().any(|edge| edge.origin == "overlay");
            assert!(has_overlay_edge);

            let keys: Vec<(String, String, String, String, String)> = data
                .edges
                .iter()
                .map(|e| {
                    (
                        e.from_node_id.clone(),
                        e.to_node_id.clone(),
                        e.relation.clone(),
                        e.evidence.clone(),
                        e.origin.clone(),
                    )
                })
                .collect();
            let mut sorted = keys.clone();
            sorted.sort();
            assert_eq!(keys, sorted);
        }
        RpcResponse::Err { error } => panic!("lineage query v2 failed: {}", error.code),
    }

    let removed = lineage_overlay_remove_rpc(LineageOverlayRemoveReq {
        vault_path: root.to_string_lossy().to_string(),
        overlay_id: overlay_id.clone(),
        lock_token: lock_token.clone(),
        now_ms: 8,
    });
    match removed {
        RpcResponse::Ok { data } => assert_eq!(data.removed_overlay_id, overlay_id),
        RpcResponse::Err { error } => panic!("overlay remove failed: {}", error.code),
    }

    let released = lineage_lock_release_rpc(LineageLockReleaseReq {
        vault_path: root.to_string_lossy().to_string(),
        doc_id: seed_doc_id.clone(),
        token: lock_token,
    });
    match released {
        RpcResponse::Ok { data } => assert!(data.released),
        RpcResponse::Err { error } => panic!("lineage lock release failed: {}", error.code),
    }

    let listed_after_remove = lineage_overlay_list_rpc(LineageOverlayListReq {
        vault_path: root.to_string_lossy().to_string(),
        doc_id: seed_doc_id,
    });
    match listed_after_remove {
        RpcResponse::Ok { data } => assert!(data.overlays.is_empty()),
        RpcResponse::Err { error } => panic!("overlay list after remove failed: {}", error.code),
    }
}

#[test]
fn rpc_lineage_role_and_scope_lock_round_trip() {
    let root = tempfile::tempdir().expect("tempdir").keep();

    let init = vault_init_rpc(VaultInitReq {
        vault_path: root.to_string_lossy().to_string(),
        vault_slug: "demo".to_string(),
        now_ms: 1,
    });
    match init {
        RpcResponse::Ok { .. } => {}
        RpcResponse::Err { error } => panic!("vault init failed: {}", error.code),
    }

    let granted = lineage_role_grant_rpc(LineageRoleGrantReq {
        vault_path: root.to_string_lossy().to_string(),
        subject: "team-user".to_string(),
        role: "viewer".to_string(),
        granted_by: Some("desktop".to_string()),
        now_ms: 2,
    });
    match granted {
        RpcResponse::Ok { data } => {
            assert_eq!(data.binding.subject_id, "team-user");
            assert_eq!(data.binding.role_name, "viewer");
        }
        RpcResponse::Err { error } => panic!("role grant failed: {}", error.code),
    }

    let listed = lineage_role_list_rpc(LineageRoleListReq {
        vault_path: root.to_string_lossy().to_string(),
    });
    match listed {
        RpcResponse::Ok { data } => {
            assert!(data
                .bindings
                .iter()
                .any(|binding| binding.subject_id == "team-user" && binding.role_name == "viewer"));
        }
        RpcResponse::Err { error } => panic!("role list failed: {}", error.code),
    }

    let scoped = lineage_lock_acquire_scope_rpc(LineageLockAcquireScopeReq {
        vault_path: root.to_string_lossy().to_string(),
        scope_kind: "doc".to_string(),
        scope_value: "doc-42".to_string(),
        owner: "team-user".to_string(),
        now_ms: 3,
    });
    match scoped {
        RpcResponse::Ok { data } => {
            assert_eq!(data.lease.scope_kind, "doc");
            assert_eq!(data.lease.scope_value, "doc-42");
            assert_eq!(data.lease.owner, "team-user");
        }
        RpcResponse::Err { error } => panic!("scope lock acquire failed: {}", error.code),
    }

    let revoked = lineage_role_revoke_rpc(LineageRoleRevokeReq {
        vault_path: root.to_string_lossy().to_string(),
        subject: "team-user".to_string(),
        role: "viewer".to_string(),
    });
    match revoked {
        RpcResponse::Ok { data } => assert!(data.revoked),
        RpcResponse::Err { error } => panic!("role revoke failed: {}", error.code),
    }
}

#[test]
fn rpc_ingest_inbox_start_and_stop() {
    let root = tempfile::tempdir().expect("tempdir").keep();
    let input = root.join("note.txt");
    std::fs::write(&input, b"hello").expect("write input");

    let init = vault_init_rpc(VaultInitReq {
        vault_path: root.to_string_lossy().to_string(),
        vault_slug: "demo".to_string(),
        now_ms: 1,
    });
    match init {
        RpcResponse::Ok { .. } => {}
        RpcResponse::Err { error } => panic!("vault init failed: {}", error.code),
    }

    let started = ingest_inbox_start_rpc(IngestInboxStartReq {
        vault_path: root.to_string_lossy().to_string(),
        file_path: input.to_string_lossy().to_string(),
        source_kind: "notes".to_string(),
        now_ms: 2,
    });

    let job_id = match started {
        RpcResponse::Ok { data } => {
            assert!(!data.doc_id.is_empty());
            data.job_id
        }
        RpcResponse::Err { error } => panic!("inbox start failed: {}", error.code),
    };

    let stopped = ingest_inbox_stop_rpc(IngestInboxStopReq {
        vault_path: root.to_string_lossy().to_string(),
        job_id,
    });
    match stopped {
        RpcResponse::Ok { data } => assert!(data.stopped),
        RpcResponse::Err { error } => panic!("inbox stop failed: {}", error.code),
    }
}

#[test]
fn tauri_command_wrappers_use_rpc_envelope_contract() {
    let root = tempfile::tempdir().expect("tempdir").keep();
    let via_command = commands::vault_init(VaultInitReq {
        vault_path: root.to_string_lossy().to_string(),
        vault_slug: "demo".to_string(),
        now_ms: 1,
    });
    let via_rpc = vault_init_rpc(VaultInitReq {
        vault_path: root.to_string_lossy().to_string(),
        vault_slug: "demo".to_string(),
        now_ms: 1,
    });

    let command_json = serde_json::to_value(via_command).expect("serialize command response");
    let rpc_json = serde_json::to_value(via_rpc).expect("serialize rpc response");
    assert_eq!(
        command_json.get("ok").and_then(|v| v.as_bool()),
        rpc_json.get("ok").and_then(|v| v.as_bool())
    );
    assert!(command_json.get("data").is_some());
}
