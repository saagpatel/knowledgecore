mod cli;
mod commands {
    pub mod bench;
    pub mod deps;
    pub mod export;
    pub mod federation;
    pub mod fixtures;
    pub mod gc;
    pub mod index;
    pub mod ingest;
    pub mod lineage;
    pub mod sync;
    pub mod trust;
    pub mod vault;
    pub mod verify;
}
mod verifier;

use clap::Parser;
use cli::{
    BenchCmd, Cli, Command, DepsCmd, FederationCmd, FixturesCmd, GcCmd, IndexCmd, IngestCmd,
    LineageCmd, LineageLockCmd, LineageOverlayCmd, LineagePolicyCmd, LineageRoleCmd, SyncCmd,
    TrustCmd, TrustDeviceCmd, TrustIdentityCmd, TrustPolicyCmd, TrustProviderCmd, VaultCmd,
    VaultDbEncryptCmd, VaultEncryptCmd, VaultRecoveryCmd, VaultRecoveryEscrowCmd,
    VaultRecoveryEscrowProviderCmd,
};
use kc_core::vault::{vault_init, vault_open};

fn now_ms() -> i64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time before unix epoch");
    now.as_millis() as i64
}

fn main() {
    let cli = Cli::parse();
    let result = match cli.cmd {
        Command::Vault { cmd } => match cmd {
            VaultCmd::Init {
                vault_path,
                vault_slug,
            } => {
                let created = vault_init(std::path::Path::new(&vault_path), &vault_slug, now_ms());
                if let Ok(v) = &created {
                    println!("vault initialized: {} ({})", v.vault_slug, v.vault_id);
                }
                created.map(|_| ())
            }
            VaultCmd::Open { vault_path } => {
                let opened = vault_open(std::path::Path::new(&vault_path));
                if let Ok(v) = &opened {
                    println!("vault opened: {} ({})", v.vault_slug, v.vault_id);
                }
                opened.map(|_| ())
            }
            VaultCmd::Verify { vault_path } => commands::vault::run_verify(&vault_path),
            VaultCmd::Unlock {
                vault_path,
                passphrase_env,
            } => commands::vault::run_unlock(&vault_path, &passphrase_env),
            VaultCmd::Lock { vault_path } => commands::vault::run_lock(&vault_path),
            VaultCmd::LockStatus { vault_path } => commands::vault::run_lock_status(&vault_path),
            VaultCmd::Encrypt { cmd } => match cmd {
                VaultEncryptCmd::Status { vault_path } => {
                    commands::vault::run_encrypt_status(&vault_path)
                }
                VaultEncryptCmd::Enable {
                    vault_path,
                    passphrase_env,
                } => commands::vault::run_encrypt_enable(&vault_path, &passphrase_env),
                VaultEncryptCmd::Migrate {
                    vault_path,
                    passphrase_env,
                    now_ms,
                } => commands::vault::run_encrypt_migrate(&vault_path, &passphrase_env, now_ms),
            },
            VaultCmd::DbEncrypt { cmd } => match cmd {
                VaultDbEncryptCmd::Status { vault_path } => {
                    commands::vault::run_db_encrypt_status(&vault_path)
                }
                VaultDbEncryptCmd::Enable {
                    vault_path,
                    passphrase_env,
                } => commands::vault::run_db_encrypt_enable(&vault_path, &passphrase_env),
                VaultDbEncryptCmd::Migrate {
                    vault_path,
                    passphrase_env,
                    now_ms,
                } => commands::vault::run_db_encrypt_migrate(&vault_path, &passphrase_env, now_ms),
            },
            VaultCmd::Recovery { cmd } => match cmd {
                VaultRecoveryCmd::Status { vault_path } => {
                    commands::vault::run_recovery_status(&vault_path)
                }
                VaultRecoveryCmd::Escrow { cmd } => match cmd {
                    VaultRecoveryEscrowCmd::Status { vault_path } => {
                        commands::vault::run_recovery_escrow_status(&vault_path)
                    }
                    VaultRecoveryEscrowCmd::Provider { cmd } => match cmd {
                        VaultRecoveryEscrowProviderCmd::Add {
                            vault_path,
                            provider,
                            config_ref,
                            now_ms: now_ms_opt,
                        } => commands::vault::run_recovery_escrow_provider_add(
                            &vault_path,
                            &provider,
                            &config_ref,
                            now_ms_opt.unwrap_or_else(now_ms),
                        ),
                        VaultRecoveryEscrowProviderCmd::List { vault_path } => {
                            commands::vault::run_recovery_escrow_provider_list(&vault_path)
                        }
                    },
                    VaultRecoveryEscrowCmd::Enable {
                        vault_path,
                        provider,
                        now_ms: now_ms_opt,
                    } => commands::vault::run_recovery_escrow_enable(
                        &vault_path,
                        &provider,
                        now_ms_opt.unwrap_or_else(now_ms),
                    ),
                    VaultRecoveryEscrowCmd::Rotate {
                        vault_path,
                        passphrase_env,
                        now_ms: now_ms_opt,
                    } => commands::vault::run_recovery_escrow_rotate(
                        &vault_path,
                        &passphrase_env,
                        now_ms_opt.unwrap_or_else(now_ms),
                    ),
                    VaultRecoveryEscrowCmd::RotateAll {
                        vault_path,
                        passphrase_env,
                        now_ms: now_ms_opt,
                    } => commands::vault::run_recovery_escrow_rotate_all(
                        &vault_path,
                        &passphrase_env,
                        now_ms_opt.unwrap_or_else(now_ms),
                    ),
                    VaultRecoveryEscrowCmd::Restore {
                        vault_path,
                        bundle,
                        now_ms: now_ms_opt,
                    } => commands::vault::run_recovery_escrow_restore(
                        &vault_path,
                        &bundle,
                        now_ms_opt.unwrap_or_else(now_ms),
                    ),
                },
                VaultRecoveryCmd::Generate {
                    vault_path,
                    output,
                    passphrase_env,
                    now_ms,
                } => commands::vault::run_recovery_generate(
                    &vault_path,
                    &output,
                    &passphrase_env,
                    now_ms,
                ),
                VaultRecoveryCmd::Verify {
                    vault_path,
                    bundle,
                    phrase_env,
                } => commands::vault::run_recovery_verify(&vault_path, &bundle, &phrase_env),
            },
        },
        Command::Ingest { cmd } => match cmd {
            IngestCmd::ScanFolder {
                vault_path,
                scan_root,
                source_kind,
            } => commands::ingest::ingest_scan_folder(&vault_path, &scan_root, &source_kind),
            IngestCmd::InboxOnce {
                vault_path,
                file_path,
                source_kind,
            } => commands::ingest::ingest_inbox_once(&vault_path, &file_path, &source_kind),
        },
        Command::Export {
            vault_path,
            export_dir,
            zip,
        } => commands::export::run_export(&vault_path, &export_dir, zip, now_ms()).map(|bundle| {
            println!("exported bundle: {}", bundle.display());
        }),
        Command::Verify { bundle_path } => {
            commands::verify::run_verify(&bundle_path).map(|(code, report)| {
                println!(
                    "{}",
                    serde_json::to_string(&report).unwrap_or_else(|_| "{}".to_string())
                );
                if code != 0 {
                    std::process::exit(code as i32);
                }
            })
        }
        Command::Index { cmd } => match cmd {
            IndexCmd::Rebuild { vault_path } => commands::index::run_rebuild(&vault_path),
        },
        Command::Gc { cmd } => match cmd {
            GcCmd::Run { vault_path } => commands::gc::run_gc(&vault_path),
        },
        Command::Deps { cmd } => match cmd {
            DepsCmd::Check => commands::deps::run_check(),
        },
        Command::Bench { cmd } => match cmd {
            BenchCmd::Run { corpus } => commands::bench::run_bench(&corpus),
        },
        Command::Fixtures { cmd } => match cmd {
            FixturesCmd::Generate { corpus } => {
                commands::fixtures::generate_corpus(&corpus).map(|path| {
                    println!("generated fixtures at {}", path.display());
                })
            }
        },
        Command::Sync { cmd } => match cmd {
            SyncCmd::Status {
                vault_path,
                target_path,
            } => commands::sync::run_status(&vault_path, &target_path),
            SyncCmd::AuthReadiness {
                vault_path,
                target_path,
            } => commands::sync::run_auth_readiness(&vault_path, &target_path),
            SyncCmd::AuthReadinessReport {
                vault_path,
                target_paths,
            } => commands::sync::run_auth_readiness_report(&vault_path, &target_paths),
            SyncCmd::AuthStrictCheck {
                vault_path,
                target_paths,
            } => commands::sync::run_auth_strict_check(&vault_path, &target_paths),
            SyncCmd::Push {
                vault_path,
                target_path,
                now_ms,
            } => commands::sync::run_push(&vault_path, &target_path, now_ms),
            SyncCmd::Pull {
                vault_path,
                target_path,
                auto_merge,
                allow_legacy_auth,
                strict_auth,
                now_ms,
            } => commands::sync::run_pull(
                &vault_path,
                &target_path,
                now_ms,
                auto_merge.as_deref(),
                strict_auth || !allow_legacy_auth,
            ),
            SyncCmd::MergePreview {
                vault_path,
                target_path,
                policy,
                now_ms,
            } => commands::sync::run_merge_preview(
                &vault_path,
                &target_path,
                policy.as_deref(),
                now_ms,
            ),
        },
        Command::Lineage { cmd } => match cmd {
            LineageCmd::Overlay { cmd } => match cmd {
                LineageOverlayCmd::Add {
                    vault_path,
                    doc_id,
                    from_node_id,
                    to_node_id,
                    relation,
                    evidence,
                    lock_token,
                    created_by,
                    now_ms,
                } => commands::lineage::run_overlay_add(
                    &vault_path,
                    commands::lineage::RunOverlayAddReq {
                        doc_id: &doc_id,
                        from_node_id: &from_node_id,
                        to_node_id: &to_node_id,
                        relation: &relation,
                        evidence: &evidence,
                        lock_token: &lock_token,
                        created_by: &created_by,
                        now_ms,
                    },
                ),
                LineageOverlayCmd::Remove {
                    vault_path,
                    overlay_id,
                    lock_token,
                    now_ms,
                } => commands::lineage::run_overlay_remove(
                    &vault_path,
                    &overlay_id,
                    &lock_token,
                    now_ms,
                ),
                LineageOverlayCmd::List { vault_path, doc_id } => {
                    commands::lineage::run_overlay_list(&vault_path, &doc_id)
                }
            },
            LineageCmd::Role { cmd } => match cmd {
                LineageRoleCmd::Grant {
                    vault_path,
                    subject,
                    role,
                    granted_by,
                    now_ms,
                } => commands::lineage::run_role_grant(
                    &vault_path,
                    &subject,
                    &role,
                    &granted_by,
                    now_ms,
                ),
                LineageRoleCmd::Revoke {
                    vault_path,
                    subject,
                    role,
                } => commands::lineage::run_role_revoke(&vault_path, &subject, &role),
                LineageRoleCmd::List { vault_path } => {
                    commands::lineage::run_role_list(&vault_path)
                }
            },
            LineageCmd::Policy { cmd } => match cmd {
                LineagePolicyCmd::Add {
                    vault_path,
                    name,
                    effect,
                    condition_json,
                    created_by,
                    now_ms,
                } => commands::lineage::run_policy_add(
                    &vault_path,
                    &name,
                    &effect,
                    &condition_json,
                    &created_by,
                    now_ms,
                ),
                LineagePolicyCmd::Bind {
                    vault_path,
                    subject,
                    policy,
                    bound_by,
                    now_ms,
                } => commands::lineage::run_policy_bind(
                    &vault_path,
                    &subject,
                    &policy,
                    &bound_by,
                    now_ms,
                ),
                LineagePolicyCmd::List { vault_path } => {
                    commands::lineage::run_policy_list(&vault_path)
                }
            },
            LineageCmd::Lock { cmd } => match cmd {
                LineageLockCmd::Acquire {
                    vault_path,
                    doc_id,
                    owner,
                    now_ms,
                } => commands::lineage::run_lock_acquire(&vault_path, &doc_id, &owner, now_ms),
                LineageLockCmd::AcquireScope {
                    vault_path,
                    scope_kind,
                    scope_value,
                    owner,
                    now_ms,
                } => commands::lineage::run_lock_acquire_scope(
                    &vault_path,
                    &scope_kind,
                    &scope_value,
                    &owner,
                    now_ms,
                ),
                LineageLockCmd::Release {
                    vault_path,
                    doc_id,
                    token,
                } => commands::lineage::run_lock_release(&vault_path, &doc_id, &token),
                LineageLockCmd::Status {
                    vault_path,
                    doc_id,
                    now_ms,
                } => commands::lineage::run_lock_status(&vault_path, &doc_id, now_ms),
            },
        },
        Command::Federation { cmd } => match cmd {
            FederationCmd::Serve {
                vault_path,
                socket_path,
                passphrase_env,
                max_requests,
            } => commands::federation::run_serve(
                &vault_path,
                &socket_path,
                passphrase_env.as_deref(),
                max_requests,
            ),
        },
        Command::Trust { cmd } => match cmd {
            TrustCmd::Identity { cmd } => match cmd {
                TrustIdentityCmd::Start {
                    vault_path,
                    provider,
                    now_ms,
                } => commands::trust::run_identity_start(&vault_path, &provider, now_ms),
                TrustIdentityCmd::Complete {
                    vault_path,
                    provider,
                    code,
                    now_ms,
                } => commands::trust::run_identity_complete(&vault_path, &provider, &code, now_ms),
            },
            TrustCmd::Device { cmd } => match cmd {
                TrustDeviceCmd::Enroll {
                    vault_path,
                    device_label,
                    now_ms,
                } => commands::trust::run_device_enroll(&vault_path, &device_label, now_ms),
                TrustDeviceCmd::EnrollSigningKey {
                    vault_path,
                    device_label,
                    passphrase_env,
                    now_ms,
                } => commands::trust::run_device_enroll_signing_key(
                    &vault_path,
                    &device_label,
                    &passphrase_env,
                    now_ms,
                ),
                TrustDeviceCmd::VerifyChain {
                    vault_path,
                    device_id,
                    now_ms,
                } => commands::trust::run_device_verify_chain(&vault_path, &device_id, now_ms),
                TrustDeviceCmd::SigningKeyStatus {
                    vault_path,
                    device_id,
                } => commands::trust::run_device_signing_key_status(&vault_path, &device_id),
                TrustDeviceCmd::SigningKeyDelete {
                    vault_path,
                    device_id,
                    now_ms,
                } => {
                    commands::trust::run_device_signing_key_delete(&vault_path, &device_id, now_ms)
                }
                TrustDeviceCmd::SigningKeyRotate {
                    vault_path,
                    old_device_id,
                    new_device_label,
                    passphrase_env,
                    now_ms,
                } => commands::trust::run_device_signing_key_rotate(
                    &vault_path,
                    &old_device_id,
                    &new_device_label,
                    &passphrase_env,
                    now_ms,
                ),
                TrustDeviceCmd::List { vault_path } => {
                    commands::trust::run_device_list(&vault_path)
                }
            },
            TrustCmd::Provider { cmd } => match cmd {
                TrustProviderCmd::Add {
                    vault_path,
                    provider_id,
                    issuer,
                    aud,
                    jwks,
                    now_ms,
                } => commands::trust::run_provider_add(
                    &vault_path,
                    &provider_id,
                    &issuer,
                    &aud,
                    &jwks,
                    now_ms,
                ),
                TrustProviderCmd::Disable {
                    vault_path,
                    provider_id,
                    now_ms,
                } => commands::trust::run_provider_disable(&vault_path, &provider_id, now_ms),
                TrustProviderCmd::List { vault_path } => {
                    commands::trust::run_provider_list(&vault_path)
                }
                TrustProviderCmd::Discover {
                    vault_path,
                    issuer,
                    now_ms,
                } => commands::trust::run_provider_discover(&vault_path, &issuer, now_ms),
            },
            TrustCmd::Policy { cmd } => match cmd {
                TrustPolicyCmd::Set {
                    vault_path,
                    provider_id,
                    max_clock_skew_ms,
                    require_claims,
                    now_ms,
                } => commands::trust::run_policy_set(
                    &vault_path,
                    &provider_id,
                    max_clock_skew_ms,
                    &require_claims,
                    now_ms,
                ),
                TrustPolicyCmd::SetTenantTemplate {
                    vault_path,
                    provider,
                    tenant_id,
                    now_ms,
                } => commands::trust::run_policy_set_tenant_template(
                    &vault_path,
                    &provider,
                    &tenant_id,
                    now_ms,
                ),
            },
        },
    };

    if let Err(err) = result {
        eprintln!("{}: {}", err.code, err.message);
        std::process::exit(1);
    }
}
