use kc_core::app_error::{AppError, AppResult};
use kc_core::db::open_db;
use kc_core::rpc_service::{
    vault_db_encrypt_enable_service, vault_db_encrypt_migrate_service,
    vault_db_encrypt_status_service, vault_encryption_enable_service,
    vault_encryption_migrate_service, vault_encryption_status_service, vault_lock_service,
    vault_lock_status_service, vault_recovery_escrow_enable_service,
    vault_recovery_escrow_provider_add_service, vault_recovery_escrow_provider_list_service,
    vault_recovery_escrow_restore_service, vault_recovery_escrow_rotate_all_service,
    vault_recovery_escrow_rotate_service, vault_recovery_escrow_status_service,
    vault_recovery_generate_service, vault_recovery_status_service, vault_recovery_verify_service,
    vault_unlock_service,
};
use kc_core::vault::{vault_open, vault_paths};
use std::path::Path;

fn now_ms() -> i64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time before unix epoch");
    now.as_millis() as i64
}

pub fn run_verify(vault_path: &str) -> AppResult<()> {
    let vault = vault_open(Path::new(vault_path))?;
    let paths = vault_paths(Path::new(vault_path));
    let conn = open_db(&Path::new(vault_path).join(vault.db.relative_path))?;

    let db_integrity: String = conn
        .query_row("PRAGMA integrity_check(1)", [], |row| row.get(0))
        .map_err(|e| {
            AppError::new(
                "KC_DB_INTEGRITY_FAILED",
                "vault",
                "failed running sqlite integrity_check",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;
    if db_integrity.to_lowercase() != "ok" {
        return Err(AppError::new(
            "KC_DB_INTEGRITY_FAILED",
            "vault",
            "sqlite integrity_check failed",
            false,
            serde_json::json!({ "result": db_integrity }),
        ));
    }

    if !paths.objects_dir.exists() || !paths.vectors_dir.exists() {
        return Err(AppError::new(
            "KC_VAULT_JSON_INVALID",
            "vault",
            "vault directories are missing",
            false,
            serde_json::json!({
                "objects_dir": paths.objects_dir,
                "vectors_dir": paths.vectors_dir
            }),
        ));
    }

    let object_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM objects", [], |row| row.get(0))
        .unwrap_or(0);
    let doc_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM docs", [], |row| row.get(0))
        .unwrap_or(0);
    let event_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
        .unwrap_or(0);

    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "status": "ok",
            "vault_id": vault.vault_id,
            "counts": {
                "objects": object_count,
                "docs": doc_count,
                "events": event_count
            }
        }))
        .unwrap_or_else(|_| "{}".to_string())
    );
    Ok(())
}

fn passphrase_from_env(passphrase_env: &str) -> AppResult<String> {
    std::env::var(passphrase_env)
        .ok()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            AppError::new(
                "KC_ENCRYPTION_REQUIRED",
                "encryption",
                "passphrase env var is missing or empty",
                false,
                serde_json::json!({ "passphrase_env": passphrase_env }),
            )
        })
}

fn phrase_from_env(phrase_env: &str) -> AppResult<String> {
    std::env::var(phrase_env)
        .ok()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            AppError::new(
                "KC_RECOVERY_PHRASE_INVALID",
                "recovery",
                "recovery phrase env var is missing or empty",
                false,
                serde_json::json!({ "phrase_env": phrase_env }),
            )
        })
}

pub fn run_encrypt_status(vault_path: &str) -> AppResult<()> {
    let status = vault_encryption_status_service(Path::new(vault_path))?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "status": "ok",
            "encryption": {
                "enabled": status.enabled,
                "mode": status.mode,
                "key_reference": status.key_reference,
                "kdf_algorithm": status.kdf_algorithm,
                "objects_total": status.objects_total,
                "objects_encrypted": status.objects_encrypted,
            }
        }))
        .unwrap_or_else(|_| "{}".to_string())
    );
    Ok(())
}

pub fn run_encrypt_enable(vault_path: &str, passphrase_env: &str) -> AppResult<()> {
    let passphrase = passphrase_from_env(passphrase_env)?;
    let status = vault_encryption_enable_service(Path::new(vault_path), &passphrase)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "status": "ok",
            "enabled": status.enabled,
            "mode": status.mode,
            "objects_total": status.objects_total,
            "objects_encrypted": status.objects_encrypted,
        }))
        .unwrap_or_else(|_| "{}".to_string())
    );
    Ok(())
}

pub fn run_encrypt_migrate(vault_path: &str, passphrase_env: &str, now_ms: i64) -> AppResult<()> {
    let passphrase = passphrase_from_env(passphrase_env)?;
    let out = vault_encryption_migrate_service(Path::new(vault_path), &passphrase, now_ms)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "status": "ok",
            "event_id": out.event_id,
            "migrated_objects": out.migrated_objects,
            "already_encrypted_objects": out.already_encrypted_objects,
            "objects_total": out.status.objects_total,
            "objects_encrypted": out.status.objects_encrypted,
        }))
        .unwrap_or_else(|_| "{}".to_string())
    );
    Ok(())
}

pub fn run_db_encrypt_status(vault_path: &str) -> AppResult<()> {
    let status = vault_db_encrypt_status_service(Path::new(vault_path))?;
    let lock_status = vault_lock_status_service(Path::new(vault_path))?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "status": "ok",
            "db_encryption": {
                "enabled": status.enabled,
                "mode": status.mode,
                "key_reference": status.key_reference,
                "unlocked": status.unlocked,
                "state": status.state,
                "lock_status": {
                    "db_encryption_enabled": lock_status.db_encryption_enabled,
                    "unlocked": lock_status.unlocked,
                    "state": lock_status.state,
                }
            }
        }))
        .unwrap_or_else(|_| "{}".to_string())
    );
    Ok(())
}

pub fn run_db_encrypt_enable(vault_path: &str, passphrase_env: &str) -> AppResult<()> {
    let passphrase = passphrase_from_env(passphrase_env)?;
    let status = vault_db_encrypt_enable_service(Path::new(vault_path), &passphrase)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "status": "ok",
            "enabled": status.enabled,
            "mode": status.mode,
            "unlocked": status.unlocked,
            "state": status.state,
        }))
        .unwrap_or_else(|_| "{}".to_string())
    );
    Ok(())
}

pub fn run_db_encrypt_migrate(
    vault_path: &str,
    passphrase_env: &str,
    now_ms: i64,
) -> AppResult<()> {
    let passphrase = passphrase_from_env(passphrase_env)?;
    let out = vault_db_encrypt_migrate_service(Path::new(vault_path), &passphrase, now_ms)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "status": "ok",
            "event_id": out.event_id,
            "outcome": out.outcome,
            "db_encryption": {
                "enabled": out.status.enabled,
                "mode": out.status.mode,
                "unlocked": out.status.unlocked,
                "state": out.status.state,
            }
        }))
        .unwrap_or_else(|_| "{}".to_string())
    );
    Ok(())
}

pub fn run_unlock(vault_path: &str, passphrase_env: &str) -> AppResult<()> {
    let passphrase = passphrase_from_env(passphrase_env)?;
    let status = vault_unlock_service(Path::new(vault_path), &passphrase)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "status": "ok",
            "db_encryption_enabled": status.db_encryption_enabled,
            "unlocked": status.unlocked,
        }))
        .unwrap_or_else(|_| "{}".to_string())
    );
    Ok(())
}

pub fn run_lock(vault_path: &str) -> AppResult<()> {
    let status = vault_lock_service(Path::new(vault_path))?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "status": "ok",
            "db_encryption_enabled": status.db_encryption_enabled,
            "unlocked": status.unlocked,
        }))
        .unwrap_or_else(|_| "{}".to_string())
    );
    Ok(())
}

pub fn run_lock_status(vault_path: &str) -> AppResult<()> {
    let status = vault_lock_status_service(Path::new(vault_path))?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "status": "ok",
            "db_encryption_enabled": status.db_encryption_enabled,
            "unlocked": status.unlocked,
        }))
        .unwrap_or_else(|_| "{}".to_string())
    );
    Ok(())
}

pub fn run_recovery_status(vault_path: &str) -> AppResult<()> {
    let status = vault_recovery_status_service(Path::new(vault_path))?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "status": "ok",
            "vault_id": status.vault_id,
            "encryption_enabled": status.encryption_enabled,
            "last_bundle_path": status.last_bundle_path,
        }))
        .unwrap_or_else(|_| "{}".to_string())
    );
    Ok(())
}

pub fn run_recovery_generate(
    vault_path: &str,
    output: &str,
    passphrase_env: &str,
    now_ms_override: Option<i64>,
) -> AppResult<()> {
    let passphrase = passphrase_from_env(passphrase_env)?;
    let out = vault_recovery_generate_service(
        Path::new(vault_path),
        Path::new(output),
        &passphrase,
        now_ms_override.unwrap_or_else(now_ms),
    )?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "status": "ok",
            "bundle_path": out.bundle_path,
            "recovery_phrase": out.recovery_phrase,
            "manifest": out.manifest,
        }))
        .unwrap_or_else(|_| "{}".to_string())
    );
    Ok(())
}

pub fn run_recovery_verify(vault_path: &str, bundle: &str, phrase_env: &str) -> AppResult<()> {
    let phrase = phrase_from_env(phrase_env)?;
    let out = vault_recovery_verify_service(Path::new(vault_path), Path::new(bundle), &phrase)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "status": "ok",
            "manifest": out.manifest,
        }))
        .unwrap_or_else(|_| "{}".to_string())
    );
    Ok(())
}

pub fn run_recovery_escrow_status(vault_path: &str) -> AppResult<()> {
    let status = vault_recovery_escrow_status_service(Path::new(vault_path))?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "status": "ok",
            "escrow": {
                "enabled": status.enabled,
                "provider": status.provider,
                "provider_available": status.provider_available,
                "updated_at_ms": status.updated_at_ms,
                "details_json": status.details_json,
            }
        }))
        .unwrap_or_else(|_| "{}".to_string())
    );
    Ok(())
}

pub fn run_recovery_escrow_enable(vault_path: &str, provider: &str, now_ms: i64) -> AppResult<()> {
    let status = vault_recovery_escrow_enable_service(Path::new(vault_path), provider, now_ms)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "status": "ok",
            "escrow": {
                "enabled": status.enabled,
                "provider": status.provider,
                "provider_available": status.provider_available,
                "updated_at_ms": status.updated_at_ms,
                "details_json": status.details_json,
            }
        }))
        .unwrap_or_else(|_| "{}".to_string())
    );
    Ok(())
}

pub fn run_recovery_escrow_rotate(
    vault_path: &str,
    passphrase_env: &str,
    now_ms_override: i64,
) -> AppResult<()> {
    let passphrase = passphrase_from_env(passphrase_env)?;
    let out =
        vault_recovery_escrow_rotate_service(Path::new(vault_path), &passphrase, now_ms_override)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "status": "ok",
            "bundle_path": out.bundle_path,
            "recovery_phrase": out.recovery_phrase,
            "manifest": out.manifest,
            "escrow": {
                "enabled": out.status.enabled,
                "provider": out.status.provider,
                "provider_available": out.status.provider_available,
                "updated_at_ms": out.status.updated_at_ms,
                "details_json": out.status.details_json,
            }
        }))
        .unwrap_or_else(|_| "{}".to_string())
    );
    Ok(())
}

pub fn run_recovery_escrow_restore(
    vault_path: &str,
    bundle: &str,
    now_ms_override: i64,
) -> AppResult<()> {
    let out = vault_recovery_escrow_restore_service(
        Path::new(vault_path),
        Path::new(bundle),
        now_ms_override,
    )?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "status": "ok",
            "bundle_path": out.bundle_path,
            "restored_bytes": out.restored_bytes,
            "manifest": out.manifest,
            "escrow": {
                "enabled": out.status.enabled,
                "provider": out.status.provider,
                "provider_available": out.status.provider_available,
                "updated_at_ms": out.status.updated_at_ms,
                "details_json": out.status.details_json,
            }
        }))
        .unwrap_or_else(|_| "{}".to_string())
    );
    Ok(())
}

pub fn run_recovery_escrow_provider_add(
    vault_path: &str,
    provider: &str,
    config_ref: &str,
    now_ms: i64,
) -> AppResult<()> {
    let item = vault_recovery_escrow_provider_add_service(
        Path::new(vault_path),
        provider,
        config_ref,
        now_ms,
    )?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "status": "ok",
            "provider": {
                "provider": item.provider,
                "priority": item.priority,
                "config_ref": item.config_ref,
                "enabled": item.enabled,
                "provider_available": item.provider_available,
                "updated_at_ms": item.updated_at_ms
            }
        }))
        .unwrap_or_else(|_| "{}".to_string())
    );
    Ok(())
}

pub fn run_recovery_escrow_provider_list(vault_path: &str) -> AppResult<()> {
    let providers = vault_recovery_escrow_provider_list_service(Path::new(vault_path))?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "status": "ok",
            "providers": providers.into_iter().map(|item| serde_json::json!({
                "provider": item.provider,
                "priority": item.priority,
                "config_ref": item.config_ref,
                "enabled": item.enabled,
                "provider_available": item.provider_available,
                "updated_at_ms": item.updated_at_ms
            })).collect::<Vec<_>>()
        }))
        .unwrap_or_else(|_| "{}".to_string())
    );
    Ok(())
}

pub fn run_recovery_escrow_rotate_all(
    vault_path: &str,
    passphrase_env: &str,
    now_ms_override: i64,
) -> AppResult<()> {
    let passphrase = passphrase_from_env(passphrase_env)?;
    let out = vault_recovery_escrow_rotate_all_service(
        Path::new(vault_path),
        &passphrase,
        now_ms_override,
    )?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "status": "ok",
            "rotated": out.rotated.into_iter().map(|item| serde_json::json!({
                "provider": item.provider,
                "bundle_path": item.bundle_path,
                "recovery_phrase": item.recovery_phrase,
                "manifest": item.manifest,
                "updated_at_ms": item.updated_at_ms
            })).collect::<Vec<_>>()
        }))
        .unwrap_or_else(|_| "{}".to_string())
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        run_db_encrypt_enable, run_db_encrypt_migrate, run_db_encrypt_status, run_encrypt_enable,
        run_encrypt_migrate,
    };
    use kc_core::db::open_db;
    use kc_core::object_store::{is_encrypted_payload, ObjectStore};
    use kc_core::rpc_service::{vault_db_encrypt_status_service, vault_encryption_status_service};
    use kc_core::vault::vault_init;

    #[test]
    fn encrypt_enable_and_migrate_round_trip() {
        let root = tempfile::tempdir().expect("tempdir").keep();
        vault_init(&root, "demo", 1).expect("vault init");

        let conn = open_db(&root.join("db/knowledge.sqlite")).expect("open db");
        let store = ObjectStore::new(root.join("store/objects"));
        let hash = store.put_bytes(&conn, b"hello", 1).expect("put object");

        let env_name = format!("KC_TEST_PASSPHRASE_{}", std::process::id());
        std::env::set_var(&env_name, "test-passphrase");

        run_encrypt_enable(root.to_string_lossy().as_ref(), &env_name).expect("enable encryption");

        let status_before = vault_encryption_status_service(&root).expect("status before migrate");
        assert!(status_before.enabled);
        assert_eq!(status_before.objects_total, 1);
        assert_eq!(status_before.objects_encrypted, 0);

        run_encrypt_migrate(root.to_string_lossy().as_ref(), &env_name, 2)
            .expect("migrate encryption");

        let status_after = vault_encryption_status_service(&root).expect("status after migrate");
        assert_eq!(status_after.objects_total, 1);
        assert_eq!(status_after.objects_encrypted, 1);

        let raw = ObjectStore::new(root.join("store/objects"))
            .raw_bytes(&hash)
            .expect("raw bytes");
        assert!(is_encrypted_payload(&raw));

        std::env::remove_var(env_name);
    }

    #[test]
    fn db_encrypt_enable_and_migrate_round_trip() {
        let root = tempfile::tempdir().expect("tempdir").keep();
        vault_init(&root, "demo", 1).expect("vault init");

        let env_name = format!("KC_TEST_DB_PASSPHRASE_{}", std::process::id());
        std::env::set_var(&env_name, "test-db-passphrase");

        run_db_encrypt_enable(root.to_string_lossy().as_ref(), &env_name)
            .expect("enable db encryption");
        let status_enabled = vault_db_encrypt_status_service(&root).expect("db status enabled");
        assert!(status_enabled.enabled);
        assert!(status_enabled.unlocked);
        assert_eq!(status_enabled.state, "migrated_unlocked");

        run_db_encrypt_migrate(root.to_string_lossy().as_ref(), &env_name, 2)
            .expect("migrate db encryption");
        let status_migrated = vault_db_encrypt_status_service(&root).expect("db status migrated");
        assert_eq!(status_migrated.state, "migrated_unlocked");
        run_db_encrypt_status(root.to_string_lossy().as_ref()).expect("db status command");

        std::env::set_var("KC_VAULT_DB_PASSPHRASE", "test-db-passphrase");
        let conn = open_db(&root.join("db/knowledge.sqlite")).expect("open migrated encrypted db");
        let _: i64 = conn
            .query_row("SELECT COUNT(*) FROM docs", [], |row| row.get(0))
            .expect("query docs count");
        drop(conn);

        std::env::remove_var("KC_VAULT_DB_PASSPHRASE");
        std::env::remove_var(env_name);
    }
}
