use kc_core::db::{
    db_is_unlocked, db_lock, db_unlock, derive_db_encryption_state, migrate_db_to_sqlcipher,
    open_db, schema_version, DbEncryptionDerivedState, DbMigrationOutcome,
};
use kc_core::vault::{vault_init, vault_open, vault_paths, vault_save};
use std::sync::{Mutex, OnceLock};

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[test]
fn db_encryption_requires_passphrase_when_enabled() {
    let _guard = env_lock().lock().expect("env lock");
    std::env::remove_var("KC_VAULT_DB_PASSPHRASE");
    std::env::remove_var("KC_VAULT_PASSPHRASE");

    let root = tempfile::tempdir().expect("tempdir").keep();
    let mut vault = vault_init(&root, "demo", 1).expect("vault init");
    vault.db_encryption.enabled = true;
    vault.db_encryption.key_reference = Some(format!("vaultdb:{}", vault.vault_id));
    vault_save(&root, &vault).expect("vault save");

    let err = open_db(&vault_paths(&root).db).expect_err("expected locked db error");
    assert_eq!(err.code, "KC_DB_LOCKED");
}

#[test]
fn db_encryption_state_derives_disabled_and_pending_without_writes() {
    let _guard = env_lock().lock().expect("env lock");
    std::env::remove_var("KC_VAULT_DB_PASSPHRASE");
    std::env::remove_var("KC_VAULT_PASSPHRASE");

    let root = tempfile::tempdir().expect("tempdir").keep();
    vault_init(&root, "demo", 1).expect("vault init");
    let db_path = vault_paths(&root).db;
    let vault_before = std::fs::read(root.join("vault.json")).expect("read vault before");

    let disabled =
        derive_db_encryption_state(&root, &db_path, false).expect("derive disabled state");
    assert_eq!(disabled, DbEncryptionDerivedState::DisabledPlaintext);

    let pending = derive_db_encryption_state(&root, &db_path, true).expect("derive pending state");
    assert_eq!(pending, DbEncryptionDerivedState::PendingMigration);

    let vault_after = std::fs::read(root.join("vault.json")).expect("read vault after");
    assert_eq!(vault_after, vault_before);
}

#[test]
fn db_encryption_state_derives_migrated_lock_states() {
    let _guard = env_lock().lock().expect("env lock");
    std::env::remove_var("KC_VAULT_DB_PASSPHRASE");
    std::env::remove_var("KC_VAULT_PASSPHRASE");

    let root = tempfile::tempdir().expect("tempdir").keep();
    vault_init(&root, "demo", 1).expect("vault init");
    let db_path = vault_paths(&root).db;
    migrate_db_to_sqlcipher(&db_path, "migration-passphrase").expect("migrate db");

    let locked =
        derive_db_encryption_state(&root, &db_path, true).expect("derive locked migrated state");
    assert_eq!(locked, DbEncryptionDerivedState::MigratedLocked);

    std::env::set_var("KC_VAULT_DB_PASSPHRASE", "wrong-passphrase");
    let wrong_key =
        derive_db_encryption_state(&root, &db_path, true).expect("derive wrong-key migrated state");
    assert_eq!(wrong_key, DbEncryptionDerivedState::MigratedLocked);

    std::env::set_var("KC_VAULT_DB_PASSPHRASE", "migration-passphrase");
    let unlocked =
        derive_db_encryption_state(&root, &db_path, true).expect("derive unlocked migrated state");
    assert_eq!(unlocked, DbEncryptionDerivedState::MigratedUnlocked);

    std::env::remove_var("KC_VAULT_DB_PASSPHRASE");
    std::env::remove_var("KC_VAULT_PASSPHRASE");
}

#[test]
fn db_encryption_state_reports_recoverable_artifacts_first() {
    let _guard = env_lock().lock().expect("env lock");
    std::env::remove_var("KC_VAULT_DB_PASSPHRASE");
    std::env::remove_var("KC_VAULT_PASSPHRASE");

    let root = tempfile::tempdir().expect("tempdir").keep();
    vault_init(&root, "demo", 1).expect("vault init");
    let db_path = vault_paths(&root).db;
    std::fs::write(db_path.with_extension("sqlcipher.tmp"), b"tmp").expect("write tmp artifact");

    let state = derive_db_encryption_state(&root, &db_path, false).expect("derive artifact state");
    assert_eq!(state, DbEncryptionDerivedState::MigrationFailedRecoverable);
}

#[test]
fn db_encryption_rejects_unsupported_mode_before_unlock() {
    let _guard = env_lock().lock().expect("env lock");
    std::env::remove_var("KC_VAULT_DB_PASSPHRASE");
    std::env::remove_var("KC_VAULT_PASSPHRASE");

    let root = tempfile::tempdir().expect("tempdir").keep();
    let mut vault = vault_init(&root, "demo", 1).expect("vault init");
    vault.db_encryption.enabled = true;
    vault.db_encryption.mode = "sqlcipher_v3".to_string();
    vault.db_encryption.key_reference = Some(format!("vaultdb:{}", vault.vault_id));
    vault_save(&root, &vault).expect("vault save");

    let open_err = vault_open(&root).expect_err("vault_open should reject unsupported mode");
    assert_eq!(open_err.code, "KC_DB_ENCRYPTION_UNSUPPORTED");

    let db_err =
        open_db(&vault_paths(&root).db).expect_err("open_db should reject unsupported mode");
    assert_eq!(db_err.code, "KC_DB_ENCRYPTION_UNSUPPORTED");
}

#[test]
fn db_encryption_rejects_unsupported_kdf_algorithm() {
    let _guard = env_lock().lock().expect("env lock");
    std::env::remove_var("KC_VAULT_DB_PASSPHRASE");
    std::env::remove_var("KC_VAULT_PASSPHRASE");

    let root = tempfile::tempdir().expect("tempdir").keep();
    let mut vault = vault_init(&root, "demo", 1).expect("vault init");
    vault.db_encryption.enabled = true;
    vault.db_encryption.kdf.algorithm = "argon2id".to_string();
    vault.db_encryption.key_reference = Some(format!("vaultdb:{}", vault.vault_id));
    vault_save(&root, &vault).expect("vault save");

    let err = vault_open(&root).expect_err("vault_open should reject unsupported db kdf");
    assert_eq!(err.code, "KC_DB_ENCRYPTION_UNSUPPORTED");
}

#[test]
fn db_encryption_key_validation_is_deterministic() {
    let _guard = env_lock().lock().expect("env lock");
    std::env::remove_var("KC_VAULT_DB_PASSPHRASE");
    std::env::remove_var("KC_VAULT_PASSPHRASE");

    let root = tempfile::tempdir().expect("tempdir").keep();
    let mut vault = vault_init(&root, "demo", 1).expect("vault init");
    vault.db_encryption.enabled = true;
    vault.db_encryption.key_reference = Some(format!("vaultdb:{}", vault.vault_id));
    vault_save(&root, &vault).expect("vault save");

    std::env::set_var("KC_VAULT_DB_PASSPHRASE", "correct-passphrase");
    let conn = open_db(&vault_paths(&root).db).expect("open encrypted db with passphrase");
    assert_eq!(schema_version(&conn).expect("schema version"), 12);
    drop(conn);

    std::env::set_var("KC_VAULT_DB_PASSPHRASE", "wrong-passphrase");
    let err = open_db(&vault_paths(&root).db).expect_err("expected invalid key error");
    assert_eq!(err.code, "KC_DB_KEY_INVALID");

    std::env::remove_var("KC_VAULT_DB_PASSPHRASE");
    std::env::remove_var("KC_VAULT_PASSPHRASE");
}

#[test]
fn db_unlock_session_allows_open_without_env() {
    let _guard = env_lock().lock().expect("env lock");
    std::env::remove_var("KC_VAULT_DB_PASSPHRASE");
    std::env::remove_var("KC_VAULT_PASSPHRASE");

    let root = tempfile::tempdir().expect("tempdir").keep();
    let mut vault = vault_init(&root, "demo", 1).expect("vault init");
    vault.db_encryption.enabled = true;
    vault.db_encryption.key_reference = Some(format!("vaultdb:{}", vault.vault_id));
    vault_save(&root, &vault).expect("vault save");
    let db_path = vault_paths(&root).db;

    let locked = open_db(&db_path).expect_err("expected db locked");
    assert_eq!(locked.code, "KC_DB_LOCKED");

    db_unlock(&root, &db_path, "correct-passphrase").expect("db unlock");
    assert!(db_is_unlocked(&root));
    let conn = open_db(&db_path).expect("open db with unlock session");
    assert_eq!(schema_version(&conn).expect("schema version"), 12);
    drop(conn);

    db_lock(&root).expect("db lock");
    assert!(!db_is_unlocked(&root));
}

#[test]
fn db_migration_to_sqlcipher_requires_valid_key_after_migrate() {
    let _guard = env_lock().lock().expect("env lock");
    std::env::remove_var("KC_VAULT_DB_PASSPHRASE");
    std::env::remove_var("KC_VAULT_PASSPHRASE");

    let root = tempfile::tempdir().expect("tempdir").keep();
    let mut vault = vault_init(&root, "demo", 1).expect("vault init");
    let db_path = vault_paths(&root).db;

    let outcome = migrate_db_to_sqlcipher(&db_path, "migration-passphrase").expect("migrate db");
    assert_eq!(outcome, DbMigrationOutcome::Migrated);
    assert!(!db_path.with_extension("sqlcipher.tmp").exists());
    assert!(!db_path.with_extension("pre-sqlcipher.bak").exists());

    vault.db_encryption.enabled = true;
    vault.db_encryption.key_reference = Some(format!("vaultdb:{}", vault.vault_id));
    vault_save(&root, &vault).expect("vault save");

    let locked = open_db(&db_path).expect_err("expected locked db");
    assert_eq!(locked.code, "KC_DB_LOCKED");

    std::env::set_var("KC_VAULT_DB_PASSPHRASE", "wrong-passphrase");
    let wrong = open_db(&db_path).expect_err("expected invalid key");
    assert_eq!(wrong.code, "KC_DB_KEY_INVALID");

    std::env::set_var("KC_VAULT_DB_PASSPHRASE", "migration-passphrase");
    let conn = open_db(&db_path).expect("open migrated encrypted db");
    assert_eq!(schema_version(&conn).expect("schema version"), 12);

    std::env::remove_var("KC_VAULT_DB_PASSPHRASE");
    std::env::remove_var("KC_VAULT_PASSPHRASE");
}

#[test]
fn db_migration_to_sqlcipher_is_idempotent_after_encrypting() {
    let _guard = env_lock().lock().expect("env lock");
    std::env::remove_var("KC_VAULT_DB_PASSPHRASE");
    std::env::remove_var("KC_VAULT_PASSPHRASE");

    let root = tempfile::tempdir().expect("tempdir").keep();
    vault_init(&root, "demo", 1).expect("vault init");
    let db_path = vault_paths(&root).db;

    let migrated = migrate_db_to_sqlcipher(&db_path, "migration-passphrase")
        .expect("first migration should encrypt");
    assert_eq!(migrated, DbMigrationOutcome::Migrated);

    let already = migrate_db_to_sqlcipher(&db_path, "migration-passphrase")
        .expect("second migration should detect encrypted db");
    assert_eq!(already, DbMigrationOutcome::AlreadyEncrypted);

    let wrong =
        migrate_db_to_sqlcipher(&db_path, "wrong-passphrase").expect_err("wrong key should fail");
    assert_eq!(wrong.code, "KC_DB_KEY_INVALID");
    assert!(!db_path.with_extension("sqlcipher.tmp").exists());
    assert!(!db_path.with_extension("pre-sqlcipher.bak").exists());
}
