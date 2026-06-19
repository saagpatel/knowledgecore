use crate::app_error::{AppError, AppResult};
use rusqlite::Connection;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

const LATEST_SCHEMA_VERSION: i64 = 11;
const SQLITE_HEADER: &[u8; 16] = b"SQLite format 3\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbMigrationOutcome {
    Migrated,
    AlreadyEncrypted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbEncryptionDerivedState {
    DisabledPlaintext,
    PendingMigration,
    MigratedLocked,
    MigratedUnlocked,
    MigrationFailedRecoverable,
}

impl DbEncryptionDerivedState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DisabledPlaintext => "disabled_plaintext",
            Self::PendingMigration => "pending_migration",
            Self::MigratedLocked => "migrated_locked",
            Self::MigratedUnlocked => "migrated_unlocked",
            Self::MigrationFailedRecoverable => "migration_failed_recoverable",
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
struct VaultDbEncryptionMeta {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    mode: String,
}

#[derive(Debug, Clone, Deserialize)]
struct VaultMetaForDb {
    schema_version: u32,
    #[serde(default)]
    db_encryption: VaultDbEncryptionMeta,
}

static DB_UNLOCK_SESSIONS: OnceLock<Mutex<HashMap<PathBuf, String>>> = OnceLock::new();

fn db_unlock_sessions() -> &'static Mutex<HashMap<PathBuf, String>> {
    DB_UNLOCK_SESSIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn normalize_session_key(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

fn maybe_vault_json_path(db_path: &Path) -> Option<PathBuf> {
    let db_parent = db_path.parent()?;
    let vault_root = db_parent.parent()?;
    Some(vault_root.join("vault.json"))
}

fn maybe_vault_root(db_path: &Path) -> Option<PathBuf> {
    maybe_vault_json_path(db_path).and_then(|p| p.parent().map(|x| x.to_path_buf()))
}

fn read_vault_meta_for_db(db_path: &Path) -> AppResult<Option<VaultMetaForDb>> {
    let Some(vault_json_path) = maybe_vault_json_path(db_path) else {
        return Ok(None);
    };
    if !vault_json_path.exists() {
        return Ok(None);
    }

    let bytes = fs::read(&vault_json_path).map_err(|e| {
        AppError::new(
            "KC_DB_OPEN_FAILED",
            "db",
            "failed reading vault.json while opening database",
            false,
            serde_json::json!({ "error": e.to_string(), "path": vault_json_path }),
        )
    })?;

    let meta = serde_json::from_slice::<VaultMetaForDb>(&bytes).map_err(|e| {
        AppError::new(
            "KC_DB_OPEN_FAILED",
            "db",
            "failed parsing vault.json while opening database",
            false,
            serde_json::json!({ "error": e.to_string(), "path": vault_json_path }),
        )
    })?;

    Ok(Some(meta))
}

fn sql_string_literal(value: &str) -> String {
    value.replace('\'', "''")
}

fn attach_path_literal(path: &Path) -> String {
    path.to_string_lossy().replace('\'', "''")
}

fn passphrase_from_env() -> Option<String> {
    std::env::var("KC_VAULT_DB_PASSPHRASE")
        .ok()
        .or_else(|| std::env::var("KC_VAULT_PASSPHRASE").ok())
}

fn passphrase_from_session(db_path: &Path) -> Option<String> {
    let vault_root = maybe_vault_root(db_path)?;
    let key = normalize_session_key(&vault_root);
    let sessions = db_unlock_sessions().lock().ok()?;
    sessions.get(&key).cloned()
}

fn has_plaintext_sqlite_header(db_path: &Path) -> AppResult<bool> {
    match fs::read(db_path) {
        Ok(bytes) => Ok(bytes.starts_with(SQLITE_HEADER)),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(true),
        Err(e) => Err(AppError::new(
            "KC_DB_OPEN_FAILED",
            "db",
            "failed reading database header",
            false,
            serde_json::json!({ "error": e.to_string(), "path": db_path }),
        )),
    }
}

pub fn derive_db_encryption_state(
    _vault_path: &Path,
    db_path: &Path,
    enabled: bool,
) -> AppResult<DbEncryptionDerivedState> {
    let tmp_path = db_path.with_extension("sqlcipher.tmp");
    let bak_path = db_path.with_extension("pre-sqlcipher.bak");
    if tmp_path.exists() || bak_path.exists() {
        return Ok(DbEncryptionDerivedState::MigrationFailedRecoverable);
    }

    if !enabled {
        return Ok(DbEncryptionDerivedState::DisabledPlaintext);
    }

    if has_plaintext_sqlite_header(db_path)? {
        return Ok(DbEncryptionDerivedState::PendingMigration);
    }

    let passphrase = passphrase_from_session(db_path).or_else(passphrase_from_env);
    let Some(passphrase) = passphrase else {
        return Ok(DbEncryptionDerivedState::MigratedLocked);
    };

    match verify_db_passphrase(db_path, &passphrase) {
        Ok(()) => Ok(DbEncryptionDerivedState::MigratedUnlocked),
        Err(err) if err.code == "KC_DB_KEY_INVALID" => Ok(DbEncryptionDerivedState::MigratedLocked),
        Err(err) => Err(err),
    }
}

fn validate_key_on_connection(conn: &Connection, passphrase: &str) -> AppResult<()> {
    let escaped = sql_string_literal(passphrase);
    conn.execute_batch(&format!(
        "PRAGMA key = '{}'; PRAGMA cipher_compatibility = 4;",
        escaped
    ))
    .map_err(|e| {
        AppError::new(
            "KC_DB_KEY_INVALID",
            "db",
            "failed applying sqlcipher key pragmas",
            false,
            serde_json::json!({ "error": e.to_string() }),
        )
    })?;

    conn.query_row("SELECT count(*) FROM sqlite_master", [], |row| {
        row.get::<_, i64>(0)
    })
    .map_err(|e| {
        AppError::new(
            "KC_DB_KEY_INVALID",
            "db",
            "provided db passphrase is invalid",
            false,
            serde_json::json!({ "error": e.to_string() }),
        )
    })?;
    Ok(())
}

fn verify_db_passphrase(db_path: &Path, passphrase: &str) -> AppResult<()> {
    let conn = Connection::open(db_path).map_err(|e| {
        AppError::new(
            "KC_DB_OPEN_FAILED",
            "db",
            "failed opening database for passphrase validation",
            false,
            serde_json::json!({ "error": e.to_string(), "path": db_path }),
        )
    })?;
    validate_key_on_connection(&conn, passphrase)
}

fn remove_file_if_exists(path: &Path, phase: &str) -> AppResult<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(AppError::new(
            "KC_DB_ENCRYPTION_MIGRATION_FAILED",
            "db",
            "failed clearing migration artifact",
            false,
            serde_json::json!({
                "phase": phase,
                "path": path,
                "error": e.to_string()
            }),
        )),
    }
}

fn rollback_migration_files(
    db_path: &Path,
    tmp_path: &Path,
    bak_path: &Path,
) -> Result<(), Vec<serde_json::Value>> {
    let mut rollback_errors = Vec::new();

    if let Err(e) = remove_file_if_exists(db_path, "rollback_remove_promoted_db") {
        rollback_errors.push(serde_json::json!({
            "operation": "remove_promoted_db",
            "path": db_path,
            "error": e.details.get("error").cloned().unwrap_or_else(|| serde_json::json!(e.message))
        }));
    }

    if let Err(e) = fs::rename(bak_path, db_path) {
        rollback_errors.push(serde_json::json!({
            "operation": "restore_backup",
            "from": bak_path,
            "to": db_path,
            "error": e.to_string()
        }));
    }

    if let Err(e) = remove_file_if_exists(tmp_path, "rollback_remove_tmp") {
        rollback_errors.push(serde_json::json!({
            "operation": "remove_tmp",
            "path": tmp_path,
            "error": e.details.get("error").cloned().unwrap_or_else(|| serde_json::json!(e.message))
        }));
    }

    if rollback_errors.is_empty() {
        Ok(())
    } else {
        Err(rollback_errors)
    }
}

pub fn db_unlock(vault_path: &Path, db_path: &Path, passphrase: &str) -> AppResult<()> {
    let key = normalize_session_key(vault_path);
    verify_db_passphrase(db_path, passphrase)?;
    let mut sessions = db_unlock_sessions().lock().map_err(|_| {
        AppError::new(
            "KC_INTERNAL_ERROR",
            "db",
            "failed acquiring db unlock session lock",
            true,
            serde_json::json!({}),
        )
    })?;
    sessions.insert(key, passphrase.to_string());
    Ok(())
}

pub fn db_lock(vault_path: &Path) -> AppResult<()> {
    let key = normalize_session_key(vault_path);
    let mut sessions = db_unlock_sessions().lock().map_err(|_| {
        AppError::new(
            "KC_INTERNAL_ERROR",
            "db",
            "failed acquiring db unlock session lock",
            true,
            serde_json::json!({}),
        )
    })?;
    sessions.remove(&key);
    Ok(())
}

pub fn db_is_unlocked(vault_path: &Path) -> bool {
    let key = normalize_session_key(vault_path);
    let Ok(sessions) = db_unlock_sessions().lock() else {
        return false;
    };
    sessions.contains_key(&key)
}

pub fn migrate_db_to_sqlcipher(db_path: &Path, passphrase: &str) -> AppResult<DbMigrationOutcome> {
    let source_conn = Connection::open(db_path).map_err(|e| {
        AppError::new(
            "KC_DB_ENCRYPTION_MIGRATION_FAILED",
            "db",
            "failed opening source database for migration",
            false,
            serde_json::json!({ "error": e.to_string(), "path": db_path }),
        )
    })?;

    // If the source no longer opens as plaintext, treat as already encrypted only when the key validates.
    if source_conn
        .query_row("SELECT count(*) FROM sqlite_master", [], |row| {
            row.get::<_, i64>(0)
        })
        .is_err()
    {
        verify_db_passphrase(db_path, passphrase)?;
        return Ok(DbMigrationOutcome::AlreadyEncrypted);
    }

    let db_dir = db_path.parent().ok_or_else(|| {
        AppError::new(
            "KC_DB_ENCRYPTION_MIGRATION_FAILED",
            "db",
            "database path has no parent directory",
            false,
            serde_json::json!({ "path": db_path }),
        )
    })?;
    fs::create_dir_all(db_dir).map_err(|e| {
        AppError::new(
            "KC_DB_ENCRYPTION_MIGRATION_FAILED",
            "db",
            "failed creating migration directory",
            false,
            serde_json::json!({ "error": e.to_string(), "path": db_dir }),
        )
    })?;

    let tmp_path = db_path.with_extension("sqlcipher.tmp");
    let bak_path = db_path.with_extension("pre-sqlcipher.bak");
    remove_file_if_exists(&tmp_path, "preflight_remove_tmp")?;
    remove_file_if_exists(&bak_path, "preflight_remove_backup")?;

    let pass = sql_string_literal(passphrase);
    let tmp_lit = attach_path_literal(&tmp_path);
    source_conn
        .execute_batch(&format!(
            "ATTACH DATABASE '{}' AS encrypted KEY '{}';\
             PRAGMA encrypted.cipher_compatibility = 4;\
             SELECT sqlcipher_export('encrypted');\
             DETACH DATABASE encrypted;",
            tmp_lit, pass
        ))
        .map_err(|e| {
            AppError::new(
                "KC_DB_ENCRYPTION_MIGRATION_FAILED",
                "db",
                "failed running sqlcipher export migration",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;

    verify_db_passphrase(&tmp_path, passphrase)?;

    fs::rename(db_path, &bak_path).map_err(|e| {
        AppError::new(
            "KC_DB_ENCRYPTION_MIGRATION_FAILED",
            "db",
            "failed rotating source database before finalizing migration",
            false,
            serde_json::json!({ "error": e.to_string(), "from": db_path, "to": bak_path }),
        )
    })?;

    let finalize = (|| -> AppResult<()> {
        fs::rename(&tmp_path, db_path).map_err(|e| {
            AppError::new(
                "KC_DB_ENCRYPTION_MIGRATION_FAILED",
                "db",
                "failed promoting encrypted database",
                false,
                serde_json::json!({ "error": e.to_string(), "from": tmp_path, "to": db_path }),
            )
        })?;
        verify_db_passphrase(db_path, passphrase)?;
        Ok(())
    })();

    match finalize {
        Ok(()) => {
            remove_file_if_exists(&bak_path, "finalize_remove_plaintext_backup")?;
            Ok(DbMigrationOutcome::Migrated)
        }
        Err(err) => {
            if let Err(rollback_errors) = rollback_migration_files(db_path, &tmp_path, &bak_path) {
                return Err(AppError::new(
                    "KC_DB_ENCRYPTION_MIGRATION_FAILED",
                    "db",
                    "failed finalizing db migration and rollback",
                    false,
                    serde_json::json!({
                        "finalize_error": err,
                        "rollback_errors": rollback_errors,
                        "db_path": db_path,
                        "tmp_path": tmp_path,
                        "backup_path": bak_path
                    }),
                ));
            }
            Err(err)
        }
    }
}

fn apply_db_encryption_key_if_needed(conn: &Connection, db_path: &Path) -> AppResult<()> {
    let Some(meta) = read_vault_meta_for_db(db_path)? else {
        return Ok(());
    };

    // v1/v2 vaults have no DB-at-rest metadata.
    if meta.schema_version < 3 {
        return Ok(());
    }

    if !meta.db_encryption.enabled {
        return Ok(());
    }

    if meta.db_encryption.mode != "sqlcipher_v4" {
        return Err(AppError::new(
            "KC_DB_ENCRYPTION_UNSUPPORTED",
            "db",
            "unsupported db encryption mode",
            false,
            serde_json::json!({
                "mode": meta.db_encryption.mode,
                "supported": ["sqlcipher_v4"]
            }),
        ));
    }

    let passphrase = passphrase_from_session(db_path)
        .or_else(passphrase_from_env)
        .ok_or_else(|| {
            AppError::new(
                "KC_DB_LOCKED",
                "db",
                "database is encrypted; passphrase environment variable is required",
                false,
                serde_json::json!({
                    "accepted_env": ["KC_VAULT_DB_PASSPHRASE", "KC_VAULT_PASSPHRASE"]
                }),
            )
        })?;

    validate_key_on_connection(conn, &passphrase)
}

pub fn open_db(db_path: &Path) -> AppResult<Connection> {
    if let Some(parent) = db_path.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            AppError::new(
                "KC_DB_OPEN_FAILED",
                "db",
                "failed to create database parent directory",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;
    }

    let conn = Connection::open(db_path).map_err(|e| {
        AppError::new(
            "KC_DB_OPEN_FAILED",
            "db",
            "failed to open sqlite database",
            false,
            serde_json::json!({ "error": e.to_string(), "path": db_path }),
        )
    })?;

    apply_db_encryption_key_if_needed(&conn, db_path)?;

    conn.pragma_update(None, "foreign_keys", "ON")
        .map_err(|e| {
            AppError::new(
                "KC_DB_OPEN_FAILED",
                "db",
                "failed to enable foreign_keys pragma",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;

    apply_migrations(&conn)?;
    Ok(conn)
}

pub fn apply_migrations(conn: &Connection) -> AppResult<()> {
    let current = schema_version(conn)?;
    if current > LATEST_SCHEMA_VERSION {
        return Err(AppError::new(
            "KC_DB_SCHEMA_INCOMPATIBLE",
            "db",
            "database schema version is newer than supported",
            false,
            serde_json::json!({ "current": current, "latest": LATEST_SCHEMA_VERSION }),
        ));
    }

    if current < 1 {
        let tx = conn.unchecked_transaction().map_err(|e| {
            AppError::new(
                "KC_DB_MIGRATION_FAILED",
                "db",
                "failed to begin migration transaction",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;

        tx.execute_batch(include_str!("../migrations/0001_init.sql"))
            .map_err(|e| {
                AppError::new(
                    "KC_DB_MIGRATION_FAILED",
                    "db",
                    "failed to apply migration 0001",
                    false,
                    serde_json::json!({ "error": e.to_string() }),
                )
            })?;

        tx.pragma_update(None, "user_version", 1i64).map_err(|e| {
            AppError::new(
                "KC_DB_MIGRATION_FAILED",
                "db",
                "failed to set schema user_version",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;

        tx.commit().map_err(|e| {
            AppError::new(
                "KC_DB_MIGRATION_FAILED",
                "db",
                "failed to commit migration transaction",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;
    }

    let current_after_v1 = schema_version(conn)?;
    if current_after_v1 < 2 {
        let tx = conn.unchecked_transaction().map_err(|e| {
            AppError::new(
                "KC_DB_MIGRATION_FAILED",
                "db",
                "failed to begin migration transaction",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;

        tx.execute_batch(include_str!("../migrations/0002_sync.sql"))
            .map_err(|e| {
                AppError::new(
                    "KC_DB_MIGRATION_FAILED",
                    "db",
                    "failed to apply migration 0002",
                    false,
                    serde_json::json!({ "error": e.to_string() }),
                )
            })?;

        tx.pragma_update(None, "user_version", 2i64).map_err(|e| {
            AppError::new(
                "KC_DB_MIGRATION_FAILED",
                "db",
                "failed to set schema user_version",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;

        tx.commit().map_err(|e| {
            AppError::new(
                "KC_DB_MIGRATION_FAILED",
                "db",
                "failed to commit migration transaction",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;
    }

    let current_after_v2 = schema_version(conn)?;
    if current_after_v2 < 3 {
        let tx = conn.unchecked_transaction().map_err(|e| {
            AppError::new(
                "KC_DB_MIGRATION_FAILED",
                "db",
                "failed to begin migration transaction",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;

        tx.execute_batch(include_str!("../migrations/0003_lineage_overlays.sql"))
            .map_err(|e| {
                AppError::new(
                    "KC_DB_MIGRATION_FAILED",
                    "db",
                    "failed to apply migration 0003",
                    false,
                    serde_json::json!({ "error": e.to_string() }),
                )
            })?;

        tx.pragma_update(None, "user_version", 3i64).map_err(|e| {
            AppError::new(
                "KC_DB_MIGRATION_FAILED",
                "db",
                "failed to set schema user_version",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;

        tx.commit().map_err(|e| {
            AppError::new(
                "KC_DB_MIGRATION_FAILED",
                "db",
                "failed to commit migration transaction",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;
    }

    let current_after_v3 = schema_version(conn)?;
    if current_after_v3 < 4 {
        let tx = conn.unchecked_transaction().map_err(|e| {
            AppError::new(
                "KC_DB_MIGRATION_FAILED",
                "db",
                "failed to begin migration transaction",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;

        tx.execute_batch(include_str!("../migrations/0004_device_trust.sql"))
            .map_err(|e| {
                AppError::new(
                    "KC_DB_MIGRATION_FAILED",
                    "db",
                    "failed to apply migration 0004",
                    false,
                    serde_json::json!({ "error": e.to_string() }),
                )
            })?;

        tx.pragma_update(None, "user_version", 4i64).map_err(|e| {
            AppError::new(
                "KC_DB_MIGRATION_FAILED",
                "db",
                "failed to set schema user_version",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;

        tx.commit().map_err(|e| {
            AppError::new(
                "KC_DB_MIGRATION_FAILED",
                "db",
                "failed to commit migration transaction",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;
    }

    let current_after_v4 = schema_version(conn)?;
    if current_after_v4 < 5 {
        let tx = conn.unchecked_transaction().map_err(|e| {
            AppError::new(
                "KC_DB_MIGRATION_FAILED",
                "db",
                "failed to begin migration transaction",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;

        tx.execute_batch(include_str!("../migrations/0005_lineage_edit_locks.sql"))
            .map_err(|e| {
                AppError::new(
                    "KC_DB_MIGRATION_FAILED",
                    "db",
                    "failed to apply migration 0005",
                    false,
                    serde_json::json!({ "error": e.to_string() }),
                )
            })?;

        tx.pragma_update(None, "user_version", 5i64).map_err(|e| {
            AppError::new(
                "KC_DB_MIGRATION_FAILED",
                "db",
                "failed to set schema user_version",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;

        tx.commit().map_err(|e| {
            AppError::new(
                "KC_DB_MIGRATION_FAILED",
                "db",
                "failed to commit migration transaction",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;
    }

    let current_after_v5 = schema_version(conn)?;
    if current_after_v5 < 6 {
        let tx = conn.unchecked_transaction().map_err(|e| {
            AppError::new(
                "KC_DB_MIGRATION_FAILED",
                "db",
                "failed to begin migration transaction",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;

        tx.execute_batch(include_str!("../migrations/0006_trust_identity_v2.sql"))
            .map_err(|e| {
                AppError::new(
                    "KC_DB_MIGRATION_FAILED",
                    "db",
                    "failed to apply migration 0006",
                    false,
                    serde_json::json!({ "error": e.to_string() }),
                )
            })?;

        tx.pragma_update(None, "user_version", 6i64).map_err(|e| {
            AppError::new(
                "KC_DB_MIGRATION_FAILED",
                "db",
                "failed to set schema user_version",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;

        tx.commit().map_err(|e| {
            AppError::new(
                "KC_DB_MIGRATION_FAILED",
                "db",
                "failed to commit migration transaction",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;
    }

    let current_after_v6 = schema_version(conn)?;
    if current_after_v6 < 7 {
        let tx = conn.unchecked_transaction().map_err(|e| {
            AppError::new(
                "KC_DB_MIGRATION_FAILED",
                "db",
                "failed to begin migration transaction",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;

        tx.execute_batch(include_str!("../migrations/0007_recovery_escrow_v2.sql"))
            .map_err(|e| {
                AppError::new(
                    "KC_DB_MIGRATION_FAILED",
                    "db",
                    "failed to apply migration 0007",
                    false,
                    serde_json::json!({ "error": e.to_string() }),
                )
            })?;

        tx.pragma_update(None, "user_version", 7i64).map_err(|e| {
            AppError::new(
                "KC_DB_MIGRATION_FAILED",
                "db",
                "failed to set schema user_version",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;

        tx.commit().map_err(|e| {
            AppError::new(
                "KC_DB_MIGRATION_FAILED",
                "db",
                "failed to commit migration transaction",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;
    }

    let current_after_v7 = schema_version(conn)?;
    if current_after_v7 < 8 {
        let tx = conn.unchecked_transaction().map_err(|e| {
            AppError::new(
                "KC_DB_MIGRATION_FAILED",
                "db",
                "failed to begin migration transaction",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;

        tx.execute_batch(include_str!("../migrations/0008_lineage_rbac_v2.sql"))
            .map_err(|e| {
                AppError::new(
                    "KC_DB_MIGRATION_FAILED",
                    "db",
                    "failed to apply migration 0008",
                    false,
                    serde_json::json!({ "error": e.to_string() }),
                )
            })?;

        tx.pragma_update(None, "user_version", 8i64).map_err(|e| {
            AppError::new(
                "KC_DB_MIGRATION_FAILED",
                "db",
                "failed to set schema user_version",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;

        tx.commit().map_err(|e| {
            AppError::new(
                "KC_DB_MIGRATION_FAILED",
                "db",
                "failed to commit migration transaction",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;
    }

    let current_after_v8 = schema_version(conn)?;
    if current_after_v8 < 9 {
        let tx = conn.unchecked_transaction().map_err(|e| {
            AppError::new(
                "KC_DB_MIGRATION_FAILED",
                "db",
                "failed to begin migration transaction",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;

        tx.execute_batch(include_str!(
            "../migrations/0009_trust_provider_governance.sql"
        ))
        .map_err(|e| {
            AppError::new(
                "KC_DB_MIGRATION_FAILED",
                "db",
                "failed to apply migration 0009",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;

        tx.pragma_update(None, "user_version", 9i64).map_err(|e| {
            AppError::new(
                "KC_DB_MIGRATION_FAILED",
                "db",
                "failed to set schema user_version",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;

        tx.commit().map_err(|e| {
            AppError::new(
                "KC_DB_MIGRATION_FAILED",
                "db",
                "failed to commit migration transaction",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;
    }

    let current_after_v9 = schema_version(conn)?;
    if current_after_v9 < 10 {
        let tx = conn.unchecked_transaction().map_err(|e| {
            AppError::new(
                "KC_DB_MIGRATION_FAILED",
                "db",
                "failed to begin migration transaction",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;

        tx.execute_batch(include_str!(
            "../migrations/0010_recovery_escrow_providers_v3.sql"
        ))
        .map_err(|e| {
            AppError::new(
                "KC_DB_MIGRATION_FAILED",
                "db",
                "failed to apply migration 0010",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;

        tx.pragma_update(None, "user_version", 10i64).map_err(|e| {
            AppError::new(
                "KC_DB_MIGRATION_FAILED",
                "db",
                "failed to set schema user_version",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;

        tx.commit().map_err(|e| {
            AppError::new(
                "KC_DB_MIGRATION_FAILED",
                "db",
                "failed to commit migration transaction",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;
    }

    let current_after_v10 = schema_version(conn)?;
    if current_after_v10 < 11 {
        let tx = conn.unchecked_transaction().map_err(|e| {
            AppError::new(
                "KC_DB_MIGRATION_FAILED",
                "db",
                "failed to begin migration transaction",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;

        tx.execute_batch(include_str!(
            "../migrations/0011_lineage_policy_conditions_v3.sql"
        ))
        .map_err(|e| {
            AppError::new(
                "KC_DB_MIGRATION_FAILED",
                "db",
                "failed to apply migration 0011",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;

        tx.pragma_update(None, "user_version", LATEST_SCHEMA_VERSION)
            .map_err(|e| {
                AppError::new(
                    "KC_DB_MIGRATION_FAILED",
                    "db",
                    "failed to set schema user_version",
                    false,
                    serde_json::json!({ "error": e.to_string() }),
                )
            })?;

        tx.commit().map_err(|e| {
            AppError::new(
                "KC_DB_MIGRATION_FAILED",
                "db",
                "failed to commit migration transaction",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;
    }

    Ok(())
}

pub fn schema_version(conn: &Connection) -> AppResult<i64> {
    conn.query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|e| {
            AppError::new(
                "KC_DB_SCHEMA_INCOMPATIBLE",
                "db",
                "failed to read schema version",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })
}

#[cfg(test)]
mod tests {
    use super::{remove_file_if_exists, rollback_migration_files};

    #[test]
    fn remove_file_if_exists_reports_unexpected_errors() {
        let root = tempfile::tempdir().expect("tempdir");
        let path = root.path().join("not-a-file");
        std::fs::create_dir_all(&path).expect("create directory");

        let err = remove_file_if_exists(&path, "test-phase").expect_err("expected remove failure");
        assert_eq!(err.code, "KC_DB_ENCRYPTION_MIGRATION_FAILED");
        assert_eq!(err.details["phase"], "test-phase");
    }

    #[test]
    fn rollback_migration_files_reports_restore_failure() {
        let root = tempfile::tempdir().expect("tempdir");
        let db_path = root.path().join("knowledge.sqlite");
        let tmp_path = db_path.with_extension("sqlcipher.tmp");
        let bak_path = db_path.with_extension("pre-sqlcipher.bak");
        std::fs::write(&db_path, b"db").expect("write db");
        std::fs::write(&tmp_path, b"tmp").expect("write tmp");

        let rollback_errors = rollback_migration_files(&db_path, &tmp_path, &bak_path)
            .expect_err("expected rollback to report restore failure");
        assert!(
            rollback_errors
                .iter()
                .any(|entry| entry.get("operation") == Some(&serde_json::json!("restore_backup"))),
            "rollback errors should include restore_backup entry"
        );
    }
}
