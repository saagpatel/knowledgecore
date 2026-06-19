use kc_core::app_error::AppResult;
use kc_core::db::open_db;
use kc_core::sync::{
    sync_auth_readiness_target, sync_auth_readiness_targets, sync_auth_strict_check_targets,
    sync_merge_preview_target_with_policy, sync_pull_target_with_mode, sync_push_target,
    sync_status_target,
};
use kc_core::vault::vault_open;
use std::path::Path;

pub fn run_status(vault_path: &str, target_path: &str) -> AppResult<()> {
    let vault = vault_open(Path::new(vault_path))?;
    let conn = open_db(&Path::new(vault_path).join(vault.db.relative_path))?;
    let status = sync_status_target(&conn, target_path)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&status).unwrap_or_else(|_| "{}".to_string())
    );
    Ok(())
}

pub fn run_auth_readiness(vault_path: &str, target_path: &str) -> AppResult<()> {
    let vault = vault_open(Path::new(vault_path))?;
    let conn = open_db(&Path::new(vault_path).join(vault.db.relative_path))?;
    let report = sync_auth_readiness_target(&conn, target_path)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
    );
    Ok(())
}

pub fn run_auth_readiness_report(vault_path: &str, target_paths: &[String]) -> AppResult<()> {
    let vault = vault_open(Path::new(vault_path))?;
    let conn = open_db(&Path::new(vault_path).join(vault.db.relative_path))?;
    let report = sync_auth_readiness_targets(&conn, target_paths)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
    );
    Ok(())
}

pub fn run_auth_strict_check(vault_path: &str, target_paths: &[String]) -> AppResult<()> {
    let vault = vault_open(Path::new(vault_path))?;
    let conn = open_db(&Path::new(vault_path).join(vault.db.relative_path))?;
    let report = sync_auth_strict_check_targets(&conn, target_paths)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
    );
    Ok(())
}

pub fn run_push(vault_path: &str, target_path: &str, now_ms: i64) -> AppResult<()> {
    let vault = vault_open(Path::new(vault_path))?;
    let conn = open_db(&Path::new(vault_path).join(vault.db.relative_path))?;
    let out = sync_push_target(&conn, Path::new(vault_path), target_path, now_ms)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&out).unwrap_or_else(|_| "{}".to_string())
    );
    Ok(())
}

pub fn run_pull(
    vault_path: &str,
    target_path: &str,
    now_ms: i64,
    auto_merge_mode: Option<&str>,
    strict_auth: bool,
) -> AppResult<()> {
    let vault = vault_open(Path::new(vault_path))?;
    let conn = open_db(&Path::new(vault_path).join(vault.db.relative_path))?;
    let out = sync_pull_target_with_mode(
        &conn,
        Path::new(vault_path),
        target_path,
        now_ms,
        auto_merge_mode,
        strict_auth,
    )?;
    println!(
        "{}",
        serde_json::to_string_pretty(&out).unwrap_or_else(|_| "{}".to_string())
    );
    Ok(())
}

pub fn run_merge_preview(
    vault_path: &str,
    target_path: &str,
    policy: Option<&str>,
    now_ms: i64,
) -> AppResult<()> {
    let vault = vault_open(Path::new(vault_path))?;
    let conn = open_db(&Path::new(vault_path).join(vault.db.relative_path))?;
    let out = sync_merge_preview_target_with_policy(
        &conn,
        Path::new(vault_path),
        target_path,
        policy,
        now_ms,
    )?;
    println!(
        "{}",
        serde_json::to_string_pretty(&out).unwrap_or_else(|_| "{}".to_string())
    );
    Ok(())
}
