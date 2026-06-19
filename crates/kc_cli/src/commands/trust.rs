use kc_core::app_error::{AppError, AppResult};
use kc_core::rpc_service::{
    trust_device_enroll_service, trust_device_enroll_signing_key_service,
    trust_device_list_service, trust_device_signing_key_delete_service,
    trust_device_signing_key_status_service, trust_device_verify_chain_service,
    trust_identity_complete_service, trust_identity_start_service, trust_provider_add_service,
    trust_provider_disable_service, trust_provider_discover_service, trust_provider_list_service,
    trust_provider_policy_set_service, trust_provider_policy_set_tenant_template_service,
};
use std::path::Path;

fn now_ms() -> i64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time before unix epoch");
    now.as_millis() as i64
}

pub fn run_identity_start(
    vault_path: &str,
    provider: &str,
    now_override: Option<i64>,
) -> AppResult<()> {
    let out = trust_identity_start_service(
        Path::new(vault_path),
        provider,
        now_override.unwrap_or_else(now_ms),
    )?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "status": "ok",
            "identity": out
        }))
        .unwrap_or_else(|_| "{}".to_string())
    );
    Ok(())
}

pub fn run_identity_complete(
    vault_path: &str,
    provider: &str,
    code: &str,
    now_override: Option<i64>,
) -> AppResult<()> {
    let out = trust_identity_complete_service(
        Path::new(vault_path),
        provider,
        code,
        now_override.unwrap_or_else(now_ms),
    )?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "status": "ok",
            "session": out
        }))
        .unwrap_or_else(|_| "{}".to_string())
    );
    Ok(())
}

pub fn run_device_enroll(
    vault_path: &str,
    device_label: &str,
    now_override: Option<i64>,
) -> AppResult<()> {
    let out = trust_device_enroll_service(
        Path::new(vault_path),
        device_label,
        now_override.unwrap_or_else(now_ms),
    )?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "status": "ok",
            "device": out.device,
            "certificate": out.certificate
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

pub fn run_device_enroll_signing_key(
    vault_path: &str,
    device_label: &str,
    passphrase_env: &str,
    now_override: Option<i64>,
) -> AppResult<()> {
    let passphrase = passphrase_from_env(passphrase_env)?;
    let out = trust_device_enroll_signing_key_service(
        Path::new(vault_path),
        device_label,
        &passphrase,
        now_override.unwrap_or_else(now_ms),
    )?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "status": "ok",
            "device": out.device,
            "certificate": out.certificate,
            "signing_key": out.signing_key
        }))
        .unwrap_or_else(|_| "{}".to_string())
    );
    Ok(())
}

pub fn run_device_verify_chain(
    vault_path: &str,
    device_id: &str,
    now_override: Option<i64>,
) -> AppResult<()> {
    let out = trust_device_verify_chain_service(
        Path::new(vault_path),
        device_id,
        now_override.unwrap_or_else(now_ms),
    )?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "status": "ok",
            "certificate": out
        }))
        .unwrap_or_else(|_| "{}".to_string())
    );
    Ok(())
}

pub fn run_device_signing_key_status(vault_path: &str, device_id: &str) -> AppResult<()> {
    let out = trust_device_signing_key_status_service(Path::new(vault_path), device_id)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "status": "ok",
            "signing_key": out
        }))
        .unwrap_or_else(|_| "{}".to_string())
    );
    Ok(())
}

pub fn run_device_signing_key_delete(
    vault_path: &str,
    device_id: &str,
    now_override: Option<i64>,
) -> AppResult<()> {
    let out = trust_device_signing_key_delete_service(
        Path::new(vault_path),
        device_id,
        now_override.unwrap_or_else(now_ms),
    )?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "status": "ok",
            "deleted": out.deleted,
            "signing_key": out.signing_key
        }))
        .unwrap_or_else(|_| "{}".to_string())
    );
    Ok(())
}

pub fn run_device_list(vault_path: &str) -> AppResult<()> {
    let out = trust_device_list_service(Path::new(vault_path))?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "status": "ok",
            "devices": out
        }))
        .unwrap_or_else(|_| "{}".to_string())
    );
    Ok(())
}

pub fn run_provider_add(
    vault_path: &str,
    provider_id: &str,
    issuer: &str,
    aud: &str,
    jwks: &str,
    now_override: Option<i64>,
) -> AppResult<()> {
    let out = trust_provider_add_service(
        Path::new(vault_path),
        provider_id,
        issuer,
        aud,
        jwks,
        now_override.unwrap_or_else(now_ms),
    )?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "status": "ok",
            "provider": out
        }))
        .unwrap_or_else(|_| "{}".to_string())
    );
    Ok(())
}

pub fn run_provider_disable(
    vault_path: &str,
    provider_id: &str,
    now_override: Option<i64>,
) -> AppResult<()> {
    let out = trust_provider_disable_service(
        Path::new(vault_path),
        provider_id,
        now_override.unwrap_or_else(now_ms),
    )?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "status": "ok",
            "provider": out
        }))
        .unwrap_or_else(|_| "{}".to_string())
    );
    Ok(())
}

pub fn run_provider_list(vault_path: &str) -> AppResult<()> {
    let out = trust_provider_list_service(Path::new(vault_path))?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "status": "ok",
            "providers": out
        }))
        .unwrap_or_else(|_| "{}".to_string())
    );
    Ok(())
}

pub fn run_provider_discover(
    vault_path: &str,
    issuer: &str,
    now_override: Option<i64>,
) -> AppResult<()> {
    let out = trust_provider_discover_service(
        Path::new(vault_path),
        issuer,
        now_override.unwrap_or_else(now_ms),
    )?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "status": "ok",
            "provider": out
        }))
        .unwrap_or_else(|_| "{}".to_string())
    );
    Ok(())
}

pub fn run_policy_set(
    vault_path: &str,
    provider_id: &str,
    max_clock_skew_ms: i64,
    require_claims_json: &str,
    now_override: Option<i64>,
) -> AppResult<()> {
    let out = trust_provider_policy_set_service(
        Path::new(vault_path),
        provider_id,
        max_clock_skew_ms,
        require_claims_json,
        now_override.unwrap_or_else(now_ms),
    )?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "status": "ok",
            "policy": out
        }))
        .unwrap_or_else(|_| "{}".to_string())
    );
    Ok(())
}

pub fn run_policy_set_tenant_template(
    vault_path: &str,
    provider_ref: &str,
    tenant_id: &str,
    now_override: Option<i64>,
) -> AppResult<()> {
    let out = trust_provider_policy_set_tenant_template_service(
        Path::new(vault_path),
        provider_ref,
        tenant_id,
        now_override.unwrap_or_else(now_ms),
    )?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "status": "ok",
            "policy": out
        }))
        .unwrap_or_else(|_| "{}".to_string())
    );
    Ok(())
}
