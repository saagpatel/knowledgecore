use kc_core::vault::vault_init;
use std::process::Command;

fn run_cli(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_kc_cli"))
        .args(args)
        .output()
        .expect("run kc_cli")
}

#[test]
fn cli_trust_identity_and_device_workflow_round_trip() {
    let root = tempfile::tempdir().expect("tempdir").keep();
    vault_init(&root, "demo", 1).expect("vault init");
    let vault_path = root.to_string_lossy().to_string();

    let identity_start = run_cli(&[
        "trust",
        "identity",
        "start",
        &vault_path,
        "--provider",
        "default",
        "--now-ms",
        "10",
    ]);
    assert!(
        identity_start.status.success(),
        "identity start stderr: {}",
        String::from_utf8_lossy(&identity_start.stderr)
    );

    let identity_complete = run_cli(&[
        "trust",
        "identity",
        "complete",
        &vault_path,
        "--provider",
        "default",
        "--code",
        "sub:alice@example.com",
        "--now-ms",
        "11",
    ]);
    assert!(
        identity_complete.status.success(),
        "identity complete stderr: {}",
        String::from_utf8_lossy(&identity_complete.stderr)
    );

    let device_enroll = run_cli(&[
        "trust",
        "device",
        "enroll",
        &vault_path,
        "--device-label",
        "desktop",
        "--now-ms",
        "12",
    ]);
    assert!(
        device_enroll.status.success(),
        "device enroll stderr: {}",
        String::from_utf8_lossy(&device_enroll.stderr)
    );
    let enroll_json: serde_json::Value =
        serde_json::from_slice(&device_enroll.stdout).expect("enroll json");
    let device_id = enroll_json
        .get("device")
        .and_then(|v| v.get("device_id"))
        .and_then(|v| v.as_str())
        .expect("device id in enroll output")
        .to_string();

    let verify_chain = run_cli(&[
        "trust",
        "device",
        "verify-chain",
        &vault_path,
        "--device-id",
        &device_id,
        "--now-ms",
        "13",
    ]);
    assert!(
        verify_chain.status.success(),
        "verify-chain stderr: {}",
        String::from_utf8_lossy(&verify_chain.stderr)
    );

    let listed = run_cli(&["trust", "device", "list", &vault_path]);
    assert!(
        listed.status.success(),
        "list stderr: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let list_json: serde_json::Value = serde_json::from_slice(&listed.stdout).expect("list json");
    let devices = list_json
        .get("devices")
        .and_then(|v| v.as_array())
        .expect("devices array");
    assert!(!devices.is_empty());
    assert!(devices.iter().any(|d| {
        d.get("device_id")
            .and_then(|v| v.as_str())
            .map(|id| id == device_id)
            .unwrap_or(false)
    }));
}

#[test]
fn cli_trust_device_enroll_signing_key_records_custody_metadata() {
    let root = tempfile::tempdir().expect("tempdir").keep();
    vault_init(&root, "demo", 1).expect("vault init");
    let vault_path = root.to_string_lossy().to_string();

    let identity_start = run_cli(&[
        "trust",
        "identity",
        "start",
        &vault_path,
        "--provider",
        "default",
        "--now-ms",
        "30",
    ]);
    assert!(
        identity_start.status.success(),
        "identity start stderr: {}",
        String::from_utf8_lossy(&identity_start.stderr)
    );

    let identity_complete = run_cli(&[
        "trust",
        "identity",
        "complete",
        &vault_path,
        "--provider",
        "default",
        "--code",
        "sub:alice@example.com",
        "--now-ms",
        "31",
    ]);
    assert!(
        identity_complete.status.success(),
        "identity complete stderr: {}",
        String::from_utf8_lossy(&identity_complete.stderr)
    );

    std::env::set_var("KC_TEST_SYNC_KEY_PASSPHRASE", "custody-passphrase");
    let device_enroll = run_cli(&[
        "trust",
        "device",
        "enroll-signing-key",
        &vault_path,
        "--device-label",
        "desktop",
        "--passphrase-env",
        "KC_TEST_SYNC_KEY_PASSPHRASE",
        "--now-ms",
        "32",
    ]);
    std::env::remove_var("KC_TEST_SYNC_KEY_PASSPHRASE");
    assert!(
        device_enroll.status.success(),
        "device enroll signing key stderr: {}",
        String::from_utf8_lossy(&device_enroll.stderr)
    );
    let enroll_json: serde_json::Value =
        serde_json::from_slice(&device_enroll.stdout).expect("enroll json");
    assert_eq!(
        enroll_json
            .get("signing_key")
            .and_then(|v| v.get("signature_alg"))
            .and_then(|v| v.as_str()),
        Some("ed25519_sync_head_v1")
    );
    assert!(enroll_json
        .get("signing_key")
        .and_then(|v| v.get("key_reference"))
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .starts_with("sync-signing:"));
    assert!(enroll_json.get("seed_ciphertext").is_none());
    let device_id = enroll_json
        .get("device")
        .and_then(|v| v.get("device_id"))
        .and_then(|v| v.as_str())
        .expect("device id");

    let status = run_cli(&[
        "trust",
        "device",
        "signing-key-status",
        &vault_path,
        "--device-id",
        device_id,
    ]);
    assert!(
        status.status.success(),
        "signing key status stderr: {}",
        String::from_utf8_lossy(&status.stderr)
    );
    let status_json: serde_json::Value =
        serde_json::from_slice(&status.stdout).expect("status json");
    assert_eq!(
        status_json
            .get("signing_key")
            .and_then(|v| v.get("device_id"))
            .and_then(|v| v.as_str()),
        Some(device_id)
    );
    assert!(status_json
        .get("recovery_guidance")
        .is_some_and(|v| v.is_null()));

    std::env::set_var("KC_TEST_SYNC_KEY_PASSPHRASE", "custody-passphrase");
    let rotated = run_cli(&[
        "trust",
        "device",
        "signing-key-rotate",
        &vault_path,
        "--old-device-id",
        device_id,
        "--new-device-label",
        "desktop-rotated",
        "--passphrase-env",
        "KC_TEST_SYNC_KEY_PASSPHRASE",
        "--now-ms",
        "33",
    ]);
    std::env::remove_var("KC_TEST_SYNC_KEY_PASSPHRASE");
    assert!(
        rotated.status.success(),
        "signing key rotate stderr: {}",
        String::from_utf8_lossy(&rotated.stderr)
    );
    let rotated_json: serde_json::Value =
        serde_json::from_slice(&rotated.stdout).expect("rotate json");
    assert_eq!(
        rotated_json
            .get("old_signing_key")
            .and_then(|v| v.get("device_id"))
            .and_then(|v| v.as_str()),
        Some(device_id)
    );
    assert_eq!(
        rotated_json
            .get("old_signing_key")
            .and_then(|v| v.get("rotated_at_ms"))
            .and_then(|v| v.as_i64()),
        Some(37)
    );
    let new_device_id = rotated_json
        .get("device")
        .and_then(|v| v.get("device_id"))
        .and_then(|v| v.as_str())
        .expect("replacement device id");
    assert_ne!(new_device_id, device_id);
    assert_eq!(
        rotated_json
            .get("signing_key")
            .and_then(|v| v.get("device_id"))
            .and_then(|v| v.as_str()),
        Some(new_device_id)
    );

    let old_status_after_rotate = run_cli(&[
        "trust",
        "device",
        "signing-key-status",
        &vault_path,
        "--device-id",
        device_id,
    ]);
    assert!(
        old_status_after_rotate.status.success(),
        "old signing key status after rotate stderr: {}",
        String::from_utf8_lossy(&old_status_after_rotate.stderr)
    );
    let old_status_after_rotate_json: serde_json::Value =
        serde_json::from_slice(&old_status_after_rotate.stdout).expect("old status json");
    assert!(old_status_after_rotate_json
        .get("signing_key")
        .unwrap()
        .is_null());
    let old_recovery_guidance = old_status_after_rotate_json
        .get("recovery_guidance")
        .expect("old recovery guidance");
    assert_eq!(
        old_recovery_guidance
            .get("private_key_recoverable")
            .and_then(|v| v.as_bool()),
        Some(false)
    );
    assert!(old_recovery_guidance
        .get("summary")
        .and_then(|v| v.as_str())
        .is_some_and(|message| message.contains("re-enroll a new local signing device")));

    let listed_after_rotate = run_cli(&["trust", "device", "list", &vault_path]);
    assert!(
        listed_after_rotate.status.success(),
        "list after rotate stderr: {}",
        String::from_utf8_lossy(&listed_after_rotate.stderr)
    );
    let listed_after_rotate_json: serde_json::Value =
        serde_json::from_slice(&listed_after_rotate.stdout).expect("list after rotate json");
    let listed_devices = listed_after_rotate_json
        .get("devices")
        .and_then(|v| v.as_array())
        .expect("devices array after rotate");
    assert!(listed_devices.iter().any(|d| {
        d.get("device_id")
            .and_then(|v| v.as_str())
            .is_some_and(|id| id == device_id)
    }));
    assert!(listed_devices.iter().any(|d| {
        d.get("device_id")
            .and_then(|v| v.as_str())
            .is_some_and(|id| id == new_device_id)
    }));

    let deleted = run_cli(&[
        "trust",
        "device",
        "signing-key-delete",
        &vault_path,
        "--device-id",
        new_device_id,
        "--now-ms",
        "38",
    ]);
    assert!(
        deleted.status.success(),
        "signing key delete stderr: {}",
        String::from_utf8_lossy(&deleted.stderr)
    );
    let delete_json: serde_json::Value =
        serde_json::from_slice(&deleted.stdout).expect("delete json");
    assert_eq!(
        delete_json.get("deleted").and_then(|v| v.as_bool()),
        Some(true)
    );
    assert!(delete_json
        .get("recovery_guidance")
        .and_then(|v| v.get("command"))
        .and_then(|v| v.as_str())
        .is_some_and(|command| command.contains("enroll-signing-key")));

    let status_after_delete = run_cli(&[
        "trust",
        "device",
        "signing-key-status",
        &vault_path,
        "--device-id",
        new_device_id,
    ]);
    assert!(
        status_after_delete.status.success(),
        "signing key status after delete stderr: {}",
        String::from_utf8_lossy(&status_after_delete.stderr)
    );
    let status_after_delete_json: serde_json::Value =
        serde_json::from_slice(&status_after_delete.stdout).expect("status after delete json");
    assert!(status_after_delete_json
        .get("signing_key")
        .unwrap()
        .is_null());
    assert!(status_after_delete_json
        .get("recovery_guidance")
        .and_then(|v| v.get("summary"))
        .and_then(|v| v.as_str())
        .is_some_and(|message| message.contains("not recoverable")));
}

#[test]
fn cli_trust_device_signing_key_rotate_rejects_missing_old_custody() {
    let root = tempfile::tempdir().expect("tempdir").keep();
    vault_init(&root, "demo", 1).expect("vault init");
    let vault_path = root.to_string_lossy().to_string();

    std::env::set_var(
        "KC_TEST_SYNC_KEY_ROTATE_MISSING_PASSPHRASE",
        "custody-passphrase",
    );
    let rotate = run_cli(&[
        "trust",
        "device",
        "signing-key-rotate",
        &vault_path,
        "--old-device-id",
        "missing-device",
        "--new-device-label",
        "desktop-rotated",
        "--passphrase-env",
        "KC_TEST_SYNC_KEY_ROTATE_MISSING_PASSPHRASE",
        "--now-ms",
        "50",
    ]);
    std::env::remove_var("KC_TEST_SYNC_KEY_ROTATE_MISSING_PASSPHRASE");
    assert!(!rotate.status.success());
    assert!(
        String::from_utf8_lossy(&rotate.stderr).contains("KC_SYNC_SIGNING_KEY_NOT_FOUND"),
        "rotate missing stderr: {}",
        String::from_utf8_lossy(&rotate.stderr)
    );

    let listed = run_cli(&["trust", "device", "list", &vault_path]);
    assert!(
        listed.status.success(),
        "list after failed rotate stderr: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let listed_json: serde_json::Value =
        serde_json::from_slice(&listed.stdout).expect("list after failed rotate json");
    assert_eq!(
        listed_json
            .get("devices")
            .and_then(|v| v.as_array())
            .expect("devices array")
            .len(),
        0
    );
}

#[test]
fn cli_trust_discovery_and_tenant_template_round_trip() {
    let root = tempfile::tempdir().expect("tempdir").keep();
    vault_init(&root, "demo", 1).expect("vault init");
    let vault_path = root.to_string_lossy().to_string();

    let discovered = run_cli(&[
        "trust",
        "provider",
        "discover",
        &vault_path,
        "--issuer",
        "https://tenant.example/oidc",
        "--now-ms",
        "20",
    ]);
    assert!(
        discovered.status.success(),
        "provider discover stderr: {}",
        String::from_utf8_lossy(&discovered.stderr)
    );
    let discover_json: serde_json::Value =
        serde_json::from_slice(&discovered.stdout).expect("discover json");
    let provider_id = discover_json
        .get("provider")
        .and_then(|v| v.get("provider_id"))
        .and_then(|v| v.as_str())
        .expect("provider id in discover output")
        .to_string();
    assert!(provider_id.starts_with("auto-"));

    let tenant_template = run_cli(&[
        "trust",
        "policy",
        "set-tenant-template",
        &vault_path,
        "--provider",
        "https://tenant.example/oidc",
        "--tenant-id",
        "Tenant-A",
        "--now-ms",
        "21",
    ]);
    assert!(
        tenant_template.status.success(),
        "tenant template stderr: {}",
        String::from_utf8_lossy(&tenant_template.stderr)
    );
    let policy_json: serde_json::Value =
        serde_json::from_slice(&tenant_template.stdout).expect("tenant template json");
    assert_eq!(
        policy_json
            .get("policy")
            .and_then(|v| v.get("provider_id"))
            .and_then(|v| v.as_str()),
        Some(provider_id.as_str())
    );
    assert!(policy_json
        .get("policy")
        .and_then(|v| v.get("require_claims_json"))
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .contains("\"tenant\":\"tenant-a\""));
}
