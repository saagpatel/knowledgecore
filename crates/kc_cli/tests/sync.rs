use kc_core::db::open_db;
use kc_core::object_store::ObjectStore;
use kc_core::sync::{sync_pull, sync_push};
use kc_core::trust::{trust_device_init, trust_device_verify};
use kc_core::trust_identity::{
    trust_device_enroll, trust_device_verify_chain, trust_identity_complete, trust_identity_start,
};
use kc_core::vault::vault_init;
use std::process::Command;

macro_rules! enroll_verified_sync_author {
    ($conn:expr, $now_ms:expr) => {{
        let device =
            trust_device_init($conn, "sync-author", "tester", $now_ms).expect("trust init");
        trust_device_verify(
            $conn,
            &device.device_id,
            &device.fingerprint,
            "tester",
            $now_ms + 1,
        )
        .expect("trust verify");
        trust_identity_start($conn, "default", $now_ms + 2).expect("identity start");
        trust_identity_complete($conn, "default", "sub:sync-author", $now_ms + 3)
            .expect("identity complete");
        trust_device_enroll($conn, "default", &device.device_id, $now_ms + 4)
            .expect("device enroll");
        trust_device_verify_chain($conn, &device.device_id, $now_ms + 5).expect("verify chain");
    }};
}

#[test]
fn cli_sync_push_and_status_work() {
    let root = tempfile::tempdir().expect("tempdir").keep();
    let vault_root = root.join("vault");
    let sync_target = root.join("sync-target");

    vault_init(&vault_root, "demo", 1).expect("vault init");
    let conn = open_db(&vault_root.join("db/knowledge.sqlite")).expect("open db");
    enroll_verified_sync_author!(&conn, 10);
    let store = ObjectStore::new(vault_root.join("store/objects"));
    store
        .put_bytes(&conn, b"sync payload", 1)
        .expect("put object");

    let bin = env!("CARGO_BIN_EXE_kc_cli");

    let push = Command::new(bin)
        .args([
            "sync",
            "push",
            vault_root.to_string_lossy().as_ref(),
            sync_target.to_string_lossy().as_ref(),
            "--now-ms",
            "100",
        ])
        .output()
        .expect("run sync push");
    assert!(
        push.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&push.stderr)
    );

    let status = Command::new(bin)
        .args([
            "sync",
            "status",
            vault_root.to_string_lossy().as_ref(),
            sync_target.to_string_lossy().as_ref(),
        ])
        .output()
        .expect("run sync status");
    assert!(
        status.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&status.stderr)
    );
    let stdout = String::from_utf8(status.stdout).expect("utf8 status");
    assert!(stdout.contains("\"remote_head\""));

    let readiness = Command::new(bin)
        .args([
            "sync",
            "auth-readiness",
            vault_root.to_string_lossy().as_ref(),
            sync_target.to_string_lossy().as_ref(),
        ])
        .output()
        .expect("run sync auth-readiness");
    assert!(
        readiness.status.success(),
        "auth readiness stderr: {}",
        String::from_utf8_lossy(&readiness.stderr)
    );
    let readiness_json: serde_json::Value =
        serde_json::from_slice(&readiness.stdout).expect("auth readiness json");
    assert_eq!(
        readiness_json
            .get("classification")
            .and_then(|v| v.as_str()),
        Some("legacy_schema")
    );
    assert_eq!(
        readiness_json
            .get("depends_on_legacy_fallback")
            .and_then(|v| v.as_bool()),
        Some(true)
    );
    assert_eq!(
        readiness_json.get("strict_ready").and_then(|v| v.as_bool()),
        Some(false)
    );

    let empty_target = root.join("empty-sync-target");
    let readiness_report = Command::new(bin)
        .args([
            "sync",
            "auth-readiness-report",
            vault_root.to_string_lossy().as_ref(),
            sync_target.to_string_lossy().as_ref(),
            empty_target.to_string_lossy().as_ref(),
        ])
        .output()
        .expect("run sync auth-readiness-report");
    assert!(
        readiness_report.status.success(),
        "auth readiness report stderr: {}",
        String::from_utf8_lossy(&readiness_report.stderr)
    );
    let report_json: serde_json::Value =
        serde_json::from_slice(&readiness_report.stdout).expect("auth readiness report json");
    assert_eq!(
        report_json.get("target_count").and_then(|v| v.as_i64()),
        Some(2)
    );
    assert_eq!(
        report_json
            .get("strict_ready_count")
            .and_then(|v| v.as_i64()),
        Some(1)
    );
    assert_eq!(
        report_json
            .get("depends_on_legacy_fallback_count")
            .and_then(|v| v.as_i64()),
        Some(1)
    );
    assert_eq!(
        report_json
            .get("classification_counts")
            .and_then(|v| v.get("legacy_schema"))
            .and_then(|v| v.as_i64()),
        Some(1)
    );
    assert_eq!(
        report_json
            .get("classification_counts")
            .and_then(|v| v.get("no_remote_head"))
            .and_then(|v| v.as_i64()),
        Some(1)
    );
    assert!(!empty_target.exists());
}

#[test]
fn cli_sync_supports_s3_uri_with_emulation() {
    let root = tempfile::tempdir().expect("tempdir").keep();
    let pull_root = tempfile::tempdir().expect("pull tempdir").keep();
    let vault_root = root.join("vault");
    let pull_vault_root = pull_root.join("vault");
    let emulated_s3 = root.join("emulated-s3");
    let target_uri = "s3://demo-bucket/kc";

    vault_init(&vault_root, "demo", 1).expect("vault init");
    vault_init(&pull_vault_root, "pull-demo", 1).expect("pull vault init");

    let conn = open_db(&vault_root.join("db/knowledge.sqlite")).expect("open db");
    enroll_verified_sync_author!(&conn, 20);
    let store = ObjectStore::new(vault_root.join("store/objects"));
    store
        .put_bytes(&conn, b"sync payload", 1)
        .expect("put object");

    let bin = env!("CARGO_BIN_EXE_kc_cli");

    let push = Command::new(bin)
        .env(
            "KC_SYNC_S3_EMULATE_ROOT",
            emulated_s3.to_string_lossy().as_ref(),
        )
        .env("KC_VAULT_PASSPHRASE", "cli-sync-passphrase")
        .args([
            "sync",
            "push",
            vault_root.to_string_lossy().as_ref(),
            target_uri,
            "--now-ms",
            "100",
        ])
        .output()
        .expect("run sync push");
    assert!(
        push.status.success(),
        "push stderr: {}",
        String::from_utf8_lossy(&push.stderr)
    );

    let pull = Command::new(bin)
        .env(
            "KC_SYNC_S3_EMULATE_ROOT",
            emulated_s3.to_string_lossy().as_ref(),
        )
        .env("KC_VAULT_PASSPHRASE", "cli-sync-passphrase")
        .args([
            "sync",
            "pull",
            pull_vault_root.to_string_lossy().as_ref(),
            target_uri,
            "--now-ms",
            "101",
        ])
        .output()
        .expect("run sync pull");
    assert!(
        pull.status.success(),
        "pull stderr: {}",
        String::from_utf8_lossy(&pull.stderr)
    );

    let status = Command::new(bin)
        .env(
            "KC_SYNC_S3_EMULATE_ROOT",
            emulated_s3.to_string_lossy().as_ref(),
        )
        .args([
            "sync",
            "status",
            vault_root.to_string_lossy().as_ref(),
            target_uri,
        ])
        .output()
        .expect("run sync status");
    assert!(
        status.status.success(),
        "status stderr: {}",
        String::from_utf8_lossy(&status.stderr)
    );
    let stdout = String::from_utf8(status.stdout).expect("utf8 status");
    assert!(stdout.contains(target_uri));
}

#[test]
fn cli_sync_merge_preview_and_conservative_pull_work() {
    let root = tempfile::tempdir().expect("tempdir").keep();
    let vault_a = root.join("vault_a");
    let vault_b = root.join("vault_b");
    let sync_target = root.join("sync-target");

    vault_init(&vault_a, "a", 1).expect("vault a init");
    vault_init(&vault_b, "b", 1).expect("vault b init");

    let conn_a = open_db(&vault_a.join("db/knowledge.sqlite")).expect("open db a");
    let conn_b = open_db(&vault_b.join("db/knowledge.sqlite")).expect("open db b");
    let store_a = ObjectStore::new(vault_a.join("store/objects"));
    let store_b = ObjectStore::new(vault_b.join("store/objects"));

    store_a
        .put_bytes(&conn_a, b"baseline", 1)
        .expect("put baseline");
    sync_push(&conn_a, &vault_a, &sync_target, 100).expect("push baseline");
    sync_pull(&conn_b, &vault_b, &sync_target, 101).expect("pull baseline");
    let conn_b = open_db(&vault_b.join("db/knowledge.sqlite")).expect("reopen db b");

    store_a
        .put_bytes(&conn_a, b"local-change", 2)
        .expect("put local change");
    store_b
        .put_bytes(&conn_b, b"remote-change", 2)
        .expect("put remote change");
    sync_push(&conn_b, &vault_b, &sync_target, 200).expect("push remote change");

    let bin = env!("CARGO_BIN_EXE_kc_cli");
    let merge_preview = Command::new(bin)
        .args([
            "sync",
            "merge-preview",
            vault_a.to_string_lossy().as_ref(),
            sync_target.to_string_lossy().as_ref(),
            "--policy",
            "conservative_plus_v2",
            "--now-ms",
            "300",
        ])
        .output()
        .expect("run merge preview");
    assert!(
        merge_preview.status.success(),
        "merge preview stderr: {}",
        String::from_utf8_lossy(&merge_preview.stderr)
    );
    let preview_stdout = String::from_utf8(merge_preview.stdout).expect("preview utf8");
    assert!(preview_stdout.contains("\"safe\": true"));
    assert!(preview_stdout.contains("\"merge_policy\": \"conservative_plus_v2\""));

    let merge_preview_v3 = Command::new(bin)
        .args([
            "sync",
            "merge-preview",
            vault_a.to_string_lossy().as_ref(),
            sync_target.to_string_lossy().as_ref(),
            "--policy",
            "conservative_plus_v3",
            "--now-ms",
            "300",
        ])
        .output()
        .expect("run merge preview v3");
    assert!(
        merge_preview_v3.status.success(),
        "merge preview v3 stderr: {}",
        String::from_utf8_lossy(&merge_preview_v3.stderr)
    );
    let preview_v3_stdout = String::from_utf8(merge_preview_v3.stdout).expect("preview v3 utf8");
    assert!(preview_v3_stdout.contains("\"merge_policy\": \"conservative_plus_v3\""));
    assert!(preview_v3_stdout.contains("\"safe_disjoint\""));

    let merge_preview_v4 = Command::new(bin)
        .args([
            "sync",
            "merge-preview",
            vault_a.to_string_lossy().as_ref(),
            sync_target.to_string_lossy().as_ref(),
            "--policy",
            "conservative_plus_v4",
            "--now-ms",
            "300",
        ])
        .output()
        .expect("run merge preview v4");
    assert!(
        merge_preview_v4.status.success(),
        "merge preview v4 stderr: {}",
        String::from_utf8_lossy(&merge_preview_v4.stderr)
    );
    let preview_v4_stdout = String::from_utf8(merge_preview_v4.stdout).expect("preview v4 utf8");
    assert!(preview_v4_stdout.contains("\"merge_policy\": \"conservative_plus_v4\""));
    assert!(preview_v4_stdout.contains("\"safe_disjoint_v4\""));

    let conflict_pull = Command::new(bin)
        .args([
            "sync",
            "pull",
            vault_a.to_string_lossy().as_ref(),
            sync_target.to_string_lossy().as_ref(),
            "--now-ms",
            "301",
        ])
        .output()
        .expect("run pull without auto merge");
    assert!(
        !conflict_pull.status.success(),
        "expected conflict pull to fail"
    );

    let merged_pull = Command::new(bin)
        .args([
            "sync",
            "pull",
            vault_a.to_string_lossy().as_ref(),
            sync_target.to_string_lossy().as_ref(),
            "--auto-merge",
            "conservative_plus_v2",
            "--now-ms",
            "302",
        ])
        .output()
        .expect("run pull with conservative_plus_v2 auto merge");
    assert!(
        merged_pull.status.success(),
        "merged pull stderr: {}",
        String::from_utf8_lossy(&merged_pull.stderr)
    );

    let merged_pull_v3 = Command::new(bin)
        .args([
            "sync",
            "pull",
            vault_a.to_string_lossy().as_ref(),
            sync_target.to_string_lossy().as_ref(),
            "--auto-merge",
            "conservative_plus_v3",
            "--now-ms",
            "303",
        ])
        .output()
        .expect("run pull with conservative_plus_v3 auto merge");
    assert!(
        merged_pull_v3.status.success(),
        "merged pull v3 stderr: {}",
        String::from_utf8_lossy(&merged_pull_v3.stderr)
    );

    let merged_pull_v4 = Command::new(bin)
        .args([
            "sync",
            "pull",
            vault_a.to_string_lossy().as_ref(),
            sync_target.to_string_lossy().as_ref(),
            "--auto-merge",
            "conservative_plus_v4",
            "--now-ms",
            "304",
        ])
        .output()
        .expect("run pull with conservative_plus_v4 auto merge");
    assert!(
        merged_pull_v4.status.success(),
        "merged pull v4 stderr: {}",
        String::from_utf8_lossy(&merged_pull_v4.stderr)
    );
}

#[test]
fn cli_sync_merge_preview_v3_is_replay_stable_and_blocks_overlap_pull() {
    let root = tempfile::tempdir().expect("tempdir").keep();
    let vault_a = root.join("vault_a");
    let vault_b = root.join("vault_b");
    let sync_target = root.join("sync-target");

    vault_init(&vault_a, "a", 1).expect("vault a init");
    vault_init(&vault_b, "b", 1).expect("vault b init");

    let conn_a = open_db(&vault_a.join("db/knowledge.sqlite")).expect("open db a");
    let conn_b = open_db(&vault_b.join("db/knowledge.sqlite")).expect("open db b");
    let store_a = ObjectStore::new(vault_a.join("store/objects"));
    let store_b = ObjectStore::new(vault_b.join("store/objects"));

    store_a
        .put_bytes(&conn_a, b"baseline", 1)
        .expect("put baseline");
    sync_push(&conn_a, &vault_a, &sync_target, 100).expect("push baseline");
    sync_pull(&conn_b, &vault_b, &sync_target, 101).expect("pull baseline");
    let conn_b = open_db(&vault_b.join("db/knowledge.sqlite")).expect("reopen db b");

    // Write identical post-baseline bytes on both sides so v3 detects object overlap.
    store_a
        .put_bytes(&conn_a, b"shared-overlap", 2)
        .expect("put local shared overlap");
    store_b
        .put_bytes(&conn_b, b"shared-overlap", 2)
        .expect("put remote shared overlap");
    sync_push(&conn_b, &vault_b, &sync_target, 200).expect("push remote overlap");

    let bin = env!("CARGO_BIN_EXE_kc_cli");

    let preview_first = Command::new(bin)
        .args([
            "sync",
            "merge-preview",
            vault_a.to_string_lossy().as_ref(),
            sync_target.to_string_lossy().as_ref(),
            "--policy",
            "conservative_plus_v3",
            "--now-ms",
            "300",
        ])
        .output()
        .expect("run v3 preview first");
    assert!(
        preview_first.status.success(),
        "preview first stderr: {}",
        String::from_utf8_lossy(&preview_first.stderr)
    );
    let preview_first_stdout =
        String::from_utf8(preview_first.stdout).expect("preview first stdout utf8");
    assert!(preview_first_stdout.contains("\"merge_policy\": \"conservative_plus_v3\""));
    assert!(preview_first_stdout.contains("\"safe\": false"));
    assert!(preview_first_stdout.contains("\"unsafe_overlap_object\""));

    let preview_second = Command::new(bin)
        .args([
            "sync",
            "merge-preview",
            vault_a.to_string_lossy().as_ref(),
            sync_target.to_string_lossy().as_ref(),
            "--policy",
            "conservative_plus_v3",
            "--now-ms",
            "300",
        ])
        .output()
        .expect("run v3 preview second");
    assert!(
        preview_second.status.success(),
        "preview second stderr: {}",
        String::from_utf8_lossy(&preview_second.stderr)
    );
    let preview_second_stdout =
        String::from_utf8(preview_second.stdout).expect("preview second stdout utf8");
    assert_eq!(preview_first_stdout, preview_second_stdout);

    let unsafe_pull = Command::new(bin)
        .args([
            "sync",
            "pull",
            vault_a.to_string_lossy().as_ref(),
            sync_target.to_string_lossy().as_ref(),
            "--auto-merge",
            "conservative_plus_v3",
            "--now-ms",
            "301",
        ])
        .output()
        .expect("run v3 unsafe pull");
    assert!(
        !unsafe_pull.status.success(),
        "expected unsafe pull to fail"
    );
    let stderr = String::from_utf8(unsafe_pull.stderr).expect("unsafe pull stderr utf8");
    assert!(
        stderr.contains("KC_SYNC_MERGE_NOT_SAFE"),
        "stderr: {stderr}"
    );
}
