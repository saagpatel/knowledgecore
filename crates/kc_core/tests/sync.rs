use kc_core::db::open_db;
use kc_core::object_store::ObjectStore;
use kc_core::sync::{
    sync_merge_preview_target, sync_pull_target, sync_pull_target_with_mode, sync_push,
    sync_push_target, sync_status, sync_status_target, SyncHeadV1,
};
use kc_core::trust::{trust_device_init, trust_device_verify};
use kc_core::trust_identity::{
    trust_device_enroll, trust_device_verify_chain, trust_identity_complete, trust_identity_start,
};
use kc_core::vault::vault_init;
use std::sync::{Mutex, OnceLock};

fn insert_object(
    conn: &rusqlite::Connection,
    vault_root: &std::path::Path,
    bytes: &[u8],
    event_id: i64,
) {
    let store = ObjectStore::new(vault_root.join("store/objects"));
    store.put_bytes(conn, bytes, event_id).expect("put object");
}

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn enroll_verified_sync_author(conn: &rusqlite::Connection, now_ms: i64) {
    let device = trust_device_init(conn, "sync-author", "tester", now_ms).expect("trust init");
    trust_device_verify(
        conn,
        &device.device_id,
        &device.fingerprint,
        "tester",
        now_ms + 1,
    )
    .expect("trust verify");
    trust_identity_start(conn, "default", now_ms + 2).expect("identity start");
    trust_identity_complete(conn, "default", "sub:sync-author", now_ms + 3)
        .expect("identity complete");
    trust_device_enroll(conn, "default", &device.device_id, now_ms + 4).expect("device enroll");
    trust_device_verify_chain(conn, &device.device_id, now_ms + 5).expect("verify chain");
}

#[test]
fn sync_push_writes_head_and_status() {
    let root = tempfile::tempdir().expect("tempdir").keep();
    let vault_root = root.join("vault");
    let target_root = root.join("sync-target");

    vault_init(&vault_root, "demo", 1).expect("vault init");
    let conn = open_db(&vault_root.join("db/knowledge.sqlite")).expect("open db");
    insert_object(&conn, &vault_root, b"one", 1);

    let pushed = sync_push(&conn, &vault_root, &target_root, 100).expect("sync push");
    assert!(target_root.join("head.json").exists());
    assert!(target_root
        .join("snapshots")
        .join(&pushed.snapshot_id)
        .exists());

    let status = sync_status(&conn, &target_root).expect("sync status");
    assert_eq!(
        status.seen_remote_snapshot_id,
        Some(pushed.snapshot_id.clone())
    );
    assert_eq!(
        status.last_applied_manifest_hash,
        Some(pushed.manifest_hash.clone())
    );
}

#[test]
fn sync_pull_applies_remote_snapshot() {
    let root = tempfile::tempdir().expect("tempdir").keep();
    let source_vault = root.join("vault_source");
    let target_vault = root.join("vault_target");
    let sync_target = root.join("sync-target");

    vault_init(&source_vault, "source", 1).expect("source init");
    vault_init(&target_vault, "target", 1).expect("target init");

    let conn_source = open_db(&source_vault.join("db/knowledge.sqlite")).expect("source db");
    insert_object(&conn_source, &source_vault, b"source-object", 1);
    sync_push(&conn_source, &source_vault, &sync_target, 100).expect("push");

    let conn_target = open_db(&target_vault.join("db/knowledge.sqlite")).expect("target db");
    let strict_err = sync_pull_target(
        &conn_target,
        &target_vault,
        sync_target.to_string_lossy().as_ref(),
        101,
    )
    .expect_err("default strict pull should block legacy unsigned head");
    assert_eq!(strict_err.code, "KC_SYNC_AUTH_STRICT_BLOCKED");

    let pulled = sync_pull_target_with_mode(
        &conn_target,
        &target_vault,
        sync_target.to_string_lossy().as_ref(),
        101,
        None,
        false,
    )
    .expect("pull");
    let object_files: usize = walkdir::WalkDir::new(target_vault.join("store/objects"))
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .count();
    assert!(object_files >= 1);
    assert!(!pulled.snapshot_id.is_empty());
}

#[test]
fn sync_push_conflict_emits_artifact() {
    let root = tempfile::tempdir().expect("tempdir").keep();
    let vault_root = root.join("vault");
    let target_root = root.join("sync-target");

    vault_init(&vault_root, "demo", 1).expect("vault init");
    let conn = open_db(&vault_root.join("db/knowledge.sqlite")).expect("open db");
    insert_object(&conn, &vault_root, b"baseline", 1);

    let first = sync_push(&conn, &vault_root, &target_root, 100).expect("first push");

    insert_object(&conn, &vault_root, b"local-change", 2);

    let remote_head = SyncHeadV1 {
        schema_version: 1,
        snapshot_id: format!("{}-remote", first.snapshot_id),
        manifest_hash: "blake3:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            .to_string(),
        created_at_ms: 200,
        trust: None,
        author_device_id: None,
        author_fingerprint: None,
        author_signature: None,
        author_signature_alg: None,
        author_cert_id: None,
        author_chain_hash: None,
    };
    std::fs::write(
        target_root.join("head.json"),
        serde_json::to_vec(&remote_head).expect("head json"),
    )
    .expect("write head");

    let err = sync_push(&conn, &vault_root, &target_root, 201).expect_err("expected conflict");
    assert_eq!(err.code, "KC_SYNC_CONFLICT");

    let conflict_path = err
        .details
        .get("conflict_artifact")
        .and_then(|v| v.as_str())
        .expect("conflict path");
    assert!(std::path::Path::new(conflict_path).exists());
}

#[test]
fn sync_target_wrappers_support_file_uri() {
    let root = tempfile::tempdir().expect("tempdir").keep();
    let vault_root = root.join("vault");
    let target_root = root.join("sync-target");
    let target_uri = format!("file://{}", target_root.display());

    vault_init(&vault_root, "demo", 1).expect("vault init");
    let conn = open_db(&vault_root.join("db/knowledge.sqlite")).expect("open db");
    insert_object(&conn, &vault_root, b"uri", 1);

    let pushed = sync_push_target(&conn, &vault_root, &target_uri, 100).expect("sync push target");
    assert!(!pushed.snapshot_id.is_empty());

    let status = sync_status_target(&conn, &target_uri).expect("sync status target");
    assert_eq!(
        status.seen_remote_snapshot_id,
        Some(pushed.snapshot_id.clone())
    );

    let strict_err = sync_pull_target(&conn, &vault_root, &target_uri, 101)
        .expect_err("default strict pull should block legacy unsigned head");
    assert_eq!(strict_err.code, "KC_SYNC_AUTH_STRICT_BLOCKED");

    let pulled = sync_pull_target_with_mode(&conn, &vault_root, &target_uri, 101, None, false)
        .expect("legacy-compatible sync pull target");
    assert_eq!(pulled.snapshot_id, pushed.snapshot_id);
}

#[test]
fn sync_target_wrappers_support_s3_uri_with_emulation() {
    let _guard = env_lock().lock().expect("env lock");
    let root = tempfile::tempdir().expect("tempdir").keep();
    let vault_root = root.join("vault");
    let pull_vault_root = root.join("vault_pull");
    let emulated_s3 = root.join("emulated-s3");
    std::env::set_var(
        "KC_SYNC_S3_EMULATE_ROOT",
        emulated_s3.to_string_lossy().as_ref(),
    );
    std::env::set_var("KC_VAULT_PASSPHRASE", "sync-passphrase");

    vault_init(&vault_root, "demo", 1).expect("vault init");
    vault_init(&pull_vault_root, "pull-demo", 1).expect("pull vault init");

    let conn = open_db(&vault_root.join("db/knowledge.sqlite")).expect("open db");
    let conn_pull = open_db(&pull_vault_root.join("db/knowledge.sqlite")).expect("open pull db");
    enroll_verified_sync_author(&conn, 10);
    insert_object(&conn, &vault_root, b"s3-sync-object", 1);

    let target_uri = "s3://demo-bucket/kc";
    let pushed = sync_push_target(&conn, &vault_root, target_uri, 100).expect("s3 push");
    assert!(emulated_s3.join("demo-bucket/kc/head.json").exists());
    assert!(emulated_s3
        .join(format!(
            "demo-bucket/kc/snapshots/{}.zip",
            pushed.snapshot_id
        ))
        .exists());

    let status = sync_status_target(&conn, target_uri).expect("s3 status");
    assert_eq!(
        status.seen_remote_snapshot_id,
        Some(pushed.snapshot_id.clone())
    );

    let strict_err = sync_pull_target(&conn_pull, &pull_vault_root, target_uri, 101)
        .expect_err("default strict s3 pull should block legacy unsigned head");
    assert_eq!(strict_err.code, "KC_SYNC_AUTH_STRICT_BLOCKED");

    let pulled =
        sync_pull_target_with_mode(&conn_pull, &pull_vault_root, target_uri, 101, None, false)
            .expect("legacy-compatible s3 pull");
    assert_eq!(pulled.snapshot_id, pushed.snapshot_id);

    std::env::remove_var("KC_VAULT_PASSPHRASE");
    std::env::remove_var("KC_SYNC_S3_EMULATE_ROOT");
}

#[test]
fn sync_s3_key_mismatch_hard_fails() {
    let _guard = env_lock().lock().expect("env lock");
    let root = tempfile::tempdir().expect("tempdir").keep();
    let source_vault = root.join("vault_source");
    let target_vault = root.join("vault_target");
    let emulated_s3 = root.join("emulated-s3");
    std::env::set_var(
        "KC_SYNC_S3_EMULATE_ROOT",
        emulated_s3.to_string_lossy().as_ref(),
    );

    vault_init(&source_vault, "source", 1).expect("source init");
    vault_init(&target_vault, "target", 1).expect("target init");

    let source_conn = open_db(&source_vault.join("db/knowledge.sqlite")).expect("source db");
    let target_conn = open_db(&target_vault.join("db/knowledge.sqlite")).expect("target db");
    enroll_verified_sync_author(&source_conn, 10);
    insert_object(&source_conn, &source_vault, b"source-object", 1);

    std::env::set_var("KC_VAULT_PASSPHRASE", "alpha");
    sync_push_target(&source_conn, &source_vault, "s3://demo-bucket/kc", 200).expect("source push");

    std::env::set_var("KC_VAULT_PASSPHRASE", "beta");
    let err = sync_pull_target(&target_conn, &target_vault, "s3://demo-bucket/kc", 201)
        .expect_err("expected key mismatch");
    assert_eq!(err.code, "KC_SYNC_KEY_MISMATCH");

    std::env::remove_var("KC_VAULT_PASSPHRASE");
    std::env::remove_var("KC_SYNC_S3_EMULATE_ROOT");
}

#[test]
fn sync_s3_reports_locked_when_lock_file_is_active() {
    let _guard = env_lock().lock().expect("env lock");
    let root = tempfile::tempdir().expect("tempdir").keep();
    let vault_root = root.join("vault");
    let emulated_s3 = root.join("emulated-s3");
    std::env::set_var(
        "KC_SYNC_S3_EMULATE_ROOT",
        emulated_s3.to_string_lossy().as_ref(),
    );
    std::env::set_var("KC_VAULT_PASSPHRASE", "lock-passphrase");

    vault_init(&vault_root, "demo", 1).expect("vault init");
    let conn = open_db(&vault_root.join("db/knowledge.sqlite")).expect("open db");
    enroll_verified_sync_author(&conn, 10);
    insert_object(&conn, &vault_root, b"payload", 1);

    let lock = serde_json::json!({
        "schema_version": 1,
        "holder": "other:999",
        "vault_id": "other-vault",
        "acquired_at_ms": 100,
        "expires_at_ms": 999_999,
        "trust_fingerprint": "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    });
    let lock_path = emulated_s3.join("demo-bucket/kc/locks/write.lock");
    std::fs::create_dir_all(lock_path.parent().expect("lock parent")).expect("mkdir lock parent");
    std::fs::write(&lock_path, serde_json::to_vec(&lock).expect("lock json")).expect("write lock");

    let err = sync_push_target(&conn, &vault_root, "s3://demo-bucket/kc", 123)
        .expect_err("expected locked error");
    assert_eq!(err.code, "KC_SYNC_LOCKED");

    std::env::remove_var("KC_VAULT_PASSPHRASE");
    std::env::remove_var("KC_SYNC_S3_EMULATE_ROOT");
}

#[test]
fn sync_merge_preview_reports_safe_for_disjoint_local_and_remote_changes() {
    let root = tempfile::tempdir().expect("tempdir").keep();
    let vault_a = root.join("vault_a");
    let vault_b = root.join("vault_b");
    let sync_target = root.join("sync-target");

    vault_init(&vault_a, "a", 1).expect("vault a init");
    vault_init(&vault_b, "b", 1).expect("vault b init");

    let conn_a = open_db(&vault_a.join("db/knowledge.sqlite")).expect("open db a");
    let conn_b = open_db(&vault_b.join("db/knowledge.sqlite")).expect("open db b");
    insert_object(&conn_a, &vault_a, b"baseline", 1);

    sync_push(&conn_a, &vault_a, &sync_target, 100).expect("push baseline");
    sync_pull_target_with_mode(
        &conn_b,
        &vault_b,
        sync_target.to_string_lossy().as_ref(),
        101,
        None,
        false,
    )
    .expect("pull baseline into b");
    let conn_b = open_db(&vault_b.join("db/knowledge.sqlite")).expect("reopen db b");

    insert_object(&conn_a, &vault_a, b"local-only-change", 2);
    insert_object(&conn_b, &vault_b, b"remote-only-change", 2);
    sync_push(&conn_b, &vault_b, &sync_target, 200).expect("push remote-only delta");

    let preview = sync_merge_preview_target(
        &conn_a,
        &vault_a,
        sync_target.to_string_lossy().as_ref(),
        300,
    )
    .expect("merge preview");
    assert!(preview.report.safe);
    assert_eq!(preview.report.merge_policy, "conservative_v1");
    assert!(
        preview.report.overlap.object_hashes.is_empty(),
        "expected disjoint object hashes"
    );
}

#[test]
fn sync_pull_with_conservative_auto_merge_applies_disjoint_changes() {
    let root = tempfile::tempdir().expect("tempdir").keep();
    let vault_a = root.join("vault_a");
    let vault_b = root.join("vault_b");
    let sync_target = root.join("sync-target");

    vault_init(&vault_a, "a", 1).expect("vault a init");
    vault_init(&vault_b, "b", 1).expect("vault b init");

    let conn_a = open_db(&vault_a.join("db/knowledge.sqlite")).expect("open db a");
    let conn_b = open_db(&vault_b.join("db/knowledge.sqlite")).expect("open db b");
    insert_object(&conn_a, &vault_a, b"baseline", 1);

    sync_push(&conn_a, &vault_a, &sync_target, 100).expect("push baseline");
    sync_pull_target_with_mode(
        &conn_b,
        &vault_b,
        sync_target.to_string_lossy().as_ref(),
        101,
        None,
        false,
    )
    .expect("pull baseline into b");
    let conn_b = open_db(&vault_b.join("db/knowledge.sqlite")).expect("reopen db b");

    insert_object(&conn_a, &vault_a, b"local-only-change", 2);
    insert_object(&conn_b, &vault_b, b"remote-only-change", 2);
    sync_push(&conn_b, &vault_b, &sync_target, 200).expect("push remote-only delta");

    let conflict_err = sync_pull_target_with_mode(
        &conn_a,
        &vault_a,
        sync_target.to_string_lossy().as_ref(),
        300,
        None,
        false,
    )
    .expect_err("expected conflict without auto-merge");
    assert_eq!(conflict_err.code, "KC_SYNC_CONFLICT");

    let merged = sync_pull_target_with_mode(
        &conn_a,
        &vault_a,
        sync_target.to_string_lossy().as_ref(),
        301,
        Some("conservative"),
        false,
    )
    .expect("pull with conservative merge");
    assert!(!merged.snapshot_id.is_empty());
}

#[test]
fn sync_pull_with_conservative_plus_v2_auto_merge_applies_disjoint_changes() {
    let root = tempfile::tempdir().expect("tempdir").keep();
    let vault_a = root.join("vault_a");
    let vault_b = root.join("vault_b");
    let sync_target = root.join("sync-target");

    vault_init(&vault_a, "a", 1).expect("vault a init");
    vault_init(&vault_b, "b", 1).expect("vault b init");

    let conn_a = open_db(&vault_a.join("db/knowledge.sqlite")).expect("open db a");
    let conn_b = open_db(&vault_b.join("db/knowledge.sqlite")).expect("open db b");
    insert_object(&conn_a, &vault_a, b"baseline", 1);

    sync_push(&conn_a, &vault_a, &sync_target, 100).expect("push baseline");
    sync_pull_target_with_mode(
        &conn_b,
        &vault_b,
        sync_target.to_string_lossy().as_ref(),
        101,
        None,
        false,
    )
    .expect("pull baseline into b");
    let conn_b = open_db(&vault_b.join("db/knowledge.sqlite")).expect("reopen db b");

    insert_object(&conn_a, &vault_a, b"local-only-change", 2);
    insert_object(&conn_b, &vault_b, b"remote-only-change", 2);
    sync_push(&conn_b, &vault_b, &sync_target, 200).expect("push remote-only delta");

    let merged = sync_pull_target_with_mode(
        &conn_a,
        &vault_a,
        sync_target.to_string_lossy().as_ref(),
        301,
        Some("conservative_plus_v2"),
        false,
    )
    .expect("pull with conservative_plus_v2 merge");
    assert!(!merged.snapshot_id.is_empty());
}

#[test]
fn sync_pull_with_conservative_plus_v3_auto_merge_applies_disjoint_changes() {
    let root = tempfile::tempdir().expect("tempdir").keep();
    let vault_a = root.join("vault_a");
    let vault_b = root.join("vault_b");
    let sync_target = root.join("sync-target");

    vault_init(&vault_a, "a", 1).expect("vault a init");
    vault_init(&vault_b, "b", 1).expect("vault b init");

    let conn_a = open_db(&vault_a.join("db/knowledge.sqlite")).expect("open db a");
    let conn_b = open_db(&vault_b.join("db/knowledge.sqlite")).expect("open db b");
    insert_object(&conn_a, &vault_a, b"baseline", 1);

    sync_push(&conn_a, &vault_a, &sync_target, 100).expect("push baseline");
    sync_pull_target_with_mode(
        &conn_b,
        &vault_b,
        sync_target.to_string_lossy().as_ref(),
        101,
        None,
        false,
    )
    .expect("pull baseline into b");
    let conn_b = open_db(&vault_b.join("db/knowledge.sqlite")).expect("reopen db b");

    insert_object(&conn_a, &vault_a, b"local-only-change", 2);
    insert_object(&conn_b, &vault_b, b"remote-only-change", 2);
    sync_push(&conn_b, &vault_b, &sync_target, 200).expect("push remote-only delta");

    let merged = sync_pull_target_with_mode(
        &conn_a,
        &vault_a,
        sync_target.to_string_lossy().as_ref(),
        301,
        Some("conservative_plus_v3"),
        false,
    )
    .expect("pull with conservative_plus_v3 merge");
    assert!(!merged.snapshot_id.is_empty());
}

#[test]
fn sync_pull_with_conservative_plus_v4_auto_merge_applies_disjoint_changes() {
    let root = tempfile::tempdir().expect("tempdir").keep();
    let vault_a = root.join("vault_a");
    let vault_b = root.join("vault_b");
    let sync_target = root.join("sync-target");

    vault_init(&vault_a, "a", 1).expect("vault a init");
    vault_init(&vault_b, "b", 1).expect("vault b init");

    let conn_a = open_db(&vault_a.join("db/knowledge.sqlite")).expect("open db a");
    let conn_b = open_db(&vault_b.join("db/knowledge.sqlite")).expect("open db b");
    insert_object(&conn_a, &vault_a, b"baseline", 1);

    sync_push(&conn_a, &vault_a, &sync_target, 100).expect("push baseline");
    sync_pull_target_with_mode(
        &conn_b,
        &vault_b,
        sync_target.to_string_lossy().as_ref(),
        101,
        None,
        false,
    )
    .expect("pull baseline into b");
    let conn_b = open_db(&vault_b.join("db/knowledge.sqlite")).expect("reopen db b");

    insert_object(&conn_a, &vault_a, b"local-only-change", 2);
    insert_object(&conn_b, &vault_b, b"remote-only-change", 2);
    sync_push(&conn_b, &vault_b, &sync_target, 200).expect("push remote-only delta");

    let merged = sync_pull_target_with_mode(
        &conn_a,
        &vault_a,
        sync_target.to_string_lossy().as_ref(),
        301,
        Some("conservative_plus_v4"),
        false,
    )
    .expect("pull with conservative_plus_v4 merge");
    assert!(!merged.snapshot_id.is_empty());
}
