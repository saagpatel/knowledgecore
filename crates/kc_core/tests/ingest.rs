use kc_core::db::open_db;
use kc_core::ingest::{
    ingest_bytes, ingest_bytes_with_limits, IngestBytesReq, IngestResourceLimits,
};
use kc_core::object_store::ObjectStore;
use kc_core::resource_limits::SCAN_FOLDER_MAX_DEPTH;
use kc_core::rpc_service::ingest_scan_folder_service;
use kc_core::vault::vault_init;

#[test]
fn ingest_is_idempotent_and_persists_doc_source() {
    let temp = tempfile::tempdir().expect("tempdir");
    let conn = open_db(&temp.path().join("db/knowledge.sqlite")).expect("open db");
    let store = ObjectStore::new(temp.path().join("store/objects"));

    let input = b"same ingest payload";
    let first = ingest_bytes(
        &conn,
        &store,
        IngestBytesReq {
            bytes: input,
            mime: "text/plain",
            source_kind: "notes",
            effective_ts_ms: 100,
            source_path: Some("/tmp/a.txt"),
            now_ms: 200,
        },
    )
    .expect("first ingest");

    let second = ingest_bytes(
        &conn,
        &store,
        IngestBytesReq {
            bytes: input,
            mime: "text/plain",
            source_kind: "notes",
            effective_ts_ms: 100,
            source_path: Some("/tmp/a.txt"),
            now_ms: 201,
        },
    )
    .expect("second ingest");

    assert_eq!(first.doc_id, second.doc_id);

    let doc_id = first.doc_id.0.clone();
    let docs_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM docs WHERE doc_id=?1",
            [&doc_id],
            |r| r.get(0),
        )
        .expect("docs count");
    assert_eq!(docs_count, 1);

    let src_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM doc_sources WHERE doc_id=?1 AND source_path=?2",
            [&doc_id, "/tmp/a.txt"],
            |r| r.get(0),
        )
        .expect("doc source count");
    assert_eq!(src_count, 1);
}

#[test]
fn ingest_resource_limit_rejects_oversized_generated_payload() {
    let temp = tempfile::tempdir().expect("tempdir");
    let conn = open_db(&temp.path().join("db/knowledge.sqlite")).expect("open db");
    let store = ObjectStore::new(temp.path().join("store/objects"));
    let payload = vec![b'a'; 16];

    let err = ingest_bytes_with_limits(
        &conn,
        &store,
        IngestBytesReq {
            bytes: &payload,
            mime: "text/plain",
            source_kind: "generated-fixture",
            effective_ts_ms: 100,
            source_path: Some("/generated/oversized.txt"),
            now_ms: 200,
        },
        IngestResourceLimits { max_bytes: 8 },
    )
    .expect_err("oversized generated payload should fail");

    assert_eq!(err.code, "KC_RESOURCE_LIMIT_EXCEEDED");

    let docs_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM docs", [], |r| r.get(0))
        .expect("docs count");
    let events_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
        .expect("events count");
    assert_eq!(docs_count, 0);
    assert_eq!(events_count, 0);
}

#[test]
fn rpc_scan_folder_resource_limit_rejects_deep_generated_tree_before_ingesting() {
    let root = tempfile::tempdir().expect("tempdir").keep();
    let vault_path = root.join("vault");
    let scan_root = root.join("scan");
    vault_init(&vault_path, "demo", 1).expect("vault init");

    let mut deep = scan_root.clone();
    for idx in 0..SCAN_FOLDER_MAX_DEPTH {
        deep = deep.join(format!("d{idx}"));
    }
    std::fs::create_dir_all(&deep).expect("create deep tree");
    std::fs::write(deep.join("too-deep.txt"), b"generated").expect("write generated file");

    let err = ingest_scan_folder_service(&vault_path, &scan_root, "generated-fixture", 100)
        .expect_err("deep generated scan tree should fail");
    assert_eq!(err.code, "KC_RESOURCE_LIMIT_EXCEEDED");

    let conn = open_db(&vault_path.join("db/knowledge.sqlite")).expect("open db");
    let docs_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM docs", [], |r| r.get(0))
        .expect("docs count");
    assert_eq!(docs_count, 0);
}
