use kc_core::canonical::{load_canonical_text, persist_canonical_text};
use kc_core::db::open_db;
use kc_core::hashing::blake3_hex_prefixed;
use kc_core::object_store::ObjectStore;
use kc_core::services::CanonicalTextArtifact;
use kc_core::types::{CanonicalHash, DocId, ObjectHash};

#[test]
fn canonical_persist_round_trip() {
    let temp = tempfile::tempdir().expect("tempdir");
    let conn = open_db(&temp.path().join("db/knowledge.sqlite")).expect("open db");
    let store = ObjectStore::new(temp.path().join("store/objects"));

    let original = b"source bytes";
    let original_hash = store.put_bytes(&conn, original, 1).expect("store original");
    let doc_id = original_hash.0.clone();

    conn.execute(
        "INSERT INTO docs (doc_id, original_object_hash, bytes, mime, source_kind, effective_ts_ms, ingested_event_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![doc_id, original_hash.0, original.len() as i64, "text/plain", "notes", 1i64, 1i64],
    )
    .expect("insert doc");

    let canonical_bytes = b"canonical text\n".to_vec();
    let canonical_hash = blake3_hex_prefixed(&canonical_bytes);
    let artifact = CanonicalTextArtifact {
        doc_id: DocId(doc_id.clone()),
        canonical_bytes: canonical_bytes.clone(),
        canonical_hash: CanonicalHash(canonical_hash.clone()),
        canonical_object_hash: ObjectHash(canonical_hash),
        extractor_name: "test".to_string(),
        extractor_version: "1".to_string(),
        extractor_flags_json: "{}".to_string(),
        normalization_version: 1,
        toolchain_json: "{}".to_string(),
        page_count: None,
    };

    persist_canonical_text(&conn, &store, &artifact, 2).expect("persist");
    let loaded = load_canonical_text(&conn, &store, &DocId(doc_id)).expect("load");
    assert_eq!(loaded, canonical_bytes);
}

#[test]
fn canonical_persist_rejects_hash_mismatch() {
    let temp = tempfile::tempdir().expect("tempdir");
    let conn = open_db(&temp.path().join("db/knowledge.sqlite")).expect("open db");
    let store = ObjectStore::new(temp.path().join("store/objects"));

    let original = b"source bytes";
    let original_hash = store.put_bytes(&conn, original, 1).expect("store original");
    let doc_id = original_hash.0.clone();

    conn.execute(
        "INSERT INTO docs (doc_id, original_object_hash, bytes, mime, source_kind, effective_ts_ms, ingested_event_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![doc_id, original_hash.0, original.len() as i64, "text/plain", "notes", 1i64, 1i64],
    )
    .expect("insert doc");

    let artifact = CanonicalTextArtifact {
        doc_id: DocId(doc_id),
        canonical_bytes: b"mismatch".to_vec(),
        canonical_hash: CanonicalHash(
            "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        ),
        canonical_object_hash: ObjectHash(
            "blake3:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        ),
        extractor_name: "test".to_string(),
        extractor_version: "1".to_string(),
        extractor_flags_json: "{}".to_string(),
        normalization_version: 1,
        toolchain_json: "{}".to_string(),
        page_count: None,
    };

    let err = persist_canonical_text(&conn, &store, &artifact, 2).expect_err("must fail invariant");
    assert_eq!(err.code, "KC_DB_INTEGRITY_FAILED");
}
