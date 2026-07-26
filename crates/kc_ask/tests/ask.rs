use kc_ask::{AskRequest, AskService, RetrievedOnlyAskService};
use kc_core::canonical::persist_canonical_text;
use kc_core::chunking::{chunk_document, default_chunking_config_v1};
use kc_core::db::open_db;
use kc_core::hashing::blake3_hex_prefixed;
use kc_core::ingest::{ingest_bytes, IngestBytesReq};
use kc_core::locator::{LocatorRange, LocatorV1};
use kc_core::object_store::ObjectStore;
use kc_core::services::CanonicalTextArtifact;
use kc_core::types::{CanonicalHash, DocId};
use kc_core::vault::vault_init;

fn sample_locator(v: i64) -> LocatorV1 {
    LocatorV1 {
        v,
        doc_id: DocId(
            "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        ),
        canonical_hash: CanonicalHash(
            "blake3:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        ),
        range: LocatorRange { start: 0, end: 5 },
        hints: None,
    }
}

#[test]
fn ask_missing_citations_hard_fails() {
    let root = tempfile::tempdir().expect("tempdir").keep();
    vault_init(&root, "ask", 1).expect("vault init");

    let service = RetrievedOnlyAskService::default();
    let req = AskRequest {
        vault_path: root,
        question: "What happened?".to_string(),
        now_ms: 2,
    };

    let err = service
        .finalize_answer(&req, "answer".to_string(), vec![])
        .expect_err("must fail");
    assert_eq!(err.code, "KC_ASK_MISSING_CITATIONS");
}

#[test]
fn ask_invalid_citations_hard_fails() {
    let root = tempfile::tempdir().expect("tempdir").keep();
    vault_init(&root, "ask", 1).expect("vault init");

    let service = RetrievedOnlyAskService::default();
    let req = AskRequest {
        vault_path: root,
        question: "What happened?".to_string(),
        now_ms: 2,
    };

    let err = service
        .finalize_answer(
            &req,
            "answer".to_string(),
            vec![(0, vec![sample_locator(2)])],
        )
        .expect_err("must fail");
    assert_eq!(err.code, "KC_ASK_INVALID_CITATIONS");
}

#[test]
fn ask_writes_trace_for_valid_citations() {
    let root = tempfile::tempdir().expect("tempdir").keep();
    vault_init(&root, "ask", 1).expect("vault init");

    let service = RetrievedOnlyAskService::default();
    let req = AskRequest {
        vault_path: root,
        question: "What happened?".to_string(),
        now_ms: 2,
    };

    let out = service
        .finalize_answer(
            &req,
            "answer".to_string(),
            vec![(0, vec![sample_locator(1)])],
        )
        .expect("success");

    assert!(out.trace_path.exists());
    let trace: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.trace_path).expect("read trace"))
            .expect("parse trace");
    assert_eq!(
        trace.get("schema_version").and_then(|v| v.as_i64()),
        Some(1)
    );
}

#[test]
fn ask_runs_retrieved_only_end_to_end() {
    let root = tempfile::tempdir().expect("tempdir").keep();
    vault_init(&root, "ask", 1).expect("vault init");
    let conn = open_db(&root.join("db/knowledge.sqlite")).expect("open db");
    let store = ObjectStore::new(root.join("store/objects"));

    let ingested = ingest_bytes(
        &conn,
        &store,
        IngestBytesReq {
            bytes: b"raw bytes",
            mime: "text/plain",
            source_kind: "notes",
            effective_ts_ms: 1,
            source_path: None,
            now_ms: 1,
        },
    )
    .expect("ingest");

    let canonical_text = b"Evidence paragraph for answer.\n".to_vec();
    let canonical_hash = blake3_hex_prefixed(&canonical_text);
    let artifact = CanonicalTextArtifact {
        doc_id: ingested.doc_id.clone(),
        canonical_bytes: canonical_text.clone(),
        canonical_hash: CanonicalHash(canonical_hash.clone()),
        canonical_object_hash: kc_core::types::ObjectHash(canonical_hash),
        page_count: None,
        extractor_name: "test".to_string(),
        extractor_version: "1".to_string(),
        extractor_flags_json: "{}".to_string(),
        normalization_version: 1,
        toolchain_json: "{}".to_string(),
    };
    persist_canonical_text(&conn, &store, &artifact, 1).expect("persist canonical");

    let canonical_text_str = String::from_utf8(canonical_text.clone()).expect("utf8");
    let chunk_cfg = default_chunking_config_v1();
    let chunks = chunk_document(
        &ingested.doc_id,
        &canonical_text_str,
        "text/plain",
        &chunk_cfg,
    )
    .expect("chunk document");
    assert!(!chunks.is_empty());

    for chunk in &chunks {
        conn.execute(
            "INSERT INTO chunks(chunk_id, doc_id, ordinal, start_char, end_char, chunking_config_hash, source_kind)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                chunk.chunk_id.0,
                chunk.doc_id.0,
                chunk.ordinal,
                chunk.start_char,
                chunk.end_char,
                chunk.chunking_config_hash.0,
                "notes"
            ],
        )
        .expect("insert chunk");
    }

    conn.execute_batch(
        "CREATE VIRTUAL TABLE IF NOT EXISTS chunks_fts
         USING fts5(chunk_id UNINDEXED, doc_id UNINDEXED, content, tokenize='unicode61');",
    )
    .expect("create fts");

    for chunk in &chunks {
        let content: String = canonical_text_str
            .chars()
            .skip(chunk.start_char as usize)
            .take((chunk.end_char - chunk.start_char) as usize)
            .collect();
        conn.execute(
            "INSERT INTO chunks_fts(chunk_id, doc_id, content) VALUES (?1, ?2, ?3)",
            rusqlite::params![chunk.chunk_id.0, chunk.doc_id.0, content],
        )
        .expect("insert fts row");
    }

    let service = RetrievedOnlyAskService::default();
    let out = service
        .ask(AskRequest {
            vault_path: root.clone(),
            question: "What is the evidence?".to_string(),
            now_ms: 2,
        })
        .expect("ask");

    assert!(!out.answer_text.is_empty());
    assert!(!out.citations.is_empty());
    assert!(out.trace_path.exists());

    let trace: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.trace_path).expect("read trace"))
            .expect("trace json");
    let retrieval_chunks = trace
        .get("retrieval")
        .and_then(|r| r.get("chunks"))
        .and_then(|c| c.as_array())
        .expect("retrieval chunks");
    assert!(!retrieval_chunks.is_empty());
    assert!(retrieval_chunks[0].get("chunk_id").is_some());
}

#[test]
fn ask_normalizes_citation_locator_ordering() {
    let root = tempfile::tempdir().expect("tempdir").keep();
    vault_init(&root, "ask", 1).expect("vault init");
    let service = RetrievedOnlyAskService::default();

    let locator_b = LocatorV1 {
        v: 1,
        doc_id: DocId(
            "blake3:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        ),
        canonical_hash: CanonicalHash(
            "blake3:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        ),
        range: LocatorRange { start: 5, end: 10 },
        hints: None,
    };
    let locator_a = LocatorV1 {
        v: 1,
        doc_id: DocId(
            "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        ),
        canonical_hash: CanonicalHash(
            "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        ),
        range: LocatorRange { start: 1, end: 4 },
        hints: None,
    };

    let out = service
        .finalize_answer(
            &AskRequest {
                vault_path: root,
                question: "q".to_string(),
                now_ms: 3,
            },
            "answer".to_string(),
            vec![(0, vec![locator_b.clone(), locator_a.clone()])],
        )
        .expect("finalize");

    assert_eq!(out.citations.len(), 1);
    let ordered = &out.citations[0].1;
    assert_eq!(ordered[0].doc_id.0, locator_a.doc_id.0);
    assert_eq!(ordered[1].doc_id.0, locator_b.doc_id.0);
}
