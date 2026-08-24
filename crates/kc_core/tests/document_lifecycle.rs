use kc_core::canonical::persist_canonical_text;
use kc_core::db::open_db;
use kc_core::document_lifecycle::{
    append_document_lifecycle_event, load_document_lifecycle_events, resolve_document_lifecycle,
    DocumentLifecycleActionV1, DocumentLifecycleInitialStateV1, DocumentLifecycleMutationRequestV1,
    DocumentLifecycleTerminalStateV1, DOCUMENT_LIFECYCLE_EVENT_SCHEMA,
    DOCUMENT_LIFECYCLE_REQUEST_SCHEMA,
};
use kc_core::events::append_event;
use kc_core::hashing::blake3_hex_prefixed;
use kc_core::ingest::{ingest_bytes, IngestBytesReq};
use kc_core::lineage_policy::{lineage_policy_add, lineage_policy_bind};
use kc_core::object_store::ObjectStore;
use kc_core::services::CanonicalTextArtifact;
use kc_core::types::{CanonicalHash, ObjectHash};
use kc_core::vault::{vault_init, vault_paths};
use rusqlite::Connection;

struct Fixture {
    _temp: tempfile::TempDir,
    conn: Connection,
    store: ObjectStore,
    docs: Vec<(String, Vec<u8>)>,
}

fn fixture() -> Fixture {
    let temp = tempfile::tempdir().expect("tempdir");
    let vault_path = temp.path().join("vault");
    vault_init(&vault_path, "document-lifecycle-fixture", 1).expect("vault init");
    let paths = vault_paths(&vault_path);
    let conn = open_db(&paths.db).expect("open db");
    let store = ObjectStore::new(paths.objects_dir);
    let mut docs = Vec::new();

    for (index, bytes) in [
        b"alpha saagpatel/knowledgecore note".as_slice(),
        b"beta saagpatel/knowledgecore corrected note".as_slice(),
        b"gamma saagpatel/knowledgecore final note".as_slice(),
    ]
    .into_iter()
    .enumerate()
    {
        let now_ms = 10 + index as i64;
        let ingested = ingest_bytes(
            &conn,
            &store,
            IngestBytesReq {
                bytes,
                mime: "text/plain",
                source_kind: "notes",
                effective_ts_ms: now_ms,
                source_path: None,
                now_ms,
            },
        )
        .expect("ingest fixture document");
        let hash = blake3_hex_prefixed(bytes);
        persist_canonical_text(
            &conn,
            &store,
            &CanonicalTextArtifact {
                doc_id: ingested.doc_id.clone(),
                canonical_bytes: bytes.to_vec(),
                canonical_hash: CanonicalHash(hash.clone()),
                canonical_object_hash: ObjectHash(hash),
                extractor_name: "document-lifecycle-test".to_string(),
                extractor_version: "1".to_string(),
                extractor_flags_json: "{}".to_string(),
                normalization_version: 1,
                toolchain_json: "{}".to_string(),
            },
            now_ms,
        )
        .expect("persist canonical fixture");
        docs.push((ingested.doc_id.0, bytes.to_vec()));
    }

    Fixture {
        _temp: temp,
        conn,
        store,
        docs,
    }
}

fn allow_lifecycle(fixture: &Fixture, subject_id: &str) {
    lineage_policy_add(
        &fixture.conn,
        "allow-document-lifecycle",
        "allow",
        r#"{"action":"document.lifecycle.write"}"#,
        "tests",
        20,
    )
    .expect("add lifecycle policy");
    lineage_policy_bind(
        &fixture.conn,
        subject_id,
        "allow-document-lifecycle",
        "tests",
        21,
    )
    .expect("bind lifecycle policy");
}

fn request(
    action: DocumentLifecycleActionV1,
    doc_id: &str,
    replacement_doc_id: Option<&str>,
    subject_id: &str,
    effective_at_ms: i64,
) -> DocumentLifecycleMutationRequestV1 {
    DocumentLifecycleMutationRequestV1 {
        schema_version: DOCUMENT_LIFECYCLE_REQUEST_SCHEMA.to_string(),
        action,
        doc_id: doc_id.to_string(),
        replacement_doc_id: replacement_doc_id.map(str::to_string),
        subject_id: subject_id.to_string(),
        reason: "owner-approved synthetic lifecycle change".to_string(),
        effective_at_ms,
    }
}

fn table_counts(conn: &Connection) -> (i64, i64, i64) {
    (
        conn.query_row("SELECT COUNT(*) FROM docs", [], |row| row.get(0))
            .expect("docs count"),
        conn.query_row("SELECT COUNT(*) FROM canonical_text", [], |row| row.get(0))
            .expect("canonical count"),
        conn.query_row("SELECT COUNT(*) FROM objects", [], |row| row.get(0))
            .expect("objects count"),
    )
}

#[test]
fn lifecycle_write_is_deny_by_default_and_preserves_canonical_rows() {
    let fixture = fixture();
    let source = &fixture.docs[0].0;
    let replacement = &fixture.docs[1].0;
    let counts_before = table_counts(&fixture.conn);
    let events_before: i64 = fixture
        .conn
        .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
        .expect("event count before");

    let denied = append_document_lifecycle_event(
        &fixture.conn,
        &request(
            DocumentLifecycleActionV1::Supersede,
            source,
            Some(replacement),
            "unauthorized-subject",
            30,
        ),
    )
    .expect_err("unbound subject must be denied");
    assert_eq!(denied.code, "KC_LINEAGE_PERMISSION_DENIED");
    assert_eq!(table_counts(&fixture.conn), counts_before);
    let denied_audits: i64 = fixture
        .conn
        .query_row(
            "SELECT COUNT(*) FROM lineage_policy_audit WHERE action='document.lifecycle.write' AND allowed=0",
            [],
            |row| row.get(0),
        )
        .expect("denied lifecycle audit count");
    assert_eq!(denied_audits, 1);

    allow_lifecycle(&fixture, "owner-subject");
    let event = append_document_lifecycle_event(
        &fixture.conn,
        &request(
            DocumentLifecycleActionV1::Supersede,
            source,
            Some(replacement),
            "owner-subject",
            31,
        ),
    )
    .expect("authorized supersession");
    assert_eq!(event.action, DocumentLifecycleActionV1::Supersede);
    assert_eq!(event.doc_id, *source);
    assert_eq!(
        event.replacement_doc_id.as_deref(),
        Some(replacement.as_str())
    );
    assert!(event.reason_digest.starts_with("blake3:"));
    assert_eq!(table_counts(&fixture.conn), counts_before);
    let events_after: i64 = fixture
        .conn
        .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
        .expect("event count after");
    assert_eq!(events_after, events_before + 1);

    let by_doc = load_document_lifecycle_events(&fixture.conn).expect("load lifecycle events");
    let resolution = resolve_document_lifecycle(source, &by_doc).expect("resolve lifecycle");
    assert_eq!(
        resolution.initial_state,
        DocumentLifecycleInitialStateV1::Superseded
    );
    assert_eq!(
        resolution.terminal_state,
        DocumentLifecycleTerminalStateV1::Active
    );
    assert_eq!(
        resolution.terminal_doc_id.as_deref(),
        Some(replacement.as_str())
    );
}

#[test]
fn lifecycle_chain_resolves_corrections_and_tombstone_without_deleting_bytes() {
    let fixture = fixture();
    allow_lifecycle(&fixture, "owner-subject");
    let source = &fixture.docs[0].0;
    let replacement = &fixture.docs[1].0;
    let terminal = &fixture.docs[2].0;

    append_document_lifecycle_event(
        &fixture.conn,
        &request(
            DocumentLifecycleActionV1::Supersede,
            source,
            Some(replacement),
            "owner-subject",
            30,
        ),
    )
    .expect("source to replacement");
    append_document_lifecycle_event(
        &fixture.conn,
        &request(
            DocumentLifecycleActionV1::Supersede,
            replacement,
            Some(terminal),
            "owner-subject",
            31,
        ),
    )
    .expect("replacement to terminal");
    append_document_lifecycle_event(
        &fixture.conn,
        &request(
            DocumentLifecycleActionV1::Tombstone,
            terminal,
            None,
            "owner-subject",
            32,
        ),
    )
    .expect("terminal tombstone");

    let by_doc = load_document_lifecycle_events(&fixture.conn).expect("load lifecycle events");
    let resolution = resolve_document_lifecycle(source, &by_doc).expect("resolve lifecycle");
    assert_eq!(
        resolution.initial_state,
        DocumentLifecycleInitialStateV1::Superseded
    );
    assert_eq!(
        resolution.terminal_state,
        DocumentLifecycleTerminalStateV1::Tombstoned
    );
    assert_eq!(
        resolution.terminal_doc_id.as_deref(),
        Some(terminal.as_str())
    );
    assert_eq!(resolution.events.len(), 3);

    for (doc_id, bytes) in &fixture.docs {
        assert_eq!(
            fixture
                .store
                .get_bytes(&ObjectHash(doc_id.clone()))
                .expect("owner bytes remain present"),
            *bytes
        );
    }
}

#[test]
fn lifecycle_rejects_duplicate_transition_and_missing_replacement() {
    let fixture = fixture();
    allow_lifecycle(&fixture, "owner-subject");
    let source = &fixture.docs[0].0;
    let replacement = &fixture.docs[1].0;

    let missing = blake3_hex_prefixed(b"missing replacement");
    let error = append_document_lifecycle_event(
        &fixture.conn,
        &request(
            DocumentLifecycleActionV1::Supersede,
            source,
            Some(&missing),
            "owner-subject",
            30,
        ),
    )
    .expect_err("missing replacement must fail");
    assert_eq!(error.code, "KC_DOCUMENT_LIFECYCLE_NOT_FOUND");

    append_document_lifecycle_event(
        &fixture.conn,
        &request(
            DocumentLifecycleActionV1::Supersede,
            source,
            Some(replacement),
            "owner-subject",
            31,
        ),
    )
    .expect("first transition");
    let duplicate = append_document_lifecycle_event(
        &fixture.conn,
        &request(
            DocumentLifecycleActionV1::Tombstone,
            source,
            None,
            "owner-subject",
            32,
        ),
    )
    .expect_err("duplicate transition must not invent a winner");
    assert_eq!(duplicate.code, "KC_DOCUMENT_LIFECYCLE_CONFLICT");
}

#[test]
fn lifecycle_surfaces_multiple_successors_and_rejects_corrupt_chains() {
    let fixture = fixture();
    let source = &fixture.docs[0].0;
    let source_hash = blake3_hex_prefixed(&fixture.docs[0].1);

    for (index, replacement) in fixture.docs[1..].iter().enumerate() {
        append_event(
            &fixture.conn,
            30 + index as i64,
            "document.lifecycle.superseded.v1",
            &serde_json::json!({
                "schema_version": DOCUMENT_LIFECYCLE_EVENT_SCHEMA,
                "action": "supersede",
                "doc_id": source,
                "doc_canonical_hash": source_hash,
                "replacement_doc_id": replacement.0,
                "replacement_canonical_hash": blake3_hex_prefixed(&replacement.1),
                "subject_id": "owner-subject",
                "reason": "synthetic conflict",
                "effective_at_ms": 30 + index as i64
            }),
        )
        .expect("append synthetic conflicting owner event");
    }
    let by_doc = load_document_lifecycle_events(&fixture.conn).expect("load conflicting events");
    let resolution = resolve_document_lifecycle(source, &by_doc).expect("resolve conflict");
    assert_eq!(
        resolution.initial_state,
        DocumentLifecycleInitialStateV1::Conflicted
    );
    assert_eq!(
        resolution.terminal_state,
        DocumentLifecycleTerminalStateV1::Conflicted
    );
    assert!(resolution.terminal_doc_id.is_none());
    assert_eq!(resolution.events.len(), 2);

    fixture
        .conn
        .execute(
            "UPDATE events SET payload_json=?1 WHERE type='document.lifecycle.superseded.v1' AND event_id=(SELECT MIN(event_id) FROM events WHERE type='document.lifecycle.superseded.v1')",
            [r#"{"malformed":true}"#],
        )
        .expect("tamper lifecycle event");
    let corrupt = load_document_lifecycle_events(&fixture.conn)
        .expect_err("tampered global event chain must fail closed");
    assert_eq!(corrupt.code, "KC_DB_INTEGRITY_FAILED");
}

#[test]
fn lifecycle_detects_cycles_in_admitted_event_data() {
    let fixture = fixture();
    let source = &fixture.docs[0];
    let replacement = &fixture.docs[1];
    for (at_ms, from, to) in [(30_i64, source, replacement), (31_i64, replacement, source)] {
        append_event(
            &fixture.conn,
            at_ms,
            "document.lifecycle.superseded.v1",
            &serde_json::json!({
                "schema_version": DOCUMENT_LIFECYCLE_EVENT_SCHEMA,
                "action": "supersede",
                "doc_id": from.0,
                "doc_canonical_hash": blake3_hex_prefixed(&from.1),
                "replacement_doc_id": to.0,
                "replacement_canonical_hash": blake3_hex_prefixed(&to.1),
                "subject_id": "owner-subject",
                "reason": "synthetic cycle",
                "effective_at_ms": at_ms
            }),
        )
        .expect("append synthetic lifecycle edge");
    }
    let by_doc = load_document_lifecycle_events(&fixture.conn).expect("load cycle events");
    let error = resolve_document_lifecycle(&source.0, &by_doc).expect_err("cycle must fail closed");
    assert_eq!(error.code, "KC_DOCUMENT_LIFECYCLE_CORRUPT");

    assert!(fixture
        .store
        .exists(&ObjectHash(source.0.clone()))
        .expect("source object existence"));
    assert!(fixture
        .store
        .exists(&ObjectHash(replacement.0.clone()))
        .expect("replacement object existence"));
}
