use kc_core::db::open_db;
use kc_core::events::{append_event, read_verified_event_chain};

#[test]
fn events_chain_hashes_deterministically() {
    let temp = tempfile::tempdir().expect("tempdir");
    let conn = open_db(&temp.path().join("db/knowledge.sqlite")).expect("open db");

    let first =
        append_event(&conn, 10, "test.first", &serde_json::json!({"k": 1})).expect("first event");
    let second =
        append_event(&conn, 11, "test.second", &serde_json::json!({"k": 2})).expect("second event");

    assert_eq!(first.event_id, 1);
    assert_eq!(second.event_id, 2);
    assert_eq!(second.prev_event_hash, Some(first.event_hash));
    assert_eq!(
        read_verified_event_chain(&conn)
            .expect("verified chain")
            .len(),
        2
    );
}

#[test]
fn verified_event_chain_rejects_tampered_payload_hash_and_links() {
    for (column, value, expected_event_id) in [
        ("payload_json", r#"{"k":9}"#, 1_i64),
        (
            "event_hash",
            "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            1,
        ),
        (
            "prev_event_hash",
            "blake3:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            2,
        ),
    ] {
        let temp = tempfile::tempdir().expect("tempdir");
        let conn = open_db(&temp.path().join("db/knowledge.sqlite")).expect("open db");
        append_event(&conn, 10, "test.first", &serde_json::json!({"k": 1})).expect("first event");
        append_event(&conn, 11, "test.second", &serde_json::json!({"k": 2})).expect("second event");
        conn.execute(
            &format!("UPDATE events SET {column}=?1 WHERE event_id=?2"),
            rusqlite::params![value, expected_event_id],
        )
        .expect("tamper synthetic chain");

        let error = read_verified_event_chain(&conn).expect_err("tampering must fail closed");
        assert_eq!(error.code, "KC_DB_INTEGRITY_FAILED");
    }
}
