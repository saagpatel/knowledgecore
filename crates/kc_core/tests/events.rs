use kc_core::db::open_db;
use kc_core::events::append_event;

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
}
