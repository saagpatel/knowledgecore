use kc_core::db::{open_db, schema_version};

#[test]
fn migrations_apply_schema_v12() {
    let temp = tempfile::tempdir().expect("tempdir");
    let db_path = temp.path().join("db/knowledge.sqlite");

    let conn = open_db(&db_path).expect("open db");
    let version = schema_version(&conn).expect("schema version");
    assert_eq!(version, 12);

    let names: Vec<String> = [
        "objects",
        "docs",
        "doc_sources",
        "canonical_text",
        "chunks",
        "events",
        "sync_state",
        "sync_snapshots",
        "lineage_overlays",
        "lineage_edit_locks",
        "trusted_devices",
        "trust_events",
        "identity_providers",
        "trust_providers",
        "trust_provider_policies",
        "trust_session_revocations",
        "identity_sessions",
        "device_certificates",
        "recovery_escrow_configs",
        "recovery_escrow_provider_configs",
        "recovery_escrow_events",
        "lineage_roles",
        "lineage_permissions",
        "lineage_role_bindings",
        "lineage_lock_scopes",
        "lineage_policies",
        "lineage_policy_bindings",
        "lineage_policy_audit",
        "sync_signing_keys",
    ]
    .iter()
    .map(|table| {
        conn.query_row(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?1",
            [table],
            |row| row.get::<_, String>(0),
        )
        .expect("table must exist")
    })
    .collect();

    assert_eq!(names.len(), 29);
}
