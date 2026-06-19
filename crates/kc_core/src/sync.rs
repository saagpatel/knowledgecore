use crate::app_error::{AppError, AppResult};
use crate::canon_json::to_canonical_bytes;
use crate::db::open_db;
use crate::export::{export_bundle, ExportOptions};
use crate::hashing::blake3_hex_prefixed;
use crate::resource_limits::sync_snapshot_limits;
use crate::sync_merge::{
    ensure_conservative_merge_safe, ensure_conservative_plus_v2_merge_safe,
    ensure_conservative_plus_v3_merge_safe, ensure_conservative_plus_v4_merge_safe,
    merge_preview_conservative, merge_preview_with_policy_v2, SyncMergeChangeSetV1,
    SyncMergeContextV2, SyncMergePreviewReportV1,
};
use crate::sync_s3::S3SyncTransport;
use crate::sync_transport::{FsSyncTransport, SyncTargetUri, SyncTransport};
use crate::trust_identity;
use crate::vault::{vault_open, VaultJsonV2};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::io::Cursor;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const TRUST_MODEL_PASSPHRASE_V1: &str = "passphrase_v1";
const S3_LOCK_KEY: &str = "locks/write.lock";
const S3_LOCK_TTL_MS: i64 = 60_000;
static SYNC_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy)]
pub struct SyncSnapshotResourceLimits {
    pub max_archive_bytes: usize,
    pub max_entries: usize,
    pub max_entry_bytes: u64,
}

fn next_sync_temp_suffix() -> u64 {
    SYNC_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncTrustV1 {
    pub model: String,
    pub fingerprint: String,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncHeadV1 {
    pub schema_version: i64,
    pub snapshot_id: String,
    pub manifest_hash: String,
    pub created_at_ms: i64,
    #[serde(default)]
    pub trust: Option<SyncTrustV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author_device_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author_signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author_cert_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author_chain_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncStatusV1 {
    pub target_path: String,
    pub remote_head: Option<SyncHeadV1>,
    pub seen_remote_snapshot_id: Option<String>,
    pub last_applied_manifest_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncPushResultV1 {
    pub snapshot_id: String,
    pub manifest_hash: String,
    pub remote_head: SyncHeadV1,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncPullResultV1 {
    pub snapshot_id: String,
    pub manifest_hash: String,
    pub remote_head: SyncHeadV1,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncMergePreviewResultV1 {
    pub target_path: String,
    pub seen_remote_snapshot_id: Option<String>,
    pub remote_snapshot_id: String,
    pub report: SyncMergePreviewReportV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncAutoMergeMode {
    Conservative,
    ConservativePlusV2,
    ConservativePlusV3,
    ConservativePlusV4,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncConflictArtifactV1 {
    pub schema_version: i64,
    pub kind: String,
    pub vault_id: String,
    pub now_ms: i64,
    pub local_manifest_hash: String,
    pub remote_head_snapshot_id: Option<String>,
    pub remote_head_manifest_hash: Option<String>,
    pub seen_remote_snapshot_id: Option<String>,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub local_trust_fingerprint: Option<String>,
    #[serde(default)]
    pub remote_trust_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SyncS3WriteLockV1 {
    schema_version: i64,
    holder: String,
    vault_id: String,
    acquired_at_ms: i64,
    expires_at_ms: i64,
    trust_fingerprint: String,
}

fn sync_error(code: &str, message: &str, details: serde_json::Value) -> AppError {
    AppError::new(code, "sync", message, false, details)
}

fn parse_auto_merge_mode(mode: Option<&str>) -> AppResult<Option<SyncAutoMergeMode>> {
    match mode {
        None => Ok(None),
        Some(raw) => match raw {
            "conservative" => Ok(Some(SyncAutoMergeMode::Conservative)),
            "conservative_plus_v2" => Ok(Some(SyncAutoMergeMode::ConservativePlusV2)),
            "conservative_plus_v3" => Ok(Some(SyncAutoMergeMode::ConservativePlusV3)),
            "conservative_plus_v4" => Ok(Some(SyncAutoMergeMode::ConservativePlusV4)),
            other => Err(sync_error(
                "KC_SYNC_MERGE_POLICY_UNSUPPORTED",
                "unsupported sync auto-merge mode",
                serde_json::json!({
                    "auto_merge": other,
                    "supported": [
                        "conservative",
                        "conservative_plus_v2",
                        "conservative_plus_v3",
                        "conservative_plus_v4"
                    ]
                }),
            )),
        },
    }
}

fn ensure_sync_tables(conn: &Connection) -> AppResult<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS sync_state (
           state_key TEXT PRIMARY KEY,
           state_value TEXT NOT NULL,
           updated_at_ms INTEGER NOT NULL
         );
         CREATE TABLE IF NOT EXISTS sync_snapshots (
           snapshot_id TEXT PRIMARY KEY,
           direction TEXT NOT NULL,
           created_at_ms INTEGER NOT NULL,
           bundle_relpath TEXT NOT NULL,
           manifest_hash TEXT NOT NULL
         );",
    )
    .map_err(|e| {
        sync_error(
            "KC_SYNC_STATE_FAILED",
            "failed ensuring sync tables",
            serde_json::json!({ "error": e.to_string() }),
        )
    })
}

fn read_state(conn: &Connection, key: &str) -> AppResult<Option<String>> {
    let mut stmt = conn
        .prepare("SELECT state_value FROM sync_state WHERE state_key=?1")
        .map_err(|e| {
            sync_error(
                "KC_SYNC_STATE_FAILED",
                "failed preparing sync state query",
                serde_json::json!({ "error": e.to_string(), "key": key }),
            )
        })?;
    let mut rows = stmt.query([key]).map_err(|e| {
        sync_error(
            "KC_SYNC_STATE_FAILED",
            "failed querying sync state",
            serde_json::json!({ "error": e.to_string(), "key": key }),
        )
    })?;
    let value = rows.next().map_err(|e| {
        sync_error(
            "KC_SYNC_STATE_FAILED",
            "failed iterating sync state row",
            serde_json::json!({ "error": e.to_string(), "key": key }),
        )
    })?;
    value.map(|row| row.get(0)).transpose().map_err(|e| {
        sync_error(
            "KC_SYNC_STATE_FAILED",
            "failed decoding sync state row",
            serde_json::json!({ "error": e.to_string(), "key": key }),
        )
    })
}

fn write_state(conn: &Connection, key: &str, value: &str, now_ms: i64) -> AppResult<()> {
    conn.execute(
        "INSERT INTO sync_state(state_key, state_value, updated_at_ms)
         VALUES(?1, ?2, ?3)
         ON CONFLICT(state_key) DO UPDATE SET state_value=excluded.state_value, updated_at_ms=excluded.updated_at_ms",
        params![key, value, now_ms],
    )
    .map_err(|e| {
        sync_error(
            "KC_SYNC_STATE_FAILED",
            "failed writing sync state",
            serde_json::json!({ "error": e.to_string(), "key": key }),
        )
    })?;
    Ok(())
}

fn write_snapshot_log(
    conn: &Connection,
    snapshot_id: &str,
    direction: &str,
    created_at_ms: i64,
    bundle_relpath: &str,
    manifest_hash: &str,
) -> AppResult<()> {
    conn.execute(
        "INSERT OR REPLACE INTO sync_snapshots(snapshot_id, direction, created_at_ms, bundle_relpath, manifest_hash)
         VALUES(?1, ?2, ?3, ?4, ?5)",
        params![snapshot_id, direction, created_at_ms, bundle_relpath, manifest_hash],
    )
    .map_err(|e| {
        sync_error(
            "KC_SYNC_STATE_FAILED",
            "failed writing sync snapshot log",
            serde_json::json!({ "error": e.to_string(), "snapshot_id": snapshot_id }),
        )
    })?;
    Ok(())
}

fn main_db_path(conn: &Connection) -> AppResult<PathBuf> {
    let path: String = conn
        .query_row(
            "SELECT file FROM pragma_database_list WHERE name='main'",
            [],
            |row| row.get(0),
        )
        .map_err(|e| {
            sync_error(
                "KC_SYNC_STATE_FAILED",
                "failed resolving main database path",
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;
    Ok(PathBuf::from(path))
}

fn ensure_target_layout(target_path: &Path) -> AppResult<(PathBuf, PathBuf)> {
    let snapshots = target_path.join("snapshots");
    let conflicts = target_path.join("conflicts");
    fs::create_dir_all(&snapshots).map_err(|e| {
        sync_error(
            "KC_SYNC_TARGET_INVALID",
            "failed creating snapshots directory",
            serde_json::json!({ "error": e.to_string(), "path": snapshots }),
        )
    })?;
    fs::create_dir_all(&conflicts).map_err(|e| {
        sync_error(
            "KC_SYNC_TARGET_INVALID",
            "failed creating conflicts directory",
            serde_json::json!({ "error": e.to_string(), "path": conflicts }),
        )
    })?;
    Ok((snapshots, conflicts))
}

fn read_head(target_path: &Path) -> AppResult<Option<SyncHeadV1>> {
    FsSyncTransport::new(target_path).read_head()
}

fn write_head(target_path: &Path, head: &SyncHeadV1) -> AppResult<()> {
    FsSyncTransport::new(target_path).write_head(head)
}

fn list_files_sorted(root: &Path) -> AppResult<Vec<PathBuf>> {
    let mut files: Vec<PathBuf> = walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .map(|e| e.path().to_path_buf())
        .collect();
    files.sort();
    Ok(files)
}

fn copy_tree_sorted(src: &Path, dst: &Path) -> AppResult<()> {
    for file in list_files_sorted(src)? {
        let rel = file.strip_prefix(src).map_err(|e| {
            sync_error(
                "KC_SYNC_TARGET_INVALID",
                "failed deriving relative path while copying sync tree",
                serde_json::json!({ "error": e.to_string(), "path": file, "root": src }),
            )
        })?;
        let out = dst.join(rel);
        if let Some(parent) = out.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                sync_error(
                    "KC_SYNC_TARGET_INVALID",
                    "failed creating sync destination parent",
                    serde_json::json!({ "error": e.to_string(), "path": parent }),
                )
            })?;
        }
        fs::copy(&file, &out).map_err(|e| {
            sync_error(
                "KC_SYNC_TARGET_INVALID",
                "failed copying sync file",
                serde_json::json!({ "error": e.to_string(), "from": file, "to": out }),
            )
        })?;
    }
    Ok(())
}

fn safe_zip_relative_path(name: &str) -> AppResult<PathBuf> {
    let mut out = PathBuf::new();
    for component in Path::new(name).components() {
        match component {
            Component::Normal(part) => out.push(part),
            _ => {
                return Err(sync_error(
                    "KC_SYNC_TARGET_INVALID",
                    "sync snapshot zip contains invalid entry path",
                    serde_json::json!({ "entry": name }),
                ));
            }
        }
    }

    if out.as_os_str().is_empty() {
        return Err(sync_error(
            "KC_SYNC_TARGET_INVALID",
            "sync snapshot zip contains empty entry path",
            serde_json::json!({ "entry": name }),
        ));
    }

    Ok(out)
}

fn unpack_zip_snapshot(zip_bytes: &[u8], output_dir: &Path) -> AppResult<()> {
    unpack_zip_snapshot_with_limits(zip_bytes, output_dir, None)
}

fn unpack_zip_snapshot_with_limits(
    zip_bytes: &[u8],
    output_dir: &Path,
    limits: Option<SyncSnapshotResourceLimits>,
) -> AppResult<()> {
    if let Some(limits) = limits {
        if zip_bytes.len() > limits.max_archive_bytes {
            return Err(sync_error(
                "KC_RESOURCE_LIMIT_EXCEEDED",
                "sync snapshot archive exceeds configured byte limit",
                serde_json::json!({
                    "bytes": zip_bytes.len(),
                    "max_archive_bytes": limits.max_archive_bytes,
                }),
            ));
        }
    }

    fs::create_dir_all(output_dir).map_err(|e| {
        sync_error(
            "KC_SYNC_TARGET_INVALID",
            "failed creating zip unpack directory",
            serde_json::json!({ "error": e.to_string(), "path": output_dir }),
        )
    })?;

    let mut archive = zip::ZipArchive::new(Cursor::new(zip_bytes)).map_err(|e| {
        sync_error(
            "KC_SYNC_TARGET_INVALID",
            "failed opening sync snapshot zip",
            serde_json::json!({ "error": e.to_string() }),
        )
    })?;

    let mut names = Vec::new();
    for idx in 0..archive.len() {
        let file = archive.by_index(idx).map_err(|e| {
            sync_error(
                "KC_SYNC_TARGET_INVALID",
                "failed reading zip entry during sync snapshot unpack",
                serde_json::json!({ "error": e.to_string(), "index": idx }),
            )
        })?;
        if file.name().ends_with('/') {
            continue;
        }
        if let Some(limits) = limits {
            if names.len() + 1 > limits.max_entries {
                return Err(sync_error(
                    "KC_RESOURCE_LIMIT_EXCEEDED",
                    "sync snapshot zip exceeds configured entry limit",
                    serde_json::json!({
                        "entries": names.len() + 1,
                        "max_entries": limits.max_entries,
                    }),
                ));
            }
            if file.size() > limits.max_entry_bytes {
                return Err(sync_error(
                    "KC_RESOURCE_LIMIT_EXCEEDED",
                    "sync snapshot zip entry exceeds configured byte limit",
                    serde_json::json!({
                        "entry": file.name(),
                        "bytes": file.size(),
                        "max_entry_bytes": limits.max_entry_bytes,
                    }),
                ));
            }
        }
        names.push(file.name().to_string());
    }
    names.sort();

    for name in names {
        let rel = safe_zip_relative_path(&name)?;
        let mut file = archive.by_name(&name).map_err(|e| {
            sync_error(
                "KC_SYNC_TARGET_INVALID",
                "failed opening zip entry by name during sync snapshot unpack",
                serde_json::json!({ "error": e.to_string(), "name": name }),
            )
        })?;
        let out_path = output_dir.join(rel);
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                sync_error(
                    "KC_SYNC_TARGET_INVALID",
                    "failed creating zip unpack parent",
                    serde_json::json!({ "error": e.to_string(), "path": parent }),
                )
            })?;
        }
        let mut out = fs::File::create(&out_path).map_err(|e| {
            sync_error(
                "KC_SYNC_TARGET_INVALID",
                "failed creating zip unpack file",
                serde_json::json!({ "error": e.to_string(), "path": out_path }),
            )
        })?;
        std::io::copy(&mut file, &mut out).map_err(|e| {
            sync_error(
                "KC_SYNC_TARGET_INVALID",
                "failed writing zip unpack file",
                serde_json::json!({ "error": e.to_string(), "path": out_path }),
            )
        })?;
    }

    Ok(())
}

fn compute_manifest_hash(bundle_dir: &Path) -> AppResult<String> {
    let bytes = fs::read(bundle_dir.join("manifest.json")).map_err(|e| {
        sync_error(
            "KC_SYNC_STATE_FAILED",
            "failed reading manifest for sync hash",
            serde_json::json!({ "error": e.to_string(), "path": bundle_dir.join("manifest.json") }),
        )
    })?;
    Ok(blake3_hex_prefixed(&bytes))
}

fn extract_change_set_from_bundle_dir(bundle_dir: &Path) -> AppResult<SyncMergeChangeSetV1> {
    let manifest_path = bundle_dir.join("manifest.json");
    let manifest_bytes = fs::read(&manifest_path).map_err(|e| {
        sync_error(
            "KC_SYNC_MERGE_PRECONDITION_FAILED",
            "failed reading snapshot manifest for merge preview",
            serde_json::json!({ "error": e.to_string(), "path": manifest_path }),
        )
    })?;
    let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes).map_err(|e| {
        sync_error(
            "KC_SYNC_MERGE_PRECONDITION_FAILED",
            "failed parsing snapshot manifest for merge preview",
            serde_json::json!({ "error": e.to_string(), "path": manifest_path }),
        )
    })?;

    let objects = manifest
        .get("objects")
        .and_then(|x| x.as_array())
        .ok_or_else(|| {
            sync_error(
                "KC_SYNC_MERGE_PRECONDITION_FAILED",
                "snapshot manifest missing objects array",
                serde_json::json!({ "path": manifest_path }),
            )
        })?;

    let mut object_hashes = Vec::new();
    for object in objects {
        let hash = object.get("hash").and_then(|x| x.as_str()).ok_or_else(|| {
            sync_error(
                "KC_SYNC_MERGE_PRECONDITION_FAILED",
                "snapshot manifest object entry missing hash",
                serde_json::json!({ "path": manifest_path }),
            )
        })?;
        object_hashes.push(hash.to_string());
    }

    let db_rel = manifest
        .get("db")
        .and_then(|db| db.get("relative_path"))
        .and_then(|x| x.as_str())
        .unwrap_or("db/knowledge.sqlite");
    let db_path = bundle_dir.join(db_rel);
    let lineage_overlay_ids = read_overlay_ids_from_snapshot_db(&db_path)?;

    Ok(SyncMergeChangeSetV1 {
        object_hashes,
        lineage_overlay_ids,
    })
}

fn read_overlay_ids_from_snapshot_db(db_path: &Path) -> AppResult<Vec<String>> {
    if !db_path.exists() {
        return Ok(Vec::new());
    }

    let conn = Connection::open(db_path).map_err(|e| {
        sync_error(
            "KC_SYNC_MERGE_PRECONDITION_FAILED",
            "failed opening snapshot db for merge preview",
            serde_json::json!({ "error": e.to_string(), "path": db_path }),
        )
    })?;

    let has_lineage_overlays: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='lineage_overlays'",
            [],
            |row| row.get(0),
        )
        .map_err(|e| {
            sync_error(
                "KC_SYNC_MERGE_PRECONDITION_FAILED",
                "failed checking lineage overlay table in snapshot db",
                serde_json::json!({ "error": e.to_string(), "path": db_path }),
            )
        })?;
    if has_lineage_overlays == 0 {
        return Ok(Vec::new());
    }

    let mut stmt = conn
        .prepare("SELECT overlay_id FROM lineage_overlays ORDER BY overlay_id ASC")
        .map_err(|e| {
            sync_error(
                "KC_SYNC_MERGE_PRECONDITION_FAILED",
                "failed preparing lineage overlay query for merge preview",
                serde_json::json!({ "error": e.to_string(), "path": db_path }),
            )
        })?;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|e| {
            sync_error(
                "KC_SYNC_MERGE_PRECONDITION_FAILED",
                "failed querying lineage overlay ids for merge preview",
                serde_json::json!({ "error": e.to_string(), "path": db_path }),
            )
        })?;
    let mut overlay_ids = Vec::new();
    for row in rows {
        overlay_ids.push(row.map_err(|e| {
            sync_error(
                "KC_SYNC_MERGE_PRECONDITION_FAILED",
                "failed decoding lineage overlay id for merge preview",
                serde_json::json!({ "error": e.to_string(), "path": db_path }),
            )
        })?);
    }
    Ok(overlay_ids)
}

fn delta_change_set(
    current: &SyncMergeChangeSetV1,
    base: &SyncMergeChangeSetV1,
) -> SyncMergeChangeSetV1 {
    let base_object_hashes: BTreeSet<String> = base.object_hashes.iter().cloned().collect();
    let base_overlay_ids: BTreeSet<String> = base.lineage_overlay_ids.iter().cloned().collect();

    SyncMergeChangeSetV1 {
        object_hashes: current
            .object_hashes
            .iter()
            .filter(|h| !base_object_hashes.contains(*h))
            .cloned()
            .collect(),
        lineage_overlay_ids: current
            .lineage_overlay_ids
            .iter()
            .filter(|h| !base_overlay_ids.contains(*h))
            .cloned()
            .collect(),
    }
}

fn extract_change_set_from_s3_snapshot(
    transport: &S3SyncTransport,
    snapshot_id: &str,
    now_ms: i64,
) -> AppResult<SyncMergeChangeSetV1> {
    let snapshot_key = format!("snapshots/{}.zip", snapshot_id);
    let zip_bytes = transport.read_bytes(&snapshot_key)?.ok_or_else(|| {
        sync_error(
            "KC_SYNC_MERGE_PRECONDITION_FAILED",
            "sync merge preview snapshot is missing on remote target",
            serde_json::json!({
                "target": transport.target().display(),
                "snapshot_id": snapshot_id,
                "key": snapshot_key
            }),
        )
    })?;
    let unpack_dir = std::env::temp_dir().join(format!(
        "kc_sync_merge_unpack_{}_{}_{}_{}",
        std::process::id(),
        snapshot_id.replace(':', "_"),
        now_ms,
        next_sync_temp_suffix()
    ));
    if unpack_dir.exists() {
        fs::remove_dir_all(&unpack_dir).map_err(|e| {
            sync_error(
                "KC_SYNC_MERGE_PRECONDITION_FAILED",
                "failed clearing existing merge preview unpack directory",
                serde_json::json!({ "error": e.to_string(), "path": unpack_dir }),
            )
        })?;
    }
    unpack_zip_snapshot(&zip_bytes, &unpack_dir)?;
    extract_change_set_from_bundle_dir(&unpack_dir)
}

fn build_local_snapshot(vault_path: &Path, now_ms: i64) -> AppResult<(PathBuf, String)> {
    let staging_root = std::env::temp_dir().join(format!(
        "kc_sync_export_{}_{}_{}",
        std::process::id(),
        now_ms,
        next_sync_temp_suffix()
    ));
    fs::create_dir_all(&staging_root).map_err(|e| {
        sync_error(
            "KC_SYNC_STATE_FAILED",
            "failed creating local sync staging directory",
            serde_json::json!({ "error": e.to_string(), "path": staging_root }),
        )
    })?;

    let bundle = export_bundle(
        vault_path,
        &staging_root,
        &ExportOptions {
            include_vectors: true,
            as_zip: false,
        },
        now_ms,
    )?;
    let manifest_hash = compute_manifest_hash(&bundle)?;
    Ok((bundle, manifest_hash))
}

fn build_local_snapshot_zip(
    vault_path: &Path,
    now_ms: i64,
) -> AppResult<(PathBuf, PathBuf, String)> {
    let staging_root = std::env::temp_dir().join(format!(
        "kc_sync_export_zip_{}_{}_{}",
        std::process::id(),
        now_ms,
        next_sync_temp_suffix()
    ));
    fs::create_dir_all(&staging_root).map_err(|e| {
        sync_error(
            "KC_SYNC_STATE_FAILED",
            "failed creating local sync zip staging directory",
            serde_json::json!({ "error": e.to_string(), "path": staging_root }),
        )
    })?;

    let zip_path = export_bundle(
        vault_path,
        &staging_root,
        &ExportOptions {
            include_vectors: true,
            as_zip: true,
        },
        now_ms,
    )?;
    let bundle_dir = staging_root.join(format!("export_{}", now_ms));
    let manifest_hash = compute_manifest_hash(&bundle_dir)?;
    Ok((zip_path, bundle_dir, manifest_hash))
}

fn snapshot_id_for_manifest(manifest_hash: &str, now_ms: i64) -> String {
    blake3_hex_prefixed(format!("kc.sync.snapshot.v2\n{}\n{}", manifest_hash, now_ms).as_bytes())
}

fn create_conflict_artifact(
    target_path: &Path,
    vault_id: &str,
    now_ms: i64,
    local_manifest_hash: &str,
    remote_head: Option<&SyncHeadV1>,
    seen_remote_snapshot_id: Option<String>,
    local_trust_fingerprint: Option<String>,
) -> AppResult<PathBuf> {
    let artifact = SyncConflictArtifactV1 {
        schema_version: 1,
        kind: "sync_conflict".to_string(),
        vault_id: vault_id.to_string(),
        now_ms,
        local_manifest_hash: local_manifest_hash.to_string(),
        remote_head_snapshot_id: remote_head.map(|h| h.snapshot_id.clone()),
        remote_head_manifest_hash: remote_head.map(|h| h.manifest_hash.clone()),
        seen_remote_snapshot_id,
        target: Some(target_path.display().to_string()),
        local_trust_fingerprint,
        remote_trust_fingerprint: remote_head
            .and_then(|h| h.trust.as_ref().map(|t| t.fingerprint.clone())),
    };
    let canonical = to_canonical_bytes(&serde_json::to_value(&artifact).map_err(|e| {
        sync_error(
            "KC_SYNC_CONFLICT",
            "failed serializing sync conflict artifact",
            serde_json::json!({ "error": e.to_string() }),
        )
    })?)?;
    let digest = blake3_hex_prefixed(&canonical);
    let digest = digest.strip_prefix("blake3:").unwrap_or(&digest);
    let id = digest[..digest.len().min(16)].to_string();
    let path = target_path
        .join("conflicts")
        .join(format!("conflict_{}_{}.json", now_ms, id));
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            sync_error(
                "KC_SYNC_CONFLICT",
                "failed creating conflict artifact directory",
                serde_json::json!({ "error": e.to_string(), "path": parent }),
            )
        })?;
    }
    fs::write(&path, canonical).map_err(|e| {
        sync_error(
            "KC_SYNC_CONFLICT",
            "failed writing conflict artifact",
            serde_json::json!({ "error": e.to_string(), "path": path }),
        )
    })?;
    Ok(path)
}

fn create_conflict_artifact_s3(
    transport: &S3SyncTransport,
    vault_id: &str,
    now_ms: i64,
    local_manifest_hash: &str,
    remote_head: Option<&SyncHeadV1>,
    seen_remote_snapshot_id: Option<String>,
    local_trust_fingerprint: Option<String>,
) -> AppResult<String> {
    let artifact = SyncConflictArtifactV1 {
        schema_version: 1,
        kind: "sync_conflict".to_string(),
        vault_id: vault_id.to_string(),
        now_ms,
        local_manifest_hash: local_manifest_hash.to_string(),
        remote_head_snapshot_id: remote_head.map(|h| h.snapshot_id.clone()),
        remote_head_manifest_hash: remote_head.map(|h| h.manifest_hash.clone()),
        seen_remote_snapshot_id,
        target: Some(transport.target().display()),
        local_trust_fingerprint,
        remote_trust_fingerprint: remote_head
            .and_then(|h| h.trust.as_ref().map(|t| t.fingerprint.clone())),
    };

    let canonical = to_canonical_bytes(&serde_json::to_value(&artifact).map_err(|e| {
        sync_error(
            "KC_SYNC_CONFLICT",
            "failed serializing s3 sync conflict artifact",
            serde_json::json!({ "error": e.to_string() }),
        )
    })?)?;
    let digest = blake3_hex_prefixed(&canonical);
    let digest = digest.strip_prefix("blake3:").unwrap_or(&digest);
    let id = digest[..digest.len().min(16)].to_string();
    let key = format!("conflicts/conflict_{}_{}.json", now_ms, id);
    transport.write_bytes(&key, &canonical, "application/json")?;
    Ok(key)
}

fn should_conflict(
    remote_head: Option<&SyncHeadV1>,
    seen_remote_snapshot_id: Option<&str>,
    last_applied_manifest_hash: Option<&str>,
    local_manifest_hash: &str,
) -> bool {
    let remote_changed = match (remote_head, seen_remote_snapshot_id) {
        (Some(head), Some(seen)) => head.snapshot_id != seen,
        _ => false,
    };
    let local_changed = match last_applied_manifest_hash {
        Some(last) => last != local_manifest_hash,
        None => false,
    };
    remote_changed && local_changed
}

fn apply_snapshot_to_vault(snapshot_dir: &Path, vault_path: &Path) -> AppResult<()> {
    for top in ["db", "store", "index"] {
        let src = snapshot_dir.join(top);
        if !src.exists() {
            continue;
        }
        let dst = vault_path.join(top);
        if dst.exists() {
            if dst.is_dir() {
                fs::remove_dir_all(&dst).map_err(|e| {
                    sync_error(
                        "KC_SYNC_APPLY_FAILED",
                        "failed removing existing sync apply directory",
                        serde_json::json!({ "error": e.to_string(), "path": dst }),
                    )
                })?;
            } else {
                fs::remove_file(&dst).map_err(|e| {
                    sync_error(
                        "KC_SYNC_APPLY_FAILED",
                        "failed removing existing sync apply file",
                        serde_json::json!({ "error": e.to_string(), "path": dst }),
                    )
                })?;
            }
        }
        fs::create_dir_all(&dst).map_err(|e| {
            sync_error(
                "KC_SYNC_APPLY_FAILED",
                "failed creating destination sync apply directory",
                serde_json::json!({ "error": e.to_string(), "path": dst }),
            )
        })?;
        copy_tree_sorted(&src, &dst)?;
    }
    Ok(())
}

fn derive_local_sync_trust(vault: &VaultJsonV2, now_ms: i64) -> AppResult<SyncTrustV1> {
    let passphrase = std::env::var("KC_VAULT_PASSPHRASE").map_err(|_| {
        sync_error(
            "KC_SYNC_AUTH_FAILED",
            "remote sync requires KC_VAULT_PASSPHRASE",
            serde_json::json!({ "env": "KC_VAULT_PASSPHRASE" }),
        )
    })?;

    let key = crate::object_store::derive_object_store_key(
        &passphrase,
        &vault.encryption.kdf.salt_id,
        vault.encryption.kdf.memory_kib,
        vault.encryption.kdf.iterations,
        vault.encryption.kdf.parallelism,
    )
    .map_err(|e| {
        sync_error(
            "KC_SYNC_AUTH_FAILED",
            "failed deriving sync trust fingerprint from passphrase",
            serde_json::json!({ "error": e.message, "source_code": e.code }),
        )
    })?;

    let mut key_hex = String::with_capacity(64);
    for b in key {
        key_hex.push_str(&format!("{:02x}", b));
    }

    let fingerprint = blake3_hex_prefixed(
        format!(
            "kc.sync.passphrase.v1\n{}\n{}",
            vault.encryption.kdf.salt_id, key_hex
        )
        .as_bytes(),
    );

    Ok(SyncTrustV1 {
        model: TRUST_MODEL_PASSPHRASE_V1.to_string(),
        fingerprint,
        updated_at_ms: now_ms,
    })
}

fn sync_signature_payload(
    snapshot_id: &str,
    manifest_hash: &str,
    created_at_ms: i64,
    author_device_id: &str,
    author_fingerprint: &str,
    author_cert_id: &str,
    author_chain_hash: &str,
) -> AppResult<Vec<u8>> {
    to_canonical_bytes(&serde_json::json!({
        "snapshot_id": snapshot_id,
        "manifest_hash": manifest_hash,
        "created_at_ms": created_at_ms,
        "author_device_id": author_device_id,
        "author_fingerprint": author_fingerprint,
        "author_cert_id": author_cert_id,
        "author_chain_hash": author_chain_hash
    }))
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn sign_sync_payload(payload: &[u8]) -> String {
    let h1 = blake3::hash(payload);
    let mut second_seed = Vec::with_capacity(16 + payload.len());
    second_seed.extend_from_slice(b"kc.sync.sig.v1\n");
    second_seed.extend_from_slice(payload);
    let h2 = blake3::hash(&second_seed);
    let mut sig = String::with_capacity(128);
    sig.push_str(&bytes_to_hex(h1.as_bytes()));
    sig.push_str(&bytes_to_hex(h2.as_bytes()));
    sig
}

#[derive(Debug, Clone)]
struct SyncAuthorV3 {
    device_id: String,
    fingerprint: String,
    cert_id: String,
    chain_hash: String,
}

fn local_sync_author(conn: &Connection) -> AppResult<SyncAuthorV3> {
    let author = trust_identity::verified_author_identity(conn).map_err(|e| {
        if e.code == "KC_TRUST_DEVICE_NOT_ENROLLED" {
            sync_error(
                "KC_TRUST_DEVICE_NOT_ENROLLED",
                "sync head v3 requires a verified enrolled device certificate",
                serde_json::json!({}),
            )
        } else {
            sync_error(
                "KC_TRUST_CERT_CHAIN_INVALID",
                "failed resolving local sync author identity",
                serde_json::json!({ "source_code": e.code, "source_message": e.message }),
            )
        }
    })?;
    Ok(SyncAuthorV3 {
        device_id: author.device_id,
        fingerprint: author.fingerprint,
        cert_id: author.cert_id,
        chain_hash: author.cert_chain_hash,
    })
}

fn ensure_remote_trust_matches(
    _conn: &Connection,
    remote_head: Option<&SyncHeadV1>,
    local: &SyncTrustV1,
) -> AppResult<()> {
    let Some(head) = remote_head else {
        return Ok(());
    };
    let remote = head.trust.as_ref().ok_or_else(|| {
        sync_error(
            "KC_SYNC_KEY_MISMATCH",
            "remote sync head is missing trust metadata",
            serde_json::json!({ "snapshot_id": head.snapshot_id }),
        )
    })?;

    if remote.model != TRUST_MODEL_PASSPHRASE_V1 {
        return Err(sync_error(
            "KC_SYNC_KEY_MISMATCH",
            "remote sync head uses unsupported trust model",
            serde_json::json!({
                "expected": TRUST_MODEL_PASSPHRASE_V1,
                "actual": remote.model,
                "snapshot_id": head.snapshot_id
            }),
        ));
    }

    if remote.fingerprint != local.fingerprint {
        return Err(sync_error(
            "KC_SYNC_KEY_MISMATCH",
            "remote sync trust fingerprint does not match local passphrase",
            serde_json::json!({
                "expected": local.fingerprint,
                "actual": remote.fingerprint,
                "snapshot_id": head.snapshot_id
            }),
        ));
    }

    if head.schema_version >= 3 {
        let author_device_id = head.author_device_id.as_deref().ok_or_else(|| {
            sync_error(
                "KC_TRUST_DEVICE_NOT_ENROLLED",
                "sync head v3 is missing author_device_id",
                serde_json::json!({ "snapshot_id": head.snapshot_id }),
            )
        })?;
        let author_fingerprint = head.author_fingerprint.as_deref().ok_or_else(|| {
            sync_error(
                "KC_TRUST_DEVICE_NOT_ENROLLED",
                "sync head v3 is missing author_fingerprint",
                serde_json::json!({ "snapshot_id": head.snapshot_id }),
            )
        })?;
        let author_signature = head.author_signature.as_deref().ok_or_else(|| {
            sync_error(
                "KC_TRUST_SIGNATURE_INVALID",
                "sync head v3 is missing author_signature",
                serde_json::json!({ "snapshot_id": head.snapshot_id }),
            )
        })?;
        let author_cert_id = head.author_cert_id.as_deref().ok_or_else(|| {
            sync_error(
                "KC_TRUST_CERT_CHAIN_INVALID",
                "sync head v3 is missing author_cert_id",
                serde_json::json!({ "snapshot_id": head.snapshot_id }),
            )
        })?;
        let author_chain_hash = head.author_chain_hash.as_deref().ok_or_else(|| {
            sync_error(
                "KC_TRUST_CERT_CHAIN_INVALID",
                "sync head v3 is missing author_chain_hash",
                serde_json::json!({ "snapshot_id": head.snapshot_id }),
            )
        })?;

        let expected_chain_hash = trust_identity::expected_cert_chain_hash(
            author_cert_id,
            author_device_id,
            author_fingerprint,
        );
        if expected_chain_hash != author_chain_hash {
            return Err(sync_error(
                "KC_TRUST_CERT_CHAIN_INVALID",
                "sync head v3 certificate chain hash mismatch",
                serde_json::json!({
                    "snapshot_id": head.snapshot_id,
                    "expected": expected_chain_hash,
                    "actual": author_chain_hash
                }),
            ));
        }

        let payload = sync_signature_payload(
            &head.snapshot_id,
            &head.manifest_hash,
            head.created_at_ms,
            author_device_id,
            author_fingerprint,
            author_cert_id,
            author_chain_hash,
        )?;
        let expected_signature = sign_sync_payload(&payload);
        if expected_signature != author_signature {
            return Err(sync_error(
                "KC_TRUST_SIGNATURE_INVALID",
                "sync head v3 signature mismatch",
                serde_json::json!({
                    "snapshot_id": head.snapshot_id,
                    "expected": expected_signature,
                    "actual": author_signature
                }),
            ));
        }
    }

    Ok(())
}

fn read_s3_lock(transport: &S3SyncTransport) -> AppResult<Option<SyncS3WriteLockV1>> {
    let Some(bytes) = transport.read_bytes(S3_LOCK_KEY)? else {
        return Ok(None);
    };
    serde_json::from_slice(&bytes).map(Some).map_err(|e| {
        sync_error(
            "KC_SYNC_TARGET_INVALID",
            "failed parsing sync write lock",
            serde_json::json!({
                "error": e.to_string(),
                "target": transport.target().display(),
                "key": S3_LOCK_KEY
            }),
        )
    })
}

fn acquire_s3_lock(
    transport: &S3SyncTransport,
    vault_id: &str,
    trust: &SyncTrustV1,
    now_ms: i64,
) -> AppResult<SyncS3WriteLockV1> {
    if let Some(lock) = read_s3_lock(transport)? {
        if lock.expires_at_ms > now_ms {
            return Err(sync_error(
                "KC_SYNC_LOCKED",
                "remote sync target is already locked",
                serde_json::json!({
                    "holder": lock.holder,
                    "expires_at_ms": lock.expires_at_ms,
                    "target": transport.target().display()
                }),
            ));
        }
        transport.delete_key(S3_LOCK_KEY)?;
    }

    let lock = SyncS3WriteLockV1 {
        schema_version: 1,
        holder: format!("{}:{}", vault_id, now_ms),
        vault_id: vault_id.to_string(),
        acquired_at_ms: now_ms,
        expires_at_ms: now_ms + S3_LOCK_TTL_MS,
        trust_fingerprint: trust.fingerprint.clone(),
    };
    let bytes = to_canonical_bytes(&serde_json::to_value(&lock).map_err(|e| {
        sync_error(
            "KC_SYNC_TARGET_INVALID",
            "failed serializing sync lock payload",
            serde_json::json!({ "error": e.to_string() }),
        )
    })?)?;

    let created = transport.write_bytes_if_absent(S3_LOCK_KEY, &bytes, "application/json")?;
    if !created {
        if let Some(existing) = read_s3_lock(transport)? {
            return Err(sync_error(
                "KC_SYNC_LOCKED",
                "remote sync target lock already exists",
                serde_json::json!({
                    "holder": existing.holder,
                    "expires_at_ms": existing.expires_at_ms,
                    "target": transport.target().display()
                }),
            ));
        }
        return Err(sync_error(
            "KC_SYNC_LOCKED",
            "remote sync target lock already exists",
            serde_json::json!({ "target": transport.target().display() }),
        ));
    }

    Ok(lock)
}

fn release_s3_lock(transport: &S3SyncTransport, holder: &str) -> AppResult<()> {
    let Some(existing) = read_s3_lock(transport)? else {
        return Ok(());
    };
    if existing.holder == holder {
        transport.delete_key(S3_LOCK_KEY)?;
    }
    Ok(())
}

fn with_s3_lock<T>(
    transport: &S3SyncTransport,
    vault_id: &str,
    trust: &SyncTrustV1,
    now_ms: i64,
    f: impl FnOnce() -> AppResult<T>,
) -> AppResult<T> {
    let lock = acquire_s3_lock(transport, vault_id, trust, now_ms)?;
    let result = f();
    let release_result = release_s3_lock(transport, &lock.holder);

    match (result, release_result) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(e)) => Err(e),
        (Err(e), _) => Err(e),
    }
}

pub fn sync_status(conn: &Connection, target_path: &Path) -> AppResult<SyncStatusV1> {
    ensure_sync_tables(conn)?;
    let remote_head = read_head(target_path)?;
    let seen_remote_snapshot_id = read_state(conn, "sync_remote_head_seen")?;
    let last_applied_manifest_hash = read_state(conn, "sync_last_applied_manifest_hash")?;

    Ok(SyncStatusV1 {
        target_path: target_path.display().to_string(),
        remote_head,
        seen_remote_snapshot_id,
        last_applied_manifest_hash,
    })
}

pub fn sync_status_target(conn: &Connection, target_uri: &str) -> AppResult<SyncStatusV1> {
    ensure_sync_tables(conn)?;
    let target = SyncTargetUri::parse(target_uri)?;
    let remote_head = match &target {
        SyncTargetUri::FilePath { path } => FsSyncTransport::new(Path::new(path)).read_head()?,
        SyncTargetUri::S3 { bucket, prefix } => {
            S3SyncTransport::new(bucket.clone(), prefix.clone()).read_head()?
        }
    };
    let seen_remote_snapshot_id = read_state(conn, "sync_remote_head_seen")?;
    let last_applied_manifest_hash = read_state(conn, "sync_last_applied_manifest_hash")?;
    Ok(SyncStatusV1 {
        target_path: target.display(),
        remote_head,
        seen_remote_snapshot_id,
        last_applied_manifest_hash,
    })
}

fn sync_merge_preview_file_target(
    conn: &Connection,
    vault_path: &Path,
    target_path: &Path,
    policy: Option<&str>,
    now_ms: i64,
) -> AppResult<SyncMergePreviewResultV1> {
    ensure_sync_tables(conn)?;
    let remote_head = read_head(target_path)?.ok_or_else(|| {
        sync_error(
            "KC_SYNC_MERGE_PRECONDITION_FAILED",
            "sync merge preview requires a remote head",
            serde_json::json!({ "target_path": target_path }),
        )
    })?;
    let seen_remote_snapshot_id = read_state(conn, "sync_remote_head_seen")?;
    let (local_bundle, _local_manifest_hash) = build_local_snapshot(vault_path, now_ms)?;
    let local_current = extract_change_set_from_bundle_dir(&local_bundle)?;

    let remote_snapshot_dir = target_path.join("snapshots").join(&remote_head.snapshot_id);
    if !remote_snapshot_dir.exists() {
        return Err(sync_error(
            "KC_SYNC_MERGE_PRECONDITION_FAILED",
            "sync merge preview remote snapshot is missing",
            serde_json::json!({
                "target_path": target_path,
                "snapshot_id": remote_head.snapshot_id,
                "path": remote_snapshot_dir
            }),
        ));
    }
    let remote_current = extract_change_set_from_bundle_dir(&remote_snapshot_dir)?;

    let base = if let Some(seen_snapshot_id) = seen_remote_snapshot_id.as_deref() {
        let seen_snapshot_dir = target_path.join("snapshots").join(seen_snapshot_id);
        if !seen_snapshot_dir.exists() {
            return Err(sync_error(
                "KC_SYNC_MERGE_PRECONDITION_FAILED",
                "sync merge preview base snapshot is missing",
                serde_json::json!({
                    "target_path": target_path,
                    "snapshot_id": seen_snapshot_id,
                    "path": seen_snapshot_dir
                }),
            ));
        }
        extract_change_set_from_bundle_dir(&seen_snapshot_dir)?
    } else {
        SyncMergeChangeSetV1::default()
    };

    let local_delta = delta_change_set(&local_current, &base);
    let remote_delta = delta_change_set(&remote_current, &base);
    let report = merge_preview_report_for_policy(&local_delta, &remote_delta, policy, now_ms)?;

    Ok(SyncMergePreviewResultV1 {
        target_path: target_path.display().to_string(),
        seen_remote_snapshot_id,
        remote_snapshot_id: remote_head.snapshot_id,
        report,
    })
}

fn sync_merge_preview_s3_target(
    conn: &Connection,
    vault_path: &Path,
    transport: S3SyncTransport,
    policy: Option<&str>,
    now_ms: i64,
) -> AppResult<SyncMergePreviewResultV1> {
    ensure_sync_tables(conn)?;
    let vault = vault_open(vault_path)?;
    let local_trust = derive_local_sync_trust(&vault, now_ms)?;
    let remote_head = transport.read_head()?.ok_or_else(|| {
        sync_error(
            "KC_SYNC_MERGE_PRECONDITION_FAILED",
            "sync merge preview requires a remote head",
            serde_json::json!({ "target": transport.target().display() }),
        )
    })?;
    ensure_remote_trust_matches(conn, Some(&remote_head), &local_trust)?;
    let seen_remote_snapshot_id = read_state(conn, "sync_remote_head_seen")?;

    let (local_bundle, _local_manifest_hash) = build_local_snapshot(vault_path, now_ms)?;
    let local_current = extract_change_set_from_bundle_dir(&local_bundle)?;
    let remote_current =
        extract_change_set_from_s3_snapshot(&transport, &remote_head.snapshot_id, now_ms)?;

    let base = if let Some(seen_snapshot_id) = seen_remote_snapshot_id.as_deref() {
        extract_change_set_from_s3_snapshot(&transport, seen_snapshot_id, now_ms)?
    } else {
        SyncMergeChangeSetV1::default()
    };

    let local_delta = delta_change_set(&local_current, &base);
    let remote_delta = delta_change_set(&remote_current, &base);
    let report = merge_preview_report_for_policy(&local_delta, &remote_delta, policy, now_ms)?;

    Ok(SyncMergePreviewResultV1 {
        target_path: transport.target().display(),
        seen_remote_snapshot_id,
        remote_snapshot_id: remote_head.snapshot_id,
        report,
    })
}

fn merge_preview_report_for_policy(
    local_delta: &SyncMergeChangeSetV1,
    remote_delta: &SyncMergeChangeSetV1,
    policy: Option<&str>,
    now_ms: i64,
) -> AppResult<SyncMergePreviewReportV1> {
    match policy {
        None | Some("conservative") => {
            merge_preview_conservative(local_delta, remote_delta, now_ms)
        }
        Some("conservative_plus_v2") => {
            let report = merge_preview_with_policy_v2(
                local_delta,
                remote_delta,
                &SyncMergeContextV2::default(),
                "conservative_plus_v2",
                now_ms,
            )?;
            Ok(report.into())
        }
        Some("conservative_plus_v3") => {
            let report = merge_preview_with_policy_v2(
                local_delta,
                remote_delta,
                &SyncMergeContextV2::default(),
                "conservative_plus_v3",
                now_ms,
            )?;
            Ok(report.into())
        }
        Some("conservative_plus_v4") => {
            let report = merge_preview_with_policy_v2(
                local_delta,
                remote_delta,
                &SyncMergeContextV2::default(),
                "conservative_plus_v4",
                now_ms,
            )?;
            Ok(report.into())
        }
        Some(other) => Err(sync_error(
            "KC_SYNC_MERGE_POLICY_UNSUPPORTED",
            "unsupported sync merge preview policy",
            serde_json::json!({
                "policy": other,
                "supported": [
                    "conservative",
                    "conservative_plus_v2",
                    "conservative_plus_v3",
                    "conservative_plus_v4"
                ]
            }),
        )),
    }
}

pub fn sync_merge_preview_target_with_policy(
    conn: &Connection,
    vault_path: &Path,
    target_uri: &str,
    policy: Option<&str>,
    now_ms: i64,
) -> AppResult<SyncMergePreviewResultV1> {
    match SyncTargetUri::parse(target_uri)? {
        SyncTargetUri::FilePath { path } => {
            sync_merge_preview_file_target(conn, vault_path, Path::new(&path), policy, now_ms)
        }
        SyncTargetUri::S3 { bucket, prefix } => sync_merge_preview_s3_target(
            conn,
            vault_path,
            S3SyncTransport::new(bucket, prefix),
            policy,
            now_ms,
        ),
    }
}

pub fn sync_merge_preview_target(
    conn: &Connection,
    vault_path: &Path,
    target_uri: &str,
    now_ms: i64,
) -> AppResult<SyncMergePreviewResultV1> {
    sync_merge_preview_target_with_policy(conn, vault_path, target_uri, None, now_ms)
}

pub fn sync_push(
    conn: &Connection,
    vault_path: &Path,
    target_path: &Path,
    now_ms: i64,
) -> AppResult<SyncPushResultV1> {
    ensure_sync_tables(conn)?;
    let vault = vault_open(vault_path)?;
    let (_snapshots, _conflicts) = ensure_target_layout(target_path)?;
    let remote_head = read_head(target_path)?;

    let seen_remote = read_state(conn, "sync_remote_head_seen")?;
    let last_applied_manifest = read_state(conn, "sync_last_applied_manifest_hash")?;

    let (local_bundle, local_manifest_hash) = build_local_snapshot(vault_path, now_ms)?;

    if should_conflict(
        remote_head.as_ref(),
        seen_remote.as_deref(),
        last_applied_manifest.as_deref(),
        &local_manifest_hash,
    ) {
        let conflict_path = create_conflict_artifact(
            target_path,
            &vault.vault_id,
            now_ms,
            &local_manifest_hash,
            remote_head.as_ref(),
            seen_remote,
            None,
        )?;
        return Err(sync_error(
            "KC_SYNC_CONFLICT",
            "remote and local changes diverged; conflict artifact emitted",
            serde_json::json!({ "conflict_artifact": conflict_path }),
        ));
    }

    let snapshot_id = snapshot_id_for_manifest(&local_manifest_hash, now_ms);
    let snapshot_dir = target_path.join("snapshots").join(&snapshot_id);
    if snapshot_dir.exists() {
        fs::remove_dir_all(&snapshot_dir).map_err(|e| {
            sync_error(
                "KC_SYNC_TARGET_INVALID",
                "failed replacing existing snapshot directory",
                serde_json::json!({ "error": e.to_string(), "path": snapshot_dir }),
            )
        })?;
    }
    fs::create_dir_all(&snapshot_dir).map_err(|e| {
        sync_error(
            "KC_SYNC_TARGET_INVALID",
            "failed creating snapshot directory",
            serde_json::json!({ "error": e.to_string(), "path": snapshot_dir }),
        )
    })?;
    copy_tree_sorted(&local_bundle, &snapshot_dir)?;

    let head = SyncHeadV1 {
        schema_version: 2,
        snapshot_id: snapshot_id.clone(),
        manifest_hash: local_manifest_hash.clone(),
        created_at_ms: now_ms,
        trust: None,
        author_device_id: None,
        author_fingerprint: None,
        author_signature: None,
        author_cert_id: None,
        author_chain_hash: None,
    };
    write_head(target_path, &head)?;

    write_state(conn, "sync_remote_head_seen", &snapshot_id, now_ms)?;
    write_state(
        conn,
        "sync_last_applied_manifest_hash",
        &local_manifest_hash,
        now_ms,
    )?;
    write_state(conn, "sync_last_applied_snapshot_id", &snapshot_id, now_ms)?;
    write_snapshot_log(
        conn,
        &snapshot_id,
        "push",
        now_ms,
        &format!("snapshots/{}", snapshot_id),
        &local_manifest_hash,
    )?;

    Ok(SyncPushResultV1 {
        snapshot_id,
        manifest_hash: local_manifest_hash,
        remote_head: head,
    })
}

fn sync_push_s3_target(
    conn: &Connection,
    vault_path: &Path,
    transport: S3SyncTransport,
    now_ms: i64,
) -> AppResult<SyncPushResultV1> {
    ensure_sync_tables(conn)?;
    let vault = vault_open(vault_path)?;
    let local_trust = derive_local_sync_trust(&vault, now_ms)?;
    let local_author = local_sync_author(conn)?;

    let seen_remote = read_state(conn, "sync_remote_head_seen")?;
    let last_applied_manifest = read_state(conn, "sync_last_applied_manifest_hash")?;

    let (zip_path, _bundle_dir, local_manifest_hash) =
        build_local_snapshot_zip(vault_path, now_ms)?;
    let remote_head = transport.read_head()?;
    ensure_remote_trust_matches(conn, remote_head.as_ref(), &local_trust)?;

    if should_conflict(
        remote_head.as_ref(),
        seen_remote.as_deref(),
        last_applied_manifest.as_deref(),
        &local_manifest_hash,
    ) {
        let conflict_key = create_conflict_artifact_s3(
            &transport,
            &vault.vault_id,
            now_ms,
            &local_manifest_hash,
            remote_head.as_ref(),
            seen_remote,
            Some(local_trust.fingerprint.clone()),
        )?;
        return Err(sync_error(
            "KC_SYNC_CONFLICT",
            "remote and local changes diverged; conflict artifact emitted",
            serde_json::json!({ "conflict_artifact": conflict_key, "target": transport.target().display() }),
        ));
    }

    with_s3_lock(&transport, &vault.vault_id, &local_trust, now_ms, || {
        let latest_remote_head = transport.read_head()?;
        ensure_remote_trust_matches(conn, latest_remote_head.as_ref(), &local_trust)?;

        if should_conflict(
            latest_remote_head.as_ref(),
            seen_remote.as_deref(),
            last_applied_manifest.as_deref(),
            &local_manifest_hash,
        ) {
            let conflict_key = create_conflict_artifact_s3(
                &transport,
                &vault.vault_id,
                now_ms,
                &local_manifest_hash,
                latest_remote_head.as_ref(),
                seen_remote.clone(),
                Some(local_trust.fingerprint.clone()),
            )?;
            return Err(sync_error(
                "KC_SYNC_CONFLICT",
                "remote and local changes diverged; conflict artifact emitted",
                serde_json::json!({ "conflict_artifact": conflict_key, "target": transport.target().display() }),
            ));
        }

        let snapshot_id = snapshot_id_for_manifest(&local_manifest_hash, now_ms);
        let snapshot_key = format!("snapshots/{}.zip", snapshot_id);
        let zip_bytes = fs::read(&zip_path).map_err(|e| {
            sync_error(
                "KC_SYNC_STATE_FAILED",
                "failed reading local snapshot zip for upload",
                serde_json::json!({ "error": e.to_string(), "path": zip_path }),
            )
        })?;
        transport.write_bytes(&snapshot_key, &zip_bytes, "application/zip")?;

        let head = SyncHeadV1 {
            schema_version: 3,
            snapshot_id: snapshot_id.clone(),
            manifest_hash: local_manifest_hash.clone(),
            created_at_ms: now_ms,
            trust: Some(local_trust.clone()),
            author_device_id: Some(local_author.device_id.clone()),
            author_fingerprint: Some(local_author.fingerprint.clone()),
            author_signature: Some(sign_sync_payload(&sync_signature_payload(
                &snapshot_id,
                &local_manifest_hash,
                now_ms,
                &local_author.device_id,
                &local_author.fingerprint,
                &local_author.cert_id,
                &local_author.chain_hash,
            )?)),
            author_cert_id: Some(local_author.cert_id.clone()),
            author_chain_hash: Some(local_author.chain_hash.clone()),
        };
        transport.write_head(&head)?;

        write_state(conn, "sync_remote_head_seen", &snapshot_id, now_ms)?;
        write_state(
            conn,
            "sync_last_applied_manifest_hash",
            &local_manifest_hash,
            now_ms,
        )?;
        write_state(conn, "sync_last_applied_snapshot_id", &snapshot_id, now_ms)?;
        write_snapshot_log(
            conn,
            &snapshot_id,
            "push",
            now_ms,
            &snapshot_key,
            &local_manifest_hash,
        )?;

        Ok(SyncPushResultV1 {
            snapshot_id,
            manifest_hash: local_manifest_hash,
            remote_head: head,
        })
    })
}

pub fn sync_push_target(
    conn: &Connection,
    vault_path: &Path,
    target_uri: &str,
    now_ms: i64,
) -> AppResult<SyncPushResultV1> {
    match SyncTargetUri::parse(target_uri)? {
        SyncTargetUri::FilePath { path } => sync_push(conn, vault_path, Path::new(&path), now_ms),
        SyncTargetUri::S3 { bucket, prefix } => sync_push_s3_target(
            conn,
            vault_path,
            S3SyncTransport::new(bucket, prefix),
            now_ms,
        ),
    }
}

fn sync_pull_with_mode(
    conn: &Connection,
    vault_path: &Path,
    target_path: &Path,
    now_ms: i64,
    auto_merge_mode: Option<SyncAutoMergeMode>,
) -> AppResult<SyncPullResultV1> {
    ensure_sync_tables(conn)?;
    let db_path = main_db_path(conn)?;
    let vault = vault_open(vault_path)?;
    let remote_head = read_head(target_path)?.ok_or_else(|| {
        sync_error(
            "KC_SYNC_TARGET_INVALID",
            "sync target has no head.json",
            serde_json::json!({ "target_path": target_path }),
        )
    })?;

    let seen_remote = read_state(conn, "sync_remote_head_seen")?;
    let last_applied_manifest = read_state(conn, "sync_last_applied_manifest_hash")?;

    let (_local_bundle, local_manifest_hash) = build_local_snapshot(vault_path, now_ms)?;

    if should_conflict(
        Some(&remote_head),
        seen_remote.as_deref(),
        last_applied_manifest.as_deref(),
        &local_manifest_hash,
    ) {
        match auto_merge_mode {
            Some(SyncAutoMergeMode::Conservative) => {
                let preview =
                    sync_merge_preview_file_target(conn, vault_path, target_path, None, now_ms)?;
                ensure_conservative_merge_safe(&preview.report)?;
            }
            Some(SyncAutoMergeMode::ConservativePlusV2) => {
                let preview =
                    sync_merge_preview_file_target(conn, vault_path, target_path, None, now_ms)?;
                let report_v2 = merge_preview_with_policy_v2(
                    &preview.report.local,
                    &preview.report.remote,
                    &SyncMergeContextV2::default(),
                    "conservative_plus_v2",
                    now_ms,
                )?;
                ensure_conservative_plus_v2_merge_safe(&report_v2)?;
            }
            Some(SyncAutoMergeMode::ConservativePlusV3) => {
                let preview =
                    sync_merge_preview_file_target(conn, vault_path, target_path, None, now_ms)?;
                let report_v3 = merge_preview_with_policy_v2(
                    &preview.report.local,
                    &preview.report.remote,
                    &SyncMergeContextV2::default(),
                    "conservative_plus_v3",
                    now_ms,
                )?;
                ensure_conservative_plus_v3_merge_safe(&report_v3)?;
            }
            Some(SyncAutoMergeMode::ConservativePlusV4) => {
                let preview =
                    sync_merge_preview_file_target(conn, vault_path, target_path, None, now_ms)?;
                let report_v4 = merge_preview_with_policy_v2(
                    &preview.report.local,
                    &preview.report.remote,
                    &SyncMergeContextV2::default(),
                    "conservative_plus_v4",
                    now_ms,
                )?;
                ensure_conservative_plus_v4_merge_safe(&report_v4)?;
            }
            None => {
                let conflict_path = create_conflict_artifact(
                    target_path,
                    &vault.vault_id,
                    now_ms,
                    &local_manifest_hash,
                    Some(&remote_head),
                    seen_remote,
                    None,
                )?;
                return Err(sync_error(
                    "KC_SYNC_CONFLICT",
                    "remote and local changes diverged; conflict artifact emitted",
                    serde_json::json!({ "conflict_artifact": conflict_path }),
                ));
            }
        }
    }

    let snapshot_dir = target_path.join("snapshots").join(&remote_head.snapshot_id);
    if !snapshot_dir.exists() {
        return Err(sync_error(
            "KC_SYNC_TARGET_INVALID",
            "remote snapshot directory missing for head",
            serde_json::json!({
                "snapshot_id": remote_head.snapshot_id,
                "path": snapshot_dir
            }),
        ));
    }

    apply_snapshot_to_vault(&snapshot_dir, vault_path)?;

    let post_conn = open_db(&db_path)?;
    write_state(
        &post_conn,
        "sync_remote_head_seen",
        &remote_head.snapshot_id,
        now_ms,
    )?;
    write_state(
        &post_conn,
        "sync_last_applied_manifest_hash",
        &remote_head.manifest_hash,
        now_ms,
    )?;
    write_state(
        &post_conn,
        "sync_last_applied_snapshot_id",
        &remote_head.snapshot_id,
        now_ms,
    )?;
    write_snapshot_log(
        &post_conn,
        &remote_head.snapshot_id,
        "pull",
        now_ms,
        &format!("snapshots/{}", remote_head.snapshot_id),
        &remote_head.manifest_hash,
    )?;

    Ok(SyncPullResultV1 {
        snapshot_id: remote_head.snapshot_id.clone(),
        manifest_hash: remote_head.manifest_hash.clone(),
        remote_head,
    })
}

pub fn sync_pull(
    conn: &Connection,
    vault_path: &Path,
    target_path: &Path,
    now_ms: i64,
) -> AppResult<SyncPullResultV1> {
    sync_pull_with_mode(conn, vault_path, target_path, now_ms, None)
}

fn sync_pull_s3_target(
    conn: &Connection,
    vault_path: &Path,
    transport: S3SyncTransport,
    now_ms: i64,
    auto_merge_mode: Option<SyncAutoMergeMode>,
) -> AppResult<SyncPullResultV1> {
    ensure_sync_tables(conn)?;
    let db_path = main_db_path(conn)?;
    let vault = vault_open(vault_path)?;
    let local_trust = derive_local_sync_trust(&vault, now_ms)?;

    let remote_head = transport.read_head()?.ok_or_else(|| {
        sync_error(
            "KC_SYNC_TARGET_INVALID",
            "sync target has no head.json",
            serde_json::json!({ "target": transport.target().display() }),
        )
    })?;
    ensure_remote_trust_matches(conn, Some(&remote_head), &local_trust)?;

    let seen_remote = read_state(conn, "sync_remote_head_seen")?;
    let last_applied_manifest = read_state(conn, "sync_last_applied_manifest_hash")?;

    let (_local_bundle, local_manifest_hash) = build_local_snapshot(vault_path, now_ms)?;

    if should_conflict(
        Some(&remote_head),
        seen_remote.as_deref(),
        last_applied_manifest.as_deref(),
        &local_manifest_hash,
    ) {
        match auto_merge_mode {
            Some(SyncAutoMergeMode::Conservative) => {
                let preview = sync_merge_preview_s3_target(
                    conn,
                    vault_path,
                    transport.clone(),
                    None,
                    now_ms,
                )?;
                ensure_conservative_merge_safe(&preview.report)?;
            }
            Some(SyncAutoMergeMode::ConservativePlusV2) => {
                let preview = sync_merge_preview_s3_target(
                    conn,
                    vault_path,
                    transport.clone(),
                    None,
                    now_ms,
                )?;
                let report_v2 = merge_preview_with_policy_v2(
                    &preview.report.local,
                    &preview.report.remote,
                    &SyncMergeContextV2::default(),
                    "conservative_plus_v2",
                    now_ms,
                )?;
                ensure_conservative_plus_v2_merge_safe(&report_v2)?;
            }
            Some(SyncAutoMergeMode::ConservativePlusV3) => {
                let preview = sync_merge_preview_s3_target(
                    conn,
                    vault_path,
                    transport.clone(),
                    None,
                    now_ms,
                )?;
                let report_v3 = merge_preview_with_policy_v2(
                    &preview.report.local,
                    &preview.report.remote,
                    &SyncMergeContextV2::default(),
                    "conservative_plus_v3",
                    now_ms,
                )?;
                ensure_conservative_plus_v3_merge_safe(&report_v3)?;
            }
            Some(SyncAutoMergeMode::ConservativePlusV4) => {
                let preview = sync_merge_preview_s3_target(
                    conn,
                    vault_path,
                    transport.clone(),
                    None,
                    now_ms,
                )?;
                let report_v4 = merge_preview_with_policy_v2(
                    &preview.report.local,
                    &preview.report.remote,
                    &SyncMergeContextV2::default(),
                    "conservative_plus_v4",
                    now_ms,
                )?;
                ensure_conservative_plus_v4_merge_safe(&report_v4)?;
            }
            None => {
                let conflict_key = create_conflict_artifact_s3(
                    &transport,
                    &vault.vault_id,
                    now_ms,
                    &local_manifest_hash,
                    Some(&remote_head),
                    seen_remote,
                    Some(local_trust.fingerprint.clone()),
                )?;
                return Err(sync_error(
                    "KC_SYNC_CONFLICT",
                    "remote and local changes diverged; conflict artifact emitted",
                    serde_json::json!({ "conflict_artifact": conflict_key, "target": transport.target().display() }),
                ));
            }
        }
    }

    with_s3_lock(&transport, &vault.vault_id, &local_trust, now_ms, || {
        let remote_head_locked = transport.read_head()?.ok_or_else(|| {
            sync_error(
                "KC_SYNC_TARGET_INVALID",
                "sync target has no head.json",
                serde_json::json!({ "target": transport.target().display() }),
            )
        })?;
        ensure_remote_trust_matches(conn, Some(&remote_head_locked), &local_trust)?;

        if should_conflict(
            Some(&remote_head_locked),
            seen_remote.as_deref(),
            last_applied_manifest.as_deref(),
            &local_manifest_hash,
        ) {
            match auto_merge_mode {
                Some(SyncAutoMergeMode::Conservative) => {
                    let preview = sync_merge_preview_s3_target(
                        conn,
                        vault_path,
                        transport.clone(),
                        None,
                        now_ms,
                    )?;
                    ensure_conservative_merge_safe(&preview.report)?;
                }
                Some(SyncAutoMergeMode::ConservativePlusV2) => {
                    let preview = sync_merge_preview_s3_target(
                        conn,
                        vault_path,
                        transport.clone(),
                        None,
                        now_ms,
                    )?;
                    let report_v2 = merge_preview_with_policy_v2(
                        &preview.report.local,
                        &preview.report.remote,
                        &SyncMergeContextV2::default(),
                        "conservative_plus_v2",
                        now_ms,
                    )?;
                    ensure_conservative_plus_v2_merge_safe(&report_v2)?;
                }
                Some(SyncAutoMergeMode::ConservativePlusV3) => {
                    let preview = sync_merge_preview_s3_target(
                        conn,
                        vault_path,
                        transport.clone(),
                        None,
                        now_ms,
                    )?;
                    let report_v3 = merge_preview_with_policy_v2(
                        &preview.report.local,
                        &preview.report.remote,
                        &SyncMergeContextV2::default(),
                        "conservative_plus_v3",
                        now_ms,
                    )?;
                    ensure_conservative_plus_v3_merge_safe(&report_v3)?;
                }
                Some(SyncAutoMergeMode::ConservativePlusV4) => {
                    let preview = sync_merge_preview_s3_target(
                        conn,
                        vault_path,
                        transport.clone(),
                        None,
                        now_ms,
                    )?;
                    let report_v4 = merge_preview_with_policy_v2(
                        &preview.report.local,
                        &preview.report.remote,
                        &SyncMergeContextV2::default(),
                        "conservative_plus_v4",
                        now_ms,
                    )?;
                    ensure_conservative_plus_v4_merge_safe(&report_v4)?;
                }
                None => {
                    let conflict_key = create_conflict_artifact_s3(
                        &transport,
                        &vault.vault_id,
                        now_ms,
                        &local_manifest_hash,
                        Some(&remote_head_locked),
                        seen_remote.clone(),
                        Some(local_trust.fingerprint.clone()),
                    )?;
                    return Err(sync_error(
                        "KC_SYNC_CONFLICT",
                        "remote and local changes diverged; conflict artifact emitted",
                        serde_json::json!({ "conflict_artifact": conflict_key, "target": transport.target().display() }),
                    ));
                }
            }
        }

        let snapshot_key = format!("snapshots/{}.zip", remote_head_locked.snapshot_id);
        let zip_bytes = transport.read_bytes(&snapshot_key)?.ok_or_else(|| {
            sync_error(
                "KC_SYNC_TARGET_INVALID",
                "remote snapshot zip is missing for sync head",
                serde_json::json!({
                    "snapshot_id": remote_head_locked.snapshot_id,
                    "key": snapshot_key,
                    "target": transport.target().display()
                }),
            )
        })?;

        let unpack_dir = std::env::temp_dir().join(format!(
            "kc_sync_pull_unpack_{}_{}_{}",
            std::process::id(),
            now_ms,
            next_sync_temp_suffix()
        ));
        if unpack_dir.exists() {
            fs::remove_dir_all(&unpack_dir).map_err(|e| {
                sync_error(
                    "KC_SYNC_APPLY_FAILED",
                    "failed clearing existing sync unpack directory",
                    serde_json::json!({ "error": e.to_string(), "path": unpack_dir }),
                )
            })?;
        }
        unpack_zip_snapshot_with_limits(&zip_bytes, &unpack_dir, Some(sync_snapshot_limits()))?;
        apply_snapshot_to_vault(&unpack_dir, vault_path)?;

        let post_conn = open_db(&db_path)?;
        write_state(
            &post_conn,
            "sync_remote_head_seen",
            &remote_head_locked.snapshot_id,
            now_ms,
        )?;
        write_state(
            &post_conn,
            "sync_last_applied_manifest_hash",
            &remote_head_locked.manifest_hash,
            now_ms,
        )?;
        write_state(
            &post_conn,
            "sync_last_applied_snapshot_id",
            &remote_head_locked.snapshot_id,
            now_ms,
        )?;
        write_snapshot_log(
            &post_conn,
            &remote_head_locked.snapshot_id,
            "pull",
            now_ms,
            &snapshot_key,
            &remote_head_locked.manifest_hash,
        )?;

        Ok(SyncPullResultV1 {
            snapshot_id: remote_head_locked.snapshot_id.clone(),
            manifest_hash: remote_head_locked.manifest_hash.clone(),
            remote_head: remote_head_locked,
        })
    })
}

pub fn sync_pull_target(
    conn: &Connection,
    vault_path: &Path,
    target_uri: &str,
    now_ms: i64,
) -> AppResult<SyncPullResultV1> {
    sync_pull_target_with_mode(conn, vault_path, target_uri, now_ms, None)
}

pub fn sync_pull_target_with_mode(
    conn: &Connection,
    vault_path: &Path,
    target_uri: &str,
    now_ms: i64,
    auto_merge_mode: Option<&str>,
) -> AppResult<SyncPullResultV1> {
    let mode = parse_auto_merge_mode(auto_merge_mode)?;
    match SyncTargetUri::parse(target_uri)? {
        SyncTargetUri::FilePath { path } => {
            sync_pull_with_mode(conn, vault_path, Path::new(&path), now_ms, mode)
        }
        SyncTargetUri::S3 { bucket, prefix } => sync_pull_s3_target(
            conn,
            vault_path,
            S3SyncTransport::new(bucket, prefix),
            now_ms,
            mode,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::{unpack_zip_snapshot, unpack_zip_snapshot_with_limits, SyncSnapshotResourceLimits};
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    fn zip_bytes(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut bytes = std::io::Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut bytes);
            for &(name, payload) in entries {
                writer
                    .start_file(
                        name,
                        SimpleFileOptions::default()
                            .compression_method(zip::CompressionMethod::Stored),
                    )
                    .expect("start file");
                writer.write_all(payload).expect("write zip entry");
            }
            writer.finish().expect("finish zip");
        }
        bytes.into_inner()
    }

    #[test]
    fn unpack_zip_snapshot_rejects_parent_traversal() {
        let root = tempfile::tempdir().expect("tempdir");
        let out = root.path().join("out");
        let bytes = zip_bytes(&[("../escape.txt", b"owned")]);

        let err = unpack_zip_snapshot(&bytes, &out).expect_err("path traversal must fail");
        assert_eq!(err.code, "KC_SYNC_TARGET_INVALID");
        assert!(!root.path().join("escape.txt").exists());
    }

    #[test]
    fn unpack_zip_snapshot_extracts_safe_entries() {
        let root = tempfile::tempdir().expect("tempdir");
        let out = root.path().join("out");
        let bytes = zip_bytes(&[
            ("manifest.json", b"{\"schema\":1}"),
            ("db/knowledge.sqlite", b"db"),
        ]);

        unpack_zip_snapshot(&bytes, &out).expect("safe zip should unpack");
        assert!(out.join("manifest.json").exists());
        assert!(out.join("db/knowledge.sqlite").exists());
    }

    #[test]
    fn unpack_zip_snapshot_limits_reject_generated_oversized_archive_without_writes() {
        let root = tempfile::tempdir().expect("tempdir");
        let out = root.path().join("out");
        let bytes = zip_bytes(&[("manifest.json", b"{\"schema\":1}")]);

        let err = unpack_zip_snapshot_with_limits(
            &bytes,
            &out,
            Some(SyncSnapshotResourceLimits {
                max_archive_bytes: 8,
                max_entries: 8,
                max_entry_bytes: 1024,
            }),
        )
        .expect_err("oversized archive should fail");

        assert_eq!(err.code, "KC_RESOURCE_LIMIT_EXCEEDED");
        assert!(!out.exists());
    }

    #[test]
    fn unpack_zip_snapshot_limits_reject_generated_entry_count_without_writes() {
        let root = tempfile::tempdir().expect("tempdir");
        let out = root.path().join("out");
        let bytes = zip_bytes(&[("manifest.json", b"{}"), ("db/knowledge.sqlite", b"db")]);

        let err = unpack_zip_snapshot_with_limits(
            &bytes,
            &out,
            Some(SyncSnapshotResourceLimits {
                max_archive_bytes: bytes.len() + 1,
                max_entries: 1,
                max_entry_bytes: 1024,
            }),
        )
        .expect_err("too many entries should fail");

        assert_eq!(err.code, "KC_RESOURCE_LIMIT_EXCEEDED");
        assert!(!out.join("manifest.json").exists());
        assert!(!out.join("db/knowledge.sqlite").exists());
    }
}
