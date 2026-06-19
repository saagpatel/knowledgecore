use crate::app_error::{AppError, AppResult};
use crate::events::append_event;
use crate::types::{DocId, ObjectHash};
use rusqlite::{params, Connection};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct IngestedDoc {
    pub doc_id: DocId,
    pub original_object_hash: ObjectHash,
    pub bytes: i64,
    pub mime: String,
    pub source_kind: String,
    pub effective_ts_ms: i64,
}

pub struct IngestBytesReq<'a> {
    pub bytes: &'a [u8],
    pub mime: &'a str,
    pub source_kind: &'a str,
    pub effective_ts_ms: i64,
    pub source_path: Option<&'a str>,
    pub now_ms: i64,
}

#[derive(Debug, Clone, Copy)]
pub struct IngestResourceLimits {
    pub max_bytes: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct ScanFolderResourceLimits {
    pub max_files: usize,
    pub max_depth: usize,
    pub max_bytes_per_file: usize,
}

fn resource_limit_error(category: &str, message: &str, details: serde_json::Value) -> AppError {
    AppError::new(
        "KC_RESOURCE_LIMIT_EXCEEDED",
        category,
        message,
        false,
        details,
    )
}

pub fn validate_ingest_bytes_limits(
    bytes_len: usize,
    limits: IngestResourceLimits,
) -> AppResult<()> {
    if bytes_len > limits.max_bytes {
        return Err(resource_limit_error(
            "ingest",
            "ingest payload exceeds configured byte limit",
            serde_json::json!({
                "bytes": bytes_len,
                "max_bytes": limits.max_bytes,
            }),
        ));
    }
    Ok(())
}

pub fn validate_scan_folder_files(
    scan_root: &Path,
    files: &[PathBuf],
    limits: ScanFolderResourceLimits,
) -> AppResult<()> {
    if files.len() > limits.max_files {
        return Err(resource_limit_error(
            "ingest",
            "scan-folder exceeds configured file-count limit",
            serde_json::json!({
                "files": files.len(),
                "max_files": limits.max_files,
                "scan_root": scan_root,
            }),
        ));
    }

    for file in files {
        let depth = file
            .strip_prefix(scan_root)
            .ok()
            .map(|rel| rel.components().count())
            .unwrap_or_else(|| file.components().count());
        if depth > limits.max_depth {
            return Err(resource_limit_error(
                "ingest",
                "scan-folder file exceeds configured traversal depth",
                serde_json::json!({
                    "path": file,
                    "depth": depth,
                    "max_depth": limits.max_depth,
                    "scan_root": scan_root,
                }),
            ));
        }

        let metadata = std::fs::metadata(file).map_err(|e| {
            AppError::new(
                "KC_INGEST_READ_FAILED",
                "ingest",
                "failed reading scan file metadata",
                false,
                serde_json::json!({ "error": e.to_string(), "path": file }),
            )
        })?;
        let bytes = metadata.len() as usize;
        if bytes > limits.max_bytes_per_file {
            return Err(resource_limit_error(
                "ingest",
                "scan-folder file exceeds configured byte limit",
                serde_json::json!({
                    "path": file,
                    "bytes": bytes,
                    "max_bytes_per_file": limits.max_bytes_per_file,
                }),
            ));
        }
    }

    Ok(())
}

pub fn ingest_bytes_with_limits(
    conn: &Connection,
    object_store: &crate::object_store::ObjectStore,
    req: IngestBytesReq<'_>,
    limits: IngestResourceLimits,
) -> AppResult<IngestedDoc> {
    validate_ingest_bytes_limits(req.bytes.len(), limits)?;
    ingest_bytes(conn, object_store, req)
}

pub fn ingest_bytes(
    conn: &Connection,
    object_store: &crate::object_store::ObjectStore,
    req: IngestBytesReq<'_>,
) -> AppResult<IngestedDoc> {
    let bytes = req.bytes;
    let mime = req.mime;
    let source_kind = req.source_kind;
    let effective_ts_ms = req.effective_ts_ms;
    let source_path = req.source_path;
    let now_ms = req.now_ms;

    let ingest_event = append_event(
        conn,
        now_ms,
        "ingest.bytes",
        &serde_json::json!({
            "mime": mime,
            "source_kind": source_kind,
            "source_path": source_path,
            "bytes": bytes.len()
        }),
    )?;

    let original_object_hash = object_store.put_bytes(conn, bytes, ingest_event.event_id)?;
    let doc_id = DocId(original_object_hash.0.clone());

    conn.execute(
        "INSERT OR IGNORE INTO docs (doc_id, original_object_hash, bytes, mime, source_kind, effective_ts_ms, ingested_event_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            doc_id.0,
            original_object_hash.0,
            bytes.len() as i64,
            mime,
            source_kind,
            effective_ts_ms,
            ingest_event.event_id
        ],
    )
    .map_err(|e| {
        AppError::new(
            "KC_DB_INTEGRITY_FAILED",
            "ingest",
            "failed to insert doc",
            false,
            serde_json::json!({ "error": e.to_string() }),
        )
    })?;

    if let Some(path) = source_path {
        conn.execute(
            "INSERT OR IGNORE INTO doc_sources (doc_id, source_path) VALUES (?1, ?2)",
            params![doc_id.0, path],
        )
        .map_err(|e| {
            AppError::new(
                "KC_DB_INTEGRITY_FAILED",
                "ingest",
                "failed to insert doc source",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;
    }

    let row = conn
        .query_row(
            "SELECT bytes, mime, source_kind, effective_ts_ms FROM docs WHERE doc_id=?1",
            params![doc_id.0],
            |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                ))
            },
        )
        .map_err(|e| {
            AppError::new(
                "KC_DB_INTEGRITY_FAILED",
                "ingest",
                "failed to load ingested doc",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;

    Ok(IngestedDoc {
        doc_id,
        original_object_hash,
        bytes: row.0,
        mime: row.1,
        source_kind: row.2,
        effective_ts_ms: row.3,
    })
}
