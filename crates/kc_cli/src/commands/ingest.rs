use kc_core::app_error::{AppError, AppResult};
use kc_core::db::open_db;
use kc_core::ingest::{ingest_bytes_with_limits, validate_scan_folder_files, IngestBytesReq};
use kc_core::object_store::ObjectStore;
use kc_core::resource_limits::{ingest_single_file_limits, scan_folder_limits};
use kc_core::vault::{vault_open, vault_paths};
use std::fs;
use std::path::{Path, PathBuf};

fn now_ms() -> i64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time before unix epoch");
    now.as_millis() as i64
}

fn effective_ts_ms(path: &Path, fallback_ms: i64) -> i64 {
    fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as i64)
        .unwrap_or(fallback_ms)
}

fn detect_mime(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|x| x.to_str())
        .map(|x| x.to_ascii_lowercase())
    {
        Some(ext) if ext == "md" || ext == "markdown" => "text/markdown",
        Some(ext) if ext == "html" || ext == "htm" => "text/html",
        Some(ext) if ext == "pdf" => "application/pdf",
        Some(ext) if ext == "txt" => "text/plain",
        _ => "application/octet-stream",
    }
}

fn ingest_one(vault_path: &Path, file_path: &Path, source_kind: &str) -> AppResult<()> {
    let opened = vault_open(vault_path)?;
    let paths = vault_paths(vault_path);
    let db = open_db(&vault_path.join(opened.db.relative_path))?;
    let store = ObjectStore::new(paths.objects_dir);

    let bytes = fs::read(file_path).map_err(|e| {
        AppError::new(
            "KC_INGEST_READ_FAILED",
            "ingest",
            "failed reading file bytes",
            false,
            serde_json::json!({ "error": e.to_string(), "path": file_path }),
        )
    })?;

    let now = now_ms();
    let doc = ingest_bytes_with_limits(
        &db,
        &store,
        IngestBytesReq {
            bytes: &bytes,
            mime: detect_mime(file_path),
            source_kind,
            effective_ts_ms: effective_ts_ms(file_path, now),
            source_path: file_path.to_str(),
            now_ms: now,
        },
        ingest_single_file_limits(),
    )?;

    println!("ingested {} -> {}", file_path.display(), doc.doc_id.0);
    Ok(())
}

pub fn ingest_scan_folder(vault_path: &str, scan_root: &str, source_kind: &str) -> AppResult<()> {
    let scan_root_path = Path::new(scan_root);
    let mut files: Vec<PathBuf> = walkdir::WalkDir::new(scan_root_path)
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
        .collect();

    files.sort();
    validate_scan_folder_files(scan_root_path, &files, scan_folder_limits())?;
    for file in files {
        ingest_one(Path::new(vault_path), &file, source_kind)?;
    }
    Ok(())
}

pub fn ingest_inbox_once(vault_path: &str, file_path: &str, source_kind: &str) -> AppResult<()> {
    let file = PathBuf::from(file_path);
    ingest_one(Path::new(vault_path), &file, source_kind)?;

    let opened = vault_open(Path::new(vault_path))?;
    let db = open_db(&Path::new(vault_path).join(opened.db.relative_path))?;
    let doc_id: String = db
        .query_row(
            "SELECT doc_id FROM doc_sources WHERE source_path=?1 ORDER BY rowid DESC LIMIT 1",
            [file.to_string_lossy().to_string()],
            |r| r.get(0),
        )
        .map_err(|e| {
            AppError::new(
                "KC_DB_INTEGRITY_FAILED",
                "ingest",
                "failed to resolve doc_id for inbox move",
                false,
                serde_json::json!({ "error": e.to_string(), "path": file }),
            )
        })?;

    let stem = file.file_stem().and_then(|s| s.to_str()).unwrap_or("file");
    let ext = file.extension().and_then(|s| s.to_str()).unwrap_or("");
    let suffix = doc_id.chars().skip(7).take(8).collect::<String>();
    let mut target = Path::new(vault_path)
        .join("Inbox/processed")
        .join(format!("{}__{}", stem, suffix));
    if !ext.is_empty() {
        target.set_extension(ext);
    }

    fs::rename(&file, &target).map_err(|e| {
        AppError::new(
            "KC_INBOX_MOVE_FAILED",
            "ingest",
            "failed to move inbox file into processed",
            false,
            serde_json::json!({ "error": e.to_string(), "from": file, "to": target }),
        )
    })?;

    println!("moved {} -> {}", file.display(), target.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::ingest_scan_folder;
    use kc_core::db::open_db;
    use kc_core::resource_limits::SCAN_FOLDER_MAX_DEPTH;
    use kc_core::vault::vault_init;

    #[test]
    fn cli_scan_folder_resource_limit_rejects_deep_generated_tree_before_ingesting() {
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

        let err = ingest_scan_folder(
            &vault_path.to_string_lossy(),
            &scan_root.to_string_lossy(),
            "generated-fixture",
        )
        .expect_err("deep generated scan tree should fail");
        assert_eq!(err.code, "KC_RESOURCE_LIMIT_EXCEEDED");

        let conn = open_db(&vault_path.join("db/knowledge.sqlite")).expect("open db");
        let docs_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM docs", [], |r| r.get(0))
            .expect("docs count");
        assert_eq!(docs_count, 0);
    }
}
