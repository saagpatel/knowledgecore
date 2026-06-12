use kc_core::app_error::{AppError, AppResult};
use kc_core::canonical::load_canonical_text;
use kc_core::db::open_db;
use kc_core::object_store::ObjectStore;
use kc_core::types::{ChunkId, DocId};
use kc_core::vault::{vault_open, vault_paths};
use kc_index::embedding::{Embedder, EmbeddingIdentity};
use kc_index::fts::{rebuild_rows, FtsRow};
use kc_index::vector::{LanceDbVectorIndex, VectorRow};
use std::path::Path;

struct DeterministicEmbedder;

impl Embedder for DeterministicEmbedder {
    fn identity(&self) -> EmbeddingIdentity {
        EmbeddingIdentity {
            model_id: "deterministic-v1".to_string(),
            model_hash: "blake3:deterministic-v1".to_string(),
            dims: 8,
            provider: "kc_cli".to_string(),
            provider_version: "1".to_string(),
            flags_json: serde_json::json!({ "algorithm": "byte-histogram-8" }).to_string(),
        }
    }

    fn embed(&self, texts: &[String]) -> AppResult<Vec<Vec<f32>>> {
        Ok(texts
            .iter()
            .map(|text| {
                let mut bins = [0f32; 8];
                for byte in text.bytes() {
                    let idx = (byte as usize) % 8;
                    bins[idx] += 1.0;
                }
                let norm = bins.iter().map(|x| x * x).sum::<f32>().sqrt();
                if norm > 0.0 {
                    bins.iter_mut().for_each(|x| *x /= norm);
                }
                bins.to_vec()
            })
            .collect())
    }
}

fn slice_chars(text: &str, start: i64, end: i64) -> String {
    text.chars()
        .skip(start.max(0) as usize)
        .take((end - start).max(0) as usize)
        .collect()
}

pub fn run_rebuild(vault_path: &str) -> AppResult<()> {
    let vault = vault_open(Path::new(vault_path))?;
    let paths = vault_paths(Path::new(vault_path));
    let conn = open_db(&Path::new(vault_path).join(vault.db.relative_path))?;
    let object_store = ObjectStore::new(paths.objects_dir.clone());

    let mut canonical_stmt = conn
        .prepare("SELECT doc_id FROM canonical_text ORDER BY doc_id ASC")
        .map_err(|e| {
            AppError::new(
                "KC_FTS_REBUILD_FAILED",
                "index",
                "failed to prepare canonical_text query",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;

    let doc_ids: Vec<String> = canonical_stmt
        .query_map([], |row| row.get(0))
        .map_err(|e| {
            AppError::new(
                "KC_FTS_REBUILD_FAILED",
                "index",
                "failed querying canonical docs",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?
        .filter_map(Result::ok)
        .collect();

    let mut fts_rows: Vec<FtsRow> = Vec::new();
    let mut vector_rows: Vec<VectorRow> = Vec::new();

    for doc_id in doc_ids {
        let canonical = String::from_utf8(load_canonical_text(
            &conn,
            &object_store,
            &DocId(doc_id.clone()),
        )?)
        .map_err(|e| {
            AppError::new(
                "KC_FTS_REBUILD_FAILED",
                "index",
                "canonical text is not utf8",
                false,
                serde_json::json!({ "error": e.to_string(), "doc_id": doc_id }),
            )
        })?;

        let mut chunk_stmt = conn
            .prepare(
                "SELECT chunk_id, ordinal, start_char, end_char
                 FROM chunks
                 WHERE doc_id=?1
                 ORDER BY ordinal ASC, chunk_id ASC",
            )
            .map_err(|e| {
                AppError::new(
                    "KC_FTS_REBUILD_FAILED",
                    "index",
                    "failed to prepare chunks query",
                    false,
                    serde_json::json!({ "error": e.to_string() }),
                )
            })?;

        let chunk_rows: Vec<(String, i64, i64, i64)> = chunk_stmt
            .query_map([doc_id.clone()], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .map_err(|e| {
                AppError::new(
                    "KC_FTS_REBUILD_FAILED",
                    "index",
                    "failed querying chunks",
                    false,
                    serde_json::json!({ "error": e.to_string() }),
                )
            })?
            .filter_map(Result::ok)
            .collect();

        if chunk_rows.is_empty() {
            let chunk_id = format!("{}:full", doc_id);
            let content = canonical.clone();
            fts_rows.push(FtsRow {
                chunk_id: chunk_id.clone(),
                doc_id: doc_id.clone(),
                ordinal: 0,
                content: content.clone(),
            });
            vector_rows.push(VectorRow {
                chunk_id: ChunkId(chunk_id),
                doc_id: DocId(doc_id.clone()),
                ordinal: 0,
                text: content,
                vector: Vec::new(),
            });
            continue;
        }

        for (chunk_id, ordinal, start, end) in chunk_rows {
            let content = slice_chars(&canonical, start, end);
            fts_rows.push(FtsRow {
                chunk_id: chunk_id.clone(),
                doc_id: doc_id.clone(),
                ordinal,
                content: content.clone(),
            });
            vector_rows.push(VectorRow {
                chunk_id: ChunkId(chunk_id),
                doc_id: DocId(doc_id.clone()),
                ordinal,
                text: content,
                vector: Vec::new(),
            });
        }
    }

    rebuild_rows(&conn, &fts_rows)?;

    let embedder = DeterministicEmbedder;
    let texts: Vec<String> = vector_rows.iter().map(|r| r.text.clone()).collect();
    let vectors = embedder.embed(&texts)?;
    for (row, vec) in vector_rows.iter_mut().zip(vectors) {
        row.vector = vec;
    }

    let vectors_path = paths.vectors_dir.join("lancedb-v1");
    let mut vector_index = LanceDbVectorIndex::open(embedder, vectors_path)?;
    vector_index.upsert_rows(vector_rows)?;

    println!("index rebuild completed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::run_rebuild;
    use kc_core::canonical::persist_canonical_text;
    use kc_core::db::open_db;
    use kc_core::hashing::blake3_hex_prefixed;
    use kc_core::ingest::{ingest_bytes, IngestBytesReq};
    use kc_core::object_store::ObjectStore;
    use kc_core::services::CanonicalTextArtifact;
    use kc_core::types::{CanonicalHash, ObjectHash};
    use kc_core::vault::vault_init;

    #[test]
    fn index_rebuild_populates_fts_and_vectors() {
        let root = tempfile::tempdir().expect("tempdir").keep();
        vault_init(&root, "demo", 1).expect("vault init");
        let conn = open_db(&root.join("db/knowledge.sqlite")).expect("open db");
        let store = ObjectStore::new(root.join("store/objects"));

        let ingested = ingest_bytes(
            &conn,
            &store,
            IngestBytesReq {
                bytes: b"doc bytes",
                mime: "text/plain",
                source_kind: "notes",
                effective_ts_ms: 1,
                source_path: None,
                now_ms: 1,
            },
        )
        .expect("ingest");
        let canonical = b"hello deterministic index".to_vec();
        let hash = blake3_hex_prefixed(&canonical);
        persist_canonical_text(
            &conn,
            &store,
            &CanonicalTextArtifact {
                doc_id: ingested.doc_id,
                canonical_bytes: canonical,
                canonical_hash: CanonicalHash(hash.clone()),
                canonical_object_hash: ObjectHash(hash),
                extractor_name: "test".to_string(),
                extractor_version: "1".to_string(),
                extractor_flags_json: "{}".to_string(),
                normalization_version: 1,
                toolchain_json: "{}".to_string(),
                page_count: None,
            },
            1,
        )
        .expect("persist canonical");

        run_rebuild(root.to_string_lossy().as_ref()).expect("rebuild");

        let fts_rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM chunks_fts", [], |row| row.get(0))
            .expect("count fts rows");
        assert!(fts_rows >= 1);
        assert!(root.join("index/vectors/lancedb-v1").exists());
    }
}
