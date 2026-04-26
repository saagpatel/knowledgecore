use crate::embedding::{Embedder, EmbeddingIdentity};
use arrow_array::{
    types::Float32Type, Array, FixedSizeListArray, Float32Array, Int64Array, RecordBatch,
    RecordBatchIterator, RecordBatchReader, StringArray,
};
use arrow_schema::{DataType, Field, Schema};
use futures::TryStreamExt;
use kc_core::app_error::{AppError, AppResult};
use kc_core::index_traits::{VectorCandidate, VectorIndex};
use kc_core::types::{ChunkId, DocId};
use lancedb::connect;
use lancedb::query::ExecutableQuery;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;

const TABLE_NAME: &str = "chunks_vectors_v1";
const IDENTITY_FILE: &str = "embedding_identity.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VectorRow {
    pub chunk_id: ChunkId,
    pub doc_id: DocId,
    pub ordinal: i64,
    pub text: String,
    pub vector: Vec<f32>,
}

pub struct LanceDbVectorIndex<E: Embedder> {
    embedder: E,
    db_root: PathBuf,
    rows: Vec<VectorRow>,
    identity: EmbeddingIdentity,
}

fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    let dot: f32 = a.iter().zip(b).map(|(x, y)| x * y).sum();
    let na: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let nb: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
    if na == 0.0 || nb == 0.0 {
        0.0
    } else {
        dot / (na * nb)
    }
}

fn to_db_root(path: &Path) -> PathBuf {
    if path.extension().is_some() {
        path.with_extension("lancedb")
    } else {
        path.to_path_buf()
    }
}

fn with_rt<T>(fut: impl std::future::Future<Output = Result<T, lancedb::Error>>) -> AppResult<T> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| {
            AppError::new(
                "KC_VECTOR_INDEX_INIT_FAILED",
                "vector",
                "failed creating tokio runtime for lancedb",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;

    rt.block_on(fut).map_err(|e| {
        AppError::new(
            "KC_VECTOR_INDEX_INIT_FAILED",
            "vector",
            "lancedb operation failed",
            false,
            serde_json::json!({ "error": e.to_string() }),
        )
    })
}

impl<E: Embedder> LanceDbVectorIndex<E> {
    pub fn open(embedder: E, db_path: impl AsRef<Path>) -> AppResult<Self> {
        let identity = embedder.identity();
        let db_root = to_db_root(db_path.as_ref());

        std::fs::create_dir_all(&db_root).map_err(|e| {
            AppError::new(
                "KC_VECTOR_INDEX_INIT_FAILED",
                "vector",
                "failed creating lancedb root directory",
                false,
                serde_json::json!({ "error": e.to_string(), "path": db_root }),
            )
        })?;

        let mut instance = Self {
            embedder,
            db_root,
            rows: Vec::new(),
            identity,
        };
        instance.load_identity()?;
        instance.load_rows()?;
        Ok(instance)
    }

    pub fn upsert_rows(&mut self, mut rows: Vec<VectorRow>) -> AppResult<()> {
        for row in &rows {
            if row.vector.len() != self.identity.dims {
                return Err(AppError::new(
                    "KC_VECTOR_INDEX_INIT_FAILED",
                    "vector",
                    "vector dimensions do not match embedding identity",
                    false,
                    serde_json::json!({
                        "chunk_id": row.chunk_id.0,
                        "expected_dims": self.identity.dims,
                        "actual_dims": row.vector.len(),
                    }),
                ));
            }
        }

        rows.sort_by(|a, b| {
            a.doc_id
                .0
                .cmp(&b.doc_id.0)
                .then(a.ordinal.cmp(&b.ordinal))
                .then(a.chunk_id.0.cmp(&b.chunk_id.0))
        });

        self.persist_rows(&rows)?;
        self.rows = rows;
        self.persist_identity()?;
        Ok(())
    }

    pub fn embedding_identity(&self) -> &EmbeddingIdentity {
        &self.identity
    }

    fn identity_path(&self) -> PathBuf {
        self.db_root.join(IDENTITY_FILE)
    }

    fn persist_identity(&self) -> AppResult<()> {
        let bytes = serde_json::to_vec_pretty(&self.identity).map_err(|e| {
            AppError::new(
                "KC_VECTOR_INDEX_INIT_FAILED",
                "vector",
                "failed serializing embedding identity",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;
        std::fs::write(self.identity_path(), bytes).map_err(|e| {
            AppError::new(
                "KC_VECTOR_INDEX_INIT_FAILED",
                "vector",
                "failed writing embedding identity",
                false,
                serde_json::json!({ "error": e.to_string(), "path": self.identity_path() }),
            )
        })
    }

    fn load_identity(&mut self) -> AppResult<()> {
        let path = self.identity_path();
        if !path.exists() {
            return Ok(());
        }
        let bytes = std::fs::read(&path).map_err(|e| {
            AppError::new(
                "KC_VECTOR_INDEX_INIT_FAILED",
                "vector",
                "failed reading embedding identity",
                false,
                serde_json::json!({ "error": e.to_string(), "path": path }),
            )
        })?;
        self.identity = serde_json::from_slice::<EmbeddingIdentity>(&bytes).map_err(|e| {
            AppError::new(
                "KC_VECTOR_INDEX_INIT_FAILED",
                "vector",
                "failed parsing embedding identity",
                false,
                serde_json::json!({ "error": e.to_string(), "path": path }),
            )
        })?;
        Ok(())
    }

    fn persist_rows(&self, rows: &[VectorRow]) -> AppResult<()> {
        let schema = Arc::new(Schema::new(vec![
            Field::new("chunk_id", DataType::Utf8, false),
            Field::new("doc_id", DataType::Utf8, false),
            Field::new("ordinal", DataType::Int64, false),
            Field::new("text", DataType::Utf8, false),
            Field::new(
                "vector",
                DataType::FixedSizeList(
                    Arc::new(Field::new("item", DataType::Float32, true)),
                    self.identity.dims as i32,
                ),
                false,
            ),
        ]));

        let chunk_ids = StringArray::from(
            rows.iter()
                .map(|r| r.chunk_id.0.clone())
                .collect::<Vec<_>>(),
        );
        let doc_ids =
            StringArray::from(rows.iter().map(|r| r.doc_id.0.clone()).collect::<Vec<_>>());
        let ordinals = Int64Array::from(rows.iter().map(|r| r.ordinal).collect::<Vec<_>>());
        let texts = StringArray::from(rows.iter().map(|r| r.text.clone()).collect::<Vec<_>>());
        let vectors = FixedSizeListArray::from_iter_primitive::<Float32Type, _, _>(
            rows.iter()
                .map(|r| Some(r.vector.iter().copied().map(Some).collect::<Vec<_>>())),
            self.identity.dims as i32,
        );

        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(chunk_ids),
                Arc::new(doc_ids),
                Arc::new(ordinals),
                Arc::new(texts),
                Arc::new(vectors),
            ],
        )
        .map_err(|e| {
            AppError::new(
                "KC_VECTOR_INDEX_INIT_FAILED",
                "vector",
                "failed building vector record batch",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;

        let batches: Box<dyn RecordBatchReader + Send> = Box::new(RecordBatchIterator::new(
            vec![Ok(batch)].into_iter(),
            schema,
        ));
        let db_uri = self.db_root.to_string_lossy().to_string();

        with_rt(async {
            let db = connect(&db_uri).execute().await?;
            let table_names = db.table_names().execute().await?;
            if table_names.iter().any(|n| n == TABLE_NAME) {
                db.drop_table(TABLE_NAME, &[]).await?;
            }
            db.create_table(TABLE_NAME, batches).execute().await?;
            Ok(())
        })
    }

    fn load_rows(&mut self) -> AppResult<()> {
        let db_uri = self.db_root.to_string_lossy().to_string();
        self.rows = with_rt(async {
            let db = connect(&db_uri).execute().await?;
            let table_names = db.table_names().execute().await?;
            if !table_names.iter().any(|n| n == TABLE_NAME) {
                return Ok(Vec::new());
            }

            let table = db.open_table(TABLE_NAME).execute().await?;
            let batches = table
                .query()
                .execute()
                .await?
                .try_collect::<Vec<_>>()
                .await?;
            let mut rows = Vec::new();

            for batch in batches {
                let chunk_ids = batch
                    .column_by_name("chunk_id")
                    .and_then(|c| c.as_any().downcast_ref::<StringArray>())
                    .ok_or_else(|| lancedb::Error::Runtime {
                        message: "chunk_id column missing or invalid".to_string(),
                    })?;
                let doc_ids = batch
                    .column_by_name("doc_id")
                    .and_then(|c| c.as_any().downcast_ref::<StringArray>())
                    .ok_or_else(|| lancedb::Error::Runtime {
                        message: "doc_id column missing or invalid".to_string(),
                    })?;
                let ordinals = batch
                    .column_by_name("ordinal")
                    .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
                    .ok_or_else(|| lancedb::Error::Runtime {
                        message: "ordinal column missing or invalid".to_string(),
                    })?;
                let texts = batch
                    .column_by_name("text")
                    .and_then(|c| c.as_any().downcast_ref::<StringArray>())
                    .ok_or_else(|| lancedb::Error::Runtime {
                        message: "text column missing or invalid".to_string(),
                    })?;
                let vectors = batch
                    .column_by_name("vector")
                    .and_then(|c| c.as_any().downcast_ref::<FixedSizeListArray>())
                    .ok_or_else(|| lancedb::Error::Runtime {
                        message: "vector column missing or invalid".to_string(),
                    })?;

                for idx in 0..batch.num_rows() {
                    let vector_values = vectors.value(idx);
                    let float_values = vector_values
                        .as_any()
                        .downcast_ref::<Float32Array>()
                        .ok_or_else(|| lancedb::Error::Runtime {
                            message: "vector values were not float32".to_string(),
                        })?;
                    let mut vector = Vec::with_capacity(float_values.len());
                    for j in 0..float_values.len() {
                        vector.push(if float_values.is_null(j) {
                            0.0
                        } else {
                            float_values.value(j)
                        });
                    }

                    rows.push(VectorRow {
                        chunk_id: ChunkId(chunk_ids.value(idx).to_string()),
                        doc_id: DocId(doc_ids.value(idx).to_string()),
                        ordinal: ordinals.value(idx),
                        text: texts.value(idx).to_string(),
                        vector,
                    });
                }
            }

            rows.sort_by(|a, b| {
                a.doc_id
                    .0
                    .cmp(&b.doc_id.0)
                    .then(a.ordinal.cmp(&b.ordinal))
                    .then(a.chunk_id.0.cmp(&b.chunk_id.0))
            });

            Ok(rows)
        })?;

        Ok(())
    }
}

impl<E: Embedder> VectorIndex for LanceDbVectorIndex<E> {
    fn rebuild_for_doc(&self, _doc_id: &DocId) -> AppResult<()> {
        Ok(())
    }

    fn query(&self, query: &str, limit: usize) -> AppResult<Vec<VectorCandidate>> {
        let vectors = self.embedder.embed(&[query.to_string()])?;
        let q = vectors.first().ok_or_else(|| {
            AppError::new(
                "KC_VECTOR_QUERY_FAILED",
                "vector",
                "embedder returned no query vector",
                false,
                serde_json::json!({}),
            )
        })?;

        let mut scored: Vec<(ChunkId, DocId, i64, f32)> = self
            .rows
            .iter()
            .map(|row| {
                (
                    row.chunk_id.clone(),
                    row.doc_id.clone(),
                    row.ordinal,
                    cosine_similarity(&row.vector, q),
                )
            })
            .collect();

        scored.sort_by(|a, b| {
            b.3.partial_cmp(&a.3)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(a.1 .0.cmp(&b.1 .0))
                .then(a.2.cmp(&b.2))
                .then(a.0 .0.cmp(&b.0 .0))
        });

        Ok(scored
            .into_iter()
            .take(limit)
            .enumerate()
            .map(|(idx, (chunk_id, _, _, _))| VectorCandidate {
                chunk_id,
                rank: idx as i64 + 1,
            })
            .collect())
    }
}
