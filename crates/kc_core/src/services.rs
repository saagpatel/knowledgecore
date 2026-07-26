use crate::app_error::AppResult;
use crate::types::{CanonicalHash, DocId, ObjectHash};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolchainIdentity {
    pub pdfium_identity: String,
    pub tesseract_identity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalTextArtifact {
    pub doc_id: DocId,
    pub canonical_bytes: Vec<u8>,
    pub canonical_hash: CanonicalHash,
    pub canonical_object_hash: ObjectHash,
    #[serde(default)]
    pub page_count: Option<u32>,
    pub extractor_name: String,
    pub extractor_version: String,
    pub extractor_flags_json: String,
    pub normalization_version: i64,
    pub toolchain_json: String,
}

#[derive(Debug, Clone)]
pub struct ExtractInput<'a> {
    pub doc_id: &'a DocId,
    pub bytes: &'a [u8],
    pub mime: &'a str,
    pub source_kind: &'a str,
}

pub trait ExtractService: Send + Sync {
    fn extract_canonical(&self, input: ExtractInput<'_>) -> AppResult<CanonicalTextArtifact>;
}
