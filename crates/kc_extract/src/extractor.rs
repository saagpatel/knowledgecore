use crate::html::canonicalize_html;
use crate::md::canonicalize_markdown;
use crate::normalize::normalize_text_v1;
use crate::ocr::{
    ocr_pdf_via_images_with_limits, should_run_ocr, tesseract_version, traineddata_hashes,
    OcrConfig, OcrResourceLimits,
};
use crate::pdf::{extract_pdf_text_with_limits, PdfResourceLimits, PdfiumConfig};
use kc_core::app_error::{AppError, AppResult};
use kc_core::canon_json::to_canonical_bytes;
use kc_core::hashing::blake3_hex_prefixed;
use kc_core::resource_limits::{OCR_MAX_PAGES, PDF_EXTRACTED_TEXT_MAX_BYTES, PDF_INPUT_MAX_BYTES};
use kc_core::services::{CanonicalTextArtifact, ExtractInput, ExtractService, ToolchainIdentity};
use kc_core::types::{CanonicalHash, ObjectHash};

pub struct DefaultExtractor {
    pub toolchain: ToolchainIdentity,
}

impl DefaultExtractor {
    pub fn new(toolchain: ToolchainIdentity) -> Self {
        Self { toolchain }
    }
}

impl ExtractService for DefaultExtractor {
    fn extract_canonical(&self, input: ExtractInput<'_>) -> AppResult<CanonicalTextArtifact> {
        let mut ocr_used = false;
        let mut ocr_status = "not_attempted".to_string();
        let ocr_language = "eng".to_string();
        let raw = match input.mime {
            "text/markdown" => {
                let text = String::from_utf8(input.bytes.to_vec()).map_err(|e| {
                    AppError::new(
                        "KC_CANONICAL_EXTRACT_FAILED",
                        "extract",
                        "markdown input is not utf8",
                        false,
                        serde_json::json!({ "error": e.to_string() }),
                    )
                })?;
                canonicalize_markdown(&text)
            }
            "text/html" => {
                let text = String::from_utf8(input.bytes.to_vec()).map_err(|e| {
                    AppError::new(
                        "KC_CANONICAL_EXTRACT_FAILED",
                        "extract",
                        "html input is not utf8",
                        false,
                        serde_json::json!({ "error": e.to_string() }),
                    )
                })?;
                canonicalize_html(&text)
            }
            "application/pdf" => {
                let pdf = extract_pdf_text_with_limits(
                    input.bytes,
                    &PdfiumConfig { library_path: None },
                    Some(PdfResourceLimits {
                        max_input_bytes: PDF_INPUT_MAX_BYTES,
                        max_extracted_bytes: PDF_EXTRACTED_TEXT_MAX_BYTES,
                    }),
                )?;
                if should_run_ocr(pdf.extracted_len, pdf.extracted_alnum_ratio) {
                    match ocr_pdf_via_images_with_limits(
                        input.bytes,
                        &OcrConfig {
                            tesseract_cmd: None,
                            language: ocr_language.clone(),
                        },
                        Some(OcrResourceLimits {
                            max_pages: OCR_MAX_PAGES,
                        }),
                    ) {
                        Ok(ocr_text) => {
                            ocr_used = true;
                            ocr_status = "used".to_string();
                            ocr_text
                        }
                        Err(err) => return Err(err),
                    }
                } else {
                    pdf.text_with_page_markers
                }
            }
            _ => String::from_utf8(input.bytes.to_vec()).map_err(|e| {
                AppError::new(
                    "KC_CANONICAL_EXTRACT_FAILED",
                    "extract",
                    "text input is not utf8",
                    false,
                    serde_json::json!({ "error": e.to_string() }),
                )
            })?,
        };

        let normalized = normalize_text_v1(&raw);
        let canonical_bytes = normalized.into_bytes();
        let hash = blake3_hex_prefixed(&canonical_bytes);
        let tesseract_cmd = "tesseract";
        let tesseract_version = tesseract_version(tesseract_cmd).unwrap_or_default();
        let trained_hashes = traineddata_hashes(&ocr_language);

        let toolchain_json = String::from_utf8(to_canonical_bytes(&serde_json::json!({
            "pdfium": {
                "identity": self.toolchain.pdfium_identity,
                "backend": "pdfium-render",
            },
            "tesseract": {
                "identity": self.toolchain.tesseract_identity,
                "version": tesseract_version,
                "language": ocr_language,
                "traineddata_hashes": trained_hashes,
                "params": {
                    "psm": 6
                },
            },
            "ocr_used": ocr_used,
            "ocr_status": ocr_status,
        }))?)
        .map_err(|e| AppError::internal(&format!("toolchain json encoding failed: {e}")))?;

        let extractor_flags_json = String::from_utf8(to_canonical_bytes(&serde_json::json!({
            "mime": input.mime,
            "source_kind": input.source_kind,
        }))?)
        .map_err(|e| AppError::internal(&format!("flags json encoding failed: {e}")))?;

        Ok(CanonicalTextArtifact {
            doc_id: input.doc_id.clone(),
            canonical_bytes,
            canonical_hash: CanonicalHash(hash.clone()),
            canonical_object_hash: ObjectHash(hash),
            page_count: None,
            extractor_name: "kc_extract.default".to_string(),
            extractor_version: "1".to_string(),
            extractor_flags_json,
            normalization_version: 1,
            toolchain_json,
        })
    }
}
