use kc_core::services::{ExtractInput, ExtractService, ToolchainIdentity};
use kc_core::types::DocId;
use kc_extract::ocr::{ocr_pdf_via_images, should_run_ocr, OcrConfig};
use kc_extract::pdf::{
    extract_pdf_text, extract_pdf_text_with_limits, PdfResourceLimits, PdfiumConfig,
};
use kc_extract::DefaultExtractor;

#[test]
fn golden_pdf_adds_page_marker() {
    let pdf =
        extract_pdf_text(b"hello page", &PdfiumConfig { library_path: None }).expect("extract");
    assert!(pdf.text_with_page_markers.starts_with("[[PAGE:0001]]"));
}

#[test]
fn golden_pdf_ocr_trigger_threshold() {
    assert!(should_run_ocr(100, 0.5));
    assert!(should_run_ocr(1000, 0.05));
    assert!(!should_run_ocr(1000, 0.5));
}

#[test]
fn golden_pdf_extractor_hashes_canonical() {
    let extractor = DefaultExtractor::new(ToolchainIdentity {
        pdfium_identity: "pdfium:test".to_string(),
        tesseract_identity: "tesseract:test".to_string(),
    });

    let pdf_like_body = "a".repeat(900);
    let out = extractor
        .extract_canonical(ExtractInput {
            doc_id: &DocId(
                "blake3:3333333333333333333333333333333333333333333333333333333333333333"
                    .to_string(),
            ),
            bytes: pdf_like_body.as_bytes(),
            mime: "application/pdf",
            source_kind: "manuals",
        })
        .expect("extract");

    assert!(out.canonical_hash.0.starts_with("blake3:"));
    let toolchain: serde_json::Value =
        serde_json::from_str(&out.toolchain_json).expect("toolchain json");
    assert!(toolchain.get("pdfium").is_some());
    assert!(toolchain.get("tesseract").is_some());
    assert_eq!(
        toolchain
            .get("pdfium")
            .and_then(|x| x.get("backend"))
            .and_then(|x| x.as_str()),
        Some("pdfium-render")
    );
    assert!(toolchain
        .get("tesseract")
        .and_then(|x| x.get("traineddata_hashes"))
        .and_then(|x| x.as_array())
        .is_some());
    let flags: serde_json::Value =
        serde_json::from_str(&out.extractor_flags_json).expect("flags json");
    assert_eq!(
        flags.get("source_kind").and_then(|x| x.as_str()),
        Some("manuals")
    );
}

#[test]
fn golden_pdf_ocr_hard_fails_when_tesseract_missing() {
    let err = ocr_pdf_via_images(
        b"%PDF-1.4\n%",
        &OcrConfig {
            tesseract_cmd: Some("kc_missing_tesseract_cmd".to_string()),
            language: "eng".to_string(),
        },
    )
    .expect_err("missing tesseract command must hard-fail");

    assert_eq!(err.code, "KC_TESSERACT_UNAVAILABLE");
}

#[test]
fn pdf_resource_limits_reject_generated_oversized_input() {
    let err = extract_pdf_text_with_limits(
        b"generated pdf-like bytes",
        &PdfiumConfig { library_path: None },
        Some(PdfResourceLimits {
            max_input_bytes: 8,
            max_extracted_bytes: 1024,
        }),
    )
    .expect_err("oversized generated input should fail");

    assert_eq!(err.code, "KC_RESOURCE_LIMIT_EXCEEDED");
}

#[test]
fn pdf_resource_limits_reject_generated_oversized_extracted_text() {
    let err = extract_pdf_text_with_limits(
        b"generated extracted text body",
        &PdfiumConfig { library_path: None },
        Some(PdfResourceLimits {
            max_input_bytes: 1024,
            max_extracted_bytes: 8,
        }),
    )
    .expect_err("oversized generated extracted text should fail");

    assert_eq!(err.code, "KC_RESOURCE_LIMIT_EXCEEDED");
}
