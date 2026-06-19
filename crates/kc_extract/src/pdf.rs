use crate::markers::page_marker;
use kc_core::app_error::{AppError, AppResult};
use pdfium_render::prelude::*;

pub struct PdfiumConfig {
    pub library_path: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PdfExtractOutput {
    pub text_with_page_markers: String,
    pub extracted_len: usize,
    pub extracted_alnum_ratio: f64,
}

#[derive(Debug, Clone, Copy)]
pub struct PdfResourceLimits {
    pub max_input_bytes: usize,
    pub max_extracted_bytes: usize,
}

fn enforce_pdf_input_limit(pdf_bytes: &[u8], limits: PdfResourceLimits) -> AppResult<()> {
    if pdf_bytes.len() > limits.max_input_bytes {
        return Err(AppError::new(
            "KC_RESOURCE_LIMIT_EXCEEDED",
            "extract",
            "pdf input exceeds configured byte limit",
            false,
            serde_json::json!({
                "bytes": pdf_bytes.len(),
                "max_input_bytes": limits.max_input_bytes,
            }),
        ));
    }
    Ok(())
}

fn enforce_pdf_output_limit(text_len: usize, limits: PdfResourceLimits) -> AppResult<()> {
    if text_len > limits.max_extracted_bytes {
        return Err(AppError::new(
            "KC_RESOURCE_LIMIT_EXCEEDED",
            "extract",
            "pdf extracted text exceeds configured byte limit",
            false,
            serde_json::json!({
                "bytes": text_len,
                "max_extracted_bytes": limits.max_extracted_bytes,
            }),
        ));
    }
    Ok(())
}

fn alnum_ratio(content: &str) -> f64 {
    let mut total = 0usize;
    let mut alnum = 0usize;
    for ch in content.chars() {
        if ch == '[' || ch == ']' {
            continue;
        }
        total += 1;
        if ch.is_ascii_alphanumeric() {
            alnum += 1;
        }
    }
    if total == 0 {
        return 0.0;
    }
    alnum as f64 / total as f64
}

fn bind_pdfium(cfg: &PdfiumConfig) -> AppResult<Pdfium> {
    let bindings = match &cfg.library_path {
        Some(path) => Pdfium::bind_to_library(path),
        None => Pdfium::bind_to_system_library(),
    }
    .map_err(|e| {
        AppError::new(
            "KC_PDFIUM_UNAVAILABLE",
            "extract",
            "pdfium library is unavailable",
            true,
            serde_json::json!({
                "error": e.to_string(),
                "library_path": cfg.library_path,
            }),
        )
    })?;

    Ok(Pdfium::new(bindings))
}

fn extract_pdf_via_pdfium(pdf_bytes: &[u8], cfg: &PdfiumConfig) -> AppResult<String> {
    let pdfium = bind_pdfium(cfg)?;
    let doc = pdfium
        .load_pdf_from_byte_vec(pdf_bytes.to_vec(), None)
        .map_err(|e| {
            AppError::new(
                "KC_CANONICAL_EXTRACT_FAILED",
                "extract",
                "failed opening pdf document",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;

    let mut output = String::new();
    for (idx, page) in doc.pages().iter().enumerate() {
        let page_text = page
            .text()
            .map_err(|e| {
                AppError::new(
                    "KC_CANONICAL_EXTRACT_FAILED",
                    "extract",
                    "failed extracting page text",
                    false,
                    serde_json::json!({ "error": e.to_string(), "page": idx + 1 }),
                )
            })?
            .all()
            .trim()
            .to_string();

        if !output.is_empty() {
            output.push('\n');
        }
        output.push_str(&page_marker(idx + 1));
        if !page_text.is_empty() {
            output.push('\n');
            output.push_str(&page_text);
        }
    }

    if output.is_empty() {
        output = format!("{}\n", page_marker(1));
    }

    Ok(output)
}

pub fn extract_pdf_text(pdf_bytes: &[u8], cfg: &PdfiumConfig) -> AppResult<PdfExtractOutput> {
    extract_pdf_text_with_limits(pdf_bytes, cfg, None)
}

pub fn extract_pdf_text_with_limits(
    pdf_bytes: &[u8],
    cfg: &PdfiumConfig,
    limits: Option<PdfResourceLimits>,
) -> AppResult<PdfExtractOutput> {
    if let Some(limits) = limits {
        enforce_pdf_input_limit(pdf_bytes, limits)?;
    }

    let text = if pdf_bytes.starts_with(b"%PDF") {
        extract_pdf_via_pdfium(pdf_bytes, cfg)?
    } else {
        let decoded = String::from_utf8(pdf_bytes.to_vec()).map_err(|e| {
            AppError::new(
                "KC_CANONICAL_EXTRACT_FAILED",
                "extract",
                "pdf bytes could not be decoded as utf8",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;
        format!("{}\n{}", page_marker(1), decoded)
    };

    let ratio = alnum_ratio(&text);
    if let Some(limits) = limits {
        enforce_pdf_output_limit(text.len(), limits)?;
    }

    Ok(PdfExtractOutput {
        extracted_len: text.len(),
        extracted_alnum_ratio: ratio,
        text_with_page_markers: text,
    })
}
