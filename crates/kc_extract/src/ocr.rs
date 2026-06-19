use crate::markers::page_marker;
use kc_core::app_error::{AppError, AppResult};
use kc_core::hashing::blake3_hex_prefixed;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

pub struct OcrConfig {
    pub tesseract_cmd: Option<String>,
    pub language: String,
}

#[derive(Debug, Clone, Copy)]
pub struct OcrResourceLimits {
    pub max_pages: usize,
}

pub fn should_run_ocr(extracted_len: usize, alnum_ratio: f64) -> bool {
    extracted_len < 800 || alnum_ratio < 0.10
}

pub fn validate_ocr_page_count(page_count: usize, limits: OcrResourceLimits) -> AppResult<()> {
    if page_count > limits.max_pages {
        return Err(AppError::new(
            "KC_RESOURCE_LIMIT_EXCEEDED",
            "extract",
            "ocr page count exceeds configured limit",
            false,
            serde_json::json!({
                "pages": page_count,
                "max_pages": limits.max_pages,
            }),
        ));
    }
    Ok(())
}

pub fn tesseract_version(tesseract_cmd: &str) -> AppResult<String> {
    let output = Command::new(tesseract_cmd)
        .arg("--version")
        .output()
        .map_err(|e| {
            AppError::new(
                "KC_TESSERACT_UNAVAILABLE",
                "extract",
                "tesseract is unavailable",
                true,
                serde_json::json!({ "error": e.to_string(), "command": tesseract_cmd }),
            )
        })?;

    if !output.status.success() {
        return Err(AppError::new(
            "KC_TESSERACT_UNAVAILABLE",
            "extract",
            "tesseract command failed while checking version",
            true,
            serde_json::json!({
                "status": output.status.code(),
                "stderr": String::from_utf8_lossy(&output.stderr).to_string(),
            }),
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .next()
        .unwrap_or_default()
        .to_string())
}

pub fn traineddata_hashes(language: &str) -> Vec<String> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(prefix) = std::env::var("TESSDATA_PREFIX") {
        candidates.push(PathBuf::from(prefix).join(format!("{language}.traineddata")));
    }
    candidates.push(PathBuf::from(format!(
        "/usr/share/tesseract-ocr/5/tessdata/{language}.traineddata"
    )));
    candidates.push(PathBuf::from(format!(
        "/usr/local/share/tessdata/{language}.traineddata"
    )));

    let mut hashes: Vec<String> = candidates
        .into_iter()
        .filter_map(|path| fs::read(path).ok())
        .map(|bytes| blake3_hex_prefixed(&bytes))
        .collect();

    hashes.sort();
    hashes.dedup();
    hashes
}

pub fn ocr_pdf_via_images(pdf_bytes: &[u8], ocr_cfg: &OcrConfig) -> AppResult<String> {
    ocr_pdf_via_images_with_limits(pdf_bytes, ocr_cfg, None)
}

pub fn ocr_pdf_via_images_with_limits(
    pdf_bytes: &[u8],
    ocr_cfg: &OcrConfig,
    limits: Option<OcrResourceLimits>,
) -> AppResult<String> {
    if let Ok(fake) = std::env::var("KC_OCR_FAKE_TEXT") {
        if !fake.is_empty() {
            if let (Some(limits), Ok(fake_pages)) =
                (limits, std::env::var("KC_OCR_FAKE_PAGE_COUNT"))
            {
                if let Ok(fake_pages) = fake_pages.parse::<usize>() {
                    validate_ocr_page_count(fake_pages, limits)?;
                }
            }
            return Ok(fake);
        }
    }

    let tesseract_cmd = ocr_cfg.tesseract_cmd.as_deref().unwrap_or("tesseract");
    let _ = tesseract_version(tesseract_cmd)?;

    let dir = tempfile::tempdir().map_err(|e| {
        AppError::new(
            "KC_OCR_FAILED",
            "extract",
            "failed creating temporary directory for ocr",
            false,
            serde_json::json!({ "error": e.to_string() }),
        )
    })?;
    let input_pdf = dir.path().join("ocr.pdf");
    fs::write(&input_pdf, pdf_bytes).map_err(|e| {
        AppError::new(
            "KC_OCR_FAILED",
            "extract",
            "failed writing temporary pdf for ocr",
            false,
            serde_json::json!({ "error": e.to_string() }),
        )
    })?;

    // Render PDF pages to images with pdftoppm, then OCR each page deterministically.
    let prefix = dir.path().join("page");
    let render = Command::new("pdftoppm")
        .arg("-r")
        .arg("150")
        .arg("-png")
        .arg(&input_pdf)
        .arg(&prefix)
        .output();

    if let Err(e) = render {
        return Err(AppError::new(
            "KC_PDFIUM_UNAVAILABLE",
            "extract",
            "pdftoppm/PDF backend is unavailable for OCR",
            true,
            serde_json::json!({ "error": e.to_string() }),
        ));
    }
    let render = render.expect("checked err above");
    if !render.status.success() {
        return Err(AppError::new(
            "KC_OCR_FAILED",
            "extract",
            "failed converting pdf pages for OCR",
            false,
            serde_json::json!({
                "status": render.status.code(),
                "stderr": String::from_utf8_lossy(&render.stderr).to_string(),
            }),
        ));
    }

    let mut pages: Vec<_> = fs::read_dir(dir.path())
        .map_err(|e| {
            AppError::new(
                "KC_OCR_FAILED",
                "extract",
                "failed listing ocr pages",
                false,
                serde_json::json!({ "error": e.to_string() }),
            )
        })?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("png"))
        .collect();
    pages.sort();
    if let Some(limits) = limits {
        validate_ocr_page_count(pages.len(), limits)?;
    }

    let mut text = String::new();
    for (idx, page) in pages.into_iter().enumerate() {
        let out = Command::new(tesseract_cmd)
            .arg(&page)
            .arg("stdout")
            .arg("-l")
            .arg(&ocr_cfg.language)
            .arg("--psm")
            .arg("6")
            .output()
            .map_err(|e| {
                AppError::new(
                    "KC_TESSERACT_UNAVAILABLE",
                    "extract",
                    "failed running tesseract",
                    true,
                    serde_json::json!({ "error": e.to_string() }),
                )
            })?;
        if !out.status.success() {
            return Err(AppError::new(
                "KC_OCR_FAILED",
                "extract",
                "tesseract OCR command failed",
                false,
                serde_json::json!({
                    "status": out.status.code(),
                    "stderr": String::from_utf8_lossy(&out.stderr).to_string(),
                }),
            ));
        }
        let page_text = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !text.is_empty() {
            text.push('\n');
        }
        text.push_str(&page_marker(idx + 1));
        if !page_text.is_empty() {
            text.push('\n');
            text.push_str(&page_text);
        }
    }

    if text.trim().is_empty() {
        return Err(AppError::new(
            "KC_OCR_FAILED",
            "extract",
            "ocr produced empty output",
            false,
            serde_json::json!({}),
        ));
    }

    Ok(text)
}
