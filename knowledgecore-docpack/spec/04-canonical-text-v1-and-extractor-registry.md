# Canonical Text v1 and Extractor Registry

## Purpose
Defines canonical text normalization v1, marker formats, extraction provenance, OCR trigger metric, and toolchain registry fields.

## Invariants
- Canonical text is UTF-8 and stored as an object; ground truth for all downstream operations.
- Tier 1: marker lines included in canonical bytes/hashes.
- Tier 2: PDF/OCR deterministic within pinned toolchain; tool changes define boundary.
- PDF/OCR page, byte, and time/resource limits are policy boundaries; production default changes require explicit approval.

## Acceptance Tests
- Golden tests validate marker insertion and normalization.
- OCR triggers deterministically for scanned/no-text fixture; provenance recorded.
- Resource-limit tests must use generated PDFs/images and must not ingest private documents.

## Normalization v1 (assumption)
- Normalize line endings to `\n`.
- Unicode normalization NFC.
- Trim trailing whitespace per line.
- Ensure exactly one trailing newline.

## Marker formats (locked)
- PDF: `[[PAGE:0001]]` lines.
- Headings: `[[H1:Title]]`, `[[H2:Title]]`... lines.

## OCR trigger metric (v1, deterministic)
Trigger OCR if:
- extracted_len < 800 OR alnum_ratio < 0.10
where alnum_ratio counts ASCII [A-Za-z0-9] over non-marker extracted chars.

## Provenance fields (stored & exported)
- extractor_name, extractor_version, extractor_flags_json (canonical JSON)
- normalization_version
- toolchain_json (canonical JSON): pdfium identity; tesseract identity + traineddata hashes + params

## Error codes
- `KC_CANONICAL_EXTRACT_FAILED`
- `KC_PDFIUM_UNAVAILABLE`
- `KC_TESSERACT_UNAVAILABLE`
- `KC_OCR_FAILED`
