# Production Resource Limits Decision - 2026-06-19

## Purpose
Define the approved production resource-limit defaults and wiring points for KnowledgeCore. The first enforcement slice is now wired at CLI/RPC boundaries using generated-fixture tests and without changing vault formats, migrations, cloud behavior, or private-data ingest.

## Verified Current Inputs
- Opt-in `KC_RESOURCE_LIMIT_EXCEEDED` helpers and generated-fixture tests exist for ingest bytes, sync snapshot zip archive/entry limits, PDF input/extracted-text byte limits, OCR page-count limits, and vector batch/text limits.
- CLI scan-folder and inbox ingest now pass approved defaults for byte, file-count, depth, and no-symlink-following behavior.
- Tauri ingest RPC core service now passes approved defaults for scan-folder and inbox ingest.
- S3 sync pull now passes approved zip archive/entry limits before snapshot extraction.
- CLI index rebuild now passes approved vector row/text limits before LanceDB persistence.
- Default PDF extraction now passes approved input/extracted-text byte guards before canonical persistence.
- Default OCR extraction now passes approved page-count guards after PDF-to-image rendering and before Tesseract OCR.
- Filesystem snapshot directory apply now preflights approved entry-count and per-entry byte limits before replacing vault paths.

## Approved Defaults
These values are intentionally conservative for a local-first desktop vault and should be adjusted only through explicit approval.

| Surface | Proposed default | Rationale |
|---|---:|---|
| Ingest single file | 100 MiB | Prevents accidental huge binary ingest while allowing large PDFs/manuals. |
| Scan-folder file count | 10,000 files | Bounds accidental broad-folder scans. |
| Scan-folder traversal depth | 12 levels | Allows nested project folders while catching runaway trees. |
| Symlink traversal | disabled | Avoids escaping selected roots and recursive link cycles. |
| PDF input | 100 MiB | Matches single-file ingest ceiling. |
| PDF extracted text | 25 MiB | Prevents extraction/OCR blowups before canonical persistence. |
| OCR pages | 100 pages | Keeps OCR bounded before Tesseract page processing. |
| Sync snapshot archive | 2 GiB | Allows realistic local vault snapshot movement while bounding decompression work. |
| Sync snapshot entries | 250,000 entries | Bounds zip traversal and extraction loops. |
| Sync snapshot entry | 250 MiB | Prevents single-entry extraction blowups. |
| Vector rebuild rows per batch | 100,000 rows | Bounds LanceDB batch construction. |
| Vector row text | 1 MiB | Prevents pathological chunk/canonical text rows entering vector persistence. |

## Wiring State
1. Done: single repo-owned defaults live in `kc_core::resource_limits`.
2. Done: helper APIs remain opt-in internally, with defaults passed from selected production boundaries.
3. Done: CLI ingest:
   - `scan-folder`: enforces file size, file count, depth, and no symlink following.
   - `inbox-once`: enforces single-file byte limit.
4. Done: Tauri/core RPC ingest service:
   - `ingest_scan_folder`: enforces the same scan-folder defaults.
   - `ingest_inbox_start`: enforces single-file byte limit.
5. Done: Extraction:
   - `DefaultExtractor` now enforces approved PDF input and extracted-text byte limits.
   - `DefaultExtractor` now enforces approved OCR page-count limits after PDF-to-image rendering and before Tesseract OCR.
   - retain unrestricted helpers for existing deterministic tests unless tests explicitly opt into limits.
6. Done: Sync:
   - S3 pull snapshot extraction routes through the existing opt-in zip limit helper.
   - filesystem snapshot directory apply preflights entry-count and per-entry byte limits before replacing vault paths.
   - keep path traversal rejection as a separate invariant.
7. Done: Index:
   - CLI index rebuild passes vector row/text limits before LanceDB persistence.
8. UI:
   - branch on `KC_RESOURCE_LIMIT_EXCEEDED` by code only and show the existing structured error path; do not add bespoke UI business logic.

## Acceptance Tests
- CLI scan-folder rejects generated temp trees over depth limits and does not ingest partial docs.
- CLI inbox-once rejects generated oversized files before move/write.
- Tauri/core RPC scan/inbox tests return `KC_RESOURCE_LIMIT_EXCEEDED` for generated oversized fixtures.
- S3 sync pull rejects generated oversized archive/entry-count/entry-size fixtures before extraction writes.
- Filesystem snapshot directory preflight rejects generated oversized entries before vault apply writes.
- OCR page-count validation rejects generated oversized page counts before Tesseract OCR.
- Index rebuild rejects generated oversized vector batches/text rows before LanceDB writes.
- Existing unrestricted unit helpers remain available for deterministic fixture tests.

## Approval Gate
Any further production limit expansion or default-value change requires explicit approval because it changes accepted input behavior.

## Stop Conditions
- Any broad local path scan during testing.
- Any private document ingest.
- Any vault format or schema change.
- Any cloud/background sync behavior change.
- Any partial write after `KC_RESOURCE_LIMIT_EXCEEDED`.
