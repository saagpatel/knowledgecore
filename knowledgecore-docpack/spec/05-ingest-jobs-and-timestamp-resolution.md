# Ingest Jobs and Timestamp Resolution

## Purpose
Defines scan-folder and inbox ingest jobs, deterministic processed-move, and stored effective timestamp resolution.

## Invariants
- Tier 1: bytes-based identity; idempotent ingest.
- effective_ts stored once at ingest; recency uses stored values only.
- Resource limits for file size, file count, traversal depth, and symlink handling are policy boundaries; production default changes require explicit approval.

## Acceptance Tests
- Tests validate traversal order, processed move naming, and timestamp resolution priority.
- Resource-limit tests use generated fixture trees only and must not scan broad local paths or private document folders.

## Jobs
- Scan-folder: traverse lexicographic full paths; ingest each file.
- Inbox: ingest new file then move to `Inbox/processed/` deterministically.

## Processed move naming (assumption)
- `<orig>__<doc_id_prefix8>.<ext>`

## Timestamp resolution (v1)
Priority:
1) deterministic source metadata timestamp (if present)
2) filesystem mtime captured at ingest
3) ingest now_ms
Tie-break: smallest ms at same priority (assumption)

## Error codes
- `KC_INGEST_READ_FAILED`
- `KC_INBOX_MOVE_FAILED`
- `KC_TIMESTAMP_RESOLUTION_FAILED`
