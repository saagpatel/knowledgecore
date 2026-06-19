# Recovery Drill and Resource Guardrails Plan - 2026-06-19

## Purpose
Define the next approval-safe implementation lane for recovery restore confidence and resource exhaustion controls without changing vault formats, weakening crypto, scanning private paths, or introducing background/cloud behavior.

## Verified Current Inputs
- Recovery bundle verification is local-only and now decrypts `key_blob.enc`, validates the deterministic nonce, and rejects undecryptable or empty restored passphrases.
- Recovery bundle artifacts are documented in `spec/36-local-recovery-kit-v1.md`.
- Scan-folder ingest is documented as lexicographic traversal in `spec/05-ingest-jobs-and-timestamp-resolution.md`.
- PDF/OCR extraction is documented in `spec/04-canonical-text-v1-and-extractor-registry.md`.
- Filesystem snapshot sync is documented in `spec/29-sync-v1-filesystem-snapshots.md`.
- No private document ingest, real vault migration, or cloud sync operation was performed for this plan.

## Recommended Implementation Slice
This slice is implementation-ready after normal code-change approval because it avoids schema changes and does not require real user data.

1. Done in this checkpoint: add deterministic recovery restore drill tests that generate temp fixture state, generate a local recovery bundle, verify it, restore the passphrase inside recovery module test scope, and prove the restored passphrase decrypts only the generated fixture object.
2. Done in this checkpoint: add negative drill coverage for wrong phrase, tampered bundle, missing bundle files, and empty restored passphrase handling.
3. Done in this checkpoint: add explicit opt-in resource-limit APIs and generated-fixture tests for ingest bytes, sync snapshot zip archive/entry limits, PDF input/extracted-text byte limits, and vector batch/text limits.
4. Partially done in this checkpoint: approved defaults are wired into CLI/RPC ingest, S3 sync pull zip extraction, and CLI index rebuild. Remaining production wiring covers PDF/OCR extraction and filesystem snapshot directory size/count enforcement.

## Guardrail Decisions Needed
- Maximum single file size for ingest.
- Maximum files per scan-folder request.
- Maximum directory traversal depth and whether symlink following is disabled by default.
- Maximum PDF pages and maximum OCR pages per document.
- Maximum extracted canonical text bytes per document.
- Maximum sync snapshot archive size and maximum extracted entries.
- Maximum vector rows or batches accepted per rebuild/import operation.
- Whether resource-limit violations should be retryable `AppError`s or hard policy failures.

## Safety Constraints
- Use only generated temp vaults and generated fixture files.
- Do not scan broad local paths such as home, Documents, Desktop, Downloads, or repo parents.
- Do not persist recovery phrases, vault passphrases, or decrypted key material in tracked files, logs, snapshots, or exported reports.
- Do not alter recovery phrase derivation, SQLCipher parameters, Argon2 parameters, object-store encryption, or vault metadata.
- Do not introduce cloud backup, background sync, or automatic upload behavior.
- Do not enforce new production limits until default values and compatibility impact are approved.

## Acceptance Criteria
- Recovery drill tests prove that generate, verify, and restored-passphrase use are coherent on temp fixtures.
- Recovery drill tests prove common failure cases return existing recovery `AppError` codes.
- Resource-limit tests use generated fixture data and do not depend on private local documents.
- Resource-limit behavior is deterministic for opt-in ingest, sync snapshot, PDF extraction, and vector persistence helpers.
- Approved production defaults and first CLI/RPC wiring points are captured and partially enforced.
- Documentation is updated with any approved defaults and stop conditions before production enforcement lands.

## Approval Gates
- Production resource-limit defaults require approval because they can reject previously accepted local files.
- Any vault format, manifest, or schema change requires registry, fixture, migration, and rollback coverage.
- Any recovery workflow that stores or transmits secret material requires explicit design review.
- Any cloud escrow or sync behavior beyond existing explicitly configured surfaces requires explicit design approval.
