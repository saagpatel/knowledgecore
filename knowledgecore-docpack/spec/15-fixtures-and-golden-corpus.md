# Fixtures and Golden Corpus (v1)

## Purpose
Golden corpus v1 definition and snapshot expectations.

## Invariants
- Tier 1 snapshots exact; Tier 2 snapshots stable under pinned toolchain.
- Tests use fixed now_ms.

## Acceptance Tests
- `./target/release/kc_cli fixtures generate --corpus v1` and golden tests pass.

## Fixture list (minimum)
- MD: 2 docs with nested headings
- HTML Confluence: 2 pages
- PDF: 3 docs (clean, messy, scanned/no-text)

## Expected outputs
- canonical_text, chunks, retrieval order, export manifest, verifier report

## Commands
Run from the repository root after building the CLI in release mode.
- generate: `./target/release/kc_cli fixtures generate --corpus v1`
- Component checks: `cargo test -p kc_core -p kc_extract -- golden`; index tests: `cargo test -p kc_index --test fts --test vector`; verifier tests: `cargo test -p kc_cli --test verifier`. These tests use inline synthetic inputs or temporary rows/bundles and do not read the checked-in corpus.
- Known gap: corpus-backed snapshot/integration tests for the expected canonical text, chunks, retrieval order, export manifest, and verifier report are not present. The component checks above cannot detect corpus drift and do not satisfy the golden corpus acceptance requirement.
