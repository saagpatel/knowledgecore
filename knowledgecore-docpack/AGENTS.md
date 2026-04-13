# AGENTS.md

<!-- comm-contract:start -->
## Communication Contract (Global)
- Follow `/Users/d/.codex/policies/communication/BigPictureReportingV1.md` for all user-facing updates.
- Use exact section labels from `BigPictureReportingV1.md` for default status/progress updates.
- Keep default updates beginner-friendly, big-picture, and low-noise.
- Keep technical details in internal artifacts unless explicitly requested by the user.
- Honor toggles literally: `simple mode`, `show receipts`, `tech mode`, `debug mode`.
<!-- comm-contract:end -->

## Purpose
Authoritative operating contract for all agentic implementation work (Codex) for KnowledgeCore Desktop. Encodes non-negotiable boundaries, determinism tiers, verification gates, schema governance, and golden fixture workflow.

## Invariants
- **No business logic in UI.** React UI may render state and trigger actions only. It must not implement ranking, merge logic, chunking, locator resolution, export ordering, verifier logic, or any policy affecting correctness.
- **Tauri RPC is thin orchestration only.** `apps/desktop/src-tauri/` wires typed requests to Rust core APIs and returns typed responses. No truth-layer rules live here.
- **UI routes by `AppError.code` only.** UI must never branch on `message` substrings.
- **Determinism tiers apply to all work:**
  - **Tier 1 (strict deterministic):** `object_hash` (BLAKE3 bytes), `doc_id`, canonical JSON hashing, `canonical_hash` (canonical text bytes), `chunk_id`, locator range/substring resolution, retrieval merge + tie-break rules, manifest ordering, verifier exit codes + deterministic report ordering.
  - **Tier 2 (toolchain-scoped, version-bounded):** PDF text extraction + OCR outputs must be stable under pinned tool versions/settings; tool/version changes define a version boundary.
  - **Tier 3 (performance):** best-effort but measured; baselines + regression thresholds enforced.
- **Canonical text is ground truth** for chunking, indexing, citations, and snippet rendering.
- **Schema governance:** any schema creation/change requires updating `SCHEMA_REGISTRY.md` and adding schema validation tests.

## Acceptance Tests
- All verification commands pass:
  - `cargo test -p kc_core -p kc_extract -p kc_index -p kc_ask -p kc_cli`
  - `pnpm lint && pnpm test && pnpm tauri build`
- Golden corpus tests pass (see `spec/15-fixtures-and-golden-corpus.md`).
- Determinism tests pass for Tier 1 outputs: stable IDs, stable ordering, stable manifest ordering, stable verifier report ordering.

## Commands (gates)
- Rust: `cargo test -p kc_core -p kc_extract -p kc_index -p kc_ask -p kc_cli`
- Desktop: `pnpm lint && pnpm test && pnpm tauri build`

## Stop on failure
If any gate fails:
1) stop immediately,
2) diagnose,
3) fix,
4) rerun the gate(s) until green,
5) only then proceed.

## Schema versioning rules (summary)
- Any breaking schema change requires a version bump (major).
- Additive optional fields require a registry update and validation tests (no major bump required).
- Any Tier 1 deterministic algorithm change requires an explicit version boundary note in the relevant spec and updated golden snapshots.

## Where schemas live
- Canonical JSON rules: `spec/00-canonical-json.md`
- Schema registry: `SCHEMA_REGISTRY.md` (authoritative index)
- RPC boundary types: `spec/19-tauri-rpc-surface.md`
- Golden corpus: `spec/15-fixtures-and-golden-corpus.md`

## Golden fixtures workflow
- Fixtures location: `fixtures/golden_corpus/v1/` (see spec/15).
- Golden generation command (must exist in CLI by Milestone D/E): `kc_cli fixtures generate --corpus v1`
- Golden verification commands (final form):
  - `cargo test -p kc_core -- golden_*`
  - `cargo test -p kc_extract -- golden_*`
  - `cargo test -p kc_index -- golden_*`
  - `cargo test -p kc_cli -- golden_*`

## Forbidden patterns (hard no)
- UI parsing/manipulating locators beyond display formatting.
- UI reranking results; UI must display ordered hits as returned by core.
- Tauri making ad-hoc DB queries that bypass `kc_core` APIs.
