# Post-Stabilization Baseline - 2026-04-26

## Purpose
Capture the current repo baseline after the April 26 dependency stabilization pass.

## Current State
- Canonical branch: `main`.
- Canonical remote: `origin/main`.
- Verified head: `3f23f3b`.
- Open PR queue: empty.
- Local checkout: clean before recording this baseline document.
- GitHub `main` CI: PASS for `3f23f3b`.
- GitHub `main` Security Audit: PASS for `3f23f3b`.
- Remote `master` was archived to `origin/archive/master-before-main-canonical-2026-04-26` at `915c506` and removed from `origin`.

## Dependency Outcome
- Safe JavaScript dependency PRs were merged for Vite, Vitest, TypeScript, ESLint, and TypeScript ESLint packages.
- Safe Rust dependency PRs were merged for `jsonschema`, `pdfium-render`, and `sha2`.
- Duplicate app-scoped JavaScript PRs were closed after the workspace-level updates covered the same versions.
- Standalone Arrow 58 PRs were closed because `lancedb 0.27.2` currently depends on the Arrow 57.3.0 family. Future Arrow upgrades should move LanceDB/Lance/DataFusion/Arrow together.

## Verification Evidence
| Command | Result | Notes |
|---|---|---|
| `cargo fmt --all -- --check` | PASS | Formatting gate. |
| `cargo test --workspace --exclude apps_desktop_tauri` | PASS | Main Rust workspace gate. |
| `cargo build --workspace --exclude apps_desktop_tauri` | PASS | Main Rust build gate. |
| `cargo test -p apps_desktop_tauri -- rpc_` | PASS | Desktop RPC and RPC schema boundary tests. |
| `node ./scripts/audit-rust.mjs` | PASS | `vulnerabilities=0`, `advisory_warnings=19`. |
| `node ./scripts/dependency-watch.mjs` | PASS | Direct watched crates are up to date. |
| `node ./scripts/dependency-watch.mjs --no-fail` | PASS | Transitive warnings remain for `lance`, `lance-index`, and `tantivy`. |
| `pnpm lint` | PASS | Required local dependency restore first. |
| `pnpm test` | PASS | 5 test files, 10 tests. |
| `pnpm -C apps/desktop/ui build` | PASS | Vite build completed. |
| `cargo run -p kc_cli -- bench run --corpus v1` | PASS | Run twice; checksum `7311227353339408228`. |

## Remaining Follow-Ups
- GA remains blocked by the existing signing/notarization trust gap documented in the GA closeout files.
- The separate `legacy-origin` remote still has its historical `master`; keep `origin/main` canonical for active work.
- Keep RustSec policy review dates current; current entries review by `2026-06-09`.
- Treat future Arrow-family updates as coordinated stack work, not standalone crate bumps.
