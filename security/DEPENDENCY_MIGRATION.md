# Dependency Migration Notes

## Current status
- RustSec vulnerabilities: `0` after the 2026-04-26 dependency remediation.
- RustSec advisory warnings are policy-gated by `security/rustsec-policy.json`.
- Policy review window is capped by `metadata.max_review_window_days` (enforced by `scripts/audit-rust.mjs`).
- CI gate: `.github/workflows/security-audit.yml` job `rustsec-policy`.
- Weekly sweep: same workflow job `dependency-sweep` (`cargo update` + policy check).
- Upstream release watch: `security/dependency-watch.json` + `scripts/dependency-watch.mjs`.
- Vulnerabilities remain hard-blocking; the policy file only allows warning-class advisories.
- Post-stabilization baseline: `main` is canonical and aligned with `origin/main` at `3f23f3b` as of 2026-04-26.
- Open dependency PR queue: empty after merging the safe Vite/TypeScript/ESLint/Vitest and Rust dependency updates.
- Standalone Arrow 58 update PRs were closed intentionally; `lancedb 0.27.2` currently keeps the Arrow family on `57.3.0`.

## Why warnings remain
- `tauri` / `tauri-utils` chain currently brings gtk3/unic advisories transitively.
- `lancedb 0.27.2` / `lance 4.0.x` currently pins `tantivy` 0.24.x, which pulls `lru` 0.12.x.
- `rand` warning-class unsoundness is currently transitive through parser/indexing stacks.

## 2026-04-26 verification snapshot
- `node ./scripts/audit-rust.mjs`: PASS (`vulnerabilities=0`, `advisory_warnings=19`).
- `node ./scripts/dependency-watch.mjs`: PASS; direct watched crates are up to date.
- `node ./scripts/dependency-watch.mjs --no-fail`: PASS; transitive warnings remain for `lance`, `lance-index`, and `tantivy`.
- `cargo fmt --all -- --check`: PASS.
- `cargo test --workspace --exclude apps_desktop_tauri`: PASS.
- `cargo build --workspace --exclude apps_desktop_tauri`: PASS.
- `cargo test -p apps_desktop_tauri -- rpc_`: PASS.
- `pnpm lint`: PASS after restoring local UI dependencies with `pnpm -C apps/desktop/ui install --frozen-lockfile`.
- `pnpm test`: PASS after restoring local UI dependencies.
- `pnpm -C apps/desktop/ui build`: PASS after restoring local UI dependencies.
- `cargo run -p kc_cli -- bench run --corpus v1`: PASS twice with checksum `7311227353339408228`.

## Remediated vulnerability groups
- `aws-lc-sys`: updated through `aws-lc-rs` / AWS SDK lockfile refresh.
- `lz4_flex`: updated both active lockfile versions to patched releases.
- `quinn-proto`: updated to the patched release.
- `rustls-webpki`: removed the old `0.101.x` chain by disabling the AWS SDK legacy Rustls feature and updated the remaining `0.103.x` chain.
- `Cargo.lock`: keep tracked for application-style security reproducibility; the audit gate depends on this file.

## Reduction strategy
1. Keep Tauri features minimal in `apps/desktop/src-tauri/Cargo.toml`.
2. Prioritize direct dependency refreshes that remove hard-blocking vulnerabilities:
   - AWS/Rustls stack for `aws-lc-sys` and `rustls-webpki`
   - Lance/DataFusion stack for `lz4_flex`, `quinn-proto`, and `rand`
3. Track upstream releases of:
   - `tauri`, `tauri-utils`
   - `lancedb`, `lance`, `lance-index`, `tantivy`
4. Re-run local sweep:
   - `pnpm deps:sweep`
5. Watch upstream releases:
   - strict: `pnpm deps:watch`
   - advisory: `pnpm deps:watch:advisory`
6. If advisory set changes:
   - remove stale allowlist entries
   - add new entries only with reason + short review deadline
7. Verify full workspace:
   - `pnpm lint`
   - `pnpm test`
   - `pnpm -C apps/desktop/ui build`
   - `cargo fmt --all -- --check`
   - `cargo test --workspace`
   - `cargo build --workspace`
