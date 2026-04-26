# Dependency Migration Notes

## Current status
- RustSec vulnerabilities: `0` after the 2026-04-26 dependency remediation.
- RustSec advisory warnings are policy-gated by `security/rustsec-policy.json`.
- Policy review window is capped by `metadata.max_review_window_days` (enforced by `scripts/audit-rust.mjs`).
- CI gate: `.github/workflows/security-audit.yml` job `rustsec-policy`.
- Weekly sweep: same workflow job `dependency-sweep` (`cargo update` + policy check).
- Upstream release watch: `security/dependency-watch.json` + `scripts/dependency-watch.mjs`.
- Vulnerabilities remain hard-blocking; the policy file only allows warning-class advisories.

## Why warnings remain
- `tauri` / `tauri-utils` chain currently brings gtk3/unic advisories transitively.
- `lancedb` / `lance` 2.0.x currently pins `tantivy` 0.24.x, which pulls `lru` 0.12.x.
- `rand` warning-class unsoundness is currently transitive through parser/indexing stacks.

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
