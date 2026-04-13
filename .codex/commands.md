# knowledgecore .codex command map

| Action | Command | Source |
| --- | --- | --- |
| setup deps | `pnpm install --frozen-lockfile` | `README.md`, `.github/workflows/ci.yml` |
| lint (ui) | `pnpm lint` | `README.md`, `.github/workflows/ci.yml`, `package.json` |
| lint (rust fmt) | `cargo fmt --all -- --check` | `.github/workflows/ci.yml` |
| test (ui) | `pnpm test` | `README.md`, `.github/workflows/ci.yml`, `package.json` |
| test (rust) | `cargo test --workspace --exclude apps_desktop_tauri` | `.github/workflows/ci.yml` |
| build (ui) | `pnpm -C apps/desktop/ui build` | `README.md`, `.github/workflows/ci.yml` |
| build (rust) | `cargo build --workspace --exclude apps_desktop_tauri` | `.github/workflows/ci.yml` |
| lean dev | `pnpm dev:lean` | `README.md`, `package.json` |
