# Contributing

Thanks for your interest in contributing! Here's how to get started.

## Bug Reports & Feature Requests

Open a [GitHub Issue](../../issues/new) with:
- Clear description of the problem or idea
- Steps to reproduce (for bugs)
- Expected vs actual behavior

## Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/your-feature`)
3. Make your changes with clear commit messages
4. Run existing tests to ensure nothing breaks
5. Open a PR with a description of what changed and why

## Development Setup

See the README for installation and setup instructions.

## Verification

Run from the repository root with current stable Rust/Cargo, a native C/C++
build toolchain, and `protoc` available. The Rust build includes bundled
SQLCipher/OpenSSL and the Lance/Arrow dependency graph. For the UI, use Node.js
24.x and the root `packageManager` pin, pnpm 10.29.2; install with
`pnpm install --frozen-lockfile`. These checks use test fixtures, without opening
your private vault or scanning personal document folders.

```bash
# Focus a Rust verifier change on its disposable bundle fixtures:
cargo test --locked -p kc_cli --test verifier

# Broader Rust CI lane (the native Tauri app is excluded):
cargo fmt --all -- --check
cargo test --locked --workspace --exclude apps_desktop_tauri
cargo build --locked --workspace --exclude apps_desktop_tauri

# Focus a UI RPC change; paths are relative to apps/desktop/ui:
pnpm -C apps/desktop/ui test test/rpc.test.ts

# Broader UI lane:
pnpm lint
pnpm test
pnpm -C apps/desktop/ui typecheck
pnpm -C apps/desktop/ui build
```

The plain Vite build covers the frontend, not a native Tauri application. Native
Tauri checks additionally require the target platform's SDK, WebView/system
libraries, and a disposable vault; the CI exclusion above is intentional. For
changed desktop behavior, exercise the affected flow in the native app with
synthetic documents; browser-only checks cannot prove vault/native RPC behavior.
Pure instruction changes do not require an app walkthrough.

`pnpm audit:rust` runs the separate RustSec policy gate and queries advisory
data; it may fail on expired/stale policy entries or unreviewed advisories. Keep
that result separate from unit/build success. Do not use `deps:sweep` (updates
Cargo.lock), `clean:local*`, personal-document ingestion, or a private vault as
routine verification.

## Code Style

- Follow the existing patterns in the codebase
- Use meaningful variable and function names
- Add comments only where the logic isn't self-evident

## Questions?

Open an issue or start a discussion. Response time is typically within a few days.
