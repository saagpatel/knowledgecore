#!/usr/bin/env bash
set -euo pipefail

echo "knowledgecore local setup (non-destructive)."
command -v node >/dev/null 2>&1 && node -v || echo "node: missing"
command -v pnpm >/dev/null 2>&1 && pnpm -v || echo "pnpm: missing"
command -v cargo >/dev/null 2>&1 && cargo --version || echo "cargo: missing"

echo
echo "Install deps (README.md + .github/workflows/ci.yml):"
echo "  pnpm install --frozen-lockfile"
echo "Lean dev mode (README.md):"
echo "  pnpm dev:lean"
