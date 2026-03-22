#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

LEAN_TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/knowledgecore-lean.XXXXXX")"
LEAN_TARGET_DIR="$LEAN_TMP_ROOT/target"
mkdir -p "$LEAN_TARGET_DIR"

cleanup() {
  local status=$?
  rm -rf "$LEAN_TMP_ROOT"
  # Belt-and-suspenders cleanup in case tooling wrote to default paths.
  bash ./scripts/clean-heavy-artifacts.sh >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT INT TERM

echo "Lean dev mode:"
echo "  CARGO_TARGET_DIR=$LEAN_TARGET_DIR"
echo "  Cleanup on exit: enabled"

CARGO_TARGET_DIR="$LEAN_TARGET_DIR" pnpm -C apps/desktop/ui tauri dev "$@"
