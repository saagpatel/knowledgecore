#!/usr/bin/env bash
set -euo pipefail

DRY_RUN=0

usage() {
  cat <<'EOF'
Usage: scripts/clean-repro-caches.sh [--dry-run]

Removes reproducible local caches and build outputs.

This includes:
  - heavy build artifacts (target, tauri-dist, dist)
  - node_modules in workspace and app package
  - common local cache directories (.pnpm-store, .turbo, .vite)

Options:
  --dry-run   Show what would be removed
  -h, --help  Show this help
EOF
}

while (($# > 0)); do
  case "$1" in
    --dry-run)
      DRY_RUN=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown option '$1'" >&2
      usage >&2
      exit 1
      ;;
  esac
  shift
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

human_kb() {
  awk -v kb="$1" '
    BEGIN {
      split("KB MB GB TB PB", u, " ");
      v = kb + 0;
      i = 1;
      while (v >= 1024 && i < 5) {
        v /= 1024;
        i++;
      }
      printf "%.2f %s", v, u[i];
    }'
}

before_repo_kb="$(du -sk . | awk '{print $1}')"
echo "Repository: $ROOT"
echo "Before (full): $(human_kb "$before_repo_kb")"

heavy_cmd=(bash ./scripts/clean-heavy-artifacts.sh)
if ((DRY_RUN)); then
  heavy_cmd+=(--dry-run)
fi
"${heavy_cmd[@]}"

remove_dir() {
  local path="$1"
  if [[ ! -e "$path" ]]; then
    return
  fi

  if ((DRY_RUN)); then
    echo "[dry-run] would remove $path"
    return
  fi

  rm -rf "$path"
  echo "removed $path"
}

remove_dir "node_modules"
remove_dir "apps/desktop/ui/node_modules"
remove_dir ".pnpm-store"
remove_dir ".turbo"
remove_dir ".vite"
remove_dir "apps/desktop/ui/.vite"

after_repo_kb="$(du -sk . | awk '{print $1}')"
reclaimed_kb=$((before_repo_kb - after_repo_kb))
echo "After (full):  $(human_kb "$after_repo_kb")"
echo "Reclaimed (full): $(human_kb "$reclaimed_kb")"

if ((DRY_RUN)); then
  echo "Dry-run complete. Re-run without --dry-run to apply changes."
fi
