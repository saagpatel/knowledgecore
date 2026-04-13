#!/usr/bin/env bash
set -euo pipefail

DRY_RUN=0

usage() {
  cat <<'EOF'
Usage: scripts/clean-heavy-artifacts.sh [--dry-run]

Removes heavyweight build outputs while keeping dependencies installed.

Targets:
  - target
  - apps/desktop/src-tauri/target
  - apps/desktop/ui/tauri-dist
  - apps/desktop/ui/dist

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

dir_kb() {
  local path="$1"
  if [[ -e "$path" ]]; then
    du -sk "$path" 2>/dev/null | awk '{print $1}'
  else
    echo 0
  fi
}

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

before_repo_kb="$(du -sk . | awk '{print $1}')"
echo "Repository: $ROOT"
echo "Before: $(human_kb "$before_repo_kb")"

remove_dir "target"
remove_dir "apps/desktop/src-tauri/target"
remove_dir "apps/desktop/ui/tauri-dist"
remove_dir "apps/desktop/ui/dist"

after_repo_kb="$(du -sk . | awk '{print $1}')"
reclaimed_kb=$((before_repo_kb - after_repo_kb))
echo "After:  $(human_kb "$after_repo_kb")"
echo "Reclaimed: $(human_kb "$reclaimed_kb")"

if ((DRY_RUN)); then
  echo "Dry-run complete. Re-run without --dry-run to apply changes."
fi
