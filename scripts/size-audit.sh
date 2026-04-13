#!/usr/bin/env bash
set -euo pipefail

TOP=20

usage() {
  cat <<'EOF'
Usage: scripts/size-audit.sh [--top N]

Options:
  --top N    Number of rows per section (default: 20)
  -h, --help Show this help
EOF
}

while (($# > 0)); do
  case "$1" in
    --top)
      shift
      TOP="${1:-}"
      if [[ -z "$TOP" || ! "$TOP" =~ ^[0-9]+$ || "$TOP" -lt 1 ]]; then
        echo "error: --top requires a positive integer" >&2
        exit 1
      fi
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

print_rows() {
  local title="$1"
  local data="$2"
  echo
  echo "== $title =="
  if [[ -z "$data" ]]; then
    echo "(none)"
    return
  fi

  while IFS=$'\t' read -r kb path; do
    [[ -z "${kb:-}" || -z "${path:-}" ]] && continue
    printf "%12s  %s\n" "$(human_kb "$kb")" "$path"
  done <<<"$data"
}

repo_kb="$(du -sk . | awk '{print $1}')"
echo "Repository: $ROOT"
echo "Total size: $(human_kb "$repo_kb")"

top_level="$(
  find . -mindepth 1 -maxdepth 1 -exec du -sk {} + 2>/dev/null \
    | sort -nr \
    | head -n "$TOP"
)"
print_rows "Top-Level Size" "$top_level"

if [[ -d target ]]; then
  target_breakdown="$(
    find target -mindepth 1 -maxdepth 2 -exec du -sk {} + 2>/dev/null \
      | sort -nr \
      | head -n "$TOP"
  )"
  print_rows "Target Breakdown" "$target_breakdown"
fi

if [[ -d node_modules ]]; then
  node_breakdown="$(
    find node_modules -mindepth 1 -maxdepth 2 -exec du -sk {} + 2>/dev/null \
      | sort -nr \
      | head -n "$TOP"
  )"
  print_rows "Node Modules Breakdown" "$node_breakdown"
fi

large_files="$(
  find . -type f -size +10M -not -path './.git/*' -print0 2>/dev/null \
    | xargs -0 du -sk 2>/dev/null \
    | sort -nr \
    | head -n "$TOP"
)"
print_rows "Largest Files (>10MB)" "$large_files"

echo
echo "Suggested cleanup command:"
echo "  bash ./scripts/clean-heavy-artifacts.sh --dry-run"
