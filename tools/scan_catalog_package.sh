#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 4 || $# -gt 5 ]]; then
  echo "usage: scan_catalog_package.sh MANIFEST CATALOG_REPORT REVIEW_ROOT SEMANTIC_OUTPUT [PROVENANCE]" >&2
  exit 2
fi

manifest=$1
catalog_report=$2
review_root=$3
semantic_output=$4
provenance=${5:-}
archive=$(mktemp "${RUNNER_TEMP:-/tmp}/vanahub-package.XXXXXX")
trap 'rm -f "$archive"' EXIT
package_id=$(jq -er .id "$manifest")
archive_root=$(jq -er .archiveRoot "$manifest")
baseline="${review_root}/${package_id}.json"

mkdir -p "$semantic_output"
scan_args=("$(dirname "$0")/catalog_scan.py" "$manifest" --output "$catalog_report" --archive-output "$archive")
if [[ -n "$provenance" ]]; then scan_args+=(--provenance "$provenance"); fi
python3 "${scan_args[@]}"

args=(
  "$(dirname "$0")/semantic_scan.py"
  --semgrep "${SEMGREP_BIN:-semgrep}"
  --rules "$(dirname "$0")/../policy/semgrep-lua.yml"
  --archive "$archive"
  --archive-root "$archive_root"
  --package-id "$package_id"
  --output-directory "$semantic_output"
  --catalog-report "$catalog_report"
)
if [[ -f "$baseline" ]]; then args+=(--baseline "$baseline"); fi
python3 "${args[@]}"
