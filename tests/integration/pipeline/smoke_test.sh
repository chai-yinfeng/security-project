#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../../.." && pwd)"
OUTPUT="$("$ROOT_DIR/scripts/build_pipeline.sh")"

printf '%s\n' "$OUTPUT"

if [[ "$OUTPUT" != *"protected path entered"* ]]; then
  echo "pipeline smoke test failed: protected path was not reached" >&2
  exit 1
fi
