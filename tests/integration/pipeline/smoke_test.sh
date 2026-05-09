#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../../.." && pwd)"
export COMS6424_DEVICE_KEY_HEX="${COMS6424_DEVICE_KEY_HEX:-00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff}"
OUTPUT="$("$ROOT_DIR/scripts/build_pipeline.sh")"

printf '%s\n' "$OUTPUT"

if [[ "$OUTPUT" != *"bomb defused: capability chain consumed 3 encrypted stages"* ]]; then
  echo "pipeline smoke test failed: protected path was not reached" >&2
  exit 1
fi
