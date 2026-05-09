#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../../.." && pwd)"
BIN="$ROOT_DIR/artifacts/bin/license_demo"

ISSUE_DEVICE_KEY="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
RUNTIME_DEVICE_KEY="ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"

COMS6424_DEVICE_KEY_HEX="$ISSUE_DEVICE_KEY" \
  "$ROOT_DIR/scripts/build_pipeline.sh" >/tmp/coms6424_device_key_mismatch_build.log

set +e
OUTPUT="$(COMS6424_DEVICE_KEY_HEX="$RUNTIME_DEVICE_KEY" "$BIN" 2>&1)"
STATUS=$?
set -e

printf '%s\n' "$OUTPUT"

if [[ $STATUS -eq 0 ]]; then
  echo "device key mismatch smoke test failed: binary exited successfully" >&2
  exit 1
fi

if [[ "$OUTPUT" != *"license denied"* ]]; then
  echo "device key mismatch smoke test failed: expected license denial output" >&2
  exit 1
fi
