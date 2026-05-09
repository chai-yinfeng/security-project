#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../../.." && pwd)"
PROFILE="$ROOT_DIR/artifacts/device_profiles/profile_smoke.json"
DEVICE_KEY="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

PYTHON_BIN="${PYTHON_BIN:-python3}"
if ! "$PYTHON_BIN" -c "import cryptography" >/dev/null 2>&1; then
  if /opt/homebrew/anaconda3/bin/python3 -c "import cryptography" >/dev/null 2>&1; then
    PYTHON_BIN="/opt/homebrew/anaconda3/bin/python3"
  fi
fi

"$PYTHON_BIN" "$ROOT_DIR/scripts/profile_device.py" \
  --device-key-hex "$DEVICE_KEY" \
  --out "$PROFILE" >/tmp/coms6424_profile_smoke_profile.log

COMS6424_DEVICE_KEY_HEX="$DEVICE_KEY" \
  "$ROOT_DIR/scripts/issue_for_device.sh" "$PROFILE" profile_smoke_demo \
  >/tmp/coms6424_profile_smoke_issue.log

OUTPUT="$(COMS6424_DEVICE_KEY_HEX="$DEVICE_KEY" "$ROOT_DIR/artifacts/final/profile_smoke_demo")"
printf '%s\n' "$OUTPUT"

if [[ "$OUTPUT" != *"bomb defused: capability chain consumed 3 encrypted stages"* ]]; then
  echo "profile issue smoke test failed: protected path was not reached" >&2
  exit 1
fi
