#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../../.." && pwd)"
PROFILE="$ROOT_DIR/artifacts/device_profiles/malformed_profile.json"
export COMS6424_DEVICE_KEY_HEX="${COMS6424_DEVICE_KEY_HEX:-00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff}"

mkdir -p "$(dirname "$PROFILE")"
cat >"$PROFILE" <<'JSON'
{
  "profile_schema_version": 99,
  "product_id": "coms6424.demo",
  "platform": {
    "os": "macos",
    "arch": "arm64"
  },
  "device_id": "F6860FD3-99A1-5C05-8C2B-946F5F0832FD",
  "device_fingerprint_hash": "00",
  "device_payload_key_material": "00"
}
JSON

set +e
OUTPUT="$("$ROOT_DIR/scripts/issue_for_device.sh" "$PROFILE" malformed_profile_demo 2>&1)"
STATUS=$?
set -e

printf '%s\n' "$OUTPUT"

if [[ $STATUS -eq 0 ]]; then
  echo "malformed profile smoke test failed: issuer accepted invalid profile" >&2
  exit 1
fi

if [[ "$OUTPUT" != *"unsupported device profile schema version"* ]]; then
  echo "malformed profile smoke test failed: expected schema rejection" >&2
  exit 1
fi
