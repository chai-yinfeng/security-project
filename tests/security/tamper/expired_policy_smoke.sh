#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../../.." && pwd)"
BIN="$ROOT_DIR/artifacts/bin/license_demo"
NEW_BLOB="$ROOT_DIR/artifacts/signed_policy/license.expired.bin"
PYTHON_BIN="${PYTHON_BIN:-python3}"
export COMS6424_DEVICE_KEY_HEX="${COMS6424_DEVICE_KEY_HEX:-00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff}"

if ! "$PYTHON_BIN" -c "import cryptography" >/dev/null 2>&1; then
  if /opt/homebrew/anaconda3/bin/python3 -c "import cryptography" >/dev/null 2>&1; then
    PYTHON_BIN="/opt/homebrew/anaconda3/bin/python3"
  fi
fi

"$ROOT_DIR/scripts/build_pipeline.sh" >/tmp/coms6424_expired_build.log

"$PYTHON_BIN" "$ROOT_DIR/scripts/issue_license.py" \
  --executable "$BIN" \
  --out "$NEW_BLOB" \
  --rust-public-key-out "$ROOT_DIR/src/rust_core/src/issuer_public_key.rs" \
  --valid-days=-1 \
  --patch-macho-license-section >/tmp/coms6424_expired_issue.log

codesign --force --sign - "$BIN" >/tmp/coms6424_expired_codesign.log

set +e
OUTPUT="$("$BIN" 2>&1)"
STATUS=$?
set -e

printf '%s\n' "$OUTPUT"

if [[ $STATUS -eq 0 ]]; then
  echo "expired policy smoke test failed: binary exited successfully" >&2
  exit 1
fi

if [[ "$OUTPUT" != *"license denied"* ]]; then
  echo "expired policy smoke test failed: expected license denial output" >&2
  exit 1
fi
