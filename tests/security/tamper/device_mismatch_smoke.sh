#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../../.." && pwd)"
BIN="$ROOT_DIR/artifacts/bin/license_demo"
NEW_BLOB="$ROOT_DIR/artifacts/signed_policy/license.device_mismatch.bin"
PYTHON_BIN="${PYTHON_BIN:-python3}"
export COMS6424_DEVICE_KEY_HEX="${COMS6424_DEVICE_KEY_HEX:-00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff}"

if ! "$PYTHON_BIN" -c "import cryptography" >/dev/null 2>&1; then
  if /opt/homebrew/anaconda3/bin/python3 -c "import cryptography" >/dev/null 2>&1; then
    PYTHON_BIN="/opt/homebrew/anaconda3/bin/python3"
  fi
fi

SE_HELPER="$ROOT_DIR/tools/se_keygen_swift"
if [ ! -f "$SE_HELPER" ]; then
  swiftc "$ROOT_DIR/tools/se_keygen.swift" -o "$SE_HELPER"
  codesign --force --sign - "$SE_HELPER"
fi

"$ROOT_DIR/scripts/build_pipeline.sh" >/tmp/coms6424_device_mismatch_build.log

REAL_SE_OUTPUT=$("$SE_HELPER" "$ROOT_DIR/artifacts/se_key.dat")
REAL_SE_PUBKEY=$(echo "$REAL_SE_OUTPUT" | head -1)
REAL_SE_KEYDATA=$(echo "$REAL_SE_OUTPUT" | tail -1)

KEYDATA_LEN=$((${#REAL_SE_KEYDATA} / 2))
WRONG_SE_PUBKEY="$REAL_SE_PUBKEY"
WRONG_SE_KEYDATA=$(python3 -c "print('aa' * $KEYDATA_LEN)")

"$PYTHON_BIN" "$ROOT_DIR/scripts/issue_license.py" \
  --executable "$BIN" \
  --out "$NEW_BLOB" \
  --rust-public-key-out "$ROOT_DIR/src/rust_core/src/issuer_public_key.rs" \
  --se-public-key-hex "$WRONG_SE_PUBKEY" \
  --se-key-data-hex "$WRONG_SE_KEYDATA" \
  --patch-macho-license-section >/tmp/coms6424_device_mismatch_issue.log

codesign --force --sign - "$BIN" >/tmp/coms6424_device_mismatch_codesign.log

set +e
OUTPUT="$("$BIN" 2>&1)"
STATUS=$?
set -e

printf '%s\n' "$OUTPUT"

if [[ $STATUS -eq 0 ]]; then
  echo "device mismatch smoke test failed: binary exited successfully" >&2
  exit 1
fi

if [[ "$OUTPUT" != *"license denied"* ]]; then
  echo "device mismatch smoke test failed: expected license denial output" >&2
  exit 1
fi
