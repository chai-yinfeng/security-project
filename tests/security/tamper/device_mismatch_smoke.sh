#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../../.." && pwd)"
BIN="$ROOT_DIR/artifacts/bin/license_demo"
OLD_BLOB="$ROOT_DIR/artifacts/signed_policy/license.bin"
NEW_BLOB="$ROOT_DIR/artifacts/signed_policy/license.device_mismatch.bin"

"$ROOT_DIR/scripts/build_pipeline.sh" >/tmp/coms6424_device_mismatch_build.log

python3 "$ROOT_DIR/scripts/issue_license.py" \
  --executable "$BIN" \
  --embedded-blob-path "$OLD_BLOB" \
  --out "$NEW_BLOB" \
  --rust-public-key-out "$ROOT_DIR/src/rust_core/src/issuer_public_key.rs" \
  --device-id "00000000-0000-0000-0000-000000000000" >/tmp/coms6424_device_mismatch_issue.log

python3 - "$BIN" "$OLD_BLOB" "$NEW_BLOB" <<'PY'
from pathlib import Path
import sys

binary_path = Path(sys.argv[1])
old_blob = Path(sys.argv[2]).read_bytes()
new_blob = Path(sys.argv[3]).read_bytes()

if len(old_blob) != len(new_blob):
    raise SystemExit("blob lengths differ")

payload = binary_path.read_bytes()
first = payload.find(old_blob)
if first < 0:
    raise SystemExit("current blob not found in executable")
if payload.find(old_blob, first + 1) >= 0:
    raise SystemExit("current blob found multiple times in executable")

patched = payload[:first] + new_blob + payload[first + len(old_blob):]
binary_path.write_bytes(patched)
print(f"patched {binary_path}")
PY

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
