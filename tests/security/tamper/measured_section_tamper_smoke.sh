#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../../.." && pwd)"
BIN="$ROOT_DIR/artifacts/bin/license_demo"
export COMS6424_DEVICE_KEY_HEX="${COMS6424_DEVICE_KEY_HEX:-00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff}"

"$ROOT_DIR/scripts/build_pipeline.sh" >/tmp/coms6424_measured_section_build.log

PYTHON_BIN="${PYTHON_BIN:-python3}"
if ! "$PYTHON_BIN" -c "import cryptography" >/dev/null 2>&1; then
  if /opt/homebrew/anaconda3/bin/python3 -c "import cryptography" >/dev/null 2>&1; then
    PYTHON_BIN="/opt/homebrew/anaconda3/bin/python3"
  fi
fi

"$PYTHON_BIN" - "$ROOT_DIR" "$BIN" <<'PY'
from pathlib import Path
import sys

sys.path.insert(0, str(Path(sys.argv[1]) / "scripts"))
import issue_license

path = Path(sys.argv[2])
payload = bytearray(path.read_bytes())
offset, size = issue_license.find_macho_section(bytes(payload), "__TEXT", "__text")
if size < 16:
    raise SystemExit("__TEXT,__text section too small")

payload[offset + 8] ^= 0x01
path.write_bytes(payload)
print(f"patched measured __TEXT,__text content at file offset {offset + 8}")
PY

codesign --force --sign - "$BIN" >/tmp/coms6424_measured_section_codesign.log

set +e
OUTPUT="$("$BIN" 2>&1)"
STATUS=$?
set -e

printf '%s\n' "$OUTPUT"

if [[ $STATUS -eq 0 ]]; then
  echo "measured section tamper smoke test failed: binary exited successfully" >&2
  exit 1
fi

if [[ "$OUTPUT" != *"license denied"* ]]; then
  echo "measured section tamper smoke test failed: expected license denial output" >&2
  exit 1
fi
