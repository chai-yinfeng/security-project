#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../../.." && pwd)"
BIN="$ROOT_DIR/artifacts/bin/license_demo"

"$ROOT_DIR/scripts/build_pipeline.sh" >/tmp/coms6424_measured_section_build.log

python3 - "$BIN" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
payload = bytearray(path.read_bytes())
needle = b"protected path entered"
offset = payload.find(needle)
if offset < 0:
    raise SystemExit("protected string not found in executable")

payload[offset] ^= 0x01
path.write_bytes(payload)
print(f"patched measured __TEXT content at file offset {offset}")
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
