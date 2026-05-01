#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../../.." && pwd)"
BIN="$ROOT_DIR/artifacts/bin/license_demo"

"$ROOT_DIR/scripts/build_pipeline.sh" >/tmp/coms6424_pipeline_build.log

python3 - "$BIN" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
payload = bytearray(path.read_bytes())

marker = b"SLC1"
offset = payload.find(marker)
if offset < 0:
    raise SystemExit("embedded blob marker not found")

payload[offset + 12] ^= 0x01
path.write_bytes(payload)
print(f"corrupted {path}")
PY

codesign --force --sign - "$BIN" >/tmp/coms6424_tamper_codesign.log

set +e
OUTPUT="$("$BIN" 2>&1)"
STATUS=$?
set -e

printf '%s\n' "$OUTPUT"

if [[ $STATUS -eq 0 ]]; then
  echo "tamper smoke test failed: corrupted binary still exited successfully" >&2
  exit 1
fi

if [[ "$OUTPUT" != *"license denied"* ]]; then
  echo "tamper smoke test failed: expected license denial output" >&2
  exit 1
fi
