#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../../.." && pwd)"
BIN="$ROOT_DIR/artifacts/bin/license_demo"
PYTHON_BIN="${PYTHON_BIN:-python3}"

if ! "$PYTHON_BIN" -c "import cryptography" >/dev/null 2>&1; then
  if /opt/homebrew/anaconda3/bin/python3 -c "import cryptography" >/dev/null 2>&1; then
    PYTHON_BIN="/opt/homebrew/anaconda3/bin/python3"
  fi
fi

"$ROOT_DIR/scripts/build_pipeline.sh" >/tmp/coms6424_pipeline_build.log

"$PYTHON_BIN" - "$ROOT_DIR" "$BIN" <<'PY'
from pathlib import Path
import sys

sys.path.insert(0, str(Path(sys.argv[1]) / "scripts"))
import issue_license

path = Path(sys.argv[2])
payload = bytearray(path.read_bytes())

offset, size = issue_license.find_macho_section(
    bytes(payload),
    issue_license.LICENSE_SEGMENT,
    issue_license.LICENSE_SECTION,
)
if size < 13:
    raise SystemExit("embedded license section too small")

payload[offset + 12] ^= 0x01
path.write_bytes(payload)
print(f"corrupted {path} at Mach-O license section offset {offset}")
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
