#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../../.." && pwd)"
BIN="$ROOT_DIR/artifacts/bin/license_demo"
PYTHON_BIN="${PYTHON_BIN:-python3}"
export COMS6424_DEVICE_KEY_HEX="${COMS6424_DEVICE_KEY_HEX:-00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff}"

if ! "$PYTHON_BIN" -c "import cryptography" >/dev/null 2>&1; then
  if /opt/homebrew/anaconda3/bin/python3 -c "import cryptography" >/dev/null 2>&1; then
    PYTHON_BIN="/opt/homebrew/anaconda3/bin/python3"
  fi
fi

"$ROOT_DIR/scripts/build_pipeline.sh" >/tmp/coms6424_code_signature_build.log

"$PYTHON_BIN" - "$ROOT_DIR" "$BIN" <<'PY'
from pathlib import Path
import sys

sys.path.insert(0, str(Path(sys.argv[1]) / "scripts"))
import issue_license

path = Path(sys.argv[2])
payload = bytearray(path.read_bytes())
magic = int.from_bytes(payload[0:4], "little")
if magic != issue_license.MH_MAGIC_64:
    raise SystemExit("not a supported thin Mach-O")

ncmds = int.from_bytes(payload[16:20], "little")
offset = 32
for _ in range(ncmds):
    cmd = int.from_bytes(payload[offset:offset + 4], "little")
    cmdsize = int.from_bytes(payload[offset + 4:offset + 8], "little")
    if cmd == issue_license.LC_CODE_SIGNATURE:
        dataoff = int.from_bytes(payload[offset + 8:offset + 12], "little")
        datasize = int.from_bytes(payload[offset + 12:offset + 16], "little")
        if datasize == 0:
            raise SystemExit("empty code signature")
        payload[dataoff] ^= 0x01
        path.write_bytes(payload)
        print(f"patched code signature byte at file offset {dataoff}")
        break
    offset += cmdsize
else:
    raise SystemExit("LC_CODE_SIGNATURE not found")
PY

set +e
OUTPUT="$("$BIN" 2>&1)"
STATUS=$?
set -e

printf '%s\n' "$OUTPUT"

if [[ $STATUS -eq 0 ]]; then
  echo "code signature constraint smoke test failed: binary exited successfully" >&2
  exit 1
fi

# macOS may reject an invalidly signed executable before user-space Rust code
# runs. A non-zero exit is the security-relevant result for this smoke test.
