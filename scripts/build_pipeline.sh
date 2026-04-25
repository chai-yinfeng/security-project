#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
FINAL_BIN="$ROOT_DIR/artifacts/bin/license_demo"
LICENSE_BLOB="$ROOT_DIR/artifacts/signed_policy/license.bin"
PLACEHOLDER_BLOB="$ROOT_DIR/artifacts/signed_policy/license.placeholder.bin"

mkdir -p "$ROOT_DIR/artifacts/bin" "$ROOT_DIR/artifacts/signed_policy" "$ROOT_DIR/artifacts/issuer"

python3 "$ROOT_DIR/scripts/issue_license.py" \
  --executable "$FINAL_BIN" \
  --out "$LICENSE_BLOB" \
  --rust-public-key-out "$ROOT_DIR/src/rust_core/src/issuer_public_key.rs" \
  --placeholder-executable-hash

cp "$LICENSE_BLOB" "$PLACEHOLDER_BLOB"

cargo build --manifest-path "$ROOT_DIR/src/rust_core/Cargo.toml"

cc \
  "$ROOT_DIR/src/host_entry/main.c" \
  -I"$ROOT_DIR/include" \
  "$ROOT_DIR/src/rust_core/target/debug/librust_core.a" \
  -o "$FINAL_BIN"

codesign --force --sign - "$FINAL_BIN"

python3 "$ROOT_DIR/scripts/issue_license.py" \
  --executable "$FINAL_BIN" \
  --embedded-blob-path "$PLACEHOLDER_BLOB" \
  --out "$LICENSE_BLOB" \
  --rust-public-key-out "$ROOT_DIR/src/rust_core/src/issuer_public_key.rs"

python3 - "$FINAL_BIN" "$PLACEHOLDER_BLOB" "$LICENSE_BLOB" <<'PY'
from pathlib import Path
import sys

binary_path = Path(sys.argv[1])
old_blob = Path(sys.argv[2]).read_bytes()
new_blob = Path(sys.argv[3]).read_bytes()

if len(old_blob) != len(new_blob):
    raise SystemExit("placeholder and final blob lengths differ")

payload = binary_path.read_bytes()
first = payload.find(old_blob)
if first < 0:
    raise SystemExit("placeholder blob not found in executable")
if payload.find(old_blob, first + 1) >= 0:
    raise SystemExit("placeholder blob found multiple times in executable")

patched = payload[:first] + new_blob + payload[first + len(old_blob):]
binary_path.write_bytes(patched)
print(f"patched {binary_path}")
PY

codesign --force --sign - "$FINAL_BIN"

"$FINAL_BIN"
