#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
FINAL_BIN="$ROOT_DIR/artifacts/bin/license_demo"
LICENSE_BLOB="$ROOT_DIR/artifacts/signed_policy/license.bin"
PYTHON_BIN="${PYTHON_BIN:-python3}"

if ! "$PYTHON_BIN" -c "import cryptography" >/dev/null 2>&1; then
  if /opt/homebrew/anaconda3/bin/python3 -c "import cryptography" >/dev/null 2>&1; then
    PYTHON_BIN="/opt/homebrew/anaconda3/bin/python3"
  fi
fi

mkdir -p "$ROOT_DIR/artifacts/bin" "$ROOT_DIR/artifacts/signed_policy" "$ROOT_DIR/artifacts/issuer"

"$PYTHON_BIN" "$ROOT_DIR/scripts/issue_license.py" \
  --executable "$FINAL_BIN" \
  --out "$LICENSE_BLOB" \
  --rust-public-key-out "$ROOT_DIR/src/rust_core/src/issuer_public_key.rs" \
  --placeholder-executable-hash

cargo build --manifest-path "$ROOT_DIR/src/rust_core/Cargo.toml"

cc \
  "$ROOT_DIR/src/host_entry/main.c" \
  -I"$ROOT_DIR/include" \
  "$ROOT_DIR/src/rust_core/target/debug/librust_core.a" \
  -o "$FINAL_BIN"

codesign --force --sign - "$FINAL_BIN"

"$PYTHON_BIN" "$ROOT_DIR/scripts/issue_license.py" \
  --executable "$FINAL_BIN" \
  --out "$LICENSE_BLOB" \
  --rust-public-key-out "$ROOT_DIR/src/rust_core/src/issuer_public_key.rs" \
  --patch-macho-license-section

codesign --force --sign - "$FINAL_BIN"

"$FINAL_BIN"
