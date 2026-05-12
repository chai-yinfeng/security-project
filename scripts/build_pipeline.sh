#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
FINAL_BIN="$ROOT_DIR/artifacts/bin/license_demo"
LICENSE_BLOB="$ROOT_DIR/artifacts/signed_policy/license.bin"
SE_KEY_DAT="$ROOT_DIR/artifacts/se_key.dat"
PYTHON_BIN="${PYTHON_BIN:-python3}"

if ! "$PYTHON_BIN" -c "import cryptography" >/dev/null 2>&1; then
  if /opt/homebrew/anaconda3/bin/python3 -c "import cryptography" >/dev/null 2>&1; then
    PYTHON_BIN="/opt/homebrew/anaconda3/bin/python3"
  fi
fi

mkdir -p "$ROOT_DIR/artifacts/bin" "$ROOT_DIR/artifacts/signed_policy" "$ROOT_DIR/artifacts/issuer" "$ROOT_DIR/artifacts/obj"

SE_HELPER="$ROOT_DIR/tools/se_keygen_swift"
if [ ! -f "$SE_HELPER" ]; then
  swiftc "$ROOT_DIR/tools/se_keygen.swift" -o "$SE_HELPER"
  codesign --force --sign - "$SE_HELPER"
fi

SE_OUTPUT=$("$SE_HELPER" "$SE_KEY_DAT")
SE_PUBKEY=$(echo "$SE_OUTPUT" | head -1)
SE_KEYDATA=$(echo "$SE_OUTPUT" | tail -1)

"$PYTHON_BIN" "$ROOT_DIR/scripts/issue_license.py" \
  --executable "$FINAL_BIN" \
  --out "$LICENSE_BLOB" \
  --rust-public-key-out "$ROOT_DIR/src/rust_core/src/issuer_public_key.rs" \
  --placeholder-executable-hash \
  --se-public-key-hex "$SE_PUBKEY" \
  --se-key-data-hex "$SE_KEYDATA"

cargo build --manifest-path "$ROOT_DIR/src/rust_core/Cargo.toml"

swiftc -c -parse-as-library "$ROOT_DIR/tools/se_bridge.swift" -o "$ROOT_DIR/artifacts/obj/se_bridge.o"

cc -c \
  "$ROOT_DIR/src/host_entry/main.c" \
  -I"$ROOT_DIR/include" \
  -o "$ROOT_DIR/artifacts/obj/main.o"

swiftc \
  "$ROOT_DIR/artifacts/obj/main.o" \
  "$ROOT_DIR/src/rust_core/target/debug/librust_core.a" \
  "$ROOT_DIR/artifacts/obj/se_bridge.o" \
  -framework Security \
  -framework CoreFoundation \
  -o "$FINAL_BIN"

codesign --force --sign - "$FINAL_BIN"

"$PYTHON_BIN" "$ROOT_DIR/scripts/issue_license.py" \
  --executable "$FINAL_BIN" \
  --out "$LICENSE_BLOB" \
  --rust-public-key-out "$ROOT_DIR/src/rust_core/src/issuer_public_key.rs" \
  --patch-macho-license-section \
  --se-public-key-hex "$SE_PUBKEY" \
  --se-key-data-hex "$SE_KEYDATA"

codesign --force --sign - "$FINAL_BIN"

"$FINAL_BIN"
