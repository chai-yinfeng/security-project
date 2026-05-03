#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ioreg -rd1 -c IOPlatformExpertDevice | grep IOPlatformUUID
#   ./scripts/issue_for_device.sh <IOPlatformUUID> [output_name]
#
# Example:
#   ./scripts/issue_for_device.sh "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE" alice_demo
#
# Output:
#   artifacts/final/alice_demo

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

DEVICE_ID="${1:-}"
OUTPUT_NAME="${2:-license_demo_for_device}"

if [[ -z "$DEVICE_ID" ]]; then
  echo "usage: $0 <IOPlatformUUID> [output_name]" >&2
  exit 1
fi

TEMPLATE_BIN="$ROOT_DIR/artifacts/bin/license_demo"
FINAL_DIR="$ROOT_DIR/artifacts/final"
FINAL_BIN="$FINAL_DIR/$OUTPUT_NAME"

LICENSE_DIR="$ROOT_DIR/artifacts/signed_policy"
LICENSE_BLOB="$LICENSE_DIR/${OUTPUT_NAME}.license.bin"

mkdir -p "$ROOT_DIR/artifacts/bin" \
         "$ROOT_DIR/artifacts/signed_policy" \
         "$ROOT_DIR/artifacts/issuer" \
         "$ROOT_DIR/artifacts/final"

echo "[1/7] Generate placeholder license for initial Rust build"

python3 "$ROOT_DIR/scripts/issue_license.py" \
  --executable "$TEMPLATE_BIN" \
  --out "$ROOT_DIR/artifacts/signed_policy/license.bin" \
  --rust-public-key-out "$ROOT_DIR/src/rust_core/src/issuer_public_key.rs" \
  --placeholder-executable-hash

echo "[2/7] Build Rust core"

cargo build --manifest-path "$ROOT_DIR/src/rust_core/Cargo.toml"

echo "[3/7] Link C host + Rust core into template executable"

cc \
  "$ROOT_DIR/src/host_entry/main.c" \
  -I"$ROOT_DIR/include" \
  "$ROOT_DIR/src/rust_core/target/debug/librust_core.a" \
  -o "$TEMPLATE_BIN"

echo "[4/7] Codesign template executable"

codesign --force --sign - "$TEMPLATE_BIN"

echo "[5/7] Copy template executable to final output"

cp "$TEMPLATE_BIN" "$FINAL_BIN"

echo "[6/7] Issue license for target device and patch into final executable"

python3 "$ROOT_DIR/scripts/issue_license.py" \
  --device-id "$DEVICE_ID" \
  --product-id "coms6424.demo" \
  --valid-days 14 \
  --executable "$FINAL_BIN" \
  --out "$LICENSE_BLOB" \
  --rust-public-key-out "$ROOT_DIR/src/rust_core/src/issuer_public_key.rs" \
  --patch-macho-license-section

echo "[7/7] Codesign final executable after patching license section"

codesign --force --sign - "$FINAL_BIN"

echo
echo "Done."
echo "Target device ID: $DEVICE_ID"
echo "Final executable: $FINAL_BIN"
echo "License blob:      $LICENSE_BLOB"
echo
echo "You can send this executable to the target user:"
echo "  $FINAL_BIN"
echo
echo "They can run:"
echo "  chmod +x ./$(basename "$FINAL_BIN")"
echo "  ./$(basename "$FINAL_BIN")"