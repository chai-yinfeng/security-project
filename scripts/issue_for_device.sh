#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   target user:
#     ./scripts/profile_device.py --out artifacts/device_profiles/alice.json
#   issuer:
#     ./scripts/issue_for_device.sh artifacts/device_profiles/alice.json [output_name]
#
# Example:
#   ./scripts/issue_for_device.sh artifacts/device_profiles/alice.json alice_demo
#
# Output:
#   artifacts/final/alice_demo

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

DEVICE_PROFILE="${1:-}"
OUTPUT_NAME="${2:-license_demo_for_device}"

if [[ -z "$DEVICE_PROFILE" ]]; then
  echo "usage: $0 <device_profile.json> [output_name]" >&2
  exit 1
fi

if [[ ! -f "$DEVICE_PROFILE" ]]; then
  echo "device profile not found: $DEVICE_PROFILE" >&2
  exit 1
fi

TEMPLATE_BIN="$ROOT_DIR/artifacts/bin/license_demo.template"
FINAL_DIR="$ROOT_DIR/artifacts/final"
FINAL_BIN="$FINAL_DIR/$OUTPUT_NAME"

LICENSE_DIR="$ROOT_DIR/artifacts/signed_policy"
LICENSE_BLOB="$LICENSE_DIR/${OUTPUT_NAME}.license.bin"

mkdir -p "$ROOT_DIR/artifacts/bin" \
         "$ROOT_DIR/artifacts/signed_policy" \
         "$ROOT_DIR/artifacts/issuer" \
         "$ROOT_DIR/artifacts/final"

mkdir -p "$ROOT_DIR/artifacts/obj"

SE_PUBKEY=$(python3 -c "import json,sys; p=json.load(open(sys.argv[1])); print(p.get('device_se_public_key',''))" "$DEVICE_PROFILE")
SE_KEYDATA=$(python3 -c "import json,sys; p=json.load(open(sys.argv[1])); print(p.get('device_se_key_data',''))" "$DEVICE_PROFILE")

SE_ARGS=()
if [ -n "$SE_PUBKEY" ]; then
  SE_ARGS+=(--se-public-key-hex "$SE_PUBKEY" --se-key-data-hex "$SE_KEYDATA")
fi

echo "[1/7] Generate placeholder license for initial Rust build"

python3 "$ROOT_DIR/scripts/issue_license.py" \
  --executable "$TEMPLATE_BIN" \
  --out "$ROOT_DIR/artifacts/signed_policy/license.bin" \
  --rust-public-key-out "$ROOT_DIR/src/rust_core/src/issuer_public_key.rs" \
  --placeholder-executable-hash \
  "${SE_ARGS[@]}"

echo "[2/7] Build Rust core"

cargo build --manifest-path "$ROOT_DIR/src/rust_core/Cargo.toml"

echo "[3/7] Link C host + Rust core + Swift SE bridge into template executable"

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
  -o "$TEMPLATE_BIN"

echo "[4/7] Codesign template executable"

codesign --force --sign - "$TEMPLATE_BIN"

echo "[5/7] Copy template executable to final output"

cp "$TEMPLATE_BIN" "$FINAL_BIN"

echo "[6/7] Issue license for target device and patch into final executable"

python3 "$ROOT_DIR/scripts/issue_license.py" \
  --device-profile "$DEVICE_PROFILE" \
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
echo "Target profile:   $DEVICE_PROFILE"
echo "Final executable: $FINAL_BIN"
echo "License blob:      $LICENSE_BLOB"
echo
echo "You can send this executable to the target user:"
echo "  $FINAL_BIN"
echo
echo "They can run:"
echo "  chmod +x ./$(basename "$FINAL_BIN")"
echo "  ./$(basename "$FINAL_BIN")"
