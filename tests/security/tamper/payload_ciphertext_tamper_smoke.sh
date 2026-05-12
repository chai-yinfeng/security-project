#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../../.." && pwd)"
BIN="$ROOT_DIR/artifacts/bin/license_demo"
TAMPERED_BLOB="$ROOT_DIR/artifacts/signed_policy/license.payload_tamper.bin"
PYTHON_BIN="${PYTHON_BIN:-python3}"
export COMS6424_DEVICE_KEY_HEX="${COMS6424_DEVICE_KEY_HEX:-00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff}"

if ! "$PYTHON_BIN" -c "import cryptography" >/dev/null 2>&1; then
  if /opt/homebrew/anaconda3/bin/python3 -c "import cryptography" >/dev/null 2>&1; then
    PYTHON_BIN="/opt/homebrew/anaconda3/bin/python3"
  fi
fi

"$ROOT_DIR/scripts/build_pipeline.sh" >/tmp/coms6424_payload_tamper_build.log

"$PYTHON_BIN" - "$ROOT_DIR" "$BIN" "$TAMPERED_BLOB" <<'PY'
from pathlib import Path
import os
import struct
import sys
import time
import uuid

sys.path.insert(0, str(Path(sys.argv[1]) / "scripts"))
import issue_license

root = Path(sys.argv[1])
binary = sys.argv[2]
out_blob = Path(sys.argv[3])
product_id = "coms6424.demo"
device_id = issue_license.query_device_identifier()
device_secret = issue_license.load_or_create_keychain_device_secret(
    product_id,
    os.environ.get("COMS6424_DEVICE_KEY_HEX"),
)
se_result = issue_license.query_se_key()
se_public_key = se_result[0] if se_result else None
se_key_data = se_result[1] if se_result else None
profile = issue_license.build_device_profile(product_id, device_id, device_secret, se_public_key, se_key_data)
executable_hash = issue_license.sha256_file_measurement(binary)
license_id = uuid.uuid4().bytes
now = int(time.time())
protected_payload = issue_license.build_protected_payload(
    product_id,
    license_id,
    bytes.fromhex(profile["device_payload_key_material"]),
    executable_hash,
)
protected_payload[1]["ciphertext"] = (
    bytes([protected_payload[1]["ciphertext"][0] ^ 0x01])
    + protected_payload[1]["ciphertext"][1:]
)
policy = {
    "schema_version": issue_license.POLICY_SCHEMA_VERSION,
    "product_id": product_id,
    "license_id": license_id,
    "issued_at_unix": now,
    "not_before_unix": now,
    "not_after_unix": now + 14 * 24 * 3600,
    "platform": {"os": "macos", "arch": "arm64"},
    "device_fingerprint_hash": bytes.fromhex(profile["device_fingerprint_hash"]),
    "device_se_public_key": se_public_key if se_public_key else b"",
    "device_se_key_data": se_key_data if se_key_data else b"",
    "executable_hash": executable_hash,
    "protected_payload": protected_payload,
    "runtime_constraints": {
        "deny_debugger_attached": True,
        "deny_dyld_environment": True,
        "require_valid_code_signature": True,
        "max_clock_skew_seconds": 60,
    },
    "flags": 0,
}
private_key = issue_license.load_or_create_private_key(str(root / "artifacts/issuer/issuer_ed25519.pem"))
issue_license.write_public_key_rs(private_key, str(root / "src/rust_core/src/issuer_public_key.rs"))
policy_cbor = issue_license.encode_cbor(policy)
signature = private_key.sign(policy_cbor)
blob = (
    issue_license.MAGIC
    + struct.pack(">H", issue_license.BLOB_VERSION)
    + struct.pack(">I", len(policy_cbor))
    + policy_cbor
    + signature
)
out_blob.parent.mkdir(parents=True, exist_ok=True)
out_blob.write_bytes(blob)
issue_license.patch_macho_license_section(binary, str(out_blob))
PY

codesign --force --sign - "$BIN" >/tmp/coms6424_payload_tamper_codesign.log

set +e
OUTPUT="$("$BIN" 2>&1)"
STATUS=$?
set -e

printf '%s\n' "$OUTPUT"

if [[ $STATUS -eq 0 ]]; then
  echo "payload ciphertext tamper smoke test failed: binary exited successfully" >&2
  exit 1
fi

if [[ "$OUTPUT" != *"license denied"* ]]; then
  echo "payload ciphertext tamper smoke test failed: expected license denial output" >&2
  exit 1
fi
