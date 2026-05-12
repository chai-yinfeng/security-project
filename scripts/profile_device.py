#!/usr/bin/env python3

import argparse
import json
import os
from pathlib import Path

import issue_license


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--product-id", default="coms6424.demo")
    parser.add_argument("--device-id")
    parser.add_argument(
        "--device-key-hex",
        help="32-byte deterministic override for tests; otherwise macOS Keychain is used",
    )
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    device_id = args.device_id or issue_license.query_device_identifier()
    device_key_override = args.device_key_hex or os.environ.get("COMS6424_DEVICE_KEY_HEX")
    device_secret = issue_license.load_or_create_keychain_device_secret(
        args.product_id,
        device_key_override,
    )
    se_result = issue_license.query_se_key()
    se_public_key = se_result[0] if se_result else None
    se_key_data = se_result[1] if se_result else None
    profile = issue_license.build_device_profile(
        args.product_id,
        device_id,
        device_secret,
        se_public_key,
        se_key_data,
    )

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(profile, indent=2, sort_keys=True) + "\n")

    print(f"wrote {out_path}")
    print(f"product_id={args.product_id}")
    print(f"device_id={device_id}")
    print(f"device_key_source={'override' if device_key_override else 'keychain'}")
    print(f"se_public_key={'present' if se_public_key else 'unavailable'}")


if __name__ == "__main__":
    main()
