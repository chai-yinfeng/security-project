#!/usr/bin/env python3

import argparse
import hmac
import hashlib
import os
import subprocess
import struct
import time
import uuid
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


MAGIC = b"SLC1"
BLOB_VERSION = 1
POLICY_SCHEMA_VERSION = 1
PAYLOAD_SCHEMA_VERSION = 2
ZERO_SHA256 = bytes(32)
KEYCHAIN_SERVICE = "coms6424.license-demo.device-key"
MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
LC_CODE_SIGNATURE = 0x1D
LICENSE_SEGMENT = "__TEXT"
LICENSE_SECTION = "__license"
MEASURED_SECTIONS = (
    ("__TEXT", "__text"),
    ("__TEXT", "__stubs"),
    ("__TEXT", "__cstring"),
    ("__TEXT", "__const"),
    ("__TEXT", "__gcc_except_tab"),
    ("__TEXT", "__unwind_info"),
    ("__TEXT", "__eh_frame"),
    ("__DATA_CONST", "__got"),
    ("__DATA_CONST", "__const"),
)


def sha256_device(raw: str) -> bytes:
    h = hashlib.sha256()
    h.update(b"COMS6424_DEVICE_FINGERPRINT_V1")
    h.update(raw.encode("utf-8"))
    return h.digest()


def hkdf_sha256(salt: bytes, ikm: bytes, info: bytes) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


def load_or_create_keychain_device_secret(product_id: str, override_hex: str | None = None) -> bytes:
    if override_hex:
        raw = bytes.fromhex(override_hex)
        if len(raw) != 32:
            raise ValueError("device key override must be exactly 32 bytes")
        return raw

    try:
        existing = subprocess.check_output(
            [
                "/usr/bin/security",
                "find-generic-password",
                "-s",
                KEYCHAIN_SERVICE,
                "-a",
                product_id,
                "-w",
            ],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
        raw = bytes.fromhex(existing)
        if len(raw) == 32:
            return raw
    except (subprocess.CalledProcessError, FileNotFoundError, ValueError):
        pass

    secret = os.urandom(32)
    subprocess.check_call(
        [
            "/usr/bin/security",
            "add-generic-password",
            "-U",
            "-s",
            KEYCHAIN_SERVICE,
            "-a",
            product_id,
            "-w",
            secret.hex(),
        ],
    )
    return secret


def device_payload_key_material(device_id: str, product_id: str, device_secret: bytes) -> bytes:
    ikm = device_id.encode("utf-8") + b"\x00" + product_id.encode("utf-8")
    return hkdf_sha256(
        device_secret,
        ikm,
        b"COMS6424_DEVICE_PAYLOAD_KEY_V2",
    )


def derive_capability_session_key(
    product_id: str,
    license_id: bytes,
    device_id: str,
    device_secret: bytes,
    executable_hash: bytes,
) -> bytes:
    ikm = product_id.encode("utf-8") + b"\x00" + license_id + executable_hash
    return hkdf_sha256(
        device_payload_key_material(device_id, product_id, device_secret),
        ikm,
        b"COMS6424_CAPABILITY_SESSION_V2",
    )


def initial_payload_chain_hash(product_id: str, license_id: bytes, executable_hash: bytes) -> bytes:
    h = hashlib.sha256()
    h.update(b"COMS6424_PAYLOAD_CHAIN_V2")
    h.update(product_id.encode("utf-8"))
    h.update(b"\x00")
    h.update(license_id)
    h.update(executable_hash)
    return h.digest()


def next_payload_chain_hash(previous: bytes, plaintext: bytes) -> bytes:
    h = hashlib.sha256()
    h.update(b"COMS6424_PAYLOAD_CHAIN_STEP_V2")
    h.update(previous)
    h.update(hashlib.sha256(plaintext).digest())
    return h.digest()


def derive_block_key(session_key: bytes, block_id: int, chain_hash: bytes) -> bytes:
    info = b"COMS6424_PAYLOAD_BLOCK_KEY_V2"
    info += struct.pack(">Q", block_id)
    info += chain_hash
    return hkdf_sha256(session_key, b"", info)


def append_len_prefixed(payload: bytearray, value: bytes):
    payload.extend(struct.pack(">I", len(value)))
    payload.extend(value)


def payload_associated_data(
    product_id: str,
    license_id: bytes,
    executable_hash: bytes,
    block_id: int,
    chain_hash: bytes,
) -> bytes:
    out = bytearray()
    out.extend(b"COMS6424_PAYLOAD_AD_V2")
    out.extend(struct.pack(">H", POLICY_SCHEMA_VERSION))
    out.extend(struct.pack(">H", PAYLOAD_SCHEMA_VERSION))
    out.extend(struct.pack(">H", PAYLOAD_SCHEMA_VERSION))
    out.extend(struct.pack(">Q", block_id))
    out.extend(chain_hash)
    append_len_prefixed(out, product_id.encode("utf-8"))
    out.extend(license_id)
    out.extend(executable_hash)
    return bytes(out)


def build_protected_payload(
    product_id: str,
    license_id: bytes,
    device_id: str,
    device_secret: bytes,
    executable_hash: bytes,
) -> list[dict]:
    plaintext_blocks = {
        1: b"phase 1 defused: handshake wire matched the licensed silicon",
        2: b"phase 2 rulebook: fibonacci wires; rotate=5; alpha=7; beta=11; gamma=13; checksum=0x6424",
        3: b"phase 3 defused: the secret stage unlocks the protected path",
    }

    session_key = derive_capability_session_key(
        product_id,
        license_id,
        device_id,
        device_secret,
        executable_hash,
    )

    blocks = []
    chain_hash = initial_payload_chain_hash(product_id, license_id, executable_hash)
    for block_id in sorted(plaintext_blocks):
        plaintext = plaintext_blocks[block_id]
        block_key = derive_block_key(session_key, block_id, chain_hash)
        nonce = os.urandom(12)
        associated_data = payload_associated_data(
            product_id,
            license_id,
            executable_hash,
            block_id,
            chain_hash,
        )
        ciphertext = ChaCha20Poly1305(block_key).encrypt(
            nonce,
            plaintext,
            associated_data,
        )
        blocks.append({
            "payload_schema_version": PAYLOAD_SCHEMA_VERSION,
            "block_id": block_id,
            "nonce": nonce,
            "ciphertext": ciphertext,
        })
        chain_hash = next_payload_chain_hash(chain_hash, plaintext)

    return blocks


def sha256_file_measurement(path: str, embedded_blob_path: str | None = None) -> bytes:
    with open(path, "rb") as f:
        payload = f.read()

    if embedded_blob_path is not None:
        # Backward-compatible flag: older callers passed the current blob path.
        # The physical exclusion is now the Mach-O section that carries it.
        pass

    h = hashlib.sha256()
    h.update(b"COMS6424_EXECUTABLE_IMAGE_V2")

    sections = find_macho_sections(payload)
    for segment, section in MEASURED_SECTIONS:
        section_info = sections.get((segment, section))
        if section_info is None:
            continue

        section_offset, section_size = section_info
        section_bytes = payload[section_offset:section_offset + section_size]
        h.update(segment.encode("utf-8"))
        h.update(b"\x00")
        h.update(section.encode("utf-8"))
        h.update(b"\x00")
        h.update(struct.pack(">Q", len(section_bytes)))
        h.update(section_bytes)

    return h.digest()


def zero_macho_code_signature(payload: bytes) -> bytes:
    if len(payload) < 32:
        raise ValueError("Mach-O payload too short")

    magic = struct.unpack_from("<I", payload, 0)[0]
    if magic != MH_MAGIC_64:
        raise ValueError("only thin 64-bit Mach-O binaries are supported")

    ncmds = struct.unpack_from("<I", payload, 16)[0]
    offset = 32
    patched = bytearray(payload)

    for _ in range(ncmds):
        if offset + 8 > len(patched):
            raise ValueError("truncated load command header")

        cmd, cmdsize = struct.unpack_from("<II", patched, offset)
        if cmdsize < 8 or offset + cmdsize > len(patched):
            raise ValueError("invalid load command size")

        if cmd == LC_CODE_SIGNATURE:
            if cmdsize < 16:
                raise ValueError("invalid LC_CODE_SIGNATURE command")

            dataoff, datasize = struct.unpack_from("<II", patched, offset + 8)
            end = dataoff + datasize
            if end > len(patched):
                raise ValueError("code signature range exceeds file length")

            patched[offset:offset + cmdsize] = b"\x00" * cmdsize
            patched[dataoff:end] = b"\x00" * datasize

        offset += cmdsize

    return bytes(patched)


def zero_macho_license_section(payload: bytes) -> bytes:
    section_offset, section_size = find_macho_section(
        payload,
        LICENSE_SEGMENT,
        LICENSE_SECTION,
    )
    patched = bytearray(payload)
    patched[section_offset:section_offset + section_size] = b"\x00" * section_size
    return bytes(patched)


def patch_macho_license_section(executable_path: str, blob_path: str):
    with open(executable_path, "rb") as f:
        payload = bytearray(f.read())
    with open(blob_path, "rb") as f:
        blob = f.read()

    section_offset, section_size = find_macho_section(
        bytes(payload),
        LICENSE_SEGMENT,
        LICENSE_SECTION,
    )

    if len(blob) != section_size:
        raise ValueError(
            f"license blob length {len(blob)} does not match "
            f"Mach-O section size {section_size}"
        )

    payload[section_offset:section_offset + section_size] = blob

    with open(executable_path, "wb") as f:
        f.write(payload)

    print(
        f"patched {executable_path} "
        f"{LICENSE_SEGMENT},{LICENSE_SECTION} at file offset {section_offset}"
    )


def find_macho_section(payload: bytes, segment_name: str, section_name: str) -> tuple[int, int]:
    try:
        return find_macho_sections(payload)[(segment_name, section_name)]
    except KeyError:
        raise ValueError(f"Mach-O section {segment_name},{section_name} not found")


def find_macho_sections(payload: bytes) -> dict[tuple[str, str], tuple[int, int]]:
    if len(payload) < 32:
        raise ValueError("Mach-O payload too short")

    magic = struct.unpack_from("<I", payload, 0)[0]
    if magic != MH_MAGIC_64:
        raise ValueError("only thin 64-bit Mach-O binaries are supported")

    ncmds = struct.unpack_from("<I", payload, 16)[0]
    offset = 32
    sections = {}

    for _ in range(ncmds):
        if offset + 8 > len(payload):
            raise ValueError("truncated load command header")

        cmd, cmdsize = struct.unpack_from("<II", payload, offset)
        if cmdsize < 8 or offset + cmdsize > len(payload):
            raise ValueError("invalid load command size")

        if cmd == LC_SEGMENT_64:
            if cmdsize < 72:
                raise ValueError("invalid LC_SEGMENT_64 command")

            segname = read_fixed_name(payload, offset + 8)
            nsects = struct.unpack_from("<I", payload, offset + 64)[0]
            section_offset = offset + 72

            for _ in range(nsects):
                if section_offset + 80 > offset + cmdsize:
                    raise ValueError("section header exceeds LC_SEGMENT_64 command")

                sectname = read_fixed_name(payload, section_offset)
                section_segname = read_fixed_name(payload, section_offset + 16)
                if section_segname != segname:
                    raise ValueError("section segment name does not match parent segment")

                section_size = struct.unpack_from("<Q", payload, section_offset + 40)[0]
                file_offset = struct.unpack_from("<I", payload, section_offset + 48)[0]
                end = file_offset + section_size
                if end > len(payload):
                    raise ValueError("section range exceeds file length")
                sections[(section_segname, sectname)] = (file_offset, section_size)

                section_offset += 80

        offset += cmdsize

    return sections


def read_fixed_name(payload: bytes, offset: int) -> str:
    raw = payload[offset:offset + 16]
    return raw.split(b"\x00", 1)[0].decode("utf-8")


def query_device_identifier() -> str:
    output = subprocess.check_output(
        ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
        text=True,
    )

    for line in output.splitlines():
        if "IOPlatformUUID" in line:
            parts = line.split('"')
            if len(parts) >= 4:
                return parts[3]

    raise RuntimeError("failed to read IOPlatformUUID from ioreg output")


def encode_uint(major_type: int, value: int) -> bytes:
    if value < 0:
        raise ValueError("value must be non-negative")

    if value < 24:
        return bytes([(major_type << 5) | value])
    if value < 256:
        return bytes([(major_type << 5) | 24, value])
    if value < 65536:
        return bytes([(major_type << 5) | 25]) + struct.pack(">H", value)
    if value < 2**32:
        return bytes([(major_type << 5) | 26]) + struct.pack(">I", value)
    if value < 2**64:
        return bytes([(major_type << 5) | 27]) + struct.pack(">Q", value)

    raise ValueError("integer too large for this schema")


def encode_cbor(value) -> bytes:
    if isinstance(value, bool):
        return b"\xf5" if value else b"\xf4"

    if value is None:
        return b"\xf6"

    if isinstance(value, int):
        if value >= 0:
            return encode_uint(0, value)
        return encode_uint(1, -1 - value)

    if isinstance(value, bytes):
        return encode_uint(2, len(value)) + value

    if isinstance(value, str):
        raw = value.encode("utf-8")
        return encode_uint(3, len(raw)) + raw

    if isinstance(value, (list, tuple)):
        encoded_items = b"".join(encode_cbor(item) for item in value)
        return encode_uint(4, len(value)) + encoded_items

    if isinstance(value, dict):
        encoded_items = []

        for key, item_value in value.items():
            encoded_key = encode_cbor(key)
            encoded_value = encode_cbor(item_value)
            encoded_items.append((encoded_key, encoded_value))

        encoded_items.sort(key=lambda pair: (len(pair[0]), pair[0]))

        payload = b"".join(key + item for key, item in encoded_items)
        return encode_uint(5, len(value)) + payload

    raise TypeError(f"unsupported CBOR type: {type(value)!r}")


def load_or_create_private_key(path: str) -> Ed25519PrivateKey:
    if os.path.exists(path):
        with open(path, "rb") as f:
            raw = f.read()

        return serialization.load_pem_private_key(raw, password=None)

    key = Ed25519PrivateKey.generate()

    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    os.makedirs(os.path.dirname(path), exist_ok=True)

    with open(path, "wb") as f:
        f.write(pem)

    return key


def write_public_key_rs(private_key: Ed25519PrivateKey, out_path: str):
    pub = private_key.public_key()
    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    arr = ", ".join(f"0x{x:02x}" for x in raw)

    content = f"""pub const ISSUER_PUBLIC_KEY_BYTES: [u8; 32] = [
    {arr}
];
"""

    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    with open(out_path, "w") as f:
        f.write(content)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--device-id")
    parser.add_argument(
        "--device-key-hex",
        help="32-byte hex override for tests; otherwise a macOS Keychain secret is used",
    )
    parser.add_argument("--product-id", default="coms6424.demo")
    parser.add_argument("--valid-days", type=int, default=14)
    parser.add_argument("--private-key", default="artifacts/issuer/issuer_ed25519.pem")
    parser.add_argument("--executable", required=True)
    parser.add_argument("--out", default="artifacts/signed_policy/license.bin")
    parser.add_argument(
        "--rust-public-key-out",
        default="src/rust_core/src/issuer_public_key.rs",
    )
    parser.add_argument("--embedded-blob-path")
    parser.add_argument("--executable-hash-hex")
    parser.add_argument(
        "--patch-macho-license-section",
        action="store_true",
        help=f"write --out into the {LICENSE_SEGMENT},{LICENSE_SECTION} Mach-O section",
    )
    parser.add_argument(
        "--placeholder-executable-hash",
        action="store_true",
        help="use 32 zero bytes as the executable measurement",
    )
    args = parser.parse_args()

    private_key = load_or_create_private_key(args.private_key)
    write_public_key_rs(private_key, args.rust_public_key_out)

    now = int(time.time())
    device_id = args.device_id or query_device_identifier()
    device_key_override = args.device_key_hex or os.environ.get("COMS6424_DEVICE_KEY_HEX")
    device_secret = load_or_create_keychain_device_secret(args.product_id, device_key_override)

    if args.placeholder_executable_hash and args.executable_hash_hex:
        raise ValueError("choose only one executable hash override mode")

    if args.placeholder_executable_hash:
        executable_hash = ZERO_SHA256
    elif args.executable_hash_hex:
        executable_hash = bytes.fromhex(args.executable_hash_hex)
        if len(executable_hash) != 32:
            raise ValueError("executable hash must be exactly 32 bytes")
    else:
        executable_hash = sha256_file_measurement(
            args.executable,
            embedded_blob_path=args.embedded_blob_path,
        )

    license_id = uuid.uuid4().bytes
    policy = {
        "schema_version": POLICY_SCHEMA_VERSION,
        "product_id": args.product_id,
        "license_id": license_id,
        "issued_at_unix": now,
        "not_before_unix": now,
        "not_after_unix": now + args.valid_days * 24 * 3600,
        "platform": {
            "os": "macos",
            "arch": "arm64",
        },
        "device_fingerprint_hash": sha256_device(device_id),
        "executable_hash": executable_hash,
        "protected_payload": build_protected_payload(
            args.product_id,
            license_id,
            device_id,
            device_secret,
            executable_hash,
        ),
        "runtime_constraints": {
            "deny_debugger_attached": True,
            "deny_dyld_environment": True,
            "require_valid_code_signature": True,
        },
        "flags": 0,
    }

    policy_cbor = encode_cbor(policy)
    signature = private_key.sign(policy_cbor)

    blob = MAGIC
    blob += struct.pack(">H", BLOB_VERSION)
    blob += struct.pack(">I", len(policy_cbor))
    blob += policy_cbor
    blob += signature

    os.makedirs(os.path.dirname(args.out), exist_ok=True)

    with open(args.out, "wb") as f:
        f.write(blob)

    print(f"wrote {args.out}")
    print(f"policy_len={len(policy_cbor)}")
    print(f"signature_len={len(signature)}")
    print(f"device_id={device_id}")
    print(f"device_key_source={'override' if device_key_override else 'keychain'}")
    print(f"executable_hash={executable_hash.hex()}")

    if args.patch_macho_license_section:
        patch_macho_license_section(args.executable, args.out)


if __name__ == "__main__":
    main()
