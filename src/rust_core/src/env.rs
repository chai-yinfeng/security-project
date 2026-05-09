use crate::error::LicenseError;
use crate::measurement;
use sha2::{Digest, Sha256};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const KEYCHAIN_SERVICE: &str = "coms6424.license-demo.device-key";

#[derive(Debug, Clone)]
pub struct RuntimeEnvironment {
    pub os: &'static str,
    pub arch: &'static str,
    pub now_unix: u64,
    pub device_fingerprint_hash: [u8; 32],
    pub device_key_material: [u8; 32],
    pub executable_hash: [u8; 32],
    pub debugger_attached: bool,
    pub dyld_environment_present: bool,
    pub code_signature_valid: bool,
}

pub fn collect_runtime_environment(product_id: &str) -> Result<RuntimeEnvironment, LicenseError> {
    let os = current_os();
    let arch = current_arch();

    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| LicenseError::RuntimeEnvironmentFailed)?
        .as_secs();

    let raw_device_id = query_device_identifier()?;
    let device_fingerprint_hash = hash_device_identifier(&raw_device_id);
    let device_key_material = derive_device_key_material(&raw_device_id, product_id)?;

    let executable_hash = hash_current_executable()?;
    let debugger_attached = debugger_attached();
    let dyld_environment_present = dyld_environment_present();
    let code_signature_valid = verify_current_executable_code_signature()?;

    Ok(RuntimeEnvironment {
        os,
        arch,
        now_unix,
        device_fingerprint_hash,
        device_key_material,
        executable_hash,
        debugger_attached,
        dyld_environment_present,
        code_signature_valid,
    })
}

fn current_os() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "macos"
    }

    #[cfg(not(target_os = "macos"))]
    {
        "unsupported"
    }
}

fn current_arch() -> &'static str {
    #[cfg(target_arch = "aarch64")]
    {
        "arm64"
    }

    #[cfg(not(target_arch = "aarch64"))]
    {
        "unsupported"
    }
}

fn query_device_identifier() -> Result<String, LicenseError> {
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("ioreg")
            .args(["-rd1", "-c", "IOPlatformExpertDevice"])
            .output()
            .map_err(|_| LicenseError::RuntimeEnvironmentFailed)?;

        if !output.status.success() {
            return Err(LicenseError::RuntimeEnvironmentFailed);
        }

        let stdout =
            String::from_utf8(output.stdout).map_err(|_| LicenseError::RuntimeEnvironmentFailed)?;

        parse_ioplatform_uuid(&stdout)
    }

    #[cfg(not(target_os = "macos"))]
    {
        Err(LicenseError::UnsupportedPlatform)
    }
}

fn parse_ioplatform_uuid(ioreg_output: &str) -> Result<String, LicenseError> {
    for line in ioreg_output.lines() {
        if line.contains("IOPlatformUUID") {
            let parts: Vec<&str> = line.split('"').collect();

            if parts.len() >= 4 {
                return Ok(parts[3].to_string());
            }
        }
    }

    Err(LicenseError::RuntimeEnvironmentFailed)
}

fn hash_device_identifier(raw: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();

    hasher.update(b"COMS6424_DEVICE_FINGERPRINT_V1");
    hasher.update(raw.as_bytes());

    hasher.finalize().into()
}

fn derive_device_key_material(
    raw_device_id: &str,
    product_id: &str,
) -> Result<[u8; 32], LicenseError> {
    let secret = load_or_create_keychain_device_secret(product_id)?;
    let mut ikm = Vec::new();
    ikm.extend_from_slice(raw_device_id.as_bytes());
    ikm.push(0);
    ikm.extend_from_slice(product_id.as_bytes());

    let material = hkdf_sha256(&secret, &ikm, b"COMS6424_DEVICE_PAYLOAD_KEY_V2");

    zeroize_array(secret);
    zeroize_vec(&mut ikm);

    Ok(material)
}

fn load_or_create_keychain_device_secret(product_id: &str) -> Result<[u8; 32], LicenseError> {
    if let Some(raw) = std::env::var_os("COMS6424_DEVICE_KEY_HEX") {
        return parse_hex_32(&raw.to_string_lossy());
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(secret) = find_keychain_device_secret(product_id)? {
            return Ok(secret);
        }

        let mut secret = [0u8; 32];
        unsafe {
            libc::arc4random_buf(secret.as_mut_ptr().cast(), secret.len());
        }

        let encoded = encode_hex(&secret);
        let status = Command::new("/usr/bin/security")
            .args([
                "add-generic-password",
                "-U",
                "-s",
                KEYCHAIN_SERVICE,
                "-a",
                product_id,
                "-w",
                &encoded,
            ])
            .status()
            .map_err(|_| LicenseError::RuntimeEnvironmentFailed)?;

        if !status.success() {
            zeroize_array(secret);
            return Err(LicenseError::RuntimeEnvironmentFailed);
        }

        Ok(secret)
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = product_id;
        Err(LicenseError::UnsupportedPlatform)
    }
}

#[cfg(target_os = "macos")]
fn find_keychain_device_secret(product_id: &str) -> Result<Option<[u8; 32]>, LicenseError> {
    let output = Command::new("/usr/bin/security")
        .args([
            "find-generic-password",
            "-s",
            KEYCHAIN_SERVICE,
            "-a",
            product_id,
            "-w",
        ])
        .output()
        .map_err(|_| LicenseError::RuntimeEnvironmentFailed)?;

    if !output.status.success() {
        return Ok(None);
    }

    let stdout =
        String::from_utf8(output.stdout).map_err(|_| LicenseError::RuntimeEnvironmentFailed)?;
    parse_hex_32(stdout.trim()).map(Some)
}

fn parse_hex_32(input: &str) -> Result<[u8; 32], LicenseError> {
    let raw = input.trim();
    if raw.len() != 64 {
        return Err(LicenseError::RuntimeEnvironmentFailed);
    }

    let mut out = [0u8; 32];
    for (idx, chunk) in raw.as_bytes().chunks_exact(2).enumerate() {
        let text =
            std::str::from_utf8(chunk).map_err(|_| LicenseError::RuntimeEnvironmentFailed)?;
        out[idx] =
            u8::from_str_radix(text, 16).map_err(|_| LicenseError::RuntimeEnvironmentFailed)?;
    }

    Ok(out)
}

fn encode_hex(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let prk = hmac_sha256(salt, ikm);
    let mut expand_input = Vec::new();
    expand_input.extend_from_slice(info);
    expand_input.push(1);
    let okm = hmac_sha256(&prk, &expand_input);
    zeroize_array(prk);
    zeroize_vec(&mut expand_input);
    okm
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const SHA256_BLOCK_LEN: usize = 64;

    let mut normalized_key = [0u8; SHA256_BLOCK_LEN];
    if key.len() > SHA256_BLOCK_LEN {
        normalized_key[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        normalized_key[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; SHA256_BLOCK_LEN];
    let mut opad = [0x5cu8; SHA256_BLOCK_LEN];
    for idx in 0..SHA256_BLOCK_LEN {
        ipad[idx] ^= normalized_key[idx];
        opad[idx] ^= normalized_key[idx];
    }

    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(message);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_hash);

    normalized_key.fill(0);
    ipad.fill(0);
    opad.fill(0);

    outer.finalize().into()
}

fn zeroize_array<const N: usize>(mut bytes: [u8; N]) {
    bytes.fill(0);
    std::hint::black_box(bytes);
}

fn zeroize_vec(bytes: &mut Vec<u8>) {
    bytes.fill(0);
    std::hint::black_box(bytes);
}

/// First implementation placeholder.
///
/// In the full version, this should hash selected Mach-O regions:
/// - protected application code
/// - Rust checker code if measurable
/// - selected read-only metadata
///
/// It must exclude:
/// - embedded license section
/// - code signature
/// - mutable data
pub fn hash_current_executable() -> Result<[u8; 32], LicenseError> {
    let path = std::env::current_exe().map_err(|_| LicenseError::RuntimeEnvironmentFailed)?;
    let bytes = std::fs::read(path).map_err(|_| LicenseError::RuntimeEnvironmentFailed)?;
    measurement::hash_executable_image(&bytes)
}

fn debugger_attached() -> bool {
    if std::env::var_os("COMS6424_SIMULATE_DEBUGGER").is_some() {
        return true;
    }

    #[cfg(target_os = "macos")]
    {
        const P_TRACED: u32 = 0x0000_0800;

        let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
        let info_size = std::mem::size_of::<libc::proc_bsdinfo>() as i32;
        let result = unsafe {
            libc::proc_pidinfo(
                libc::getpid(),
                libc::PROC_PIDTBSDINFO,
                0,
                info.as_mut_ptr().cast(),
                info_size,
            )
        };

        if result == info_size {
            let info = unsafe { info.assume_init() };
            return (info.pbi_flags & P_TRACED) != 0;
        }
    }

    false
}

fn dyld_environment_present() -> bool {
    const DYLD_ENV_KEYS: &[&str] = &[
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "DYLD_FRAMEWORK_PATH",
        "DYLD_FALLBACK_LIBRARY_PATH",
        "DYLD_FALLBACK_FRAMEWORK_PATH",
    ];

    DYLD_ENV_KEYS
        .iter()
        .any(|key| std::env::var_os(key).is_some())
}

fn verify_current_executable_code_signature() -> Result<bool, LicenseError> {
    #[cfg(target_os = "macos")]
    {
        let path = std::env::current_exe().map_err(|_| LicenseError::RuntimeEnvironmentFailed)?;
        let status = Command::new("/usr/bin/codesign")
            .args(["--verify", "--strict"])
            .arg(path)
            .status()
            .map_err(|_| LicenseError::RuntimeEnvironmentFailed)?;

        Ok(status.success())
    }

    #[cfg(not(target_os = "macos"))]
    {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_hex_32, parse_ioplatform_uuid};
    use crate::error::LicenseError;

    #[test]
    fn parses_ioplatform_uuid_from_ioreg_output() {
        let sample = r#"
            | |   "IOPlatformUUID" = "F6860FD3-99A1-5C05-8C2B-946F5F0832FD"
        "#;

        let parsed = parse_ioplatform_uuid(sample).unwrap();

        assert_eq!(parsed, "F6860FD3-99A1-5C05-8C2B-946F5F0832FD");
    }

    #[test]
    fn rejects_ioreg_output_without_uuid() {
        let sample = r#"
            | |   "SomeOtherField" = "value"
        "#;

        let result = parse_ioplatform_uuid(sample);

        assert!(matches!(
            result,
            Err(LicenseError::RuntimeEnvironmentFailed)
        ));
    }

    #[test]
    fn parses_device_key_hex_override() {
        let parsed =
            parse_hex_32("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
                .unwrap();

        assert_eq!(parsed[0], 0);
        assert_eq!(parsed[31], 31);
    }
}
