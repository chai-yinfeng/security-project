use crate::error::LicenseError;
use crate::measurement;
use sha2::{Digest, Sha256};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

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

pub fn collect_runtime_environment() -> Result<RuntimeEnvironment, LicenseError> {
    let os = current_os();
    let arch = current_arch();

    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| LicenseError::RuntimeEnvironmentFailed)?
        .as_secs();

    let raw_device_id = query_device_identifier()?;
    let device_fingerprint_hash = hash_device_identifier(&raw_device_id);
    let device_key_material = derive_device_key_material(&raw_device_id);

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

fn derive_device_key_material(raw: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();

    hasher.update(b"COMS6424_DEVICE_PAYLOAD_KEY_V1");
    hasher.update(raw.as_bytes());

    hasher.finalize().into()
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
    use super::parse_ioplatform_uuid;
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
}
