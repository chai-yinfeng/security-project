use crate::error::LicenseError;
use sha2::{Digest, Sha256};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const MH_MAGIC_64: u32 = 0xFEEDFACF;
const LC_CODE_SIGNATURE: u32 = 0x1D;

#[derive(Debug, Clone)]
pub struct RuntimeEnvironment {
    pub os: &'static str,
    pub arch: &'static str,
    pub now_unix: u64,
    pub device_fingerprint_hash: [u8; 32],
    pub executable_hash: [u8; 32],
}

pub fn collect_runtime_environment(
    embedded_blob: &[u8],
) -> Result<RuntimeEnvironment, LicenseError> {
    let os = current_os();
    let arch = current_arch();

    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| LicenseError::RuntimeEnvironmentFailed)?
        .as_secs();

    let raw_device_id = query_device_identifier()?;
    let device_fingerprint_hash = hash_device_identifier(&raw_device_id);

    let executable_hash = hash_current_executable(embedded_blob)?;

    Ok(RuntimeEnvironment {
        os,
        arch,
        now_unix,
        device_fingerprint_hash,
        executable_hash,
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
pub fn hash_current_executable(embedded_blob: &[u8]) -> Result<[u8; 32], LicenseError> {
    let path = std::env::current_exe().map_err(|_| LicenseError::RuntimeEnvironmentFailed)?;

    let mut bytes = std::fs::read(path).map_err(|_| LicenseError::RuntimeEnvironmentFailed)?;

    zero_unique_embedded_blob(&mut bytes, embedded_blob)?;
    zero_macho_code_signature(&mut bytes)?;

    let mut hasher = Sha256::new();

    hasher.update(b"COMS6424_EXECUTABLE_IMAGE_V1");
    hasher.update(&bytes);

    Ok(hasher.finalize().into())
}

fn zero_unique_embedded_blob(haystack: &mut [u8], needle: &[u8]) -> Result<(), LicenseError> {
    if needle.is_empty() {
        return Err(LicenseError::RuntimeEnvironmentFailed);
    }

    let Some(first) = find_subslice(haystack, needle) else {
        return Err(LicenseError::RuntimeEnvironmentFailed);
    };

    if find_subslice(&haystack[first + 1..], needle).is_some() {
        return Err(LicenseError::RuntimeEnvironmentFailed);
    }

    let end = first + needle.len();
    haystack[first..end].fill(0);
    Ok(())
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn zero_macho_code_signature(payload: &mut [u8]) -> Result<(), LicenseError> {
    if payload.len() < 32 {
        return Err(LicenseError::RuntimeEnvironmentFailed);
    }

    if read_u32_le(payload, 0)? != MH_MAGIC_64 {
        return Err(LicenseError::RuntimeEnvironmentFailed);
    }

    let ncmds = read_u32_le(payload, 16)? as usize;
    let mut offset = 32usize;

    for _ in 0..ncmds {
        let cmd = read_u32_le(payload, offset)?;
        let cmdsize = read_u32_le(payload, offset + 4)? as usize;

        if cmdsize < 8 {
            return Err(LicenseError::RuntimeEnvironmentFailed);
        }

        let end = offset
            .checked_add(cmdsize)
            .ok_or(LicenseError::RuntimeEnvironmentFailed)?;
        if end > payload.len() {
            return Err(LicenseError::RuntimeEnvironmentFailed);
        }

        if cmd == LC_CODE_SIGNATURE {
            if cmdsize < 16 {
                return Err(LicenseError::RuntimeEnvironmentFailed);
            }

            let dataoff = read_u32_le(payload, offset + 8)? as usize;
            let datasize = read_u32_le(payload, offset + 12)? as usize;
            let sig_end = dataoff
                .checked_add(datasize)
                .ok_or(LicenseError::RuntimeEnvironmentFailed)?;

            if sig_end > payload.len() {
                return Err(LicenseError::RuntimeEnvironmentFailed);
            }

            payload[offset..end].fill(0);
            payload[dataoff..sig_end].fill(0);
        }

        offset = end;
    }

    Ok(())
}

fn read_u32_le(payload: &[u8], offset: usize) -> Result<u32, LicenseError> {
    let end = offset
        .checked_add(4)
        .ok_or(LicenseError::RuntimeEnvironmentFailed)?;
    let bytes = payload
        .get(offset..end)
        .ok_or(LicenseError::RuntimeEnvironmentFailed)?;

    Ok(u32::from_le_bytes(
        bytes
            .try_into()
            .map_err(|_| LicenseError::RuntimeEnvironmentFailed)?,
    ))
}
