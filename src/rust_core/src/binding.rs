use crate::env::RuntimeEnvironment;
use crate::error::LicenseError;
use crate::policy::PolicyClaims;
use subtle::ConstantTimeEq;

pub fn verify_platform(
    claims: &PolicyClaims,
    runtime: &RuntimeEnvironment,
) -> Result<(), LicenseError> {
    if claims.platform.os != runtime.os {
        return Err(LicenseError::UnsupportedPlatform);
    }

    let claim_arch = claims.platform.arch.as_str();
    let runtime_arch = runtime.arch;

    let arch_ok = (claim_arch == "arm64" || claim_arch == "aarch64")
        && (runtime_arch == "arm64" || runtime_arch == "aarch64");

    if !arch_ok {
        return Err(LicenseError::UnsupportedPlatform);
    }

    Ok(())
}

pub fn verify_device_binding(
    claims: &PolicyClaims,
    runtime: &RuntimeEnvironment,
) -> Result<(), LicenseError> {
    let equal = claims
        .device_fingerprint_hash
        .ct_eq(&runtime.device_fingerprint_hash)
        .into();

    if equal {
        Ok(())
    } else {
        Err(LicenseError::DeviceBindingMismatch)
    }
}

pub fn verify_executable_binding(
    claims: &PolicyClaims,
    runtime: &RuntimeEnvironment,
) -> Result<(), LicenseError> {
    let equal = claims
        .executable_hash
        .ct_eq(&runtime.executable_hash)
        .into();

    if equal {
        Ok(())
    } else {
        Err(LicenseError::ExecutableBindingMismatch)
    }
}
