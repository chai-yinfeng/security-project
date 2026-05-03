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

#[cfg(test)]
mod tests {
    use super::{verify_device_binding, verify_executable_binding, verify_platform};
    use crate::env::RuntimeEnvironment;
    use crate::error::LicenseError;
    use crate::policy::{PlatformClaims, PolicyClaims, RuntimeConstraints};

    fn sample_claims() -> PolicyClaims {
        PolicyClaims {
            schema_version: 1,
            product_id: "coms6424.demo".into(),
            license_id: [1u8; 16],
            issued_at_unix: 100,
            not_before_unix: 100,
            not_after_unix: 200,
            platform: PlatformClaims {
                os: "macos".into(),
                arch: "arm64".into(),
            },
            device_fingerprint_hash: [2u8; 32],
            executable_hash: [3u8; 32],
            runtime_constraints: RuntimeConstraints::default(),
            flags: 0,
        }
    }

    fn sample_runtime() -> RuntimeEnvironment {
        RuntimeEnvironment {
            os: "macos",
            arch: "arm64",
            now_unix: 150,
            device_fingerprint_hash: [2u8; 32],
            executable_hash: [3u8; 32],
            debugger_attached: false,
            dyld_environment_present: false,
            code_signature_valid: true,
        }
    }

    #[test]
    fn accepts_matching_platform() {
        let claims = sample_claims();
        let runtime = sample_runtime();

        assert!(verify_platform(&claims, &runtime).is_ok());
    }

    #[test]
    fn accepts_aarch64_aliases() {
        let mut claims = sample_claims();
        let mut runtime = sample_runtime();
        claims.platform.arch = "aarch64".into();
        runtime.arch = "aarch64";

        assert!(verify_platform(&claims, &runtime).is_ok());
    }

    #[test]
    fn rejects_mismatched_platform_os() {
        let claims = sample_claims();
        let mut runtime = sample_runtime();
        runtime.os = "linux";

        let result = verify_platform(&claims, &runtime);

        assert!(matches!(result, Err(LicenseError::UnsupportedPlatform)));
    }

    #[test]
    fn rejects_mismatched_platform_arch() {
        let claims = sample_claims();
        let mut runtime = sample_runtime();
        runtime.arch = "x86_64";

        let result = verify_platform(&claims, &runtime);

        assert!(matches!(result, Err(LicenseError::UnsupportedPlatform)));
    }

    #[test]
    fn accepts_matching_device_binding() {
        let claims = sample_claims();
        let runtime = sample_runtime();

        assert!(verify_device_binding(&claims, &runtime).is_ok());
    }

    #[test]
    fn rejects_device_binding_mismatch() {
        let claims = sample_claims();
        let mut runtime = sample_runtime();
        runtime.device_fingerprint_hash = [9u8; 32];

        let result = verify_device_binding(&claims, &runtime);

        assert!(matches!(result, Err(LicenseError::DeviceBindingMismatch)));
    }

    #[test]
    fn accepts_matching_executable_binding() {
        let claims = sample_claims();
        let runtime = sample_runtime();

        assert!(verify_executable_binding(&claims, &runtime).is_ok());
    }

    #[test]
    fn rejects_executable_binding_mismatch() {
        let claims = sample_claims();
        let mut runtime = sample_runtime();
        runtime.executable_hash = [8u8; 32];

        let result = verify_executable_binding(&claims, &runtime);

        assert!(matches!(
            result,
            Err(LicenseError::ExecutableBindingMismatch)
        ));
    }
}
