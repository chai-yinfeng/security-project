use crate::env::RuntimeEnvironment;
use crate::error::LicenseError;
use crate::policy::PolicyClaims;

pub fn verify_time_window(
    claims: &PolicyClaims,
    runtime: &RuntimeEnvironment,
) -> Result<(), LicenseError> {
    if runtime.now_unix < claims.not_before_unix {
        return Err(LicenseError::NotYetValid);
    }

    if runtime.now_unix > claims.not_after_unix {
        return Err(LicenseError::Expired);
    }

    Ok(())
}

pub fn verify_runtime_constraints(
    claims: &PolicyClaims,
    runtime: &RuntimeEnvironment,
) -> Result<(), LicenseError> {
    let constraints = &claims.runtime_constraints;

    if constraints.deny_debugger_attached && runtime.debugger_attached {
        return Err(LicenseError::RuntimeConstraintViolation);
    }

    if constraints.deny_dyld_environment && runtime.dyld_environment_present {
        return Err(LicenseError::RuntimeConstraintViolation);
    }

    if constraints.require_valid_code_signature && !runtime.code_signature_valid {
        return Err(LicenseError::RuntimeConstraintViolation);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{verify_runtime_constraints, verify_time_window};
    use crate::env::RuntimeEnvironment;
    use crate::error::LicenseError;
    use crate::policy::{PlatformClaims, PolicyClaims, RuntimeConstraints};

    fn sample_claims() -> PolicyClaims {
        PolicyClaims {
            schema_version: 1,
            product_id: "coms6424.demo".into(),
            license_id: [1u8; 16],
            issued_at_unix: 100,
            not_before_unix: 110,
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

    fn sample_runtime(now_unix: u64) -> RuntimeEnvironment {
        RuntimeEnvironment {
            os: "macos",
            arch: "arm64",
            now_unix,
            device_fingerprint_hash: [2u8; 32],
            executable_hash: [3u8; 32],
            debugger_attached: false,
            dyld_environment_present: false,
            code_signature_valid: true,
        }
    }

    #[test]
    fn accepts_time_inside_window() {
        let claims = sample_claims();
        let runtime = sample_runtime(150);

        assert!(verify_time_window(&claims, &runtime).is_ok());
    }

    #[test]
    fn rejects_not_yet_valid_time() {
        let claims = sample_claims();
        let runtime = sample_runtime(109);

        let result = verify_time_window(&claims, &runtime);

        assert!(matches!(result, Err(LicenseError::NotYetValid)));
    }

    #[test]
    fn rejects_expired_time() {
        let claims = sample_claims();
        let runtime = sample_runtime(201);

        let result = verify_time_window(&claims, &runtime);

        assert!(matches!(result, Err(LicenseError::Expired)));
    }

    #[test]
    fn rejects_disallowed_dyld_environment() {
        let mut claims = sample_claims();
        claims.runtime_constraints.deny_dyld_environment = true;
        let mut runtime = sample_runtime(150);
        runtime.dyld_environment_present = true;

        let result = verify_runtime_constraints(&claims, &runtime);

        assert!(matches!(
            result,
            Err(LicenseError::RuntimeConstraintViolation)
        ));
    }

    #[test]
    fn rejects_invalid_code_signature_when_required() {
        let mut claims = sample_claims();
        claims.runtime_constraints.require_valid_code_signature = true;
        let mut runtime = sample_runtime(150);
        runtime.code_signature_valid = false;

        let result = verify_runtime_constraints(&claims, &runtime);

        assert!(matches!(
            result,
            Err(LicenseError::RuntimeConstraintViolation)
        ));
    }
}
