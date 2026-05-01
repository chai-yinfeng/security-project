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

#[cfg(test)]
mod tests {
    use super::verify_time_window;
    use crate::env::RuntimeEnvironment;
    use crate::error::LicenseError;
    use crate::policy::{PlatformClaims, PolicyClaims};

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
}
