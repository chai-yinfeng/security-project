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
