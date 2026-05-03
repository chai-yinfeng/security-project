use crate::authz;
use crate::binding;
use crate::crypto;
use crate::embedded;
use crate::env;
use crate::error::LicenseError;
use crate::policy;

#[repr(C)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum LicenseDecision {
    Deny = 0,
    Allow = 1,
}

#[unsafe(no_mangle)]
pub extern "C" fn license_check() -> LicenseDecision {
    collapse_check_result(std::panic::catch_unwind(check_impl))
}

#[unsafe(no_mangle)]
pub extern "C" fn licensed_entry() -> i32 {
    match std::panic::catch_unwind(check_impl) {
        Ok(Ok(())) => protected_main(),
        _ => {
            eprintln!("license denied");
            1
        }
    }
}

fn collapse_check_result(result: std::thread::Result<Result<(), LicenseError>>) -> LicenseDecision {
    match result {
        Ok(Ok(())) => LicenseDecision::Allow,
        _ => LicenseDecision::Deny,
    }
}

fn protected_main() -> i32 {
    println!("protected path entered");
    0
}

fn check_impl() -> Result<(), LicenseError> {
    let blob = embedded::embedded_policy_blob()?;

    let signed_blob = policy::decode_signed_policy_blob(&blob.bytes)?;

    crypto::verify_policy_signature(signed_blob.policy_cbor, signed_blob.signature)?;

    let claims = policy::decode_and_check_canonical_policy(signed_blob.policy_cbor)?;

    let runtime = env::collect_runtime_environment()?;

    binding::verify_platform(&claims, &runtime)?;
    binding::verify_device_binding(&claims, &runtime)?;
    binding::verify_executable_binding(&claims, &runtime)?;

    authz::verify_time_window(&claims, &runtime)?;
    authz::verify_runtime_constraints(&claims, &runtime)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{LicenseDecision, collapse_check_result};
    use crate::error::LicenseError;

    #[test]
    fn returns_allow_for_successful_check() {
        let decision = collapse_check_result(Ok(Ok(())));

        assert_eq!(decision, LicenseDecision::Allow);
    }

    #[test]
    fn returns_deny_for_failed_check() {
        let decision = collapse_check_result(Ok(Err(LicenseError::SignatureFailed)));

        assert_eq!(decision, LicenseDecision::Deny);
    }

    #[test]
    fn returns_deny_for_panicking_check() {
        let panic_result = std::panic::catch_unwind(|| -> Result<(), LicenseError> {
            panic!("simulated panic across ffi boundary");
        });

        let decision = collapse_check_result(panic_result);

        assert_eq!(decision, LicenseDecision::Deny);
    }
}
