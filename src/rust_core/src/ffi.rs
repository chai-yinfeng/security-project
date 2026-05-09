use crate::authz;
use crate::binding;
use crate::capability::Capability;
use crate::crypto;
use crate::embedded;
use crate::env;
use crate::error::LicenseError;
use crate::policy;
use crate::protected_payload;

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
    match std::panic::catch_unwind(licensed_entry_impl) {
        Ok(Ok(())) => 0,
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

fn licensed_entry_impl() -> Result<(), LicenseError> {
    let verified = verify_impl()?;
    let mut capability = Capability::from_verified_context(&verified.claims, &verified.runtime);

    protected_payload::run(&mut capability, &verified.claims)
}

fn check_impl() -> Result<(), LicenseError> {
    verify_impl().map(|_| ())
}

struct VerifiedContext {
    claims: policy::PolicyClaims,
    runtime: env::RuntimeEnvironment,
}

fn verify_impl() -> Result<VerifiedContext, LicenseError> {
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

    Ok(VerifiedContext { claims, runtime })
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
