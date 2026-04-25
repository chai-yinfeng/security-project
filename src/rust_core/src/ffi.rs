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
    match std::panic::catch_unwind(|| check_impl()) {
        Ok(Ok(())) => LicenseDecision::Allow,
        _ => LicenseDecision::Deny,
    }
}

fn check_impl() -> Result<(), LicenseError> {
    let blob = embedded::embedded_policy_blob()?;

    let signed_blob = policy::decode_signed_policy_blob(blob)?;

    crypto::verify_policy_signature(signed_blob.policy_cbor, signed_blob.signature)?;

    let claims = policy::decode_and_check_canonical_policy(signed_blob.policy_cbor)?;

    let runtime = env::collect_runtime_environment(blob)?;

    binding::verify_platform(&claims, &runtime)?;
    binding::verify_device_binding(&claims, &runtime)?;
    binding::verify_executable_binding(&claims, &runtime)?;

    authz::verify_time_window(&claims, &runtime)?;

    Ok(())
}
