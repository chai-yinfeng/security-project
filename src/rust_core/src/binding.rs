use crate::env::RuntimeEnvironment;
use crate::error::LicenseError;
use crate::policy::PolicyClaims;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use p256::EncodedPoint;
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
    let hash_equal: bool = claims
        .device_fingerprint_hash
        .ct_eq(&runtime.device_fingerprint_hash)
        .into();

    if !hash_equal {
        return Err(LicenseError::DeviceBindingMismatch);
    }

    verify_se_challenge_response(
        &claims.device_se_public_key,
        &runtime.se_challenge_response.challenge,
        &runtime.se_challenge_response.signature,
        &runtime.se_challenge_response.public_key,
    )
}

fn verify_se_challenge_response(
    policy_public_key: &[u8],
    challenge: &[u8; 32],
    signature_der: &[u8],
    runtime_public_key: &[u8],
) -> Result<(), LicenseError> {
    let pk_equal: bool = policy_public_key.ct_eq(runtime_public_key).into();
    if !pk_equal {
        return Err(LicenseError::SecureEnclaveChallengeResponseFailed);
    }

    let encoded_point = EncodedPoint::from_bytes(policy_public_key)
        .map_err(|_| LicenseError::SecureEnclaveChallengeResponseFailed)?;
    let verifying_key = VerifyingKey::from_encoded_point(&encoded_point)
        .map_err(|_| LicenseError::SecureEnclaveChallengeResponseFailed)?;

    let signature = Signature::from_der(signature_der)
        .map_err(|_| LicenseError::SecureEnclaveChallengeResponseFailed)?;

    verifying_key
        .verify(challenge, &signature)
        .map_err(|_| LicenseError::SecureEnclaveChallengeResponseFailed)
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
    use super::{verify_se_challenge_response};
    use crate::env::{RuntimeEnvironment, SeChallengeResponse};
    use crate::error::LicenseError;
    use crate::policy::{PlatformClaims, PolicyClaims, RuntimeConstraints};
    use p256::ecdsa::{signature::Signer, SigningKey};
    use sha2::{Digest, Sha256};

    fn test_se_fixtures(challenge: &[u8; 32]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let signing_key = SigningKey::from_bytes(&[7u8; 32].into()).unwrap();
        let verifying_key = signing_key.verifying_key();
        let public_key = verifying_key.to_encoded_point(false).as_bytes().to_vec();
        let fingerprint_hash = {
            let mut h = Sha256::new();
            h.update(b"COMS6424_DEVICE_SE_PUBKEY_V1");
            h.update(&public_key);
            h.finalize()
        };
        let sig: p256::ecdsa::Signature = signing_key.sign(challenge);
        let signature = sig.to_der().as_bytes().to_vec();
        (public_key, signature, fingerprint_hash.to_vec())
    }

    fn sample_claims_and_runtime() -> (PolicyClaims, RuntimeEnvironment) {
        let challenge = [0x42u8; 32];
        let (public_key, signature, fingerprint_hash) = test_se_fixtures(&challenge);
        let mut fp = [0u8; 32];
        fp.copy_from_slice(&fingerprint_hash);

        let claims = PolicyClaims {
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
            device_fingerprint_hash: fp,
            device_se_public_key: public_key.clone(),
            device_se_key_data: vec![0x55; 32],
            executable_hash: [3u8; 32],
            protected_payload: Vec::new(),
            runtime_constraints: RuntimeConstraints::default(),
            flags: 0,
        };

        let runtime = RuntimeEnvironment {
            os: "macos",
            arch: "arm64",
            now_unix: 150,
            device_fingerprint_hash: fp,
            device_key_material: [4u8; 32],
            executable_hash: [3u8; 32],
            se_challenge_response: SeChallengeResponse {
                challenge,
                signature,
                public_key,
            },
            debugger_attached: false,
            dyld_environment_present: false,
            code_signature_valid: true,
            ntp_unix: None,
        };

        (claims, runtime)
    }

    #[test]
    fn accepts_matching_platform() {
        let (claims, runtime) = sample_claims_and_runtime();

        assert!(verify_platform(&claims, &runtime).is_ok());
    }

    #[test]
    fn accepts_aarch64_aliases() {
        let (mut claims, mut runtime) = sample_claims_and_runtime();
        claims.platform.arch = "aarch64".into();
        runtime.arch = "aarch64";

        assert!(verify_platform(&claims, &runtime).is_ok());
    }

    #[test]
    fn rejects_mismatched_platform_os() {
        let (claims, mut runtime) = sample_claims_and_runtime();
        runtime.os = "linux";

        let result = verify_platform(&claims, &runtime);

        assert!(matches!(result, Err(LicenseError::UnsupportedPlatform)));
    }

    #[test]
    fn rejects_mismatched_platform_arch() {
        let (claims, mut runtime) = sample_claims_and_runtime();
        runtime.arch = "x86_64";

        let result = verify_platform(&claims, &runtime);

        assert!(matches!(result, Err(LicenseError::UnsupportedPlatform)));
    }

    #[test]
    fn accepts_matching_device_binding() {
        let (claims, runtime) = sample_claims_and_runtime();

        assert!(verify_device_binding(&claims, &runtime).is_ok());
    }

    #[test]
    fn rejects_device_fingerprint_mismatch() {
        let (claims, mut runtime) = sample_claims_and_runtime();
        runtime.device_fingerprint_hash = [9u8; 32];

        let result = verify_device_binding(&claims, &runtime);

        assert!(matches!(result, Err(LicenseError::DeviceBindingMismatch)));
    }

    #[test]
    fn accepts_valid_se_challenge_response() {
        let challenge = [0xAA; 32];
        let (public_key, signature, _) = test_se_fixtures(&challenge);

        let result = verify_se_challenge_response(
            &public_key,
            &challenge,
            &signature,
            &public_key,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn rejects_se_response_with_wrong_public_key() {
        let challenge = [0xBB; 32];
        let (public_key, signature, _) = test_se_fixtures(&challenge);
        let other_key = SigningKey::from_bytes(&[9u8; 32].into())
            .unwrap()
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();

        let result = verify_se_challenge_response(
            &public_key,
            &challenge,
            &signature,
            &other_key,
        );

        assert!(matches!(
            result,
            Err(LicenseError::SecureEnclaveChallengeResponseFailed)
        ));
    }

    #[test]
    fn rejects_se_response_with_tampered_signature() {
        let challenge = [0xCC; 32];
        let (public_key, mut signature, _) = test_se_fixtures(&challenge);
        signature[4] ^= 0x01;

        let result = verify_se_challenge_response(
            &public_key,
            &challenge,
            &signature,
            &public_key,
        );

        assert!(result.is_err());
    }

    #[test]
    fn accepts_matching_executable_binding() {
        let (claims, runtime) = sample_claims_and_runtime();

        assert!(verify_executable_binding(&claims, &runtime).is_ok());
    }

    #[test]
    fn rejects_executable_binding_mismatch() {
        let (claims, mut runtime) = sample_claims_and_runtime();
        runtime.executable_hash = [8u8; 32];

        let result = verify_executable_binding(&claims, &runtime);

        assert!(matches!(
            result,
            Err(LicenseError::ExecutableBindingMismatch)
        ));
    }
}
