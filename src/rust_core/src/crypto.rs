use crate::error::LicenseError;
use crate::issuer_public_key::ISSUER_PUBLIC_KEY_BYTES;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

pub fn verify_policy_signature(
    policy_cbor: &[u8],
    signature_bytes: &[u8; 64],
) -> Result<(), LicenseError> {
    let verifying_key = VerifyingKey::from_bytes(&ISSUER_PUBLIC_KEY_BYTES)
        .map_err(|_| LicenseError::SignatureFailed)?;

    let signature = Signature::from_bytes(signature_bytes);

    verifying_key
        .verify(policy_cbor, &signature)
        .map_err(|_| LicenseError::SignatureFailed)
}
