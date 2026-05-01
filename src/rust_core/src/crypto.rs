use crate::error::LicenseError;
use crate::issuer_public_key::ISSUER_PUBLIC_KEY_BYTES;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

pub fn verify_policy_signature(
    policy_cbor: &[u8],
    signature_bytes: &[u8; 64],
) -> Result<(), LicenseError> {
    verify_policy_signature_with_key(&ISSUER_PUBLIC_KEY_BYTES, policy_cbor, signature_bytes)
}

fn verify_policy_signature_with_key(
    public_key_bytes: &[u8; 32],
    policy_cbor: &[u8],
    signature_bytes: &[u8; 64],
) -> Result<(), LicenseError> {
    let verifying_key =
        VerifyingKey::from_bytes(public_key_bytes).map_err(|_| LicenseError::SignatureFailed)?;

    let signature = Signature::from_bytes(signature_bytes);

    verifying_key
        .verify(policy_cbor, &signature)
        .map_err(|_| LicenseError::SignatureFailed)
}

#[cfg(test)]
mod tests {
    use super::verify_policy_signature_with_key;
    use crate::error::LicenseError;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn accepts_valid_signature() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let message = b"canonical-policy-bytes";
        let signature = signing_key.sign(message).to_bytes();

        let result =
            verify_policy_signature_with_key(&verifying_key.to_bytes(), message, &signature);

        assert!(result.is_ok());
    }

    #[test]
    fn rejects_modified_message() {
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let message = b"canonical-policy-bytes";
        let mut tampered_message = message.to_vec();
        tampered_message[0] ^= 0x01;
        let signature = signing_key.sign(message).to_bytes();

        let result = verify_policy_signature_with_key(
            &verifying_key.to_bytes(),
            &tampered_message,
            &signature,
        );

        assert!(matches!(result, Err(LicenseError::SignatureFailed)));
    }
}
