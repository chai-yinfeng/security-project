use crate::env::RuntimeEnvironment;
use crate::error::LicenseError;
use crate::policy::{PolicyClaims, ProtectedPayloadBlock};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

#[derive(Debug)]
pub struct Capability {
    session_key: [u8; 32],
    use_counter: u64,
}

impl Capability {
    pub fn from_verified_context(claims: &PolicyClaims, runtime: &RuntimeEnvironment) -> Self {
        let mut hasher = Sha256::new();

        hasher.update(b"COMS6424_CAPABILITY_SESSION_V1");
        hasher.update(claims.product_id.as_bytes());
        hasher.update([0]);
        hasher.update(claims.license_id);
        hasher.update(runtime.device_key_material);
        hasher.update(runtime.executable_hash);

        Self {
            session_key: hasher.finalize().into(),
            use_counter: 0,
        }
    }

    pub fn decrypt_block(
        &mut self,
        block: &ProtectedPayloadBlock,
    ) -> Result<Vec<u8>, LicenseError> {
        self.use_counter = self
            .use_counter
            .checked_add(1)
            .ok_or(LicenseError::RuntimeConstraintViolation)?;

        let block_key = self.derive_block_key(block.block_id);
        verify_block_tag(&block_key, block)?;

        let mut plaintext = block.ciphertext.clone();
        apply_payload_stream(&block_key, block.block_id, &mut plaintext);
        zeroize_array(block_key);

        Ok(plaintext)
    }

    fn derive_block_key(&self, block_id: u64) -> [u8; 32] {
        let mut hasher = Sha256::new();

        hasher.update(b"COMS6424_CAPABILITY_BLOCK_KEY_V1");
        hasher.update(self.session_key);
        hasher.update(block_id.to_be_bytes());
        hasher.update(self.use_counter.to_be_bytes());

        hasher.finalize().into()
    }
}

impl Drop for Capability {
    fn drop(&mut self) {
        self.session_key.fill(0);
        self.use_counter = 0;
    }
}

fn verify_block_tag(
    block_key: &[u8; 32],
    block: &ProtectedPayloadBlock,
) -> Result<(), LicenseError> {
    let expected = payload_tag(block_key, block.block_id, &block.ciphertext);
    let equal: bool = expected.ct_eq(&block.tag).into();

    zeroize_array(expected);

    if equal {
        Ok(())
    } else {
        Err(LicenseError::RuntimeConstraintViolation)
    }
}

fn payload_tag(block_key: &[u8; 32], block_id: u64, ciphertext: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();

    hasher.update(b"COMS6424_PAYLOAD_TAG_V1");
    hasher.update(block_key);
    hasher.update(block_id.to_be_bytes());
    hasher.update(ciphertext);

    hasher.finalize().into()
}

fn apply_payload_stream(block_key: &[u8; 32], block_id: u64, payload: &mut [u8]) {
    let mut offset = 0usize;
    let mut stream_counter = 0u64;

    while offset < payload.len() {
        let mut hasher = Sha256::new();
        hasher.update(b"COMS6424_PAYLOAD_STREAM_V1");
        hasher.update(block_key);
        hasher.update(block_id.to_be_bytes());
        hasher.update(stream_counter.to_be_bytes());
        let stream_block: [u8; 32] = hasher.finalize().into();

        for byte in stream_block {
            if offset == payload.len() {
                break;
            }

            payload[offset] ^= byte;
            offset += 1;
        }

        stream_counter += 1;
    }
}

fn zeroize_array<const N: usize>(mut bytes: [u8; N]) {
    bytes.fill(0);
    std::hint::black_box(bytes);
}
