use crate::env::RuntimeEnvironment;
use crate::error::LicenseError;
use crate::policy::{PAYLOAD_SCHEMA_VERSION, PolicyClaims, ProtectedPayloadBlock};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use sha2::{Digest, Sha256};

#[derive(Debug)]
pub struct Capability {
    session_key: [u8; 32],
    chain_hash: [u8; 32],
}

impl Capability {
    pub fn from_verified_context(claims: &PolicyClaims, runtime: &RuntimeEnvironment) -> Self {
        let mut ikm = Vec::new();
        ikm.extend_from_slice(claims.product_id.as_bytes());
        ikm.push(0);
        ikm.extend_from_slice(&claims.license_id);
        ikm.extend_from_slice(&runtime.executable_hash);

        let session_key = hkdf_sha256(
            &runtime.device_key_material,
            &ikm,
            b"COMS6424_CAPABILITY_SESSION_V2",
        );
        zeroize_vec(&mut ikm);

        Self {
            session_key,
            chain_hash: initial_chain_hash(claims),
        }
    }

    pub fn decrypt_block(
        &mut self,
        claims: &PolicyClaims,
        block: &ProtectedPayloadBlock,
    ) -> Result<Vec<u8>, LicenseError> {
        let block_key = derive_block_key(&self.session_key, block.block_id, &self.chain_hash);

        let mut associated_data = payload_associated_data(claims, block, &self.chain_hash);
        let cipher = ChaCha20Poly1305::new_from_slice(&block_key)
            .map_err(|_| LicenseError::RuntimeConstraintViolation)?;

        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&block.nonce),
                Payload {
                    msg: &block.ciphertext,
                    aad: &associated_data,
                },
            )
            .map_err(|_| LicenseError::RuntimeConstraintViolation)?;

        self.chain_hash = next_chain_hash(&self.chain_hash, &plaintext);
        zeroize_array(block_key);
        zeroize_vec(&mut associated_data);

        Ok(plaintext)
    }
}

impl Drop for Capability {
    fn drop(&mut self) {
        self.session_key.fill(0);
        self.chain_hash.fill(0);
    }
}

fn initial_chain_hash(claims: &PolicyClaims) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"COMS6424_PAYLOAD_CHAIN_V2");
    hasher.update(claims.product_id.as_bytes());
    hasher.update([0]);
    hasher.update(claims.license_id);
    hasher.update(claims.executable_hash);
    hasher.finalize().into()
}

fn next_chain_hash(previous: &[u8; 32], plaintext: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"COMS6424_PAYLOAD_CHAIN_STEP_V2");
    hasher.update(previous);
    hasher.update(Sha256::digest(plaintext));
    hasher.finalize().into()
}

fn derive_block_key(session_key: &[u8; 32], block_id: u64, chain_hash: &[u8; 32]) -> [u8; 32] {
    let mut key_info = Vec::new();
    key_info.extend_from_slice(b"COMS6424_PAYLOAD_BLOCK_KEY_V2");
    key_info.extend_from_slice(&block_id.to_be_bytes());
    key_info.extend_from_slice(chain_hash);

    let block_key = hkdf_sha256(session_key, &[], &key_info);
    zeroize_vec(&mut key_info);
    block_key
}

fn payload_associated_data(
    claims: &PolicyClaims,
    block: &ProtectedPayloadBlock,
    chain_hash: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"COMS6424_PAYLOAD_AD_V2");
    out.extend_from_slice(&claims.schema_version.to_be_bytes());
    out.extend_from_slice(&PAYLOAD_SCHEMA_VERSION.to_be_bytes());
    out.extend_from_slice(&block.payload_schema_version.to_be_bytes());
    out.extend_from_slice(&block.block_id.to_be_bytes());
    out.extend_from_slice(chain_hash);
    append_len_prefixed(&mut out, claims.product_id.as_bytes());
    out.extend_from_slice(&claims.license_id);
    out.extend_from_slice(&claims.executable_hash);
    out
}

fn append_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let prk = hmac_sha256(salt, ikm);
    let mut expand_input = Vec::new();
    expand_input.extend_from_slice(info);
    expand_input.push(1);
    let okm = hmac_sha256(&prk, &expand_input);
    zeroize_array(prk);
    zeroize_vec(&mut expand_input);
    okm
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const SHA256_BLOCK_LEN: usize = 64;

    let mut normalized_key = [0u8; SHA256_BLOCK_LEN];
    if key.len() > SHA256_BLOCK_LEN {
        normalized_key[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        normalized_key[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; SHA256_BLOCK_LEN];
    let mut opad = [0x5cu8; SHA256_BLOCK_LEN];
    for idx in 0..SHA256_BLOCK_LEN {
        ipad[idx] ^= normalized_key[idx];
        opad[idx] ^= normalized_key[idx];
    }

    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(message);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_hash);

    normalized_key.fill(0);
    ipad.fill(0);
    opad.fill(0);

    outer.finalize().into()
}

fn zeroize_array<const N: usize>(mut bytes: [u8; N]) {
    bytes.fill(0);
    std::hint::black_box(bytes);
}

fn zeroize_vec(bytes: &mut Vec<u8>) {
    bytes.fill(0);
    std::hint::black_box(bytes);
}

#[cfg(test)]
mod tests {
    use super::{
        Capability, derive_block_key, initial_chain_hash, next_chain_hash, payload_associated_data,
    };
    use crate::env::RuntimeEnvironment;
    use crate::policy::{
        PAYLOAD_SCHEMA_VERSION, PlatformClaims, PolicyClaims, ProtectedPayloadBlock,
        RuntimeConstraints,
    };
    use chacha20poly1305::aead::{Aead, Payload};
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};

    fn sample_runtime() -> RuntimeEnvironment {
        RuntimeEnvironment {
            os: "macos",
            arch: "arm64",
            now_unix: 1_700_000_001,
            device_fingerprint_hash: [0x22; 32],
            device_key_material: [0x44; 32],
            executable_hash: [0x33; 32],
            debugger_attached: false,
            dyld_environment_present: false,
            code_signature_valid: true,
        }
    }

    fn sample_claims() -> PolicyClaims {
        PolicyClaims {
            schema_version: 1,
            product_id: "coms6424.demo".into(),
            license_id: [0x11; 16],
            issued_at_unix: 1_700_000_000,
            not_before_unix: 1_700_000_000,
            not_after_unix: 1_700_086_400,
            platform: PlatformClaims {
                os: "macos".into(),
                arch: "arm64".into(),
            },
            device_fingerprint_hash: [0x22; 32],
            executable_hash: [0x33; 32],
            protected_payload: Vec::new(),
            runtime_constraints: RuntimeConstraints::default(),
            flags: 0,
        }
    }

    fn encrypted_claims() -> (PolicyClaims, RuntimeEnvironment, Vec<Vec<u8>>) {
        let runtime = sample_runtime();
        let mut claims = sample_claims();
        let capability = Capability::from_verified_context(&claims, &runtime);
        let plaintexts = vec![
            b"phase one plaintext".to_vec(),
            b"phase two depends on phase one".to_vec(),
            b"phase three depends on phase two".to_vec(),
        ];
        let mut chain_hash = initial_chain_hash(&claims);

        for (idx, plaintext) in plaintexts.iter().enumerate() {
            let block_id = (idx + 1) as u64;
            let nonce = [block_id as u8; 12];
            let mut block = ProtectedPayloadBlock {
                payload_schema_version: PAYLOAD_SCHEMA_VERSION,
                block_id,
                nonce,
                ciphertext: Vec::new(),
            };
            let block_key = derive_block_key(&capability.session_key, block_id, &chain_hash);
            let associated_data = payload_associated_data(&claims, &block, &chain_hash);
            block.ciphertext = ChaCha20Poly1305::new_from_slice(&block_key)
                .unwrap()
                .encrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: plaintext,
                        aad: &associated_data,
                    },
                )
                .unwrap();
            claims.protected_payload.push(block);
            chain_hash = next_chain_hash(&chain_hash, plaintext);
        }

        (claims, runtime, plaintexts)
    }

    #[test]
    fn decrypts_plaintext_dependent_chain_in_order() {
        let (claims, runtime, plaintexts) = encrypted_claims();
        let mut capability = Capability::from_verified_context(&claims, &runtime);

        for (idx, expected) in plaintexts.iter().enumerate() {
            let decrypted = capability
                .decrypt_block(&claims, &claims.protected_payload[idx])
                .unwrap();

            assert_eq!(&decrypted, expected);
        }
    }

    #[test]
    fn rejects_skipping_prior_plaintext() {
        let (claims, runtime, _) = encrypted_claims();
        let mut capability = Capability::from_verified_context(&claims, &runtime);

        let result = capability.decrypt_block(&claims, &claims.protected_payload[1]);

        assert!(result.is_err());
    }

    #[test]
    fn rejects_associated_data_rebinding() {
        let (mut claims, runtime, _) = encrypted_claims();
        let mut capability = Capability::from_verified_context(&claims, &runtime);
        claims.executable_hash = [0xaa; 32];

        let result = capability.decrypt_block(&claims, &claims.protected_payload[0]);

        assert!(result.is_err());
    }
}
