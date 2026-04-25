use crate::error::LicenseError;
use ciborium::value::Value;
use serde::{Deserialize, Serialize};

pub const SIGNED_BLOB_MAGIC: &[u8; 4] = b"SLC1";
pub const SIGNED_BLOB_VERSION: u16 = 1;
pub const POLICY_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyClaims {
    pub schema_version: u16,
    pub product_id: String,
    #[serde(with = "bytes_16")]
    pub license_id: [u8; 16],
    pub issued_at_unix: u64,
    pub not_before_unix: u64,
    pub not_after_unix: u64,
    pub platform: PlatformClaims,
    #[serde(with = "bytes_32")]
    pub device_fingerprint_hash: [u8; 32],
    #[serde(with = "bytes_32")]
    pub executable_hash: [u8; 32],
    pub flags: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlatformClaims {
    pub os: String,
    pub arch: String,
}

#[derive(Debug, Clone, Copy)]
pub struct SignedPolicyBlob<'a> {
    pub policy_cbor: &'a [u8],
    pub signature: &'a [u8; 64],
}

pub fn decode_signed_policy_blob(input: &[u8]) -> Result<SignedPolicyBlob<'_>, LicenseError> {
    const HEADER_LEN: usize = 10;
    const SIG_LEN: usize = 64;

    if input.len() < HEADER_LEN + SIG_LEN {
        return Err(LicenseError::MalformedBlob);
    }

    if &input[0..4] != SIGNED_BLOB_MAGIC {
        return Err(LicenseError::InvalidMagic);
    }

    let version = u16::from_be_bytes([input[4], input[5]]);
    if version != SIGNED_BLOB_VERSION {
        return Err(LicenseError::UnsupportedBlobVersion);
    }

    let policy_len = u32::from_be_bytes([input[6], input[7], input[8], input[9]]) as usize;

    let expected_len = HEADER_LEN
        .checked_add(policy_len)
        .and_then(|v| v.checked_add(SIG_LEN))
        .ok_or(LicenseError::MalformedBlob)?;

    if input.len() != expected_len {
        return Err(LicenseError::MalformedBlob);
    }

    let policy_start = HEADER_LEN;
    let policy_end = HEADER_LEN + policy_len;
    let sig_start = policy_end;
    let sig_end = sig_start + SIG_LEN;

    let signature: &[u8; 64] = input[sig_start..sig_end]
        .try_into()
        .map_err(|_| LicenseError::MalformedBlob)?;

    Ok(SignedPolicyBlob {
        policy_cbor: &input[policy_start..policy_end],
        signature,
    })
}

pub fn decode_and_check_canonical_policy(input: &[u8]) -> Result<PolicyClaims, LicenseError> {
    let claims: PolicyClaims =
        ciborium::from_reader(input).map_err(|_| LicenseError::PolicyDecodeFailed)?;

    validate_policy_shape(&claims)?;

    let reencoded = to_schema_constrained_canonical_cbor(&claims)
        .map_err(|_| LicenseError::PolicyDecodeFailed)?;

    if reencoded.as_slice() != input {
        return Err(LicenseError::NonCanonicalPolicy);
    }

    Ok(claims)
}

pub fn to_schema_constrained_canonical_cbor(
    claims: &PolicyClaims,
) -> Result<Vec<u8>, ciborium::ser::Error<std::io::Error>> {
    let platform = canonical_map(vec![
        (
            Value::Text("os".into()),
            Value::Text(claims.platform.os.clone()),
        ),
        (
            Value::Text("arch".into()),
            Value::Text(claims.platform.arch.clone()),
        ),
    ])?;

    let root = canonical_map(vec![
        (
            Value::Text("schema_version".into()),
            Value::Integer(claims.schema_version.into()),
        ),
        (
            Value::Text("product_id".into()),
            Value::Text(claims.product_id.clone()),
        ),
        (
            Value::Text("license_id".into()),
            Value::Bytes(claims.license_id.to_vec()),
        ),
        (
            Value::Text("issued_at_unix".into()),
            Value::Integer(claims.issued_at_unix.into()),
        ),
        (
            Value::Text("not_before_unix".into()),
            Value::Integer(claims.not_before_unix.into()),
        ),
        (
            Value::Text("not_after_unix".into()),
            Value::Integer(claims.not_after_unix.into()),
        ),
        (Value::Text("platform".into()), platform),
        (
            Value::Text("device_fingerprint_hash".into()),
            Value::Bytes(claims.device_fingerprint_hash.to_vec()),
        ),
        (
            Value::Text("executable_hash".into()),
            Value::Bytes(claims.executable_hash.to_vec()),
        ),
        (
            Value::Text("flags".into()),
            Value::Integer(claims.flags.into()),
        ),
    ])?;

    let mut out = Vec::new();
    ciborium::into_writer(&root, &mut out)?;
    Ok(out)
}

fn validate_policy_shape(claims: &PolicyClaims) -> Result<(), LicenseError> {
    if claims.schema_version != POLICY_SCHEMA_VERSION {
        return Err(LicenseError::PolicyDecodeFailed);
    }

    if claims.product_id.is_empty() || claims.product_id.len() > 128 {
        return Err(LicenseError::PolicyDecodeFailed);
    }

    if claims.not_before_unix > claims.not_after_unix {
        return Err(LicenseError::PolicyDecodeFailed);
    }

    if claims.platform.os != "macos" {
        return Err(LicenseError::UnsupportedPlatform);
    }

    if claims.platform.arch != "arm64" && claims.platform.arch != "aarch64" {
        return Err(LicenseError::UnsupportedPlatform);
    }

    Ok(())
}

fn canonical_map(
    mut entries: Vec<(Value, Value)>,
) -> Result<Value, ciborium::ser::Error<std::io::Error>> {
    entries.sort_by(|(left, _), (right, _)| {
        let left_bytes = encode_value(left).expect("CBOR key serialization should not fail");
        let right_bytes = encode_value(right).expect("CBOR key serialization should not fail");

        left_bytes
            .len()
            .cmp(&right_bytes.len())
            .then_with(|| left_bytes.cmp(&right_bytes))
    });

    Ok(Value::Map(entries))
}

fn encode_value(value: &Value) -> Result<Vec<u8>, ciborium::ser::Error<std::io::Error>> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out)?;
    Ok(out)
}

mod bytes_16 {
    use serde::de::{Error, SeqAccess, Visitor};
    use serde::{Deserializer, Serializer};
    use std::fmt;

    pub fn serialize<S>(value: &[u8; 16], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(value)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 16], D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(ByteArrayVisitor::<16>)
    }

    struct ByteArrayVisitor<const N: usize>;

    impl<'de, const N: usize> Visitor<'de> for ByteArrayVisitor<N> {
        type Value = [u8; N];

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "a CBOR byte string with exactly {N} bytes")
        }

        fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
        where
            E: Error,
        {
            value
                .try_into()
                .map_err(|_| E::invalid_length(value.len(), &self))
        }

        fn visit_byte_buf<E>(self, value: Vec<u8>) -> Result<Self::Value, E>
        where
            E: Error,
        {
            self.visit_bytes(&value)
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut out = [0u8; N];

            for slot in &mut out {
                *slot = seq
                    .next_element()?
                    .ok_or_else(|| A::Error::invalid_length(0, &self))?;
            }

            if seq.next_element::<u8>()?.is_some() {
                return Err(A::Error::invalid_length(N + 1, &self));
            }

            Ok(out)
        }
    }
}

mod bytes_32 {
    use serde::de::{Error, SeqAccess, Visitor};
    use serde::{Deserializer, Serializer};
    use std::fmt;

    pub fn serialize<S>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(value)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(ByteArrayVisitor::<32>)
    }

    struct ByteArrayVisitor<const N: usize>;

    impl<'de, const N: usize> Visitor<'de> for ByteArrayVisitor<N> {
        type Value = [u8; N];

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "a CBOR byte string with exactly {N} bytes")
        }

        fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
        where
            E: Error,
        {
            value
                .try_into()
                .map_err(|_| E::invalid_length(value.len(), &self))
        }

        fn visit_byte_buf<E>(self, value: Vec<u8>) -> Result<Self::Value, E>
        where
            E: Error,
        {
            self.visit_bytes(&value)
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut out = [0u8; N];

            for slot in &mut out {
                *slot = seq
                    .next_element()?
                    .ok_or_else(|| A::Error::invalid_length(0, &self))?;
            }

            if seq.next_element::<u8>()?.is_some() {
                return Err(A::Error::invalid_length(N + 1, &self));
            }

            Ok(out)
        }
    }
}
