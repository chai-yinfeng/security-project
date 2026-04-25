use crate::error::LicenseError;

const RAW_EMBEDDED_POLICY: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../artifacts/signed_policy/license.bin"
));

pub fn embedded_policy_blob() -> Result<&'static [u8], LicenseError> {
    if RAW_EMBEDDED_POLICY.is_empty() {
        return Err(LicenseError::EmptyBlob);
    }

    Ok(RAW_EMBEDDED_POLICY)
}
