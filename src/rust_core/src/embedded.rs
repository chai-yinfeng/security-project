use crate::error::LicenseError;
use crate::macho;

const LICENSE_SEGMENT: &str = "__TEXT";
const LICENSE_SECTION: &str = "__license";
const EMBEDDED_POLICY_BYTES: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../artifacts/signed_policy/license.bin"
));

#[used]
#[unsafe(link_section = "__TEXT,__license")]
static RAW_EMBEDDED_POLICY: [u8; EMBEDDED_POLICY_BYTES.len()] = *include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../artifacts/signed_policy/license.bin"
));

#[derive(Debug, Clone)]
pub struct EmbeddedPolicyBlob {
    pub bytes: Vec<u8>,
}

pub fn embedded_policy_blob() -> Result<EmbeddedPolicyBlob, LicenseError> {
    let path = std::env::current_exe().map_err(|_| LicenseError::RuntimeEnvironmentFailed)?;
    let image = std::fs::read(path).map_err(|_| LicenseError::RuntimeEnvironmentFailed)?;
    let section = macho::find_section(&image, LICENSE_SEGMENT, LICENSE_SECTION)?.file_range;
    let bytes = image
        .get(section.clone())
        .ok_or(LicenseError::RuntimeEnvironmentFailed)?
        .to_vec();

    if bytes.is_empty() {
        return Err(LicenseError::EmptyBlob);
    }

    Ok(EmbeddedPolicyBlob { bytes })
}
