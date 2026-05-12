use crate::error::LicenseError;

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn se_bridge_sign_challenge(
        key_data_ptr: *const u8,
        key_data_len: usize,
        challenge_ptr: *const u8,
        challenge_len: usize,
        sig_out: *mut u8,
        sig_out_len: *mut usize,
        pubkey_out: *mut u8,
        pubkey_out_len: *mut usize,
    ) -> i32;
}

#[cfg(target_os = "macos")]
pub fn se_sign_challenge(
    key_data: &[u8],
    challenge: &[u8; 32],
) -> Result<(Vec<u8>, Vec<u8>), LicenseError> {
    let mut sig_buf = [0u8; 128];
    let mut sig_len = sig_buf.len();
    let mut pub_buf = [0u8; 65];
    let mut pub_len = pub_buf.len();

    let result = unsafe {
        se_bridge_sign_challenge(
            key_data.as_ptr(),
            key_data.len(),
            challenge.as_ptr(),
            challenge.len(),
            sig_buf.as_mut_ptr(),
            &mut sig_len,
            pub_buf.as_mut_ptr(),
            &mut pub_len,
        )
    };

    if result != 0 || pub_len != 65 {
        return Err(LicenseError::SecureEnclaveUnavailable);
    }

    Ok((sig_buf[..sig_len].to_vec(), pub_buf[..pub_len].to_vec()))
}

#[cfg(not(target_os = "macos"))]
pub fn se_sign_challenge(
    _key_data: &[u8],
    _challenge: &[u8; 32],
) -> Result<(Vec<u8>, Vec<u8>), LicenseError> {
    Err(LicenseError::SecureEnclaveUnavailable)
}
