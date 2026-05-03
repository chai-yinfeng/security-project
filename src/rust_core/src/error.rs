use thiserror::Error;

#[derive(Error, Debug)]
pub enum LicenseError {
    #[error("embedded policy blob is empty")]
    EmptyBlob,

    #[error("invalid signed blob magic")]
    InvalidMagic,

    #[error("unsupported signed blob version")]
    UnsupportedBlobVersion,

    #[error("malformed signed blob")]
    MalformedBlob,

    #[error("policy decoding failed")]
    PolicyDecodeFailed,

    #[error("policy canonical encoding mismatch")]
    NonCanonicalPolicy,

    #[error("signature verification failed")]
    SignatureFailed,

    #[error("runtime environment query failed")]
    RuntimeEnvironmentFailed,

    #[error("device binding mismatch")]
    DeviceBindingMismatch,

    #[error("executable binding mismatch")]
    ExecutableBindingMismatch,

    #[error("license is not yet valid")]
    NotYetValid,

    #[error("license has expired")]
    Expired,

    #[error("runtime constraint violation")]
    RuntimeConstraintViolation,

    #[error("unsupported platform")]
    UnsupportedPlatform,
}
