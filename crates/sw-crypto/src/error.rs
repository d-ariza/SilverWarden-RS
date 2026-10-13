use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum CryptoError {
    #[error("Memory lock error: {0}")]
    MemLockError(String),

    #[error("Invalid EncString format: {0}")]
    InvalidEncString(String),

    #[error("Unsupported cipher type: {0}")]
    UnsupportedCipherType(i32),

    #[error("Missing component in EncString: {0}")]
    MissingEncStringComponent(&'static str),

    #[error("Base64 decoding failed: {0}")]
    Base64Error(String),

    #[error("HMAC verification failed")]
    HmacVerificationFailed,

    #[error("Key derivation failed: {0}")]
    KdfError(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
}
