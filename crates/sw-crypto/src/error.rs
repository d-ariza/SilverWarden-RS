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

    #[error("Invalid KDF parameters: {0}")]
    InvalidKdfParams(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Invalid key length: {0}")]
    InvalidKeyLength(String),

    #[error("Feature not implemented: {0}")]
    NotImplemented(String),

    #[error("Invalid PKCS7 padding: {0}")]
    InvalidPadding(String),

    #[error("MAC mismatch: {0}")]
    MacMismatch(String),

    #[error("Invalid ciphertext: {0}")]
    InvalidCiphertext(String),
}
