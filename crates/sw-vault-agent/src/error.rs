use thiserror::Error;

#[derive(Error, Debug)]
pub enum SshAgentError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid agent message: {0}")]
    InvalidMessage(String),

    #[error("Key parsing error: {0}")]
    KeyError(String),

    #[error("Key not found")]
    KeyNotFound,

    #[error("Vault is locked")]
    VaultLocked,

    #[error("Approval denied: {0}")]
    ApprovalDenied(String),

    #[error("Signing error: {0}")]
    SigningError(String),

    #[error("Encoding error: {0}")]
    EncodingError(String),

    #[error("Agent failure")]
    AgentFailure,

    #[error("Error: {0}")]
    Other(String),
}
