use thiserror::Error;

pub const SSH_AGENT_FAILURE: u8 = 5;
pub const SSH_AGENT_SUCCESS: u8 = 6;
pub const SSH2_AGENTC_REQUEST_IDENTITIES: u8 = 11;
pub const SSH2_AGENT_IDENTITIES_ANSWER: u8 = 12;
pub const SSH2_AGENTC_SIGN_REQUEST: u8 = 13;
pub const SSH2_AGENT_SIGN_RESPONSE: u8 = 14;

#[derive(Error, Debug)]
pub enum SshAgentError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid agent message: {0}")]
    InvalidMessage(String),

    #[error("Key parsing error: {0}")]
    KeyError(String),
}

pub struct SshAgentServer {
    socket_path: String,
}

impl SshAgentServer {
    pub fn new(socket_path: impl Into<String>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    pub fn socket_path(&self) -> &str {
        &self.socket_path
    }
}
