use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod dto;

pub use dto::{
    AgentStatus, ConfigView, LoginDetail, LoginSummary, OpaqueValue, OperationAck, PinChangeResult,
    ResponseData, SshKeySummary, SyncPayload, SyncResult,
};

pub const IPC_PROTOCOL_VERSION: u32 = 1;
pub const MAX_IPC_MESSAGE_SIZE: usize = 4 * 1024 * 1024; // 4MB

#[derive(Error, Debug)]
pub enum IpcError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Message exceeded maximum size ({MAX_IPC_MESSAGE_SIZE} bytes)")]
    MessageTooLarge,

    #[error("Unexpected end of stream")]
    UnexpectedEof,

    #[error("Protocol error: {0}")]
    Protocol(String),
}

/// Typed IPC requests sent from clients (CLI, GUI) to daemon (Agent)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", content = "payload")]
pub enum Request {
    Status,
    Unlock {
        #[serde(default)]
        pin: Option<String>,
    },
    Lock,
    Sync,
    SyncData(SyncPayload),
    #[serde(alias = "ReloadVault")]
    ReloadVault(SyncPayload),
    ListLogins,
    GetLogin {
        name: String,
    },
    CreateLogin {
        name: String,
        username: String,
        password: String,
    },
    DeleteLogin {
        name: String,
    },
    #[serde(alias = "ListSSHKeys")]
    ListSshKeys,
    #[serde(alias = "ImportSSHKey")]
    ImportSshKey {
        name: String,
        pem: String,
    },
    #[serde(alias = "NewSSHKey")]
    NewSshKey {
        name: String,
        key_type: String,
    },
    #[serde(alias = "DeleteSSHKey")]
    DeleteSshKey {
        id: String,
    },
    #[serde(alias = "Login")]
    SetSession {
        #[serde(default)]
        token: Option<OpaqueValue>,
        #[serde(default)]
        encrypted_token: Option<String>,
        #[serde(default)]
        encrypted_user_symmetric_key: Option<String>,
        #[serde(default)]
        user_symmetric_key: Option<String>,
        #[serde(default)]
        identity_url: Option<String>,
        #[serde(default)]
        api_url: Option<String>,
        #[serde(default)]
        notifications_url: Option<String>,
        #[serde(default)]
        danger_accept_invalid_certs: Option<bool>,
    },
    PinSet {
        pin: String,
    },
    PinUpdate {
        old_pin: String,
        new_pin: String,
    },
    #[serde(alias = "get_config", alias = "getconfig")]
    GetConfig,
    #[serde(alias = "set_config", alias = "setconfig")]
    SetConfig(ConfigView),
    AgentShutdown,
}

/// Typed IPC response sent from daemon to clients
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", content = "data")]
pub enum Response {
    Ok(ResponseData),
    Error { code: String, message: String },
}

impl Response {
    pub fn ok(data: impl Into<ResponseData>) -> Self {
        Response::Ok(data.into())
    }

    pub fn error(code: impl Into<String>, message: impl Into<String>) -> Self {
        Response::Error {
            code: code.into(),
            message: message.into(),
        }
    }

    pub fn is_ok(&self) -> bool {
        matches!(self, Response::Ok(_))
    }

    pub fn is_err(&self) -> bool {
        matches!(self, Response::Error { .. })
    }

    pub fn unwrap_ok(self) -> Result<ResponseData, (String, String)> {
        match self {
            Response::Ok(val) => Ok(val),
            Response::Error { code, message } => Err((code, message)),
        }
    }
}

/// Length-prefixed framing helper: reads u32 big-endian length then decodes JSON payload
pub async fn read_message<R: tokio::io::AsyncReadExt + Unpin, T: serde::de::DeserializeOwned>(
    reader: &mut R,
) -> Result<T, IpcError> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len > MAX_IPC_MESSAGE_SIZE {
        return Err(IpcError::MessageTooLarge);
    }

    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    serde_json::from_slice(&buf).map_err(IpcError::Json)
}

/// Length-prefixed framing helper: encodes payload as JSON and writes u32 big-endian length then bytes
pub async fn write_message<W: tokio::io::AsyncWriteExt + Unpin, T: serde::Serialize>(
    writer: &mut W,
    msg: &T,
) -> Result<(), IpcError> {
    let data = serde_json::to_vec(msg)?;
    if data.len() > MAX_IPC_MESSAGE_SIZE {
        return Err(IpcError::MessageTooLarge);
    }
    let len_bytes = (data.len() as u32).to_be_bytes();
    writer.write_all(&len_bytes).await?;
    writer.write_all(&data).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests;
