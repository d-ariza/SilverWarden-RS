use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const IPC_PROTOCOL_VERSION: u32 = 1;
pub const MAX_IPC_MESSAGE_SIZE: usize = 4 * 1024 * 1024; // 4MB

#[derive(Error, Debug)]
pub enum IpcError {
    #[error("IO error: {0}")]
    Io(#[io::source] std::io::Error),

    #[error("Serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Message exceeded maximum size ({MAX_IPC_MESSAGE_SIZE} bytes)")]
    MessageTooLarge,

    #[error("Unexpected end of stream")]
    UnexpectedEof,

    #[error("Protocol error: {0}")]
    Protocol(String),
}

impl From<std::io::Error> for IpcError {
    fn from(err: std::io::Error) -> Self {
        IpcError::Io(err)
    }
}

/// Request commands sent from CLI or GUI to Daemon
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", content = "payload")]
pub enum IpcRequest {
    Status,
    Unlock { pin: String },
    Lock,
    Sync,
    GetLogins { filter: Option<String> },
}

/// Response sent from Daemon to CLI or GUI
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", content = "data")]
pub enum IpcResponse {
    Ok(serde_json::Value),
    Error(String),
}

/// Length-prefixed framing helper: read u32 big-endian length then payload bytes
pub async fn read_message<R: tokio::io::AsyncReadExt + Unpin>(reader: &mut R) -> Result<Vec<u8>, IpcError> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len > MAX_IPC_MESSAGE_SIZE {
        return Err(IpcError::MessageTooLarge);
    }

    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Length-prefixed framing helper: write u32 big-endian length then payload bytes
pub async fn write_message<W: tokio::io::AsyncWriteExt + Unpin>(writer: &mut W, data: &[u8]) -> Result<(), IpcError> {
    if data.len() > MAX_IPC_MESSAGE_SIZE {
        return Err(IpcError::MessageTooLarge);
    }
    let len_bytes = (data.len() as u32).to_be_bytes();
    writer.write_all(&len_bytes).await?;
    writer.write_all(data).await?;
    writer.flush().await?;
    Ok(())
}
