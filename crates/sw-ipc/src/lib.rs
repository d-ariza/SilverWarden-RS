use serde::{Deserialize, Serialize};
use thiserror::Error;

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

/// Structured IPC message exchanged between clients (CLI, GUI) and daemon (Agent)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpcMessage {
    pub action: String,
    pub payload: serde_json::Value,
}

impl IpcMessage {
    pub fn new(action: impl Into<String>, payload: serde_json::Value) -> Self {
        Self {
            action: action.into(),
            payload,
        }
    }
}

/// Request commands sent from CLI or GUI to Daemon
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "action", content = "payload")]
pub enum IpcRequest {
    Status,
    Unlock { pin: String },
    Lock,
    Sync,
    GetLogins { filter: Option<String> },
}

/// Response sent from Daemon to CLI or GUI
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", content = "data")]
pub enum IpcResponse {
    Ok(serde_json::Value),
    Error(String),
}

/// Length-prefixed framing helper: reads u32 big-endian length then decodes JSON IpcMessage
pub async fn read_message<R: tokio::io::AsyncReadExt + Unpin>(
    reader: &mut R,
) -> Result<IpcMessage, IpcError> {
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

/// Length-prefixed framing helper: encodes IpcMessage as JSON and writes u32 big-endian length then bytes
pub async fn write_message<W: tokio::io::AsyncWriteExt + Unpin>(
    writer: &mut W,
    msg: &IpcMessage,
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
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn test_roundtrip_duplex() {
        let (mut client, mut server) = tokio::io::duplex(8192);

        let client_msg = IpcMessage::new(
            "Status",
            serde_json::json!({
                "client": "sw-cli",
                "version": "0.1.0"
            }),
        );

        // Client writes to server
        write_message(&mut client, &client_msg)
            .await
            .expect("Client write should succeed");

        // Server reads from client
        let received_by_server = read_message(&mut server)
            .await
            .expect("Server read should succeed");
        assert_eq!(received_by_server, client_msg);

        // Server responds to client
        let server_response = IpcMessage::new(
            "StatusResponse",
            serde_json::json!({
                "locked": true,
                "version": "0.1.0"
            }),
        );
        write_message(&mut server, &server_response)
            .await
            .expect("Server write should succeed");

        // Client reads response
        let received_by_client = read_message(&mut client)
            .await
            .expect("Client read response should succeed");
        assert_eq!(received_by_client, server_response);
    }

    #[tokio::test]
    async fn test_write_message_too_large_fails() {
        let (mut client, _server) = tokio::io::duplex(8192);

        // Create a payload that exceeds 4MB
        let large_string = "a".repeat(MAX_IPC_MESSAGE_SIZE + 10);
        let large_msg = IpcMessage::new("LargeAction", serde_json::Value::String(large_string));

        let result = write_message(&mut client, &large_msg).await;
        assert!(matches!(result, Err(IpcError::MessageTooLarge)));
    }

    #[tokio::test]
    async fn test_read_message_too_large_fails() {
        let (mut client, mut server) = tokio::io::duplex(1024);

        // Send a length header exceeding 4MB
        let invalid_len = ((MAX_IPC_MESSAGE_SIZE + 100) as u32).to_be_bytes();
        client.write_all(&invalid_len).await.unwrap();

        let result = read_message(&mut server).await;
        assert!(matches!(result, Err(IpcError::MessageTooLarge)));
    }

    #[tokio::test]
    async fn test_read_malformed_json_fails() {
        let (mut client, mut server) = tokio::io::duplex(1024);

        let bad_json = b"{not_valid_json:";
        let len_bytes = (bad_json.len() as u32).to_be_bytes();
        client.write_all(&len_bytes).await.unwrap();
        client.write_all(bad_json).await.unwrap();

        let result = read_message(&mut server).await;
        assert!(matches!(result, Err(IpcError::Json(_))));
    }

    #[test]
    fn test_ipc_error_display() {
        let io_err = IpcError::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "conn reset",
        ));
        assert!(io_err.to_string().contains("conn reset"));

        let large_err = IpcError::MessageTooLarge;
        assert!(large_err.to_string().contains("4194304"));

        let eof_err = IpcError::UnexpectedEof;
        assert!(eof_err.to_string().contains("Unexpected end of stream"));

        let proto_err = IpcError::Protocol("version mismatch".to_string());
        assert!(proto_err.to_string().contains("version mismatch"));
    }
}
