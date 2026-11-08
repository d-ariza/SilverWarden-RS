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
    SyncData(serde_json::Value),
    #[serde(alias = "ReloadVault")]
    ReloadVault(serde_json::Value),
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
        token: Option<serde_json::Value>,
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
    AgentShutdown,
}

/// Typed IPC response sent from daemon to clients
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", content = "data")]
pub enum Response {
    Ok(serde_json::Value),
    Error { code: String, message: String },
}

impl Response {
    pub fn ok(data: serde_json::Value) -> Self {
        Response::Ok(data)
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

    pub fn unwrap_ok(self) -> Result<serde_json::Value, (String, String)> {
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
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn test_golden_json_contract_unlock() {
        let req = Request::Unlock {
            pin: Some("1234".to_string()),
        };
        let serialized = serde_json::to_string(&req).expect("Serialization failed");
        assert_eq!(
            serialized,
            r#"{"action":"Unlock","payload":{"pin":"1234"}}"#
        );

        let deserialized: Request =
            serde_json::from_str(&serialized).expect("Deserialization failed");
        assert_eq!(deserialized, req);
    }

    #[tokio::test]
    async fn test_golden_json_contract_status_and_lock() {
        let req = Request::Status;
        let serialized = serde_json::to_string(&req).expect("Serialization failed");
        assert_eq!(serialized, r#"{"action":"Status"}"#);

        let deserialized: Request =
            serde_json::from_str(&serialized).expect("Deserialization failed");
        assert_eq!(deserialized, req);

        let lock_req = Request::Lock;
        let lock_ser = serde_json::to_string(&lock_req).expect("Serialization failed");
        assert_eq!(lock_ser, r#"{"action":"Lock"}"#);
    }

    #[tokio::test]
    async fn test_golden_json_contract_response() {
        let ok_resp = Response::Ok(serde_json::json!({ "status": "unlocked" }));
        let ok_json = serde_json::to_string(&ok_resp).expect("Serialization failed");
        assert_eq!(ok_json, r#"{"status":"Ok","data":{"status":"unlocked"}}"#);

        let deserialized_ok: Response =
            serde_json::from_str(&ok_json).expect("Deserialization failed");
        assert_eq!(deserialized_ok, ok_resp);

        let err_resp = Response::Error {
            code: "AUTH_FAILED".into(),
            message: "PIN incorrecto".into(),
        };
        let err_json = serde_json::to_string(&err_resp).expect("Serialization failed");
        assert_eq!(
            err_json,
            r#"{"status":"Error","data":{"code":"AUTH_FAILED","message":"PIN incorrecto"}}"#
        );

        let deserialized_err: Response =
            serde_json::from_str(&err_json).expect("Deserialization failed");
        assert_eq!(deserialized_err, err_resp);
    }

    #[tokio::test]
    async fn test_roundtrip_duplex_request_response() {
        let (mut client, mut server) = tokio::io::duplex(8192);

        let client_req = Request::Status;

        // Client writes Request to server
        write_message(&mut client, &client_req)
            .await
            .expect("Client write should succeed");

        // Server reads Request from client
        let received_by_server: Request = read_message(&mut server)
            .await
            .expect("Server read should succeed");
        assert_eq!(received_by_server, client_req);

        // Server responds with Response
        let server_response = Response::Ok(serde_json::json!({
            "locked": true,
            "version": "0.1.0"
        }));
        write_message(&mut server, &server_response)
            .await
            .expect("Server write should succeed");

        // Client reads Response
        let received_by_client: Response = read_message(&mut client)
            .await
            .expect("Client read response should succeed");
        assert_eq!(received_by_client, server_response);
    }

    #[tokio::test]
    async fn test_write_message_too_large_fails() {
        let (mut client, _server) = tokio::io::duplex(8192);

        let large_string = "a".repeat(MAX_IPC_MESSAGE_SIZE + 10);
        let large_msg = Request::GetLogin { name: large_string };

        let result = write_message(&mut client, &large_msg).await;
        assert!(matches!(result, Err(IpcError::MessageTooLarge)));
    }

    #[tokio::test]
    async fn test_read_message_too_large_fails() {
        let (mut client, mut server) = tokio::io::duplex(1024);

        let invalid_len = ((MAX_IPC_MESSAGE_SIZE + 100) as u32).to_be_bytes();
        client.write_all(&invalid_len).await.unwrap();

        let result: Result<Request, _> = read_message(&mut server).await;
        assert!(matches!(result, Err(IpcError::MessageTooLarge)));
    }

    #[tokio::test]
    async fn test_read_malformed_json_fails() {
        let (mut client, mut server) = tokio::io::duplex(1024);

        let bad_json = b"{not_valid_json:";
        let len_bytes = (bad_json.len() as u32).to_be_bytes();
        client.write_all(&len_bytes).await.unwrap();
        client.write_all(bad_json).await.unwrap();

        let result: Result<Request, _> = read_message(&mut server).await;
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
