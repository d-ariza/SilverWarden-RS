use std::path::{Path, PathBuf};
use sw_ipc::{read_message, write_message};
pub use sw_ipc::{Request, Response};
use thiserror::Error;
use tokio::net::UnixStream;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum ClientError {
    #[error("El agente no está corriendo o el socket no existe: {0}")]
    SocketNotFound(PathBuf),

    #[error("Error al conectar al socket '{0}': {1}")]
    ConnectionFailed(PathBuf, String),

    #[error("Error al enviar mensaje al agente: {0}")]
    SendFailed(String),

    #[error("Error al recibir respuesta del agente: {0}")]
    ReceiveFailed(String),

    #[error("Bóveda bloqueada")]
    Locked,

    #[error("PIN incorrecto")]
    InvalidPin,

    #[error("No encontrado: {0}")]
    NotFound(String),

    #[error("No autorizado: {0}")]
    Unauthorized(String),

    #[error("Error del servidor: {0}")]
    ServerError(String),

    #[error("Error de validación: {0}")]
    Validation(String),

    #[error("{message}")]
    AgentError { code: String, message: String },

    #[error("Error de E/S: {0}")]
    Io(String),
}

impl ClientError {
    pub fn from_agent_error(code: impl Into<String>, message: impl Into<String>) -> Self {
        let code = code.into();
        let message = message.into();
        match code.to_ascii_lowercase().as_str() {
            "locked" => ClientError::Locked,
            "invalid_pin" => ClientError::InvalidPin,
            "not_found" => ClientError::NotFound(message),
            "unauthorized" => ClientError::Unauthorized(message),
            "server_error" => ClientError::ServerError(message),
            "validation" => ClientError::Validation(message),
            "io" => ClientError::Io(message),
            _ => ClientError::AgentError { code, message },
        }
    }
}

impl From<std::io::Error> for ClientError {
    fn from(e: std::io::Error) -> Self {
        ClientError::Io(e.to_string())
    }
}

/// Facade client for communicating with the SilverWarden agent daemon over Unix Domain Socket.
#[derive(Clone, Debug)]
pub struct AgentClient {
    socket_path: PathBuf,
}

impl AgentClient {
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Connects to the agent socket, returning an active connection.
    pub async fn connect(&self) -> Result<AgentConnection, ClientError> {
        if !self.socket_path.exists() {
            return Err(ClientError::SocketNotFound(self.socket_path.clone()));
        }

        let stream = UnixStream::connect(&self.socket_path)
            .await
            .map_err(|e| ClientError::ConnectionFailed(self.socket_path.clone(), e.to_string()))?;

        Ok(AgentConnection { stream })
    }

    /// Single-shot request: opens a connection, sends the request, waits for response, and closes.
    pub async fn call(&self, request: Request) -> Result<Response, ClientError> {
        let mut conn = self.connect().await?;
        conn.send(request).await
    }

    /// Sends a command and returns the inner `serde_json::Value` payload, or returns an error.
    pub async fn call_ok(&self, request: Request) -> Result<serde_json::Value, ClientError> {
        match self.call(request).await? {
            Response::Ok(val) => Ok(val),
            Response::Error { code, message } => Err(ClientError::from_agent_error(code, message)),
        }
    }

    // --- Typed convenience methods ---

    pub async fn status(&self) -> Result<Response, ClientError> {
        self.call(Request::Status).await
    }

    pub async fn unlock(&self, pin: Option<String>) -> Result<Response, ClientError> {
        self.call(Request::Unlock { pin }).await
    }

    pub async fn lock(&self) -> Result<Response, ClientError> {
        self.call(Request::Lock).await
    }

    pub async fn sync(&self) -> Result<Response, ClientError> {
        self.call(Request::Sync).await
    }

    pub async fn sync_data(&self, data: serde_json::Value) -> Result<Response, ClientError> {
        self.call(Request::SyncData(data)).await
    }

    pub async fn list_logins(&self) -> Result<Response, ClientError> {
        self.call(Request::ListLogins).await
    }

    pub async fn get_login(&self, name: impl Into<String>) -> Result<Response, ClientError> {
        self.call(Request::GetLogin { name: name.into() }).await
    }

    pub async fn create_login(
        &self,
        name: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<Response, ClientError> {
        self.call(Request::CreateLogin {
            name: name.into(),
            username: username.into(),
            password: password.into(),
        })
        .await
    }

    pub async fn delete_login(&self, name: impl Into<String>) -> Result<Response, ClientError> {
        self.call(Request::DeleteLogin { name: name.into() }).await
    }

    pub async fn list_ssh_keys(&self) -> Result<Response, ClientError> {
        self.call(Request::ListSshKeys).await
    }

    pub async fn pin_set(&self, pin: impl Into<String>) -> Result<Response, ClientError> {
        self.call(Request::PinSet { pin: pin.into() }).await
    }

    pub async fn pin_update(
        &self,
        old_pin: impl Into<String>,
        new_pin: impl Into<String>,
    ) -> Result<Response, ClientError> {
        self.call(Request::PinUpdate {
            old_pin: old_pin.into(),
            new_pin: new_pin.into(),
        })
        .await
    }
}

/// Active streaming connection to the agent daemon.
pub struct AgentConnection {
    stream: UnixStream,
}

impl AgentConnection {
    pub fn into_inner(self) -> UnixStream {
        self.stream
    }

    /// Sends a request over the connection and awaits the typed response.
    /// If the agent returns `Response::Error`, converts it to `ClientError::AgentError`.
    pub async fn send(&mut self, request: Request) -> Result<Response, ClientError> {
        write_message(&mut self.stream, &request)
            .await
            .map_err(|e| ClientError::SendFailed(e.to_string()))?;

        let response: Response = read_message(&mut self.stream)
            .await
            .map_err(|e| ClientError::ReceiveFailed(e.to_string()))?;

        match response {
            Response::Ok(_) => Ok(response),
            Response::Error { code, message } => Err(ClientError::from_agent_error(code, message)),
        }
    }

    /// Sends a request and unwraps the success payload directly.
    pub async fn send_ok(&mut self, request: Request) -> Result<serde_json::Value, ClientError> {
        match self.send(request).await? {
            Response::Ok(val) => Ok(val),
            Response::Error { code, message } => Err(ClientError::from_agent_error(code, message)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UnixListener;

    #[tokio::test]
    async fn test_client_socket_not_found() {
        let non_existent = PathBuf::from("/tmp/non_existent_sw_client_socket.sock");
        let client = AgentClient::new(&non_existent);
        assert_eq!(client.socket_path(), non_existent.as_path());

        let res = client.call(Request::Status).await;
        assert_eq!(res, Err(ClientError::SocketNotFound(non_existent)));
    }

    #[tokio::test]
    async fn test_client_connection_receive_failed_on_server_drop() {
        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("drop.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();

        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                drop(stream);
            }
        });

        let client = AgentClient::new(&socket_path);
        let res = client.call(Request::Status).await;
        assert!(matches!(res, Err(ClientError::ReceiveFailed(_))));
    }

    #[tokio::test]
    async fn test_client_call_ok_and_agent_error() {
        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("agent.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();

        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let req: Request = read_message(&mut stream).await.unwrap();
                match req {
                    Request::Status => {
                        let resp = Response::Ok(serde_json::json!({ "locked": false }));
                        write_message(&mut stream, &resp).await.unwrap();
                    }
                    Request::Lock => {
                        let resp = Response::Error {
                            code: "LOCKED".into(),
                            message: "Already locked".into(),
                        };
                        write_message(&mut stream, &resp).await.unwrap();
                    }
                    _ => {}
                }
            }
        });

        let client = AgentClient::new(&socket_path);

        // Success call
        let val = client.call_ok(Request::Status).await.unwrap();
        assert_eq!(val["locked"], false);

        // Error call
        let err = client.call(Request::Lock).await.unwrap_err();
        assert_eq!(err, ClientError::Locked);

        // Generic error mapping
        assert_eq!(
            ClientError::from_agent_error("CUSTOM_CODE", "Something custom"),
            ClientError::AgentError {
                code: "CUSTOM_CODE".into(),
                message: "Something custom".into(),
            }
        );
    }

    #[tokio::test]
    async fn test_client_typed_convenience_methods() {
        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("typed.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();

        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let req: Request = read_message(&mut stream).await.unwrap();
                let resp = match req {
                    Request::Status => Response::Ok(serde_json::json!({ "status": "ok" })),
                    Request::ListLogins => Response::Ok(serde_json::json!([])),
                    Request::GetLogin { name } => Response::Ok(serde_json::json!({ "name": name })),
                    _ => Response::Ok(serde_json::json!({})),
                };
                write_message(&mut stream, &resp).await.unwrap();
            }
        });

        let client = AgentClient::new(&socket_path);
        assert!(client.status().await.is_ok());
        assert!(client.list_logins().await.is_ok());
        let get_res = client.get_login("github").await.unwrap();
        assert_eq!(get_res.unwrap_ok().unwrap()["name"], "github");
    }
}
