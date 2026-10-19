use std::path::{Path, PathBuf};
use std::sync::Arc;
use sw_config::ConfigFile;
use sw_ipc::{read_message, write_message, IpcMessage, IpcRequest, IpcResponse};
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Error, Debug)]
pub enum AgentError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("IPC error: {0}")]
    Ipc(#[from] sw_ipc::IpcError),

    #[error("El socket ya está en uso por otra instancia del agente: {0}")]
    SocketAlreadyInUse(PathBuf),

    #[error("Error del agente: {0}")]
    Other(String),
}

#[derive(Debug, Clone)]
pub struct AgentState {
    pub is_locked: bool,
    pub config: ConfigFile,
}

impl Default for AgentState {
    fn default() -> Self {
        Self {
            is_locked: true,
            config: ConfigFile::default(),
        }
    }
}

pub struct AgentDaemon {
    pub state: Arc<RwLock<AgentState>>,
}

impl AgentDaemon {
    pub fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(AgentState::default())),
        }
    }

    pub async fn handle_request(&self, request: IpcRequest) -> IpcResponse {
        match request {
            IpcRequest::Status => {
                let state = self.state.read().await;
                IpcResponse::Ok(serde_json::json!({
                    "locked": state.is_locked,
                    "version": env!("CARGO_PKG_VERSION"),
                }))
            }
            IpcRequest::Unlock { pin: _ } => {
                let mut state = self.state.write().await;
                state.is_locked = false;
                IpcResponse::Ok(serde_json::json!({ "status": "unlocked" }))
            }
            IpcRequest::Lock => {
                let mut state = self.state.write().await;
                state.is_locked = true;
                IpcResponse::Ok(serde_json::json!({ "status": "locked" }))
            }
            IpcRequest::Sync => IpcResponse::Ok(serde_json::json!({ "status": "synced" })),
            IpcRequest::GetLogins { filter: _ } => IpcResponse::Ok(serde_json::json!([])),
        }
    }
}

impl Default for AgentDaemon {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns the default socket path `~/.silverwarden.sock` for the current user.
pub fn default_socket_path() -> Result<PathBuf, AgentError> {
    let home =
        std::env::var("HOME").map_err(|e| AgentError::Other(format!("HOME no definido: {e}")))?;
    Ok(PathBuf::from(home).join(".silverwarden.sock"))
}

/// Checks if a socket file exists. If another process is actively listening, returns `SocketAlreadyInUse`.
/// If the socket is orphaned, removes it cleanly.
pub async fn check_and_prepare_socket(socket_path: &Path) -> Result<(), AgentError> {
    if socket_path.exists() {
        match tokio::net::UnixStream::connect(socket_path).await {
            Ok(_) => {
                return Err(AgentError::SocketAlreadyInUse(socket_path.to_path_buf()));
            }
            Err(_) => {
                tracing::warn!(
                    "Socket huérfano detectado en {}, eliminándolo...",
                    socket_path.display()
                );
                std::fs::remove_file(socket_path)?;
            }
        }
    }
    Ok(())
}

/// Runs the agent server on the specified Unix domain socket path indefinitely.
pub async fn run_agent(socket_path: &Path) -> Result<(), AgentError> {
    run_agent_with_shutdown(socket_path, std::future::pending()).await
}

/// Runs the agent server on the specified Unix domain socket path with a shutdown future.
pub async fn run_agent_with_shutdown<F>(
    socket_path: &Path,
    shutdown_signal: F,
) -> Result<(), AgentError>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    check_and_prepare_socket(socket_path).await?;

    let listener = tokio::net::UnixListener::bind(socket_path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))?;
    }

    tokio::pin!(shutdown_signal);

    loop {
        tokio::select! {
            _ = &mut shutdown_signal => {
                tracing::info!("Señal de parada recibida para el agente.");
                break;
            }
            accept_res = listener.accept() => {
                match accept_res {
                    Ok((stream, _remote_addr)) => {
                        tokio::spawn(async move {
                            let (mut reader, mut writer) = stream.into_split();
                            match read_message(&mut reader).await {
                                Ok(_request) => {
                                    let response = IpcMessage {
                                        action: "Error".to_string(),
                                        payload: serde_json::Value::String("Not implemented".to_string()),
                                    };
                                    if let Err(e) = write_message(&mut writer, &response).await {
                                        tracing::warn!("Error al escribir respuesta IPC: {e}");
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!("Error al leer mensaje IPC: {e}");
                                }
                            }
                        });
                    }
                    Err(e) => {
                        tracing::error!("Error al aceptar conexión Unix: {e}");
                    }
                }
            }
        }
    }

    // Clean up socket file on shutdown
    let _ = std::fs::remove_file(socket_path);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::net::UnixStream;

    #[tokio::test]
    async fn test_agent_socket_request_response_not_implemented() {
        let temp_dir = tempfile::tempdir().expect("Create temp dir");
        let socket_path = temp_dir.path().join(".silverwarden.sock");

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let agent_socket = socket_path.clone();

        let agent_task = tokio::spawn(async move {
            run_agent_with_shutdown(&agent_socket, async {
                let _ = shutdown_rx.await;
            })
            .await
        });

        // Wait for socket to become available
        let mut client_connected = false;
        let mut attempts = 0;
        let mut stream = None;

        while attempts < 50 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            if let Ok(s) = UnixStream::connect(&socket_path).await {
                stream = Some(s);
                client_connected = true;
                break;
            }
            attempts += 1;
        }

        assert!(
            client_connected,
            "Client should successfully connect to agent socket"
        );
        let mut stream = stream.unwrap();

        // Verify socket permissions 0600 on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(&socket_path).expect("Metadata exists");
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        }

        // Send request message
        let request = IpcMessage::new("Status", serde_json::json!({ "check": true }));
        write_message(&mut stream, &request)
            .await
            .expect("Client write should succeed");

        // Read response
        let response = read_message(&mut stream)
            .await
            .expect("Client read should succeed");

        assert_eq!(response.action, "Error");
        assert_eq!(response.payload, "Not implemented");

        // Test collision while agent is running
        let collision_res = check_and_prepare_socket(&socket_path).await;
        assert!(matches!(
            collision_res,
            Err(AgentError::SocketAlreadyInUse(_))
        ));

        // Signal shutdown
        let _ = shutdown_tx.send(());
        let agent_res = agent_task.await.expect("Agent task finished");
        assert!(agent_res.is_ok());

        // Verify socket is cleaned up on shutdown
        assert!(!socket_path.exists());
    }

    #[tokio::test]
    async fn test_agent_orphan_socket_removal() {
        let temp_dir = tempfile::tempdir().expect("Create temp dir");
        let socket_path = temp_dir.path().join("orphan.sock");

        // Create a dummy orphan file at socket path
        std::fs::write(&socket_path, b"orphaned socket content").unwrap();
        assert!(socket_path.exists());

        // check_and_prepare_socket should detect no listener, remove it, and return Ok
        let res = check_and_prepare_socket(&socket_path).await;
        assert!(res.is_ok());
        assert!(!socket_path.exists());
    }

    #[test]
    fn test_default_socket_path() {
        if let Ok(home) = std::env::var("HOME") {
            let path = default_socket_path().expect("Default socket path succeeds");
            assert_eq!(path, PathBuf::from(home).join(".silverwarden.sock"));
        }
    }

    #[test]
    fn test_agent_error_display() {
        let io_err = AgentError::Io(std::io::Error::new(
            std::io::ErrorKind::AddrInUse,
            "address in use",
        ));
        assert!(io_err.to_string().contains("address in use"));

        let collision = AgentError::SocketAlreadyInUse(PathBuf::from("/test.sock"));
        assert!(collision.to_string().contains("ya está en uso"));

        let other = AgentError::Other("custom msg".to_string());
        assert!(other.to_string().contains("custom msg"));
    }

    #[tokio::test]
    async fn test_agent_daemon_handle_request() {
        let daemon = AgentDaemon::default();
        let status = daemon.handle_request(IpcRequest::Status).await;
        assert!(matches!(status, IpcResponse::Ok(_)));

        let unlock = daemon
            .handle_request(IpcRequest::Unlock { pin: "123".into() })
            .await;
        assert!(matches!(unlock, IpcResponse::Ok(_)));

        let lock = daemon.handle_request(IpcRequest::Lock).await;
        assert!(matches!(lock, IpcResponse::Ok(_)));

        let sync = daemon.handle_request(IpcRequest::Sync).await;
        assert!(matches!(sync, IpcResponse::Ok(_)));

        let logins = daemon
            .handle_request(IpcRequest::GetLogins { filter: None })
            .await;
        assert!(matches!(logins, IpcResponse::Ok(_)));
    }

    #[tokio::test]
    async fn test_run_agent_entrypoint_aborted() {
        let temp_dir = tempfile::tempdir().expect("Create temp dir");
        let socket_path = temp_dir.path().join("run_agent.sock");
        let handle = tokio::spawn(async move {
            let _ = run_agent(&socket_path).await;
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        handle.abort();
    }

    #[tokio::test]
    async fn test_agent_corrupted_message_handled() {
        let temp_dir = tempfile::tempdir().expect("Create temp dir");
        let socket_path = temp_dir.path().join("corrupted.sock");
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let agent_socket = socket_path.clone();

        tokio::spawn(async move {
            let _ = run_agent_with_shutdown(&agent_socket, async {
                let _ = shutdown_rx.await;
            })
            .await;
        });

        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            if let Ok(mut stream) = UnixStream::connect(&socket_path).await {
                use tokio::io::AsyncWriteExt;
                let _ = stream.write_all(&[0, 0, 0, 10, 1, 2]).await;
                break;
            }
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = shutdown_tx.send(());
    }
}
