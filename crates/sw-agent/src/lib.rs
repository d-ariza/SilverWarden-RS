use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use sw_config::ConfigFile;
use sw_ipc::{read_message, write_message, IpcMessage, IpcRequest, IpcResponse};
use sw_systemauth::{CallingContext, SessionStore, SessionType};
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

/// Central state maintained by the agent daemon.
#[derive(Debug, Clone)]
pub struct AgentState {
    pub config: ConfigFile,
    pub sessions: SessionStore,
    pub is_locked: bool,
    pub has_pin: bool,
    pub shutdown_sender: Option<tokio::sync::mpsc::Sender<()>>,
}

impl AgentState {
    pub fn new(config: ConfigFile) -> Self {
        let has_pin = !config.config_key_hash.is_empty();
        Self {
            config,
            sessions: SessionStore::new(),
            is_locked: true,
            has_pin,
            shutdown_sender: None,
        }
    }

    /// Loads the configuration file from ~/.config/goldwarden/goldwarden.json or defaults.
    pub fn load_or_default() -> Self {
        if let Ok(home) = std::env::var("HOME") {
            let path = sw_config::get_new_config_path(Path::new(&home));
            if path.exists() {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if let Ok(cfg) = serde_json::from_str::<ConfigFile>(&content) {
                        return Self::new(cfg);
                    }
                }
            }
        }
        Self::new(ConfigFile::default())
    }
}

impl Default for AgentState {
    fn default() -> Self {
        Self::new(ConfigFile::default())
    }
}

/// Trait implemented by IPC action handlers.
pub trait ActionFn: Send + Sync {
    fn execute(
        &self,
        state: &mut AgentState,
        ctx: &CallingContext,
        payload: &serde_json::Value,
    ) -> Result<serde_json::Value, String>;
}

impl<F> ActionFn for F
where
    F: Fn(
            &mut AgentState,
            &CallingContext,
            &serde_json::Value,
        ) -> Result<serde_json::Value, String>
        + Send
        + Sync,
{
    fn execute(
        &self,
        state: &mut AgentState,
        ctx: &CallingContext,
        payload: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        self(state, ctx, payload)
    }
}

/// Registry mapping action name strings to dynamic handlers.
#[derive(Default)]
pub struct ActionsRegistry {
    actions: HashMap<String, Box<dyn ActionFn>>,
}

impl ActionsRegistry {
    pub fn new() -> Self {
        Self {
            actions: HashMap::new(),
        }
    }

    pub fn register<F>(&mut self, action: impl Into<String>, handler: F)
    where
        F: ActionFn + 'static,
    {
        self.actions.insert(action.into(), Box::new(handler));
    }

    pub fn execute(
        &self,
        action: &str,
        state: &mut AgentState,
        ctx: &CallingContext,
        payload: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        if let Some(handler) = self.actions.get(action) {
            return handler.execute(state, ctx, payload);
        }

        for (k, handler) in &self.actions {
            if k.eq_ignore_ascii_case(action) {
                return handler.execute(state, ctx, payload);
            }
        }

        Err(format!("Acción no reconocida: {action}"))
    }
}

/// Saves the configuration file atomically using a temporary file and rename.
pub fn save_config_file(config: &ConfigFile, path: &Path) -> Result<(), std::io::Error> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }
    let json_bytes = serde_json::to_vec_pretty(config)?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    use std::io::Write;
    temp.write_all(&json_bytes)?;
    temp.flush()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o600));
    }
    temp.persist(path).map_err(|e| e.error)?;
    Ok(())
}

/// Builds the default registry with all core SilverWarden agent actions.
pub fn default_registry() -> ActionsRegistry {
    let mut registry = ActionsRegistry::new();

    // Status: devuelve { locked, has_pin, logged_in, version }
    registry.register(
        "Status",
        |state: &mut AgentState, _ctx: &CallingContext, _payload: &serde_json::Value| {
            let logged_in = !state.config.encrypted_token.is_empty();
            Ok(serde_json::json!({
                "locked": state.is_locked,
                "has_pin": state.has_pin,
                "logged_in": logged_in,
                "version": env!("CARGO_PKG_VERSION"),
            }))
        },
    );

    // Unlock: recibe { pin }, verifica contra sw-config, actualiza estado, crea sesión Pin
    registry.register(
        "Unlock",
        |state: &mut AgentState, ctx: &CallingContext, payload: &serde_json::Value| {
            let pin = match payload {
                serde_json::Value::Object(map) => map
                    .get("pin")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| "Campo 'pin' requerido en payload".to_string())?,
                serde_json::Value::String(s) => s.as_str(),
                _ => {
                    return Err(
                        "Payload inválido para Unlock: se esperaba objeto con 'pin' o string"
                            .to_string(),
                    )
                }
            };

            if !state.has_pin {
                return Err("No hay PIN configurado en el agente".to_string());
            }

            match state.config.verify_pin(pin) {
                Ok(true) => {
                    state.is_locked = false;
                    state
                        .sessions
                        .create_session(ctx, SessionType::Pin, Duration::from_secs(3600));
                    state.sessions.create_session(
                        ctx,
                        SessionType::AccessVault,
                        Duration::from_secs(3600),
                    );
                    Ok(serde_json::json!({ "status": "unlocked" }))
                }
                Ok(false) => Err("PIN incorrecto".to_string()),
                Err(e) => Err(format!("Error al verificar PIN: {e}")),
            }
        },
    );

    // Lock: borra la clave de memoria y wipea sesiones
    registry.register(
        "Lock",
        |state: &mut AgentState, _ctx: &CallingContext, _payload: &serde_json::Value| {
            state.is_locked = true;
            state.sessions.wipe();
            Ok(serde_json::json!({ "status": "locked" }))
        },
    );

    // PinSet: delega a sw-config
    registry.register(
        "PinSet",
        |state: &mut AgentState, _ctx: &CallingContext, payload: &serde_json::Value| {
            let pin = match payload {
                serde_json::Value::Object(map) => map
                    .get("pin")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| "Campo 'pin' requerido en payload".to_string())?,
                serde_json::Value::String(s) => s.as_str(),
                _ => {
                    return Err(
                        "Payload inválido para PinSet: se esperaba objeto con 'pin'".to_string()
                    )
                }
            };

            if state.has_pin {
                return Err("El PIN ya está configurado. Usa PinUpdate para cambiarlo.".to_string());
            }

            let key = sw_config::derive_config_key(pin, &state.config.device_uuid)
                .map_err(|e| format!("Error al derivar clave de PIN: {e}"))?;
            state.config.config_key_hash = sw_config::hash_config_key(&key);
            state.has_pin = true;

            if let Ok(home) = std::env::var("HOME") {
                let path = sw_config::get_new_config_path(Path::new(&home));
                let _ = save_config_file(&state.config, &path);
            }

            Ok(serde_json::json!({ "status": "pin_set" }))
        },
    );

    // PinUpdate: delega a sw-config
    registry.register(
        "PinUpdate",
        |state: &mut AgentState, _ctx: &CallingContext, payload: &serde_json::Value| {
            let (old_pin, new_pin) = match payload {
                serde_json::Value::Object(map) => {
                    let old = map
                        .get("old_pin")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "Campo 'old_pin' requerido".to_string())?;
                    let new = map
                        .get("new_pin")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "Campo 'new_pin' requerido".to_string())?;
                    (old, new)
                }
                _ => return Err(
                    "Payload inválido para PinUpdate: se esperaba objeto con 'old_pin' y 'new_pin'"
                        .to_string(),
                ),
            };

            if !state.has_pin {
                return Err("El PIN no está configurado. Usa PinSet.".to_string());
            }

            state
                .config
                .update_pin(old_pin, new_pin)
                .map_err(|e| format!("Error al actualizar PIN: {e}"))?;

            if let Ok(home) = std::env::var("HOME") {
                let path = sw_config::get_new_config_path(Path::new(&home));
                let _ = save_config_file(&state.config, &path);
            }

            Ok(serde_json::json!({ "status": "pin_updated" }))
        },
    );

    // AgentShutdown: para detener el agente (útil para tests)
    registry.register(
        "AgentShutdown",
        |state: &mut AgentState, _ctx: &CallingContext, _payload: &serde_json::Value| {
            if let Some(tx) = &state.shutdown_sender {
                let _ = tx.try_send(());
            }
            Ok(serde_json::json!({ "status": "shutting_down" }))
        },
    );

    registry
}

/// Agent daemon managing shared state and dispatching IPC requests.
#[derive(Clone)]
pub struct AgentDaemon {
    pub state: Arc<RwLock<AgentState>>,
    pub registry: Arc<ActionsRegistry>,
}

impl AgentDaemon {
    pub fn new() -> Self {
        Self::with_state(AgentState::load_or_default())
    }

    pub fn with_state(state: AgentState) -> Self {
        Self {
            state: Arc::new(RwLock::new(state)),
            registry: Arc::new(default_registry()),
        }
    }

    pub fn with_state_and_registry(state: AgentState, registry: ActionsRegistry) -> Self {
        Self {
            state: Arc::new(RwLock::new(state)),
            registry: Arc::new(registry),
        }
    }

    pub async fn handle_message(&self, ctx: &CallingContext, msg: IpcMessage) -> IpcMessage {
        let mut state = self.state.write().await;
        match self
            .registry
            .execute(&msg.action, &mut state, ctx, &msg.payload)
        {
            Ok(data) => IpcMessage::new("Ok", data),
            Err(err) => IpcMessage::new("Error", serde_json::Value::String(err)),
        }
    }

    pub async fn handle_request(&self, request: IpcRequest) -> IpcResponse {
        match request {
            IpcRequest::Status => {
                let state = self.state.read().await;
                IpcResponse::Ok(serde_json::json!({
                    "locked": state.is_locked,
                    "has_pin": state.has_pin,
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
                state.sessions.wipe();
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
    let daemon = AgentDaemon::new();
    run_agent_daemon_with_shutdown(socket_path, daemon, shutdown_signal).await
}

/// Runs the agent server using a custom daemon instance and a shutdown future.
pub async fn run_agent_daemon_with_shutdown<F>(
    socket_path: &Path,
    daemon: AgentDaemon,
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

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::channel::<()>(1);
    {
        let mut state = daemon.state.write().await;
        state.shutdown_sender = Some(shutdown_tx);
    }

    tokio::pin!(shutdown_signal);

    loop {
        tokio::select! {
            _ = &mut shutdown_signal => {
                tracing::info!("Señal de parada recibida para el agente.");
                break;
            }
            _ = shutdown_rx.recv() => {
                tracing::info!("Parada del agente solicitada vía comando IPC.");
                break;
            }
            accept_res = listener.accept() => {
                match accept_res {
                    Ok((stream, _remote_addr)) => {
                        let daemon = daemon.clone();
                        tokio::spawn(async move {
                            let ctx = sw_systemauth::get_calling_context(&stream);
                            let (mut reader, mut writer) = stream.into_split();
                            while let Ok(request) = read_message(&mut reader).await {
                                let response = daemon.handle_message(&ctx, request).await;
                                if let Err(e) = write_message(&mut writer, &response).await {
                                    tracing::warn!("Error al escribir respuesta IPC: {e}");
                                    break;
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
    async fn test_agent_socket_actions_flow() {
        let temp_dir = tempfile::tempdir().expect("Create temp dir");
        let socket_path = temp_dir.path().join(".silverwarden.sock");

        let test_pin = "agent_test_pin_987";
        let test_salt = "agent_uuid_test";
        let derived_key = sw_config::derive_config_key(test_pin, test_salt).unwrap();
        let config = ConfigFile {
            device_uuid: test_salt.to_string(),
            config_key_hash: sw_config::hash_config_key(&derived_key),
            ..Default::default()
        };

        let daemon = AgentDaemon::with_state(AgentState::new(config));
        let daemon_clone = daemon.clone();
        let agent_socket = socket_path.clone();

        let agent_task = tokio::spawn(async move {
            run_agent_daemon_with_shutdown(&agent_socket, daemon_clone, std::future::pending())
                .await
        });

        // Wait for socket to become available
        let mut stream = None;
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            if let Ok(s) = UnixStream::connect(&socket_path).await {
                stream = Some(s);
                break;
            }
        }

        assert!(
            stream.is_some(),
            "Client should successfully connect to agent socket"
        );
        let mut stream = stream.unwrap();

        // 1. Send Status request
        let status_req = IpcMessage::new("Status", serde_json::json!({}));
        write_message(&mut stream, &status_req).await.unwrap();
        let status_resp = read_message(&mut stream).await.unwrap();
        assert_eq!(status_resp.action, "Ok");
        assert_eq!(status_resp.payload["locked"], true);
        assert_eq!(status_resp.payload["has_pin"], true);

        // 2. Unlock with wrong PIN -> should fail
        let wrong_unlock_req = IpcMessage::new("Unlock", serde_json::json!({ "pin": "wrong_pin" }));
        write_message(&mut stream, &wrong_unlock_req).await.unwrap();
        let wrong_resp = read_message(&mut stream).await.unwrap();
        assert_eq!(wrong_resp.action, "Error");

        // 3. Unlock with correct PIN -> should succeed
        let unlock_req = IpcMessage::new("Unlock", serde_json::json!({ "pin": test_pin }));
        write_message(&mut stream, &unlock_req).await.unwrap();
        let unlock_resp = read_message(&mut stream).await.unwrap();
        assert_eq!(unlock_resp.action, "Ok");
        assert_eq!(unlock_resp.payload["status"], "unlocked");

        // Status after unlock -> locked must be false
        write_message(&mut stream, &status_req).await.unwrap();
        let status_after_unlock = read_message(&mut stream).await.unwrap();
        assert_eq!(status_after_unlock.payload["locked"], false);

        // 4. Send Lock request
        let lock_req = IpcMessage::new("Lock", serde_json::json!({}));
        write_message(&mut stream, &lock_req).await.unwrap();
        let lock_resp = read_message(&mut stream).await.unwrap();
        assert_eq!(lock_resp.action, "Ok");
        assert_eq!(lock_resp.payload["status"], "locked");

        // 5. Send AgentShutdown request to stop the daemon
        let shutdown_req = IpcMessage::new("AgentShutdown", serde_json::json!({}));
        write_message(&mut stream, &shutdown_req).await.unwrap();
        let shutdown_resp = read_message(&mut stream).await.unwrap();
        assert_eq!(shutdown_resp.action, "Ok");
        assert_eq!(shutdown_resp.payload["status"], "shutting_down");

        let agent_res = agent_task.await.expect("Agent task completed");
        assert!(agent_res.is_ok());
        assert!(!socket_path.exists());
    }

    #[tokio::test]
    async fn test_actions_registry_direct() {
        let mut state = AgentState::default();
        assert!(!state.has_pin);

        let registry = default_registry();
        let ctx = CallingContext {
            username: "tester".into(),
            process_name: "test".into(),
            parent_process_name: "test_runner".into(),
            grandparent_process_name: "cargo".into(),
            process_pid: 10,
            parent_process_pid: 5,
            grandparent_process_pid: 1,
            error: false,
            authenticated: true,
        };

        // Status on unconfigured agent
        let status_res = registry
            .execute("Status", &mut state, &ctx, &serde_json::json!({}))
            .unwrap();
        assert_eq!(status_res["has_pin"], false);
        assert_eq!(status_res["locked"], true);

        // PinSet
        let pin_set_res = registry
            .execute(
                "PinSet",
                &mut state,
                &ctx,
                &serde_json::json!({ "pin": "initial_pin_123" }),
            )
            .unwrap();
        assert_eq!(pin_set_res["status"], "pin_set");
        assert!(state.has_pin);

        // Second PinSet should fail
        assert!(registry
            .execute(
                "PinSet",
                &mut state,
                &ctx,
                &serde_json::json!({ "pin": "other_pin" })
            )
            .is_err());

        // Unlock with wrong PIN
        assert!(registry
            .execute(
                "Unlock",
                &mut state,
                &ctx,
                &serde_json::json!({ "pin": "bad_pin" })
            )
            .is_err());

        // Unlock with correct PIN
        let unlock_res = registry
            .execute(
                "Unlock",
                &mut state,
                &ctx,
                &serde_json::json!({ "pin": "initial_pin_123" }),
            )
            .unwrap();
        assert_eq!(unlock_res["status"], "unlocked");
        assert!(!state.is_locked);
        assert!(state
            .sessions
            .verify_session(&ctx, SessionType::AccessVault));

        // PinUpdate
        let update_res = registry
            .execute(
                "PinUpdate",
                &mut state,
                &ctx,
                &serde_json::json!({
                    "old_pin": "initial_pin_123",
                    "new_pin": "new_pin_456"
                }),
            )
            .unwrap();
        assert_eq!(update_res["status"], "pin_updated");

        // Verify old PIN no longer unlocks
        assert!(registry
            .execute(
                "Unlock",
                &mut state,
                &ctx,
                &serde_json::json!({ "pin": "initial_pin_123" })
            )
            .is_err());

        // New PIN unlocks
        assert!(registry
            .execute(
                "Unlock",
                &mut state,
                &ctx,
                &serde_json::json!({ "pin": "new_pin_456" })
            )
            .is_ok());

        // Lock wipes sessions
        let lock_res = registry
            .execute("Lock", &mut state, &ctx, &serde_json::json!({}))
            .unwrap();
        assert_eq!(lock_res["status"], "locked");
        assert!(state.is_locked);
        assert!(!state
            .sessions
            .verify_session(&ctx, SessionType::AccessVault));

        // Unknown action
        let unknown_res = registry.execute("NonExistent", &mut state, &ctx, &serde_json::json!({}));
        assert!(unknown_res.is_err());
    }

    #[tokio::test]
    async fn test_agent_orphan_socket_removal() {
        let temp_dir = tempfile::tempdir().expect("Create temp dir");
        let socket_path = temp_dir.path().join("orphan.sock");

        std::fs::write(&socket_path, b"orphaned socket content").unwrap();
        assert!(socket_path.exists());

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
