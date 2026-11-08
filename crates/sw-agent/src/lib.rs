use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use sw_ipc::{read_message, write_message, Request, Response};
use sw_ssh_agent::VaultAgentServer;
use sw_systemauth::CallingContext;
use thiserror::Error;
use tokio::sync::RwLock;

pub mod handlers;
pub mod ports;
pub mod state;

pub use handlers::*;
pub use ports::*;
pub use state::*;
pub use sw_config::ConfigFile;
pub use sw_systemauth::SessionType;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Error, Debug)]
pub enum AgentError {
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
    #[error("Error de IO: {0}")]
    Io(#[from] std::io::Error),
    #[error("IPC error: {0}")]
    Ipc(#[from] sw_ipc::IpcError),
    #[error("El socket ya está en uso por otra instancia del agente: {0}")]
    SocketAlreadyInUse(PathBuf),
    #[error("Error del agente: {0}")]
    Other(String),
}

impl AgentError {
    pub fn code(&self) -> &'static str {
        match self {
            AgentError::Locked => "locked",
            AgentError::InvalidPin => "invalid_pin",
            AgentError::NotFound(_) => "not_found",
            AgentError::Unauthorized(_) => "unauthorized",
            AgentError::ServerError(_) => "server_error",
            AgentError::Validation(_) => "validation",
            AgentError::Io(_) => "io",
            AgentError::Ipc(_) => "ipc",
            AgentError::SocketAlreadyInUse(_) => "socket_in_use",
            AgentError::Other(_) => "agent_error",
        }
    }

    pub fn contains(&self, pat: &str) -> bool {
        self.to_string().contains(pat)
    }
}

impl From<String> for AgentError {
    fn from(s: String) -> Self {
        if s.contains("PIN incorrecto") {
            AgentError::InvalidPin
        } else if s.contains("Bóveda bloqueada") || s.contains("Vault is locked") {
            AgentError::Locked
        } else {
            AgentError::Other(s)
        }
    }
}

#[allow(clippy::cmp_owned)]
impl PartialEq for AgentError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (AgentError::Locked, AgentError::Locked) => true,
            (AgentError::InvalidPin, AgentError::InvalidPin) => true,
            (AgentError::NotFound(a), AgentError::NotFound(b)) => a == b,
            (AgentError::Unauthorized(a), AgentError::Unauthorized(b)) => a == b,
            (AgentError::ServerError(a), AgentError::ServerError(b)) => a == b,
            (AgentError::Validation(a), AgentError::Validation(b)) => a == b,
            (AgentError::SocketAlreadyInUse(a), AgentError::SocketAlreadyInUse(b)) => a == b,
            (AgentError::Other(a), AgentError::Other(b)) => a == b,
            _ => self.to_string() == other.to_string(),
        }
    }
}

#[allow(clippy::cmp_owned)]
impl PartialEq<&str> for AgentError {
    fn eq(&self, other: &&str) -> bool {
        self.to_string() == *other || self.to_string().contains(*other)
    }
}

#[allow(clippy::cmp_owned)]
impl PartialEq<str> for AgentError {
    fn eq(&self, other: &str) -> bool {
        self.to_string() == other || self.to_string().contains(other)
    }
}

#[allow(clippy::cmp_owned)]
impl PartialEq<String> for AgentError {
    fn eq(&self, other: &String) -> bool {
        self.to_string() == *other || self.to_string().contains(other.as_str())
    }
}

impl From<&str> for AgentError {
    fn from(s: &str) -> Self {
        s.to_string().into()
    }
}

/// Type alias for dynamic asynchronous action handlers.
#[rustfmt::skip]
pub type ActionHandler = Box<dyn for<'a> Fn(&'a mut AgentState, &'a CallingContext, &'a serde_json::Value) -> BoxFuture<'a, Result<serde_json::Value, AgentError>> + Send + Sync>;

/// Registry mapping action name strings to dynamic handlers.
pub struct ActionsRegistry {
    pub actions: HashMap<String, ActionHandler>,
}

impl Default for ActionsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ActionsRegistry {
    pub fn new() -> Self {
        Self {
            actions: HashMap::new(),
        }
    }

    #[rustfmt::skip]
    pub fn register<F>(&mut self, action: impl Into<String>, handler: F)
    where
        F: Fn(&mut AgentState, &CallingContext, &serde_json::Value) -> Result<serde_json::Value, AgentError> + Send + Sync + 'static,
    {
        self.register_async(action, move |state, ctx, payload| {
            Box::pin(std::future::ready(handler(state, ctx, payload)))
        });
    }

    #[rustfmt::skip]
    pub fn register_async<F>(&mut self, action: impl Into<String>, handler: F)
    where
        F: (for<'a> Fn(&'a mut AgentState, &'a CallingContext, &'a serde_json::Value) -> BoxFuture<'a, Result<serde_json::Value, AgentError>>) + Send + Sync + 'static,
    {
        self.actions.insert(action.into(), Box::new(handler));
    }
}

impl ActionsRegistry {
    /// Registers SSH agent IPC actions (`ListSSHKeys`, `ImportSSHKey`, `NewSSHKey`, `DeleteSSHKey`)
    /// bound to the given `VaultAgentServer`.
    pub fn register_ssh_actions(&mut self, agent: Arc<VaultAgentServer>) {
        let a = agent.clone();
        self.register_async("ListSSHKeys", move |_state, _ctx, _payload| {
            let a = a.clone();
            Box::pin(async move { handle_list_ssh_keys(&a).await })
        });

        let a = agent.clone();
        self.register_async("ImportSSHKey", move |_state, _ctx, payload| {
            let a = a.clone();
            let payload = payload.clone();
            Box::pin(async move { handle_import_ssh_key(&a, &payload).await })
        });

        let a = agent.clone();
        self.register_async("NewSSHKey", move |_state, _ctx, payload| {
            let a = a.clone();
            let payload = payload.clone();
            Box::pin(async move { handle_new_ssh_key(&a, &payload).await })
        });

        let a = agent;
        self.register_async("DeleteSSHKey", move |_state, _ctx, payload| {
            let a = a.clone();
            let payload = payload.clone();
            Box::pin(async move { handle_delete_ssh_key(&a, &payload).await })
        });
    }

    #[rustfmt::skip]
    pub async fn execute(&self, action: &str, state: &mut AgentState, ctx: &CallingContext, payload: &serde_json::Value) -> Result<serde_json::Value, AgentError> {
        if let Some(handler) = self.actions.get(action) {
            return handler(state, ctx, payload).await;
        }

        for (k, handler) in &self.actions {
            if k.eq_ignore_ascii_case(action) {
                return handler(state, ctx, payload).await;
            }
        }

        Err(AgentError::NotFound(format!("Acción no reconocida: {action}")))
    }
}

/// Builds the default registry with all core SilverWarden agent actions.
pub fn default_registry() -> ActionsRegistry {
    let mut registry = ActionsRegistry::new();

    registry.register_async("Status", |state, ctx, _payload| {
        Box::pin(async move { handle_status(state, ctx).await })
    });
    registry.register_async("Unlock", |state, ctx, payload| {
        let p = payload.clone();
        Box::pin(async move { handle_unlock(state, ctx, &p).await })
    });
    registry.register_async("Lock", |state, ctx, _payload| {
        Box::pin(async move { handle_lock(state, ctx).await })
    });
    registry.register("PinSet", |state, _ctx, payload| {
        handle_pin_set(state, payload)
    });
    registry.register("PinUpdate", |state, _ctx, payload| {
        handle_pin_update(state, payload)
    });
    registry.register("AgentShutdown", |state, _ctx, _payload| {
        handle_agent_shutdown(state)
    });
    registry.register_async("ListSSHKeys", |state, _ctx, _payload| {
        let agent = state.vault_agent.clone();
        Box::pin(async move { handle_list_ssh_keys(&agent).await })
    });
    registry.register_async("ImportSSHKey", |state, _ctx, payload| {
        let agent = state.vault_agent.clone();
        let payload = payload.clone();
        Box::pin(async move { handle_import_ssh_key(&agent, &payload).await })
    });
    registry.register_async("NewSSHKey", |state, _ctx, payload| {
        let agent = state.vault_agent.clone();
        let payload = payload.clone();
        Box::pin(async move { handle_new_ssh_key(&agent, &payload).await })
    });
    registry.register_async("DeleteSSHKey", |state, _ctx, payload| {
        let agent = state.vault_agent.clone();
        let payload = payload.clone();
        Box::pin(async move { handle_delete_ssh_key(&agent, &payload).await })
    });
    registry.register_async("Sync", |state, _ctx, payload| {
        let p = payload.clone();
        Box::pin(async move { handle_sync(state, &p).await })
    });
    registry.register_async("SyncData", |state, _ctx, payload| {
        let p = payload.clone();
        Box::pin(async move { handle_sync_data(state, &p).await })
    });
    registry.register_async("ReloadVault", |state, _ctx, payload| {
        let p = payload.clone();
        Box::pin(async move { handle_sync_data(state, &p).await })
    });
    registry.register_async("ListLogins", |state, _ctx, _payload| {
        Box::pin(handle_list_logins(state))
    });
    registry.register_async("GetLogin", |state, _ctx, payload| {
        let p = payload.clone();
        Box::pin(async move { handle_get_login(state, &p).await })
    });
    registry.register_async("CreateLogin", |state, _ctx, payload| {
        let p = payload.clone();
        Box::pin(async move { handle_create_login(state, &p).await })
    });
    registry.register_async("DeleteLogin", |state, _ctx, payload| {
        let p = payload.clone();
        Box::pin(async move { handle_delete_login(state, &p).await })
    });
    registry.register_async("SetSession", |state, _ctx, payload| {
        let p = payload.clone();
        Box::pin(async move { handle_set_session(state, &p).await })
    });
    registry.register_async("Login", |state, _ctx, payload| {
        let p = payload.clone();
        Box::pin(async move { handle_set_session(state, &p).await })
    });

    registry
}

/// Builds a default registry and registers SSH actions bound to the specified `VaultAgentServer`.
pub fn default_registry_with_ssh(agent: Arc<VaultAgentServer>) -> ActionsRegistry {
    let mut registry = default_registry();
    registry.register_ssh_actions(agent);
    registry
}

/// Agent daemon managing shared state and dispatching IPC requests.
#[derive(Clone)]
pub struct AgentDaemon {
    pub state: Arc<RwLock<AgentState>>,
}

impl AgentDaemon {
    pub fn new() -> Self {
        let va = Arc::new(VaultAgentServer::default());
        let state = AgentState::load_or_default_with(va.clone());
        Self::with_vault_agent(state, va)
    }

    pub fn with_state(state: AgentState) -> Self {
        Self {
            state: Arc::new(RwLock::new(state)),
        }
    }

    pub fn with_state_and_registry(state: AgentState, _registry: ActionsRegistry) -> Self {
        Self::with_state(state)
    }

    pub fn with_vault_agent(mut state: AgentState, vault_agent: Arc<VaultAgentServer>) -> Self {
        // Cargar vault.json automáticamente al iniciar el daemon si existe en disco
        if let Some(vault_path) = state.vault_path() {
            if vault_path.exists() {
                if let Ok(sync_data) = sw_vault::load_vault(&vault_path) {
                    let agent = vault_agent.clone();
                    if let Ok(handle) = tokio::runtime::Handle::try_current() {
                        handle.spawn(async move {
                            agent.vault().load_sync_data(sync_data).await;
                        });
                    }
                }
            }
        }

        state.vault_agent = vault_agent;
        Self::with_state(state)
    }

    pub async fn handle_message(&self, ctx: &CallingContext, req: Request) -> Response {
        {
            let state = self.state.read().await;
            state.touch_activity().await;
        }
        let mut state = self.state.write().await;
        Self::dispatch_request(&mut state, ctx, req).await
    }

    pub async fn dispatch_request(
        state: &mut AgentState,
        ctx: &CallingContext,
        req: Request,
    ) -> Response {
        let res = match req {
            Request::Status => handle_status(state, ctx).await,
            Request::Unlock { pin } => {
                let payload = serde_json::json!({ "pin": pin });
                handle_unlock(state, ctx, &payload).await
            }
            Request::Lock => handle_lock(state, ctx).await,
            Request::Sync => handle_sync(state, &serde_json::json!({})).await,
            Request::SyncData(payload) | Request::ReloadVault(payload) => {
                handle_sync_data(state, &payload).await
            }
            Request::ListLogins => handle_list_logins(state).await,
            Request::GetLogin { name } => {
                handle_get_login(state, &serde_json::json!({ "name": name })).await
            }
            Request::CreateLogin {
                name,
                username,
                password,
            } => {
                let payload = serde_json::json!({
                    "name": name,
                    "username": username,
                    "password": password
                });
                handle_create_login(state, &payload).await
            }
            Request::DeleteLogin { name } => {
                handle_delete_login(state, &serde_json::json!({ "name": name })).await
            }
            Request::ListSshKeys => {
                let agent = state.vault_agent.clone();
                handle_list_ssh_keys(&agent).await
            }
            Request::ImportSshKey { name, pem } => {
                let agent = state.vault_agent.clone();
                handle_import_ssh_key(&agent, &serde_json::json!({ "name": name, "pem": pem }))
                    .await
            }
            Request::NewSshKey { name, key_type } => {
                let agent = state.vault_agent.clone();
                handle_new_ssh_key(
                    &agent,
                    &serde_json::json!({ "name": name, "key_type": key_type }),
                )
                .await
            }
            Request::DeleteSshKey { id } => {
                let agent = state.vault_agent.clone();
                handle_delete_ssh_key(&agent, &serde_json::json!({ "id": id })).await
            }
            Request::SetSession {
                token,
                encrypted_token,
                encrypted_user_symmetric_key,
                user_symmetric_key,
                identity_url,
                api_url,
                notifications_url,
                danger_accept_invalid_certs,
            } => {
                let payload = serde_json::json!({
                    "token": token,
                    "encrypted_token": encrypted_token,
                    "encrypted_user_symmetric_key": encrypted_user_symmetric_key,
                    "user_symmetric_key": user_symmetric_key,
                    "identity_url": identity_url,
                    "api_url": api_url,
                    "notifications_url": notifications_url,
                    "danger_accept_invalid_certs": danger_accept_invalid_certs,
                });
                handle_set_session(state, &payload).await
            }
            Request::PinSet { pin } => handle_pin_set(state, &serde_json::json!({ "pin": pin })),
            Request::PinUpdate { old_pin, new_pin } => handle_pin_update(
                state,
                &serde_json::json!({ "old_pin": old_pin, "new_pin": new_pin }),
            ),
            Request::AgentShutdown => handle_agent_shutdown(state),
        };

        match res {
            Ok(data) => Response::Ok(data),
            Err(err) => Response::Error {
                code: err.code().to_string(),
                message: err.to_string(),
            },
        }
    }
}

impl Default for AgentDaemon {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns the socket path `~/.silverwarden.sock` for a specific home or falling back to the current user's `$HOME`.
pub fn socket_path_from_home(home: Option<&str>) -> Result<PathBuf, AgentError> {
    let home = home
        .map(String::from)
        .or_else(|| std::env::var("HOME").ok())
        .ok_or_else(|| AgentError::Other("HOME no definido".into()))?;
    Ok(PathBuf::from(home).join(".silverwarden.sock"))
}

/// Returns the default socket path `~/.silverwarden.sock` for the current user.
pub fn default_socket_path() -> Result<PathBuf, AgentError> {
    socket_path_from_home(None)
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

/// Event from systemd-logind via D-Bus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogindEvent {
    PrepareForSleep(bool),
    Lock,
}

/// Handles systemd-logind events (PrepareForSleep, Lock), locking the vault if appropriate.
pub async fn handle_logind_event(state: &Arc<RwLock<AgentState>>, event: LogindEvent) {
    let should_lock = match event {
        LogindEvent::PrepareForSleep(start) => start,
        LogindEvent::Lock => true,
    };
    if !should_lock {
        return;
    }
    let mut state_guard = state.write().await;
    if state_guard.is_locked {
        return;
    }
    state_guard.pin_cache.clear();
    state_guard.is_locked = true;
    state_guard.sessions.wipe();
    let va = state_guard.vault_agent.clone();
    let notifier = state_guard.notifier.clone();
    drop(state_guard);

    va.lock().await;
    let reason = match event {
        LogindEvent::PrepareForSleep(_) => "Bóveda bloqueada por suspensión del sistema",
        LogindEvent::Lock => "Bóveda bloqueada por bloqueo de pantalla",
    };
    let _ = notifier.notify("SilverWarden", reason).await;
}

/// Spawns the inactivity monitor task which periodically checks if idle duration exceeded TTL.
pub fn spawn_idle_monitor(
    state: Arc<RwLock<AgentState>>,
    mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    check_interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(check_interval);
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let state_guard = state.read().await;
                    if state_guard.is_locked {
                        continue;
                    }
                    let idle = state_guard.idle_duration().await;
                    let ttl = state_guard.idle_ttl().await;
                    drop(state_guard);
                    if idle >= ttl {
                        let mut state_guard = state.write().await;
                        if state_guard.is_locked {
                            continue;
                        }
                        state_guard.pin_cache.clear();
                        state_guard.is_locked = true;
                        state_guard.sessions.wipe();
                        let va = state_guard.vault_agent.clone();
                        let notifier = state_guard.notifier.clone();
                        drop(state_guard);

                        va.lock().await;
                        let _ = notifier.notify("SilverWarden", "Bóveda bloqueada por inactividad").await;
                    }
                }
                _ = shutdown_rx.recv() => break,
            }
        }
    })
}

/// Spawns the systemd-logind monitor task subscribing to PrepareForSleep and Lock signals.
pub fn spawn_logind_monitor(
    state: Arc<RwLock<AgentState>>,
    mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        use zbus::export::ordered_stream::OrderedStreamExt;

        let connection = match zbus::Connection::system().await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("systemd-logind no disponible vía system D-Bus: {e}");
                return;
            }
        };

        let proxy = match zbus::proxy::Proxy::new(
            &connection,
            "org.freedesktop.login1",
            "/org/freedesktop/login1",
            "org.freedesktop.login1.Manager",
        )
        .await
        {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("Proxy org.freedesktop.login1 no disponible: {e}");
                return;
            }
        };

        let mut prepare_for_sleep = match proxy.receive_signal("PrepareForSleep").await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("No se pudo suscribir a señal PrepareForSleep de logind: {e}");
                return;
            }
        };

        let mut lock_signal = match proxy.receive_signal("Lock").await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("No se pudo suscribir a señal Lock de logind: {e}");
                return;
            }
        };

        loop {
            tokio::select! {
                res = prepare_for_sleep.next() => {
                    match res {
                        Some(msg) => {
                            if let Ok(start) = msg.body().deserialize::<bool>() {
                                handle_logind_event(&state, LogindEvent::PrepareForSleep(start)).await;
                            }
                        }
                        None => break,
                    }
                }
                res = lock_signal.next() => {
                    match res {
                        Some(_) => {
                            handle_logind_event(&state, LogindEvent::Lock).await;
                        }
                        None => break,
                    }
                }
                _ = shutdown_rx.recv() => break,
            }
        }
    })
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
    set_permissions_unix(socket_path, 0o600)?;

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::channel::<()>(1);
    {
        let mut state = daemon.state.write().await;
        state.shutdown_sender = Some(shutdown_tx);
    }

    // Cargar vault.json en VaultStore si existe en disco al arrancar el daemon
    {
        let state = daemon.state.read().await;
        let vp = state.vault_path().or_else(|| {
            sw_vault::VaultPaths::default_paths()
                .ok()
                .map(|p| p.vault_file())
        });
        if let Some(vault_path) = vp {
            if vault_path.exists() {
                if let Ok(sync_data) = sw_vault::load_vault(&vault_path) {
                    let agent = state.vault_agent.clone();
                    agent.vault().load_sync_data(sync_data).await;
                    tracing::info!("Cargados ciphers de vault.json en memoria");
                }
            }
        }
    }

    let (monitor_shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(1);
    let idle_handle = spawn_idle_monitor(
        daemon.state.clone(),
        monitor_shutdown_tx.subscribe(),
        Duration::from_secs(5),
    );
    let logind_handle = spawn_logind_monitor(daemon.state.clone(), monitor_shutdown_tx.subscribe());

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

    let _ = monitor_shutdown_tx.send(());
    let _ = tokio::join!(idle_handle, logind_handle);

    // Clean up socket file on shutdown
    let _ = std::fs::remove_file(socket_path);
    Ok(())
}

#[cfg(test)]
mod tests;
