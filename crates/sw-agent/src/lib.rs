use std::collections::HashMap;
use std::future::Future;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use sw_config::ConfigFile;
use sw_crypto::mem::{LockedBuffer, MemLockedBuffer};
use sw_ipc::{read_message, write_message, IpcMessage, IpcRequest, IpcResponse};
use sw_ssh_agent::VaultAgentServer;
use sw_systemauth::{CallingContext, SessionStore, SessionType};
use thiserror::Error;
use tokio::sync::RwLock;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

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

#[cfg(not(test))]
const AGENT_KDF_MEMORY_KIB: u32 = sw_config::KDF_MEMORY_KIB;
#[cfg(test)]
const AGENT_KDF_MEMORY_KIB: u32 = sw_config::KDF_MEMORY_KIB_TEST;

/// In-memory cache for the derived 32-byte config key (in locked RAM).
/// Protects against repeated Argon2i executions (which consume ~2-5s and 2 GiB RAM).
/// Does NOT store the user's PIN or the user symmetric key.
pub struct PinCache {
    config_key: Option<MemLockedBuffer>,
    expires_at: Option<tokio::time::Instant>,
    ttl: Duration,
}

impl PinCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            config_key: None,
            expires_at: None,
            ttl,
        }
    }

    pub fn store(&mut self, key: &[u8]) {
        if key.len() != 32 {
            return;
        }
        if let Ok(buf) = MemLockedBuffer::new(key) {
            self.config_key = Some(buf);
            self.expires_at = Some(tokio::time::Instant::now() + self.ttl);
        }
    }

    pub fn get(&mut self) -> Option<[u8; 32]> {
        if !self.is_valid() {
            return None;
        }
        // Sliding TTL: resets expires_at on each successful get
        self.expires_at = Some(tokio::time::Instant::now() + self.ttl);
        self.config_key.as_ref().and_then(|buf| {
            let slice = buf.as_slice();
            if slice.len() != 32 {
                None
            } else {
                let mut out = [0u8; 32];
                out.copy_from_slice(slice);
                Some(out)
            }
        })
    }

    pub fn is_valid(&self) -> bool {
        match (self.expires_at, &self.config_key) {
            (Some(exp), Some(buf)) => tokio::time::Instant::now() < exp && buf.len() == 32,
            _ => false,
        }
    }

    pub fn remaining(&self) -> Option<Duration> {
        if !self.is_valid() {
            return None;
        }
        self.expires_at.and_then(|exp| {
            let now = tokio::time::Instant::now();
            if exp > now {
                Some(exp - now)
            } else {
                None
            }
        })
    }

    pub fn clear(&mut self) {
        self.config_key = None;
        self.expires_at = None;
    }
}

impl Clone for PinCache {
    fn clone(&self) -> Self {
        Self {
            config_key: self
                .config_key
                .as_ref()
                .and_then(|buf| MemLockedBuffer::new(buf.as_slice()).ok()),
            expires_at: self.expires_at,
            ttl: self.ttl,
        }
    }
}

impl std::fmt::Debug for PinCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PinCache")
            .field("has_key", &self.config_key.is_some())
            .field("expires_at", &self.expires_at)
            .field("ttl", &self.ttl)
            .finish()
    }
}

impl Default for PinCache {
    fn default() -> Self {
        Self::new(Duration::from_secs(sw_config::DEFAULT_PIN_CACHE_TTL_SECS))
    }
}

/// Central state maintained by the agent daemon.
#[derive(Clone, Debug)]
pub struct AgentState {
    pub config: ConfigFile,
    pub sessions: SessionStore,
    pub is_locked: bool,
    pub has_pin: bool,
    pub shutdown_sender: Option<tokio::sync::mpsc::Sender<()>>,
    pub vault_agent: Option<Arc<VaultAgentServer>>,
    pub config_directory: Option<PathBuf>,
    pub api_client: Option<Arc<sw_bitwarden_api::AuthenticatedClient>>,
    pub pin_cache: PinCache,
    pub notifier: Arc<dyn sw_notify::Notifier>,
    pub last_activity: Arc<tokio::sync::RwLock<tokio::time::Instant>>,
    pub biometrics: Arc<dyn sw_systemauth::Biometrics>,
}

impl AgentState {
    pub fn new(config: ConfigFile) -> Self {
        let has_pin = !config.config_key_hash.is_empty();
        let pin_cache_ttl = Duration::from_secs(config.runtime_config.pin_cache_ttl_secs);
        Self {
            config,
            sessions: SessionStore::new(),
            is_locked: true,
            has_pin,
            shutdown_sender: None,
            vault_agent: None,
            config_directory: None,
            api_client: None,
            pin_cache: PinCache::new(pin_cache_ttl),
            notifier: Arc::new(sw_notify::DbusNotifier::new()),
            last_activity: Arc::new(tokio::sync::RwLock::new(tokio::time::Instant::now())),
            biometrics: Arc::new(sw_systemauth::PolkitBiometrics::new()),
        }
    }

    /// Touches the last activity timestamp, resetting the inactivity counter.
    pub async fn touch_activity(&self) {
        let mut guard = self.last_activity.write().await;
        *guard = tokio::time::Instant::now();
    }

    /// Returns the duration elapsed since the last IPC or user activity.
    pub async fn idle_duration(&self) -> Duration {
        let guard = self.last_activity.read().await;
        tokio::time::Instant::now().saturating_duration_since(*guard)
    }

    /// Returns the configured idle time-to-live before automatic lock.
    pub async fn idle_ttl(&self) -> Duration {
        Duration::from_secs(self.config.runtime_config.idle_ttl_secs)
    }

    /// Sets an injectable desktop notifier.
    pub fn with_notifier(mut self, notifier: Arc<dyn sw_notify::Notifier>) -> Self {
        self.notifier = notifier;
        self
    }

    /// Sets an injectable biometrics backend.
    pub fn with_biometrics(mut self, biometrics: Arc<dyn sw_systemauth::Biometrics>) -> Self {
        self.biometrics = biometrics;
        self
    }

    /// Sets an authenticated API client in state.
    pub fn with_api_client(mut self, client: Arc<sw_bitwarden_api::AuthenticatedClient>) -> Self {
        self.api_client = Some(client);
        self
    }

    /// Sets an injectable configuration directory for saving and loading config.
    pub fn with_config_directory(mut self, dir: impl Into<PathBuf>) -> Self {
        self.config_directory = Some(dir.into());
        self
    }

    /// Returns the target path for saving/loading configuration.
    /// In test mode (`#[cfg(test)]`), this NEVER touches `$HOME` unless `config_directory` was explicitly set.
    pub fn config_path(&self) -> Option<PathBuf> {
        if let Some(dir) = &self.config_directory {
            if dir.ends_with("goldwarden.json") {
                Some(dir.clone())
            } else {
                Some(dir.join("goldwarden.json"))
            }
        } else {
            #[cfg(test)]
            {
                // In test builds, NEVER write to or touch the user's real $HOME directory
                None
            }
            #[cfg(not(test))]
            {
                std::env::var("HOME")
                    .ok()
                    .map(|home| sw_config::get_new_config_path(Path::new(&home)))
            }
        }
    }

    /// Returns the resolved vault path if available.
    pub fn vault_path(&self) -> Option<PathBuf> {
        #[cfg(test)]
        {
            self.config_directory
                .as_ref()
                .map(|dir| dir.join("vault.json"))
        }
        #[cfg(not(test))]
        {
            if let Some(dir) = &self.config_directory {
                Some(dir.join("vault.json"))
            } else {
                sw_vault::VaultPaths::default_paths()
                    .ok()
                    .map(|p| p.vault_file())
            }
        }
    }

    /// Sets the `VaultAgentServer` instance in state.
    pub fn with_vault_agent(mut self, agent: Arc<VaultAgentServer>) -> Self {
        self.vault_agent = Some(agent);
        self
    }

    /// Loads the configuration file from ~/.config/goldwarden/goldwarden.json or defaults.
    pub fn load_or_default() -> Self {
        Self::load_or_default_from(None)
    }

    /// Loads the configuration from an optional directory, or defaults.
    pub fn load_or_default_from(config_dir: Option<PathBuf>) -> Self {
        let mut state = Self::new(ConfigFile::default());
        if let Some(dir) = config_dir {
            state.config_directory = Some(dir);
        }
        if let Some(path) = state.config_path() {
            if path.exists() {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if let Ok(cfg) = serde_json::from_str::<ConfigFile>(&content) {
                        state.config = cfg;
                        state.has_pin = !state.config.config_key_hash.is_empty();
                        return state;
                    }
                }
            }
        }
        state
    }
}

impl Default for AgentState {
    fn default() -> Self {
        Self::new(ConfigFile::default())
    }
}

/// Type alias for dynamic asynchronous action handlers.
#[rustfmt::skip]
pub type ActionHandler = Box<dyn for<'a> Fn(&'a mut AgentState, &'a CallingContext, &'a serde_json::Value) -> BoxFuture<'a, Result<serde_json::Value, String>> + Send + Sync>;

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
        F: Fn(&mut AgentState, &CallingContext, &serde_json::Value) -> Result<serde_json::Value, String> + Send + Sync + 'static,
    {
        self.register_async(action, move |state, ctx, payload| {
            Box::pin(std::future::ready(handler(state, ctx, payload)))
        });
    }

    #[rustfmt::skip]
    pub fn register_async<F>(&mut self, action: impl Into<String>, handler: F)
    where
        F: (for<'a> Fn(&'a mut AgentState, &'a CallingContext, &'a serde_json::Value) -> BoxFuture<'a, Result<serde_json::Value, String>>) + Send + Sync + 'static,
    {
        self.actions.insert(action.into(), Box::new(handler));
    }
}

async fn handle_list_ssh_keys(agent: &VaultAgentServer) -> Result<serde_json::Value, String> {
    if agent.is_locked() {
        return Err("Vault is locked".to_string());
    }
    let keys = agent.list_ssh_keys().await.map_err(|e| e.to_string())?;
    serde_json::to_value(&keys).map_err(|e| e.to_string())
}

async fn handle_import_ssh_key(
    agent: &VaultAgentServer,
    payload: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    let sym_key = agent
        .get_symmetric_key()
        .await
        .ok_or_else(|| "Vault is locked".to_string())?;

    let (name, pem) = match payload {
        serde_json::Value::Object(map) => {
            let name = map
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Campo 'name' requerido".to_string())?;
            let pem = map
                .get("private_key_pem")
                .or_else(|| map.get("private_key"))
                .or_else(|| map.get("pem"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Campo 'private_key_pem' requerido".to_string())?;
            (name.to_string(), pem.to_string())
        }
        _ => return Err("Payload inválido para ImportSSHKey: se esperaba objeto".to_string()),
    };

    let summary = agent
        .import_ssh_key(&name, &pem, &sym_key)
        .await
        .map_err(|e| e.to_string())?;
    serde_json::to_value(&summary).map_err(|e| e.to_string())
}

async fn handle_new_ssh_key(
    agent: &VaultAgentServer,
    payload: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    let sym_key = agent
        .get_symmetric_key()
        .await
        .ok_or_else(|| "Vault is locked".to_string())?;

    let (name, key_type) = match payload {
        serde_json::Value::Object(map) => {
            let name = map
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Campo 'name' requerido".to_string())?;
            let kt = map
                .get("key_type")
                .or_else(|| map.get("type"))
                .and_then(|v| v.as_str())
                .unwrap_or("Ed25519");
            (name.to_string(), kt.to_string())
        }
        _ => return Err("Payload inválido para NewSSHKey: se esperaba objeto".to_string()),
    };

    let summary = agent
        .new_ssh_key(&name, &key_type, &sym_key)
        .await
        .map_err(|e| e.to_string())?;
    serde_json::to_value(&summary).map_err(|e| e.to_string())
}

async fn handle_delete_ssh_key(
    agent: &VaultAgentServer,
    payload: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    if agent.is_locked() {
        return Err("Vault is locked".to_string());
    }
    #[rustfmt::skip]
    let id_str = match payload {
        serde_json::Value::Object(map) => map.get("id").and_then(|v| v.as_str()).ok_or_else(|| "Campo 'id' requerido".to_string())?,
        serde_json::Value::String(s) => s.as_str(),
        _ => return Err("Payload inválido para DeleteSSHKey: se esperaba objeto o id string".to_string()),
    };
    let id = uuid::Uuid::parse_str(id_str).map_err(|e| format!("ID de clave inválido: {e}"))?;
    agent.delete_ssh_key(&id).await.map_err(|e| e.to_string())?;
    Ok(serde_json::json!({
        "status": "deleted",
        "id": id.to_string(),
    }))
}

async fn handle_sync(
    state: &mut AgentState,
    payload: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    if state.is_locked {
        return Err("Bóveda bloqueada. Desbloquea con 'silverwarden unlock' primero.".to_string());
    }

    // 1. Sync config fields from payload if provided
    if let Some(map) = payload.as_object() {
        if let Some(enc_tok) = map.get("encrypted_token").and_then(|v| v.as_str()) {
            if !enc_tok.is_empty() {
                state.config.encrypted_token = enc_tok.to_string();
            }
        }
        if let Some(enc_sym) = map
            .get("encrypted_user_symmetric_key")
            .and_then(|v| v.as_str())
        {
            if !enc_sym.is_empty() {
                state.config.encrypted_user_symmetric_key = enc_sym.to_string();
            }
        }
        if let Some(id_url) = map.get("identity_url").and_then(|v| v.as_str()) {
            state.config.identity_url = id_url.to_string();
        }
        if let Some(api_url) = map.get("api_url").and_then(|v| v.as_str()) {
            state.config.api_url = api_url.to_string();
        }
        if let Some(insecure) = map
            .get("danger_accept_invalid_certs")
            .and_then(|v| v.as_bool())
        {
            state.config.danger_accept_invalid_certs = insecure;
        }
        if let Some(token_val) = map.get("token") {
            if let Ok(token) = serde_json::from_value::<sw_config::LoginToken>(token_val.clone()) {
                let client = Arc::new(
                    sw_bitwarden_api::AuthenticatedClient::from_token_with_options(
                        state.config.identity_url.clone(),
                        state.config.api_url.clone(),
                        token,
                        state.config.danger_accept_invalid_certs,
                    ),
                );
                state.api_client = Some(client);
            }
        }
    }

    // 2. If still not logged in according to state.config and api_client is missing, check disk config
    if !state.config.is_logged_in() && state.api_client.is_none() {
        if let Some(path) = state.config_path() {
            if path.exists() {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if let Ok(disk_cfg) = serde_json::from_str::<sw_config::ConfigFile>(&content) {
                        if disk_cfg.is_logged_in() {
                            state.config.encrypted_token = disk_cfg.encrypted_token;
                            state.config.encrypted_user_symmetric_key =
                                disk_cfg.encrypted_user_symmetric_key;
                            state.config.identity_url = disk_cfg.identity_url;
                            state.config.api_url = disk_cfg.api_url;
                            state.config.notifications_url = disk_cfg.notifications_url;
                            state.config.danger_accept_invalid_certs =
                                disk_cfg.danger_accept_invalid_certs;
                        }
                    }
                }
            }
        }
    }

    if !state.config.is_logged_in() && state.api_client.is_none() {
        return Err("No hay sesión iniciada. Ejecuta 'silverwarden login' primero.".to_string());
    }

    let agent = match state.vault_agent.as_ref() {
        Some(a) => a.clone(),
        None => sw_ssh_agent::shared_vault_agent(),
    };

    let client = state.api_client.as_ref().or_else(|| agent.api_client());
    if let Some(c) = client {
        match c.sync().await {
            Ok(sync_data) => {
                if let Some(vp) = state.vault_path() {
                    let _ = sw_vault::save_vault(&vp, &sync_data);
                }
                agent.vault().load_sync_data(sync_data).await;
            }
            Err(sw_bitwarden_api::ApiError::RateLimitExceeded) => {
                return Err("El servidor ha bloqueado temporalmente tu IP por demasiados intentos de login. Espera unos minutos o cambia de red (por ejemplo, usa datos móviles).".to_string());
            }
            Err(e) => return Err(format!("Error al sincronizar con el servidor: {e}")),
        }
    }

    let all_ciphers = agent.vault().all().await;
    let non_deleted: Vec<_> = all_ciphers
        .into_iter()
        .filter(|c| c.deleted_date.is_none())
        .collect();
    let total = non_deleted.len();
    let logins = non_deleted
        .iter()
        .filter(|c| c.r#type == sw_vault::CipherType::Login)
        .count();
    let ssh_keys = non_deleted
        .iter()
        .filter(|c| c.r#type == sw_vault::CipherType::SshKey)
        .count();

    Ok(serde_json::json!({
        "status": "synced",
        "logins": logins,
        "total": total,
        "ssh_keys": ssh_keys,
    }))
}

async fn handle_sync_data(
    state: &mut AgentState,
    payload: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    let sync_data: sw_vault::SyncData = serde_json::from_value(payload.clone())
        .map_err(|e| format!("Error deserializando SyncData: {e}"))?;

    if let Some(vp) = state.vault_path() {
        let _ = sw_vault::save_vault(&vp, &sync_data);
    }

    let agent = match state.vault_agent.as_ref() {
        Some(a) => a.clone(),
        None => sw_ssh_agent::shared_vault_agent(),
    };

    // Load sync data into the agent's VaultStore without modifying existing user_symmetric_key in memory
    agent.vault().load_sync_data(sync_data).await;

    let all_ciphers = agent.vault().all().await;
    let non_deleted: Vec<_> = all_ciphers
        .into_iter()
        .filter(|c| c.deleted_date.is_none())
        .collect();
    let total = non_deleted.len();
    let logins = non_deleted
        .iter()
        .filter(|c| c.r#type == sw_vault::CipherType::Login)
        .count();
    let ssh_keys = non_deleted
        .iter()
        .filter(|c| c.r#type == sw_vault::CipherType::SshKey)
        .count();

    Ok(serde_json::json!({
        "status": "synced",
        "logins": logins,
        "total": total,
        "ssh_keys": ssh_keys,
    }))
}

async fn handle_list_logins(state: &AgentState) -> Result<serde_json::Value, String> {
    if state.is_locked {
        return Err("Bóveda bloqueada. Desbloquea con 'silverwarden unlock' primero.".to_string());
    }
    let agent = match state.vault_agent.as_ref() {
        Some(a) => a.clone(),
        None => sw_ssh_agent::shared_vault_agent(),
    };
    let sym_key = agent
        .get_symmetric_key()
        .await
        .ok_or_else(|| "Bóveda bloqueada".to_string())?;

    let all = agent.vault().all().await;
    let mut list = Vec::new();
    for c in all {
        if c.r#type == sw_vault::CipherType::Login && c.deleted_date.is_none() {
            if let Ok(dec) = sw_vault::VaultStore::decrypt_cipher(&c, &sym_key) {
                list.push(serde_json::json!({
                    "id": dec.id,
                    "name": dec.name,
                    "username": dec.username.unwrap_or_default(),
                }));
            }
        }
    }
    Ok(serde_json::json!(list))
}

async fn handle_get_login(
    state: &AgentState,
    payload: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    if state.is_locked {
        return Err("Bóveda bloqueada. Desbloquea con 'silverwarden unlock' primero.".to_string());
    }
    let target_name = payload
        .get("name")
        .and_then(|v| v.as_str())
        .or_else(|| payload.as_str())
        .ok_or_else(|| "Campo 'name' requerido".to_string())?;

    let agent = match state.vault_agent.as_ref() {
        Some(a) => a.clone(),
        None => sw_ssh_agent::shared_vault_agent(),
    };
    let sym_key = agent
        .get_symmetric_key()
        .await
        .ok_or_else(|| "Bóveda bloqueada".to_string())?;

    let all = agent.vault().all().await;
    for c in all {
        if c.r#type == sw_vault::CipherType::Login && c.deleted_date.is_none() {
            if let Ok(dec) = sw_vault::VaultStore::decrypt_cipher(&c, &sym_key) {
                if dec.name.eq_ignore_ascii_case(target_name) {
                    return Ok(serde_json::json!({
                        "id": dec.id,
                        "name": dec.name,
                        "username": dec.username.unwrap_or_default(),
                        "password": dec.password.unwrap_or_default(),
                        "totp": dec.totp.unwrap_or_default(),
                    }));
                }
            }
        }
    }
    Err(format!(
        "No se encontró ningún acceso con el nombre '{target_name}'"
    ))
}

async fn handle_create_login(
    state: &mut AgentState,
    payload: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    if state.is_locked {
        return Err("Bóveda bloqueada. Desbloquea con 'silverwarden unlock' primero.".to_string());
    }
    let obj = payload
        .as_object()
        .ok_or_else(|| "El payload debe ser un objeto JSON".to_string())?;

    let name = obj
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Campo 'name' requerido".to_string())?;
    let username = obj
        .get("username")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Campo 'username' requerido".to_string())?;
    let password = obj
        .get("password")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Campo 'password' requerido".to_string())?;

    if name.trim().is_empty() {
        return Err("El campo 'name' no puede estar vacío".to_string());
    }
    if username.trim().is_empty() {
        return Err("El campo 'username' no puede estar vacío".to_string());
    }
    if password.trim().is_empty() {
        return Err("El campo 'password' no puede estar vacío".to_string());
    }

    let agent = match state.vault_agent.as_ref() {
        Some(a) => a.clone(),
        None => sw_ssh_agent::shared_vault_agent(),
    };

    let profile = agent.vault().profile().await;
    let mut profile_id = profile.and_then(|p| p.id);
    if profile_id.is_none() {
        if let Some(vp) = state.vault_path() {
            if vp.exists() {
                if let Ok(disk_sync) = sw_vault::load_vault(&vp) {
                    profile_id = disk_sync.profile.id;
                    agent.vault().load_sync_data(disk_sync).await;
                }
            }
        }
    }

    let profile_id = match profile_id {
        Some(id) => id,
        None => {
            return Err(
                "No se ha sincronizado el perfil. Ejecuta 'silverwarden sync' primero.".to_string(),
            );
        }
    };

    let sym_key = agent
        .get_symmetric_key()
        .await
        .ok_or_else(|| "Bóveda bloqueada".to_string())?;

    let enc_name = sw_vault::encrypt_with(
        name.as_bytes(),
        sw_vault::EncStringType::AesCbc256HmacSha256B64,
        &sym_key,
    )
    .map_err(|e| format!("Error al cifrar nombre: {e}"))?;
    let enc_user = sw_vault::encrypt_with(
        username.as_bytes(),
        sw_vault::EncStringType::AesCbc256HmacSha256B64,
        &sym_key,
    )
    .map_err(|e| format!("Error al cifrar usuario: {e}"))?;
    let enc_pass = sw_vault::encrypt_with(
        password.as_bytes(),
        sw_vault::EncStringType::AesCbc256HmacSha256B64,
        &sym_key,
    )
    .map_err(|e| format!("Error al cifrar contraseña: {e}"))?;

    let cipher = sw_vault::Cipher {
        id: None,
        r#type: sw_vault::CipherType::Login,
        name: enc_name,
        favorite: false,
        reprompt: 0,
        fields: vec![],
        encrypted_for: Some(profile_id),
        login: Some(sw_vault::LoginCipher {
            username: Some(enc_user),
            password: Some(enc_pass),
            uri: None,
            uris: vec![],
            totp: None,
        }),
        ..Default::default()
    };

    let client = state.api_client.as_ref().or_else(|| agent.api_client());
    let client = client.ok_or_else(|| {
        "No hay sesión iniciada en el servidor. Inicia sesión con 'silverwarden login' primero."
            .to_string()
    })?;

    let created_cipher = client
        .post_cipher(&cipher)
        .await
        .map_err(|e| format!("Error del servidor al crear acceso: {e}"))?;

    let server_id = created_cipher
        .id
        .ok_or_else(|| "El servidor no devolvió un ID para el acceso creado".to_string())?;

    agent.vault().insert(created_cipher).await;

    Ok(serde_json::json!({
        "status": "created",
        "id": server_id.to_string(),
        "name": name,
    }))
}

async fn handle_delete_login(
    state: &mut AgentState,
    payload: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    if state.is_locked {
        return Err("Bóveda bloqueada. Desbloquea con 'silverwarden unlock' primero.".to_string());
    }
    let target_name = payload
        .get("name")
        .and_then(|v| v.as_str())
        .or_else(|| payload.as_str())
        .ok_or_else(|| "Campo 'name' requerido".to_string())?;

    let agent = match state.vault_agent.as_ref() {
        Some(a) => a.clone(),
        None => sw_ssh_agent::shared_vault_agent(),
    };
    let sym_key = agent
        .get_symmetric_key()
        .await
        .ok_or_else(|| "Bóveda bloqueada".to_string())?;

    let all = agent.vault().all().await;
    let mut to_delete = None;
    for c in all {
        if c.r#type == sw_vault::CipherType::Login && c.deleted_date.is_none() {
            if let Ok(dec) = sw_vault::VaultStore::decrypt_cipher(&c, &sym_key) {
                if dec.name.eq_ignore_ascii_case(target_name) {
                    to_delete = Some((c.id, dec.name));
                    break;
                }
            }
        }
    }

    let (id_opt, found_name) = to_delete
        .ok_or_else(|| format!("No se encontró ningún acceso con el nombre '{target_name}'"))?;

    if let Some(id) = id_opt {
        let client = state.api_client.as_ref().or_else(|| agent.api_client());
        if let Some(c) = client {
            if let Err(e) = c.delete_cipher(&id).await {
                tracing::warn!("Failed to delete cipher from server: {e}");
            }
        }
        agent.vault().delete(&id).await;
    }

    Ok(serde_json::json!({
        "status": "deleted",
        "name": found_name,
    }))
}

async fn handle_set_session(
    state: &mut AgentState,
    payload: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    if let Some(ident) = payload.get("identity_url").and_then(|v| v.as_str()) {
        state.config.identity_url = ident.to_string();
    }
    if let Some(api) = payload.get("api_url").and_then(|v| v.as_str()) {
        state.config.api_url = api.to_string();
    }
    if let Some(notif) = payload.get("notifications_url").and_then(|v| v.as_str()) {
        state.config.notifications_url = notif.to_string();
    }
    if let Some(insecure) = payload
        .get("danger_accept_invalid_certs")
        .and_then(|v| v.as_bool())
    {
        state.config.danger_accept_invalid_certs = insecure;
    }

    if let Some(enc_tok) = payload.get("encrypted_token").and_then(|v| v.as_str()) {
        if !enc_tok.is_empty() {
            state.config.encrypted_token = enc_tok.to_string();
        }
    }
    if let Some(enc_sym) = payload
        .get("encrypted_user_symmetric_key")
        .and_then(|v| v.as_str())
    {
        if !enc_sym.is_empty() {
            state.config.encrypted_user_symmetric_key = enc_sym.to_string();
        }
    }

    if let Some(token_val) = payload.get("token") {
        if let Ok(token) = serde_json::from_value::<sw_config::LoginToken>(token_val.clone()) {
            let identity_url = state.config.identity_url.clone();
            let api_url = state.config.api_url.clone();
            let client = Arc::new(
                sw_bitwarden_api::AuthenticatedClient::from_token_with_options(
                    identity_url,
                    api_url,
                    token.clone(),
                    state.config.danger_accept_invalid_certs,
                ),
            );
            state.api_client = Some(client);
        }
    }

    if let Some(sym_key_b64) = payload.get("user_symmetric_key").and_then(|v| v.as_str()) {
        use base64::Engine;
        if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(sym_key_b64.trim()) {
            if let Ok(sym_key) = sw_crypto::SymmetricKey::from_bytes(&bytes) {
                if let Some(agent) = &state.vault_agent {
                    agent.unlock(sym_key).await;
                }
            }
        }
    }

    if let Some(path) = state.config_path() {
        let _ = save_config_file(&state.config, &path);
    }

    Ok(serde_json::json!({ "status": "session_saved" }))
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
    pub async fn execute(&self, action: &str, state: &mut AgentState, ctx: &CallingContext, payload: &serde_json::Value) -> Result<serde_json::Value, String> {
        if let Some(handler) = self.actions.get(action) {
            return handler(state, ctx, payload).await;
        }

        for (k, handler) in &self.actions {
            if k.eq_ignore_ascii_case(action) {
                return handler(state, ctx, payload).await;
            }
        }

        Err(format!("Acción no reconocida: {action}"))
    }
}

#[inline]
fn set_permissions_unix(path: &Path, mode: u32) -> Result<(), std::io::Error> {
    #[cfg(unix)]
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    #[cfg(not(unix))]
    let _ = (path, mode);
    Ok(())
}

/// Saves the configuration file atomically using a temporary file and rename.
pub fn save_config_file(config: &ConfigFile, path: &Path) -> Result<(), std::io::Error> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        let _ = set_permissions_unix(parent, 0o700);
    }
    let json_bytes = serde_json::to_vec_pretty(config)?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    temp.write_all(&json_bytes)?;
    temp.flush()?;
    let _ = set_permissions_unix(temp.path(), 0o600);
    temp.persist(path).map_err(|e| e.error)?;
    Ok(())
}

/// Builds the default registry with all core SilverWarden agent actions.
pub fn default_registry() -> ActionsRegistry {
    let mut registry = ActionsRegistry::new();

    // Status: devuelve { locked, has_pin, logged_in, version, pin_cached, pin_cached_remaining_secs }
    registry.register(
        "Status",
        |state: &mut AgentState, _ctx: &CallingContext, _payload: &serde_json::Value| {
            let logged_in =
                !state.is_locked && (state.config.is_logged_in() || state.api_client.is_some());
            Ok(serde_json::json!({
                "locked": state.is_locked,
                "has_pin": state.has_pin,
                "logged_in": logged_in,
                "version": env!("CARGO_PKG_VERSION"),
                "pin_cached": state.pin_cache.is_valid(),
                "pin_cached_remaining_secs": state.pin_cache.remaining().map(|d| d.as_secs()).unwrap_or(0),
            }))
        },
    );

    // Unlock: recibe { pin } opcional, verifica caché o KDF, actualiza estado, crea sesiones
    registry.register_async(
        "Unlock",
        |state: &mut AgentState, ctx: &CallingContext, payload: &serde_json::Value| {
            let pin_opt = match payload {
                serde_json::Value::Object(map) => map
                    .get("pin")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                serde_json::Value::String(s) => Some(s.clone()),
                _ => None,
            };

            // Sync from payload if present
            if let Some(map) = payload.as_object() {
                if let Some(enc_tok) = map.get("encrypted_token").and_then(|v| v.as_str()) {
                    if !enc_tok.is_empty() {
                        state.config.encrypted_token = enc_tok.to_string();
                    }
                }
                if let Some(enc_sym) = map
                    .get("encrypted_user_symmetric_key")
                    .and_then(|v| v.as_str())
                {
                    if !enc_sym.is_empty() {
                        state.config.encrypted_user_symmetric_key = enc_sym.to_string();
                    }
                }
            }

            // Sync from config file on disk if available
            if let Some(path) = state.config_path() {
                if path.exists() {
                    if let Ok(content) = std::fs::read_to_string(&path) {
                        if let Ok(disk_cfg) = serde_json::from_str::<ConfigFile>(&content) {
                            if !disk_cfg.config_key_hash.is_empty() {
                                state.config.config_key_hash = disk_cfg.config_key_hash;
                                state.has_pin = true;
                            }
                            if !disk_cfg.encrypted_token.is_empty() {
                                state.config.encrypted_token = disk_cfg.encrypted_token;
                            }
                            if !disk_cfg.encrypted_user_symmetric_key.is_empty() {
                                state.config.encrypted_user_symmetric_key =
                                    disk_cfg.encrypted_user_symmetric_key;
                            }
                            state.config.identity_url = disk_cfg.identity_url;
                            state.config.api_url = disk_cfg.api_url;
                            state.config.notifications_url = disk_cfg.notifications_url;
                            state.config.danger_accept_invalid_certs =
                                disk_cfg.danger_accept_invalid_certs;
                        }
                    }
                }
            }

            if !state.has_pin {
                return Box::pin(async { Err("No hay PIN configurado en el agente".to_string()) });
            }

            // 1. Si no hay PIN en el payload: intentar cache hit (evita Argon2i)
            if pin_opt.is_none() {
                if let Some(config_key) = state.pin_cache.get() {
                    let biometrics_enabled = state.config.runtime_config.biometrics_enabled;
                    let biometrics = state.biometrics.clone();
                    let va = state.vault_agent.clone();
                    let enc_sym = state.config.encrypted_user_symmetric_key.clone();

                    return Box::pin(async move {
                        if biometrics_enabled {
                            match biometrics
                                .authenticate("Desbloquear SilverWarden", ctx)
                                .await
                            {
                                Ok(true) => {}
                                _ => return Err("Biometría cancelada o fallida".to_string()),
                            }
                        }

                        state.is_locked = false;
                        state.sessions.create_session(
                            ctx,
                            SessionType::Pin,
                            Duration::from_secs(3600),
                        );
                        state.sessions.create_session(
                            ctx,
                            SessionType::AccessVault,
                            Duration::from_secs(3600),
                        );

                        if state.api_client.is_none() && !state.config.encrypted_token.is_empty() {
                            if let Ok(token) = state.config.decrypt_token(&config_key) {
                                state.api_client = Some(Arc::new(
                                    sw_bitwarden_api::AuthenticatedClient::from_token_with_options(
                                        state.config.identity_url.clone(),
                                        state.config.api_url.clone(),
                                        token,
                                        state.config.danger_accept_invalid_certs,
                                    ),
                                ));
                            }
                        }

                        if let Some(agent) = va {
                            let sym_key = if !enc_sym.is_empty() {
                                if let Ok(dec) = sw_config::decrypt_string(&enc_sym, &config_key) {
                                    use base64::Engine;
                                    if let Ok(bytes) =
                                        base64::engine::general_purpose::STANDARD.decode(dec.trim())
                                    {
                                        sw_crypto::SymmetricKey::from_bytes(&bytes).or_else(|_| {
                                            sw_crypto::SymmetricKey::from_parts(
                                                &config_key,
                                                &config_key,
                                            )
                                        })
                                    } else {
                                        sw_crypto::SymmetricKey::from_parts(
                                            &config_key,
                                            &config_key,
                                        )
                                    }
                                } else {
                                    sw_crypto::SymmetricKey::from_parts(&config_key, &config_key)
                                }
                            } else {
                                sw_crypto::SymmetricKey::from_parts(&config_key, &config_key)
                            };

                            if let Ok(sk) = sym_key {
                                agent.unlock(sk).await;
                            }
                        }
                        Ok(serde_json::json!({
                            "status": "unlocked",
                            "from_cache": true,
                            "biometrics": biometrics_enabled
                        }))
                    });
                } else {
                    return Box::pin(async {
                        Err("Campo 'pin' requerido en payload (no hay caché válido)".to_string())
                    });
                }
            }

            // 2. Si hay PIN en el payload: se valida el PIN con KDF y se actualiza el caché
            let pin = pin_opt.unwrap();

            let (verified, memory_kib) = match state
                .config
                .verify_pin_with_params(&pin, AGENT_KDF_MEMORY_KIB)
            {
                Ok(true) => (true, AGENT_KDF_MEMORY_KIB),
                Ok(false) => {
                    match state
                        .config
                        .verify_pin_with_params(&pin, sw_config::KDF_MEMORY_KIB_TEST)
                    {
                        Ok(true) => (true, sw_config::KDF_MEMORY_KIB_TEST),
                        Ok(false) => (false, AGENT_KDF_MEMORY_KIB),
                        Err(e) => {
                            return Box::pin(
                                async move { Err(format!("Error al verificar PIN: {e}")) },
                            )
                        }
                    }
                }
                Err(e) => {
                    return Box::pin(async move { Err(format!("Error al verificar PIN: {e}")) })
                }
            };

            if !verified {
                return Box::pin(async { Err("PIN incorrecto".to_string()) });
            }

            state.is_locked = false;
            state
                .sessions
                .create_session(ctx, SessionType::Pin, Duration::from_secs(3600));
            state
                .sessions
                .create_session(ctx, SessionType::AccessVault, Duration::from_secs(3600));
            let va = state.vault_agent.clone();
            let enc_sym = state.config.encrypted_user_symmetric_key.clone();
            let key_res = sw_config::derive_config_key_with_params(
                &pin,
                &state.config.device_uuid,
                memory_kib,
            );

            if let Ok(key) = &key_res {
                state.pin_cache.store(key);

                if state.api_client.is_none() && !state.config.encrypted_token.is_empty() {
                    if let Ok(token) = state.config.decrypt_token(key) {
                        state.api_client = Some(Arc::new(
                            sw_bitwarden_api::AuthenticatedClient::from_token_with_options(
                                state.config.identity_url.clone(),
                                state.config.api_url.clone(),
                                token,
                                state.config.danger_accept_invalid_certs,
                            ),
                        ));
                    }
                }
            }

            Box::pin(async move {
                if let Some(agent) = va {
                    if let Ok(key) = key_res {
                        let sym_key = if !enc_sym.is_empty() {
                            if let Ok(dec) = sw_config::decrypt_string(&enc_sym, &key) {
                                use base64::Engine;
                                if let Ok(bytes) =
                                    base64::engine::general_purpose::STANDARD.decode(dec.trim())
                                {
                                    sw_crypto::SymmetricKey::from_bytes(&bytes).or_else(|_| {
                                        sw_crypto::SymmetricKey::from_parts(&key, &key)
                                    })
                                } else {
                                    sw_crypto::SymmetricKey::from_parts(&key, &key)
                                }
                            } else {
                                sw_crypto::SymmetricKey::from_parts(&key, &key)
                            }
                        } else {
                            sw_crypto::SymmetricKey::from_parts(&key, &key)
                        };

                        if let Ok(sk) = sym_key {
                            agent.unlock(sk).await;
                        }
                    }
                }
                Ok(serde_json::json!({ "status": "unlocked", "from_cache": false }))
            })
        },
    );

    // Lock: borra la clave de memoria y wipea sesiones
    registry.register_async(
        "Lock",
        |state: &mut AgentState, _ctx: &CallingContext, _payload: &serde_json::Value| {
            state.pin_cache.clear();
            state.is_locked = true;
            state.sessions.wipe();
            let va = state.vault_agent.clone();
            let notifier = state.notifier.clone();
            Box::pin(async move {
                if let Some(agent) = va {
                    agent.lock().await;
                }
                // Notificar bloqueo (ignorar error, fallback silencioso)
                let _ = notifier.notify("SilverWarden", "Bóveda bloqueada").await;
                Ok(serde_json::json!({ "status": "locked" }))
            })
        },
    );

    // PinSet: delega a sw-config
    registry.register(
        "PinSet",
        |state: &mut AgentState, _ctx: &CallingContext, payload: &serde_json::Value| {
            #[rustfmt::skip]
            let pin = match payload {
                serde_json::Value::Object(map) => map.get("pin").and_then(|v| v.as_str()).ok_or_else(|| "Campo 'pin' requerido en payload".to_string())?,
                serde_json::Value::String(s) => s.as_str(),
                _ => return Err("Payload inválido para PinSet: se esperaba objeto con 'pin'".to_string()),
            };

            if state.has_pin {
                return Err("El PIN ya está configurado. Usa PinUpdate para cambiarlo.".to_string());
            }

            let key = sw_config::derive_config_key_with_params(pin, &state.config.device_uuid, AGENT_KDF_MEMORY_KIB)
                .map_err(|e| format!("Error al derivar clave de PIN: {e}"))?;
            state.config.config_key_hash = sw_config::hash_config_key(&key);
            state.has_pin = true;
            state.pin_cache.store(&key);

            if let Some(path) = state.config_path() {
                let _ = save_config_file(&state.config, &path);
            }

            Ok(serde_json::json!({ "status": "pin_set" }))
        },
    );

    // PinUpdate: delega a sw-config
    registry.register(
        "PinUpdate",
        |state: &mut AgentState, _ctx: &CallingContext, payload: &serde_json::Value| {
            #[rustfmt::skip]
            let (old_pin, new_pin) = match payload {
                serde_json::Value::Object(map) => {
                    let old = map.get("old_pin").and_then(|v| v.as_str()).ok_or_else(|| "Campo 'old_pin' requerido".to_string())?;
                    let new = map.get("new_pin").and_then(|v| v.as_str()).ok_or_else(|| "Campo 'new_pin' requerido".to_string())?;
                    (old, new)
                }
                _ => return Err("Payload inválido para PinUpdate: se esperaba objeto con 'old_pin' y 'new_pin'".to_string()),
            };

            if !state.has_pin {
                return Err("El PIN no está configurado. Usa PinSet.".to_string());
            }

            state.pin_cache.clear();

            state
                .config
                .update_pin_with_params(old_pin, new_pin, AGENT_KDF_MEMORY_KIB)
                .map_err(|e| format!("Error al actualizar PIN: {e}"))?;

            if let Ok(new_key) = sw_config::derive_config_key_with_params(
                new_pin,
                &state.config.device_uuid,
                AGENT_KDF_MEMORY_KIB,
            ) {
                state.pin_cache.store(&new_key);
            }

            if let Some(path) = state.config_path() {
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

    // ListSSHKeys (delegates to state.vault_agent)
    registry.register_async("ListSSHKeys", |state, _ctx, _payload| {
        let agent = state.vault_agent.clone();
        Box::pin(async move {
            let agent = agent.ok_or_else(|| "Vault agent no configurado".to_string())?;
            handle_list_ssh_keys(&agent).await
        })
    });

    // ImportSSHKey (delegates to state.vault_agent)
    registry.register_async("ImportSSHKey", |state, _ctx, payload| {
        let agent = state.vault_agent.clone();
        let payload = payload.clone();
        Box::pin(async move {
            let agent = agent.ok_or_else(|| "Vault agent no configurado".to_string())?;
            handle_import_ssh_key(&agent, &payload).await
        })
    });

    // NewSSHKey (delegates to state.vault_agent)
    registry.register_async("NewSSHKey", |state, _ctx, payload| {
        let agent = state.vault_agent.clone();
        let payload = payload.clone();
        Box::pin(async move {
            let agent = agent.ok_or_else(|| "Vault agent no configurado".to_string())?;
            handle_new_ssh_key(&agent, &payload).await
        })
    });

    // DeleteSSHKey (delegates to state.vault_agent)
    registry.register_async("DeleteSSHKey", |state, _ctx, payload| {
        let agent = state.vault_agent.clone();
        let payload = payload.clone();
        Box::pin(async move {
            let agent = agent.ok_or_else(|| "Vault agent no configurado".to_string())?;
            handle_delete_ssh_key(&agent, &payload).await
        })
    });

    // Sync
    registry.register_async("Sync", |state, _ctx, payload| {
        let p = payload.clone();
        Box::pin(async move { handle_sync(state, &p).await })
    });

    // SyncData / ReloadVault
    registry.register_async("SyncData", |state, _ctx, payload| {
        let p = payload.clone();
        Box::pin(async move { handle_sync_data(state, &p).await })
    });
    registry.register_async("ReloadVault", |state, _ctx, payload| {
        let p = payload.clone();
        Box::pin(async move { handle_sync_data(state, &p).await })
    });

    // ListLogins
    registry.register_async("ListLogins", |state, _ctx, _payload| {
        Box::pin(handle_list_logins(state))
    });

    // GetLogin
    registry.register_async("GetLogin", |state, _ctx, payload| {
        let p = payload.clone();
        Box::pin(async move { handle_get_login(state, &p).await })
    });

    // CreateLogin
    registry.register_async("CreateLogin", |state, _ctx, payload| {
        let p = payload.clone();
        Box::pin(async move { handle_create_login(state, &p).await })
    });

    // DeleteLogin
    registry.register_async("DeleteLogin", |state, _ctx, payload| {
        let p = payload.clone();
        Box::pin(async move { handle_delete_login(state, &p).await })
    });

    // SetSession / Login
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
    pub registry: Arc<ActionsRegistry>,
}

impl AgentDaemon {
    pub fn new() -> Self {
        let va = sw_ssh_agent::shared_vault_agent();
        Self::with_vault_agent(AgentState::load_or_default(), va)
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

    pub fn with_vault_agent(mut state: AgentState, vault_agent: Arc<VaultAgentServer>) -> Self {
        state.vault_agent = Some(vault_agent.clone());
        let registry = default_registry_with_ssh(vault_agent);
        Self::with_state_and_registry(state, registry)
    }

    pub async fn handle_message(&self, ctx: &CallingContext, msg: IpcMessage) -> IpcMessage {
        {
            let state = self.state.read().await;
            state.touch_activity().await;
        }
        let mut state = self.state.write().await;
        match self
            .registry
            .execute(&msg.action, &mut state, ctx, &msg.payload)
            .await
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
            IpcRequest::SyncData(val) | IpcRequest::ReloadVault(val) => {
                let mut state = self.state.write().await;
                match handle_sync_data(&mut state, &val).await {
                    Ok(resp) => IpcResponse::Ok(resp),
                    Err(e) => IpcResponse::Error(e),
                }
            }
            IpcRequest::GetLogins { filter: _ } => IpcResponse::Ok(serde_json::json!([])),
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

    if let Some(agent) = va {
        agent.lock().await;
    }
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

                        if let Some(agent) = va {
                            agent.lock().await;
                        }
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
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
    use tokio::net::UnixStream;

    #[tokio::test]
    async fn test_agent_socket_actions_flow() {
        let temp_dir = tempfile::tempdir().expect("Create temp dir");
        let socket_path = temp_dir.path().join(".silverwarden.sock");

        let test_pin = "agent_test_pin_987";
        let test_salt = "agent_uuid_test";
        let derived_key =
            sw_config::derive_config_key_with_params(test_pin, test_salt, AGENT_KDF_MEMORY_KIB)
                .unwrap();
        let config = ConfigFile {
            device_uuid: test_salt.to_string(),
            config_key_hash: sw_config::hash_config_key(&derived_key),
            ..Default::default()
        };

        let daemon =
            AgentDaemon::with_state(AgentState::new(config).with_config_directory(temp_dir.path()));
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
        let temp_dir = tempfile::tempdir().unwrap();
        let mut state = AgentState::default().with_config_directory(temp_dir.path());
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
            .await
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
            .await
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
            .await
            .is_err());

        // Unlock with wrong PIN
        assert!(registry
            .execute(
                "Unlock",
                &mut state,
                &ctx,
                &serde_json::json!({ "pin": "bad_pin" })
            )
            .await
            .is_err());

        // Unlock with correct PIN
        let unlock_res = registry
            .execute(
                "Unlock",
                &mut state,
                &ctx,
                &serde_json::json!({ "pin": "initial_pin_123" }),
            )
            .await
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
            .await
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
            .await
            .is_err());

        // New PIN unlocks
        assert!(registry
            .execute(
                "Unlock",
                &mut state,
                &ctx,
                &serde_json::json!({ "pin": "new_pin_456" })
            )
            .await
            .is_ok());

        // Lock wipes sessions
        let lock_res = registry
            .execute("Lock", &mut state, &ctx, &serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(lock_res["status"], "locked");
        assert!(state.is_locked);
        assert!(!state
            .sessions
            .verify_session(&ctx, SessionType::AccessVault));

        // Unknown action
        let unknown_res = registry
            .execute("NonExistent", &mut state, &ctx, &serde_json::json!({}))
            .await;
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

        // Socket does not exist -> Ok
        let non_existent = temp_dir.path().join("does_not_exist.sock");
        assert!(check_and_prepare_socket(&non_existent).await.is_ok());

        // Socket already in use -> SocketAlreadyInUse
        let active_path = temp_dir.path().join("active.sock");
        let listener = tokio::net::UnixListener::bind(&active_path).unwrap();
        let in_use = check_and_prepare_socket(&active_path).await;
        assert!(matches!(in_use, Err(AgentError::SocketAlreadyInUse(_))));
        drop(listener);
    }

    #[test]
    fn test_default_socket_path() {
        let path = default_socket_path().expect("Default socket path succeeds");
        assert!(path.to_string_lossy().contains(".silverwarden.sock"));

        let custom = socket_path_from_home(Some("/custom/home")).unwrap();
        assert_eq!(custom, PathBuf::from("/custom/home/.silverwarden.sock"));
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

        let ipc = AgentError::from(sw_ipc::IpcError::Protocol("bad payload".into()));
        assert!(ipc.to_string().contains("bad payload"));
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

        let ctx = CallingContext {
            username: "tester".into(),
            process_name: "test".into(),
            parent_process_name: "parent".into(),
            grandparent_process_name: "grandparent".into(),
            process_pid: 1,
            parent_process_pid: 2,
            grandparent_process_pid: 3,
            error: false,
            authenticated: true,
        };
        let ok_msg = daemon
            .handle_message(&ctx, IpcMessage::new("Status", serde_json::json!({})))
            .await;
        assert_eq!(ok_msg.action, "Ok");
        let err_msg = daemon
            .handle_message(&ctx, IpcMessage::new("NonExistent", serde_json::json!({})))
            .await;
        assert_eq!(err_msg.action, "Error");
    }

    #[tokio::test]
    async fn test_run_agent_entrypoint_error() {
        let res = run_agent(Path::new("/proc/impossible/agent.sock")).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_agent_corrupted_message_handled() {
        let temp_dir = tempfile::tempdir().expect("Create temp dir");
        let socket_path = temp_dir.path().join("corrupted.sock");
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let agent_socket = socket_path.clone();

        let handle = tokio::spawn(async move {
            let _ = run_agent_with_shutdown(&agent_socket, async {
                let _ = shutdown_rx.await;
            })
            .await;
        });

        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            if let Ok(mut stream) = UnixStream::connect(&socket_path).await {
                let _ = stream.write_all(&[0, 0, 0, 10, 1, 2]).await;
                break;
            }
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = shutdown_tx.send(());
        let _ = handle.await;
    }

    #[tokio::test]
    async fn test_ssh_actions_full_lifecycle() {
        use sw_crypto::SymmetricKey;
        use sw_vault::VaultStore;

        let key = SymmetricKey::from_bytes(&[42u8; 64]).unwrap();
        let vault = Arc::new(VaultStore::new());
        let vault_agent = Arc::new(VaultAgentServer::new(vault.clone()));

        let mut state = AgentState::default().with_vault_agent(vault_agent.clone());
        let registry = default_registry_with_ssh(vault_agent.clone());
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

        // 1. Locked: all SSH actions fail with "Vault is locked"
        let res = registry
            .execute("ListSSHKeys", &mut state, &ctx, &serde_json::json!({}))
            .await;
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), "Vault is locked");

        let res = registry
            .execute(
                "ImportSSHKey",
                &mut state,
                &ctx,
                &serde_json::json!({ "name": "foo", "private_key_pem": "bar" }),
            )
            .await;
        assert_eq!(res.unwrap_err(), "Vault is locked");

        let res = registry
            .execute(
                "NewSSHKey",
                &mut state,
                &ctx,
                &serde_json::json!({ "name": "foo" }),
            )
            .await;
        assert_eq!(res.unwrap_err(), "Vault is locked");

        let res = registry
            .execute(
                "DeleteSSHKey",
                &mut state,
                &ctx,
                &serde_json::json!({ "id": uuid::Uuid::new_v4().to_string() }),
            )
            .await;
        assert_eq!(res.unwrap_err(), "Vault is locked");

        // 2. Unlock vault agent
        vault_agent.unlock(key.try_clone().unwrap()).await;

        // 3. test_list_ssh_keys empty initially
        let list_val = registry
            .execute("ListSSHKeys", &mut state, &ctx, &serde_json::json!({}))
            .await
            .unwrap();
        let list: Vec<serde_json::Value> = serde_json::from_value(list_val).unwrap();
        assert!(list.is_empty());

        // 4. test_new_ssh_key_ed25519
        let ed_val = registry
            .execute(
                "NewSSHKey",
                &mut state,
                &ctx,
                &serde_json::json!({ "name": "ed-key-1", "key_type": "Ed25519" }),
            )
            .await
            .unwrap();
        assert_eq!(ed_val["name"], "ed-key-1");
        assert!(ed_val["fingerprint"]
            .as_str()
            .unwrap()
            .starts_with("SHA256:"));
        assert!(ed_val["public_key"]
            .as_str()
            .unwrap()
            .starts_with("ssh-ed25519"));
        assert!(ed_val.get("private_key").is_none());
        let ed_id = ed_val["id"].as_str().unwrap().to_string();

        // 5. test_new_ssh_key_rsa
        let rsa_val = registry
            .execute(
                "NewSSHKey",
                &mut state,
                &ctx,
                &serde_json::json!({ "name": "rsa-key-1", "key_type": "RSA" }),
            )
            .await
            .unwrap();
        assert_eq!(rsa_val["name"], "rsa-key-1");
        assert!(rsa_val["public_key"]
            .as_str()
            .unwrap()
            .starts_with("ssh-rsa"));

        // 6. test_list_ssh_keys: vault with 2 keys, ListSSHKeys returns 2
        let list_val = registry
            .execute("ListSSHKeys", &mut state, &ctx, &serde_json::json!({}))
            .await
            .unwrap();
        let list: Vec<serde_json::Value> = serde_json::from_value(list_val).unwrap();
        assert_eq!(list.len(), 2);

        // 7. test_list_ssh_keys_never_returns_private
        for item in &list {
            assert!(item.get("private_key").is_none());
            assert!(item.get("private_key_pem").is_none());
            let pub_str = item["public_key"].as_str().unwrap();
            assert!(!pub_str.contains("PRIVATE KEY"));
        }

        // 8. test_import_ssh_key
        let keypair = russh::keys::ssh_key::private::KeypairData::Ed25519(
            russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&[77u8; 32]),
        );
        let pk = russh::keys::PrivateKey::new(keypair, "imported-key").unwrap();
        let ed25519_pem = pk
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .unwrap()
            .to_string();
        let import_val = registry
            .execute(
                "ImportSSHKey",
                &mut state,
                &ctx,
                &serde_json::json!({
                    "name": "imported-key",
                    "private_key_pem": ed25519_pem
                }),
            )
            .await
            .unwrap();
        assert_eq!(import_val["name"], "imported-key");
        assert!(import_val["public_key"]
            .as_str()
            .unwrap()
            .starts_with("ssh-ed25519"));

        // Now 3 keys in vault
        let list_val = registry
            .execute("ListSSHKeys", &mut state, &ctx, &serde_json::json!({}))
            .await
            .unwrap();
        let list: Vec<serde_json::Value> = serde_json::from_value(list_val).unwrap();
        assert_eq!(list.len(), 3);

        // 9. test_delete_ssh_key
        let del_val = registry
            .execute(
                "DeleteSSHKey",
                &mut state,
                &ctx,
                &serde_json::json!({ "id": ed_id }),
            )
            .await
            .unwrap();
        assert_eq!(del_val["status"], "deleted");
        assert_eq!(del_val["id"], ed_id);

        let list_val = registry
            .execute("ListSSHKeys", &mut state, &ctx, &serde_json::json!({}))
            .await
            .unwrap();
        let list: Vec<serde_json::Value> = serde_json::from_value(list_val).unwrap();
        assert_eq!(list.len(), 2);
        assert!(!list.iter().any(|k| k["id"] == ed_id));

        // 10. Lock via registry also locks vault agent
        let lock_val = registry
            .execute("Lock", &mut state, &ctx, &serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(lock_val["status"], "locked");
        assert!(vault_agent.is_locked());
    }

    #[tokio::test]
    async fn test_ssh_actions_daemon_ipc_messages() {
        use sw_crypto::SymmetricKey;
        use sw_vault::VaultStore;

        let key = SymmetricKey::from_bytes(&[77u8; 64]).unwrap();
        let vault = Arc::new(VaultStore::new());
        let vault_agent = Arc::new(VaultAgentServer::new(vault.clone()));
        vault_agent.unlock(key).await;

        let state = AgentState::default().with_vault_agent(vault_agent.clone());
        let daemon = AgentDaemon::with_vault_agent(state, vault_agent);
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

        // Create key via handle_message
        let req = IpcMessage::new(
            "NewSSHKey",
            serde_json::json!({ "name": "daemon-key", "key_type": "Ed25519" }),
        );
        let resp = daemon.handle_message(&ctx, req).await;
        assert_eq!(resp.action, "Ok");
        assert_eq!(resp.payload["name"], "daemon-key");

        // List keys via handle_message
        let list_req = IpcMessage::new("ListSSHKeys", serde_json::json!({}));
        let list_resp = daemon.handle_message(&ctx, list_req).await;
        assert_eq!(list_resp.action, "Ok");
        assert_eq!(list_resp.payload.as_array().unwrap().len(), 1);

        // Import key via handle_message
        let keypair = russh::keys::ssh_key::private::KeypairData::Ed25519(
            russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&[33u8; 32]),
        );
        let pk = russh::keys::PrivateKey::new(keypair, "daemon-imported").unwrap();
        let pem = pk
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .unwrap()
            .to_string();
        let imp_req = IpcMessage::new(
            "ImportSSHKey",
            serde_json::json!({ "name": "daemon-imported", "private_key_pem": pem }),
        );
        let imp_resp = daemon.handle_message(&ctx, imp_req).await;
        assert_eq!(imp_resp.action, "Ok");
        let imp_id = imp_resp.payload["id"].as_str().unwrap();

        // Delete key via handle_message
        let del_req = IpcMessage::new("DeleteSSHKey", serde_json::json!({ "id": imp_id }));
        let del_resp = daemon.handle_message(&ctx, del_req).await;
        assert_eq!(del_resp.action, "Ok");
    }

    #[tokio::test]
    async fn test_ssh_actions_invalid_payloads() {
        use sw_crypto::SymmetricKey;
        use sw_vault::VaultStore;

        let key = SymmetricKey::from_bytes(&[88u8; 64]).unwrap();
        let vault = Arc::new(VaultStore::new());
        let vault_agent = Arc::new(VaultAgentServer::new(vault.clone()));
        vault_agent.unlock(key).await;

        let mut state = AgentState::default().with_vault_agent(vault_agent.clone());
        let registry = default_registry_with_ssh(vault_agent);
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

        // ImportSSHKey missing name
        let res = registry
            .execute(
                "ImportSSHKey",
                &mut state,
                &ctx,
                &serde_json::json!({ "private_key_pem": "abc" }),
            )
            .await;
        assert!(res.is_err());

        // ImportSSHKey missing private_key_pem
        let res = registry
            .execute(
                "ImportSSHKey",
                &mut state,
                &ctx,
                &serde_json::json!({ "name": "my-key" }),
            )
            .await;
        assert!(res.is_err());

        // ImportSSHKey non-object payload
        let res = registry
            .execute(
                "ImportSSHKey",
                &mut state,
                &ctx,
                &serde_json::json!("string"),
            )
            .await;
        assert!(res.is_err());

        // NewSSHKey missing name
        let res = registry
            .execute(
                "NewSSHKey",
                &mut state,
                &ctx,
                &serde_json::json!({ "key_type": "RSA" }),
            )
            .await;
        assert!(res.is_err());

        // NewSSHKey non-object
        let res = registry
            .execute("NewSSHKey", &mut state, &ctx, &serde_json::json!(42))
            .await;
        assert!(res.is_err());

        // DeleteSSHKey missing id
        let res = registry
            .execute(
                "DeleteSSHKey",
                &mut state,
                &ctx,
                &serde_json::json!({ "not_id": "foo" }),
            )
            .await;
        assert!(res.is_err());

        // DeleteSSHKey invalid UUID
        let res = registry
            .execute(
                "DeleteSSHKey",
                &mut state,
                &ctx,
                &serde_json::json!({ "id": "not-a-uuid" }),
            )
            .await;
        assert!(res.is_err());

        // DeleteSSHKey non-object non-string
        let res = registry
            .execute("DeleteSSHKey", &mut state, &ctx, &serde_json::json!(false))
            .await;
        assert!(res.is_err());

        // Unconfigured vault agent error
        let mut unconf_state = AgentState::default();
        let unconf_reg = default_registry();
        let res = unconf_reg
            .execute(
                "ListSSHKeys",
                &mut unconf_state,
                &ctx,
                &serde_json::json!({}),
            )
            .await;
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), "Vault agent no configurado");
    }

    #[tokio::test]
    async fn test_agent_state_load_or_default_and_save_config() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config_file = temp_dir.path().join("goldwarden.json");

        let config = ConfigFile {
            device_uuid: "test-device-uuid-123".into(),
            ..Default::default()
        };
        save_config_file(&config, &config_file).expect("Failed to save config");
        assert!(config_file.exists());

        let loaded_state = AgentState::load_or_default_from(Some(temp_dir.path().to_path_buf()));
        assert_eq!(loaded_state.config.device_uuid, "test-device-uuid-123");

        // Test with invalid json in config file
        std::fs::write(&config_file, b"not json").unwrap();
        let fallback_state = AgentState::load_or_default_from(Some(temp_dir.path().to_path_buf()));
        assert_ne!(fallback_state.config.device_uuid, "test-device-uuid-123");

        // Test when config path is a directory (read_to_string fails)
        let _ = std::fs::remove_file(&config_file);
        std::fs::create_dir(&config_file).unwrap();
        let dir_fallback = AgentState::load_or_default_from(Some(temp_dir.path().to_path_buf()));
        assert_ne!(dir_fallback.config.device_uuid, "test-device-uuid-123");
        let _ = std::fs::remove_dir(&config_file);

        // Test with empty dir where config doesn't exist
        let empty_dir = tempfile::tempdir().unwrap();
        let empty_fallback = AgentState::load_or_default_from(Some(empty_dir.path().to_path_buf()));
        assert!(!empty_fallback.config.device_uuid.is_empty());
        assert_ne!(empty_fallback.config.device_uuid, "test-device-uuid-123");

        // Test when config_dir is None (load_or_default)
        let no_home_fallback = AgentState::load_or_default();
        assert!(!no_home_fallback.config.device_uuid.is_empty());

        // Test save_config_file with relative path without parent
        let rel_path = Path::new("temp_test_local_cfg.json");
        assert!(save_config_file(&ConfigFile::default(), rel_path).is_ok());
        let _ = std::fs::remove_file(rel_path);
    }

    #[tokio::test]
    async fn test_run_agent_with_shutdown_signal_clean() {
        let temp_dir = tempfile::tempdir().expect("Create temp dir");
        let socket_path = temp_dir.path().join("clean_shutdown.sock");
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();

        let sock = socket_path.clone();
        let handle = tokio::spawn(async move {
            run_agent_with_shutdown(&sock, async {
                let _ = rx.await;
            })
            .await
        });

        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            if socket_path.exists() {
                break;
            }
        }
        let _ = tx.send(());
        let res = handle.await.unwrap();
        assert!(res.is_ok());
        assert!(!socket_path.exists());
    }

    #[tokio::test]
    async fn test_default_registry_with_vault_agent_in_state() {
        use sw_crypto::SymmetricKey;
        use sw_vault::VaultStore;

        let key = SymmetricKey::from_bytes(&[99u8; 64]).unwrap();
        let vault = Arc::new(VaultStore::new());
        let vault_agent = Arc::new(VaultAgentServer::new(vault.clone()));
        vault_agent.unlock(key).await;

        let mut state = AgentState::default().with_vault_agent(vault_agent.clone());
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

        // List keys
        let list = registry
            .execute("ListSSHKeys", &mut state, &ctx, &serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(list.as_array().unwrap().len(), 0);

        // New key
        let new_key = registry
            .execute(
                "NewSSHKey",
                &mut state,
                &ctx,
                &serde_json::json!({ "name": "state-key", "key_type": "Ed25519" }),
            )
            .await
            .unwrap();
        assert_eq!(new_key["name"], "state-key");
        let key_id = new_key["id"].as_str().unwrap().to_string();

        // Import key
        let keypair = russh::keys::ssh_key::private::KeypairData::Ed25519(
            russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&[55u8; 32]),
        );
        let pk = russh::keys::PrivateKey::new(keypair, "state-imported").unwrap();
        let pem = pk
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .unwrap()
            .to_string();
        let imported = registry
            .execute(
                "ImportSSHKey",
                &mut state,
                &ctx,
                &serde_json::json!({ "name": "state-imported", "private_key_pem": pem }),
            )
            .await
            .unwrap();
        assert_eq!(imported["name"], "state-imported");

        // Delete key
        let del = registry
            .execute(
                "DeleteSSHKey",
                &mut state,
                &ctx,
                &serde_json::json!({ "id": key_id }),
            )
            .await
            .unwrap();
        assert_eq!(del["status"], "deleted");
    }

    #[tokio::test]
    async fn test_agent_edge_cases_and_validations() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut state = AgentState::default().with_config_directory(temp_dir.path());
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

        // Status with logged_in
        state.is_locked = false;
        state.config.encrypted_token = "some_encrypted_token".into();
        let st = registry
            .execute("Status", &mut state, &ctx, &serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(st["logged_in"], true);
        state.is_locked = true;

        // Unlock without PIN configured
        assert!(registry
            .execute(
                "Unlock",
                &mut state,
                &ctx,
                &serde_json::json!({ "pin": "123" })
            )
            .await
            .is_err());

        // Unlock with invalid payload type
        assert!(registry
            .execute("Unlock", &mut state, &ctx, &serde_json::json!(42))
            .await
            .is_err());

        // Unlock with object missing pin
        assert!(registry
            .execute(
                "Unlock",
                &mut state,
                &ctx,
                &serde_json::json!({ "other": 123 })
            )
            .await
            .is_err());

        // PinSet with invalid payload type
        assert!(registry
            .execute("PinSet", &mut state, &ctx, &serde_json::json!(true))
            .await
            .is_err());

        // PinSet with object missing pin
        assert!(registry
            .execute(
                "PinSet",
                &mut state,
                &ctx,
                &serde_json::json!({ "other": 123 })
            )
            .await
            .is_err());

        // PinSet with string payload
        assert!(registry
            .execute(
                "PinSet",
                &mut state,
                &ctx,
                &serde_json::json!("str_pin_123")
            )
            .await
            .is_ok());

        // Unlock with string payload
        assert!(registry
            .execute(
                "Unlock",
                &mut state,
                &ctx,
                &serde_json::json!("str_pin_123")
            )
            .await
            .is_ok());

        // PinUpdate with missing fields or invalid type
        assert!(registry
            .execute(
                "PinUpdate",
                &mut state,
                &ctx,
                &serde_json::json!("not_an_obj")
            )
            .await
            .is_err());
        assert!(registry
            .execute(
                "PinUpdate",
                &mut state,
                &ctx,
                &serde_json::json!({ "old_pin": "123" })
            )
            .await
            .is_err());
        assert!(registry
            .execute(
                "PinUpdate",
                &mut state,
                &ctx,
                &serde_json::json!({ "new_pin": "456" })
            )
            .await
            .is_err());

        // PinUpdate without pin set
        let mut unconf = AgentState::default();
        assert!(registry
            .execute(
                "PinUpdate",
                &mut unconf,
                &ctx,
                &serde_json::json!({ "old_pin": "a", "new_pin": "b" }),
            )
            .await
            .is_err());

        // Check socket in use
        let temp_dir = tempfile::tempdir().unwrap();
        let sock_path = temp_dir.path().join("in_use.sock");
        let listener = tokio::net::UnixListener::bind(&sock_path).unwrap();
        let prep_err = check_and_prepare_socket(&sock_path).await;
        assert!(matches!(prep_err, Err(AgentError::SocketAlreadyInUse(_))));
        drop(listener);

        // Case-insensitive execute
        let st_lower = registry
            .execute("status", &mut state, &ctx, &serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(st_lower["locked"], false);

        // Custom registered sync closure
        let mut custom_reg = ActionsRegistry::new();
        custom_reg.register("CustomSync", |_state, _ctx, _payload| {
            Ok(serde_json::json!({ "custom": true }))
        });
        let c_res = custom_reg
            .execute("CustomSync", &mut state, &ctx, &serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(c_res["custom"], true);

        // SSH helper edge cases: "type" alias and string ID delete
        use sw_crypto::SymmetricKey;
        use sw_vault::VaultStore;

        let key = SymmetricKey::from_bytes(&[123u8; 64]).unwrap();
        let vault = Arc::new(VaultStore::new());
        let va = Arc::new(VaultAgentServer::new(vault.clone()));
        va.unlock(key.try_clone().unwrap()).await;

        let new_k =
            handle_new_ssh_key(&va, &serde_json::json!({ "name": "k1", "type": "Ed25519" }))
                .await
                .unwrap();
        let k1_id = new_k["id"].as_str().unwrap();

        // New SSH key with default type (no key_type / type field)
        let def_k = handle_new_ssh_key(&va, &serde_json::json!({ "name": "default-type-key" }))
            .await
            .unwrap();
        assert_eq!(def_k["name"], "default-type-key");
        assert!(def_k["public_key"]
            .as_str()
            .unwrap()
            .starts_with("ssh-ed25519"));

        // Delete using raw string id
        let del_str = handle_delete_ssh_key(&va, &serde_json::json!(k1_id))
            .await
            .unwrap();
        assert_eq!(del_str["status"], "deleted");

        // Import using "private_key" instead of "private_key_pem"
        let keypair = russh::keys::ssh_key::private::KeypairData::Ed25519(
            russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&[11u8; 32]),
        );
        let pk = russh::keys::PrivateKey::new(keypair, "k-priv").unwrap();
        let pem = pk
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .unwrap()
            .to_string();
        let imp = handle_import_ssh_key(
            &va,
            &serde_json::json!({ "name": "k-priv", "private_key": pem }),
        )
        .await
        .unwrap();
        assert_eq!(imp["name"], "k-priv");

        // Import using "pem" alias
        let keypair2 = russh::keys::ssh_key::private::KeypairData::Ed25519(
            russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&[22u8; 32]),
        );
        let pk2 = russh::keys::PrivateKey::new(keypair2, "k-pem").unwrap();
        let pem2 = pk2
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .unwrap()
            .to_string();
        let imp_pem =
            handle_import_ssh_key(&va, &serde_json::json!({ "name": "k-pem", "pem": pem2 }))
                .await
                .unwrap();
        assert_eq!(imp_pem["name"], "k-pem");

        // Generate RSA and ECDSA
        let rsa_gen = handle_new_ssh_key(
            &va,
            &serde_json::json!({ "name": "k-rsa", "key_type": "RSA" }),
        )
        .await
        .unwrap();
        assert_eq!(rsa_gen["name"], "k-rsa");

        let ecdsa_gen = handle_new_ssh_key(
            &va,
            &serde_json::json!({ "name": "k-ecdsa", "key_type": "ECDSA" }),
        )
        .await
        .unwrap();
        assert_eq!(ecdsa_gen["name"], "k-ecdsa");

        // AgentShutdown without shutdown_sender
        let mut no_shutdown_state = AgentState::default();
        let shutdown_res = registry
            .execute(
                "AgentShutdown",
                &mut no_shutdown_state,
                &ctx,
                &serde_json::json!({}),
            )
            .await
            .unwrap();
        assert_eq!(shutdown_res["status"], "shutting_down");

        // AgentShutdown with shutdown_sender present
        let (shut_tx, mut shut_rx) = tokio::sync::mpsc::channel(1);
        let mut with_shut_state = AgentState {
            shutdown_sender: Some(shut_tx),
            ..Default::default()
        };
        let shut_with_sender = registry
            .execute(
                "AgentShutdown",
                &mut with_shut_state,
                &ctx,
                &serde_json::json!({}),
            )
            .await
            .unwrap();
        assert_eq!(shut_with_sender["status"], "shutting_down");
        assert!(shut_rx.try_recv().is_ok());

        // Lock with no vault agent in state
        let mut lock_no_va_state = AgentState::default();
        let lock_no_va = registry
            .execute("Lock", &mut lock_no_va_state, &ctx, &serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(lock_no_va["status"], "locked");

        // Constructors coverage
        let d = AgentDaemon::new();
        assert!(d.state.read().await.is_locked);
        let d_state = AgentDaemon::with_state(AgentState::default());
        assert!(d_state.state.read().await.is_locked);
        let reg = ActionsRegistry::new();
        assert!(reg.actions.is_empty());
        let reg_default = ActionsRegistry::default();
        assert!(reg_default.actions.is_empty());
        let default_daemon = AgentDaemon::default();
        assert!(default_daemon.state.read().await.is_locked);
        let d_default = AgentDaemon::default();
        assert!(d_default.state.read().await.is_locked);
        let d_with_state = AgentDaemon::with_state(AgentState::new(ConfigFile::default()));
        assert!(d_with_state.state.read().await.is_locked);
        let d_with_both =
            AgentDaemon::with_state_and_registry(AgentState::default(), default_registry());
        assert!(d_with_both.state.read().await.is_locked);
        let d_va = AgentDaemon::with_vault_agent(AgentState::default(), va.clone());
        assert!(d_va.state.read().await.is_locked);
        let d_va_cloned = d_va.clone();
        assert!(d_va_cloned.state.read().await.is_locked);
        assert!(set_permissions_unix(temp_dir.path(), 0o700).is_ok());

        // AgentState Debug, Clone, with_vault_agent with full fields
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let mut full_state = AgentState::new(ConfigFile::default()).with_vault_agent(va.clone());
        full_state.shutdown_sender = Some(tx);
        let cloned_st = full_state.clone();
        let dbg_st = format!("{cloned_st:?}");
        assert!(dbg_st.contains("AgentState"));

        let default_st = AgentState::default();
        let cloned_default = default_st.clone();
        let dbg_default = format!("{cloned_default:?}");
        assert!(dbg_default.contains("AgentState"));

        // Default registry unconfigured vault_agent error for all 4 SSH actions
        let mut unconf_state = AgentState::default();
        let default_reg = default_registry();
        assert_eq!(
            default_reg
                .execute(
                    "ListSSHKeys",
                    &mut unconf_state,
                    &ctx,
                    &serde_json::json!({})
                )
                .await
                .unwrap_err(),
            "Vault agent no configurado"
        );
        assert_eq!(
            default_reg
                .execute(
                    "ImportSSHKey",
                    &mut unconf_state,
                    &ctx,
                    &serde_json::json!({})
                )
                .await
                .unwrap_err(),
            "Vault agent no configurado"
        );
        assert_eq!(
            default_reg
                .execute("NewSSHKey", &mut unconf_state, &ctx, &serde_json::json!({}))
                .await
                .unwrap_err(),
            "Vault agent no configurado"
        );
        assert_eq!(
            default_reg
                .execute(
                    "DeleteSSHKey",
                    &mut unconf_state,
                    &ctx,
                    &serde_json::json!({})
                )
                .await
                .unwrap_err(),
            "Vault agent no configurado"
        );

        // Lock on default_registry with vault_agent present
        let mut state_with_va = AgentState::default().with_vault_agent(va.clone());
        assert!(!va.is_locked());
        let lock_res = default_reg
            .execute("Lock", &mut state_with_va, &ctx, &serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(lock_res["status"], "locked");
        assert!(va.is_locked());

        // SSH handlers when locked
        assert_eq!(
            handle_list_ssh_keys(&va).await.unwrap_err(),
            "Vault is locked"
        );
        assert_eq!(
            handle_import_ssh_key(&va, &serde_json::json!({ "name": "k", "pem": "abc" }))
                .await
                .unwrap_err(),
            "Vault is locked"
        );
        assert_eq!(
            handle_new_ssh_key(&va, &serde_json::json!({ "name": "k" }))
                .await
                .unwrap_err(),
            "Vault is locked"
        );
        assert_eq!(
            handle_delete_ssh_key(
                &va,
                &serde_json::json!({ "id": uuid::Uuid::new_v4().to_string() })
            )
            .await
            .unwrap_err(),
            "Vault is locked"
        );

        // Unlock va again for payload edge cases
        va.unlock(SymmetricKey::from_bytes(&[123u8; 64]).unwrap())
            .await;
        assert!(!va.is_locked());

        // Invalid payloads for SSH handlers
        assert!(handle_import_ssh_key(&va, &serde_json::json!("not_an_obj"))
            .await
            .is_err());
        assert!(
            handle_import_ssh_key(&va, &serde_json::json!({ "pem": "abc" }))
                .await
                .is_err()
        );
        assert!(
            handle_import_ssh_key(&va, &serde_json::json!({ "name": "k" }))
                .await
                .is_err()
        );
        assert!(handle_import_ssh_key(
            &va,
            &serde_json::json!({ "name": "k", "private_key_pem": "not-a-valid-pem" })
        )
        .await
        .is_err());

        assert!(handle_new_ssh_key(&va, &serde_json::json!("not_an_obj"))
            .await
            .is_err());
        assert!(handle_new_ssh_key(&va, &serde_json::json!({}))
            .await
            .is_err());
        assert!(handle_new_ssh_key(
            &va,
            &serde_json::json!({ "name": "k", "key_type": "UNKNOWN_TYPE" })
        )
        .await
        .is_err());

        assert!(handle_delete_ssh_key(&va, &serde_json::json!(42))
            .await
            .is_err());
        assert!(handle_delete_ssh_key(&va, &serde_json::json!({}))
            .await
            .is_err());
        assert!(
            handle_delete_ssh_key(&va, &serde_json::json!({ "id": "not-a-uuid" }))
                .await
                .is_err()
        );
        assert!(handle_delete_ssh_key(&va, &serde_json::json!("not-a-uuid"))
            .await
            .is_err());
        assert!(handle_delete_ssh_key(
            &va,
            &serde_json::json!({ "id": uuid::Uuid::new_v4().to_string() })
        )
        .await
        .is_ok());

        // Unlock with corrupted config_key_hash where verify_pin returns Err
        let mut corrupted_pin_state = AgentState {
            has_pin: true,
            config: ConfigFile {
                device_uuid: "".into(),
                config_key_hash: "0".repeat(64),
                ..Default::default()
            },
            ..Default::default()
        };
        let err = default_reg
            .execute(
                "Unlock",
                &mut corrupted_pin_state,
                &ctx,
                &serde_json::json!({ "pin": "123" }),
            )
            .await
            .unwrap_err();
        assert!(err.contains("Error al verificar PIN"));

        // PinSet with config_directory saving config
        let home_dir = tempfile::tempdir().unwrap();
        let mut home_state = AgentState::default().with_config_directory(home_dir.path());
        let pin_set_home = default_reg
            .execute(
                "PinSet",
                &mut home_state,
                &ctx,
                &serde_json::json!({ "pin": "test_pin_home_1" }),
            )
            .await
            .unwrap();
        assert_eq!(pin_set_home["status"], "pin_set");
        assert!(home_dir.path().join("goldwarden.json").exists());

        // PinSet when already set
        assert!(default_reg
            .execute(
                "PinSet",
                &mut home_state,
                &ctx,
                &serde_json::json!({ "pin": "already_set" }),
            )
            .await
            .is_err());

        // PinUpdate with config_directory saving config
        let pin_update_home = default_reg
            .execute(
                "PinUpdate",
                &mut home_state,
                &ctx,
                &serde_json::json!({ "old_pin": "test_pin_home_1", "new_pin": "new_pin_home_2" }),
            )
            .await
            .unwrap();
        assert_eq!(pin_update_home["status"], "pin_updated");

        // PinUpdate with wrong old_pin
        assert!(default_reg
            .execute(
                "PinUpdate",
                &mut home_state,
                &ctx,
                &serde_json::json!({ "old_pin": "wrong", "new_pin": "new" }),
            )
            .await
            .is_err());

        // save_config_file error with non-writable path
        let bad_path = Path::new("/proc/invalid_dir/goldwarden.json");
        assert!(save_config_file(&ConfigFile::default(), bad_path).is_err());
    }

    #[tokio::test]
    async fn test_agent_write_message_failure_on_closed_client() {
        let temp_dir = tempfile::tempdir().expect("Create temp dir");
        let socket_path = temp_dir.path().join("write_fail.sock");
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let agent_socket = socket_path.clone();

        let handle = tokio::spawn(async move {
            let _ = run_agent_with_shutdown(&agent_socket, async {
                let _ = shutdown_rx.await;
            })
            .await;
        });

        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            if let Ok(mut stream) = UnixStream::connect(&socket_path).await {
                let req = IpcMessage::new("Status", serde_json::json!({}));
                let _ = write_message(&mut stream, &req).await;
                let _ = stream.shutdown().await;
                drop(stream);
                break;
            }
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = shutdown_tx.send(());
        let _ = handle.await;
    }

    #[tokio::test]
    async fn test_run_agent_ipc_shutdown() {
        let temp_dir = tempfile::tempdir().unwrap();
        let sock = temp_dir.path().join("run_agent_ipc.sock");
        let s = sock.clone();
        let handle = tokio::spawn(async move { run_agent(&s).await });
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            if let Ok(mut stream) = UnixStream::connect(&sock).await {
                let req = IpcMessage::new("AgentShutdown", serde_json::json!({}));
                let _ = write_message(&mut stream, &req).await;
                break;
            }
        }
        let res = handle.await.unwrap();
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_ssh_handlers_and_registry_edge_cases() {
        use sw_crypto::SymmetricKey;
        use sw_vault::VaultStore;

        let key = SymmetricKey::from_bytes(&[88u8; 64]).unwrap();
        let vault = Arc::new(VaultStore::new());
        let va = Arc::new(VaultAgentServer::new(vault));
        va.unlock(key).await;

        let reg = default_registry();
        let mut state = AgentState::default().with_vault_agent(va.clone());
        let ctx = CallingContext {
            username: "tester".into(),
            process_name: "test".into(),
            parent_process_name: "p".into(),
            grandparent_process_name: "gp".into(),
            process_pid: 1,
            parent_process_pid: 2,
            grandparent_process_pid: 3,
            error: false,
            authenticated: true,
        };

        // Unknown action error in registry
        assert!(reg
            .execute(
                "NonExistentAction",
                &mut state,
                &ctx,
                &serde_json::json!({})
            )
            .await
            .is_err());

        // ImportSSHKey edge cases through registry
        assert!(reg
            .execute(
                "ImportSSHKey",
                &mut state,
                &ctx,
                &serde_json::json!("not_obj")
            )
            .await
            .is_err());
        assert!(reg
            .execute(
                "ImportSSHKey",
                &mut state,
                &ctx,
                &serde_json::json!({ "name": "k" })
            )
            .await
            .is_err());
        assert!(reg
            .execute(
                "ImportSSHKey",
                &mut state,
                &ctx,
                &serde_json::json!({ "private_key_pem": "invalid" })
            )
            .await
            .is_err());
        assert!(reg
            .execute(
                "ImportSSHKey",
                &mut state,
                &ctx,
                &serde_json::json!({ "name": "k", "private_key_pem": "not_valid_pem" })
            )
            .await
            .is_err());

        // NewSSHKey edge cases through registry
        assert!(reg
            .execute("NewSSHKey", &mut state, &ctx, &serde_json::json!("not_obj"))
            .await
            .is_err());
        assert!(reg
            .execute("NewSSHKey", &mut state, &ctx, &serde_json::json!({}))
            .await
            .is_err());
        assert!(reg
            .execute(
                "NewSSHKey",
                &mut state,
                &ctx,
                &serde_json::json!({ "name": "k", "key_type": "UNKNOWN" })
            )
            .await
            .is_err());

        // DeleteSSHKey edge cases through registry
        assert!(reg
            .execute("DeleteSSHKey", &mut state, &ctx, &serde_json::json!(123))
            .await
            .is_err());
        assert!(reg
            .execute("DeleteSSHKey", &mut state, &ctx, &serde_json::json!({}))
            .await
            .is_err());
        assert!(reg
            .execute(
                "DeleteSSHKey",
                &mut state,
                &ctx,
                &serde_json::json!({ "id": "not_uuid" })
            )
            .await
            .is_err());
        assert!(reg
            .execute(
                "DeleteSSHKey",
                &mut state,
                &ctx,
                &serde_json::json!("not_uuid")
            )
            .await
            .is_err());

        // Direct helper validations
        assert!(
            handle_import_ssh_key(&va, &serde_json::json!({ "name": "k" }))
                .await
                .is_err()
        );
        assert!(
            handle_import_ssh_key(&va, &serde_json::json!({ "private_key_pem": "pem" }))
                .await
                .is_err()
        );
        assert!(handle_new_ssh_key(&va, &serde_json::json!({}))
            .await
            .is_err());
        assert!(handle_delete_ssh_key(&va, &serde_json::json!({}))
            .await
            .is_err());
        assert!(handle_delete_ssh_key(&va, &serde_json::json!(123))
            .await
            .is_err());
        assert!(handle_delete_ssh_key(&va, &serde_json::json!("bad-uuid"))
            .await
            .is_err());

        // Daemon handle_message with unknown action
        let daemon = AgentDaemon::with_vault_agent(AgentState::default(), va.clone());
        let err_resp = daemon
            .handle_message(
                &ctx,
                IpcMessage::new("UnknownAction", serde_json::json!({})),
            )
            .await;
        assert_eq!(err_resp.action, "Error");
    }

    #[tokio::test]
    async fn test_regression_home_config_untouched() {
        let real_config_path = std::env::var("HOME")
            .ok()
            .map(|h| sw_config::get_new_config_path(Path::new(&h)));

        let before_content = real_config_path
            .as_ref()
            .and_then(|p| std::fs::read(p).ok());

        // Run full PinSet and PinUpdate flow without config_directory set
        let registry = default_registry();
        let mut state = AgentState::default();
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

        // PinSet must succeed without writing to real $HOME
        let pin_set = registry
            .execute(
                "PinSet",
                &mut state,
                &ctx,
                &serde_json::json!({ "pin": "regression_pin_123" }),
            )
            .await
            .unwrap();
        assert_eq!(pin_set["status"], "pin_set");

        // PinUpdate must succeed without writing to real $HOME
        let pin_upd = registry
            .execute(
                "PinUpdate",
                &mut state,
                &ctx,
                &serde_json::json!({
                    "old_pin": "regression_pin_123",
                    "new_pin": "regression_pin_456"
                }),
            )
            .await
            .unwrap();
        assert_eq!(pin_upd["status"], "pin_updated");

        // Verify that real ~/.config/goldwarden/goldwarden.json was NOT modified
        let after_content = real_config_path
            .as_ref()
            .and_then(|p| std::fs::read(p).ok());

        assert_eq!(
            before_content, after_content,
            "Regression: PinSet or PinUpdate wrote to real ~/.config/goldwarden/goldwarden.json!"
        );
    }

    // ====================================================================
    // FASE 0 — Helpers de test
    // ====================================================================

    fn test_ctx() -> CallingContext {
        CallingContext {
            username: "tester".into(),
            process_name: "test".into(),
            parent_process_name: "test_runner".into(),
            grandparent_process_name: "cargo".into(),
            process_pid: 10,
            parent_process_pid: 5,
            grandparent_process_pid: 1,
            error: false,
            authenticated: true,
        }
    }

    fn test_agent(seed: u8) -> (Arc<VaultAgentServer>, sw_crypto::SymmetricKey) {
        let key = sw_crypto::SymmetricKey::from_bytes(&[seed; 64]).unwrap();
        let vault = Arc::new(sw_vault::VaultStore::new());
        let agent = Arc::new(VaultAgentServer::new(vault));
        (agent, key)
    }

    fn encrypted_login(
        name: &str,
        username: &str,
        password: &str,
        key: &sw_crypto::SymmetricKey,
    ) -> sw_vault::Cipher {
        let enc_name = sw_vault::encrypt_with(
            name.as_bytes(),
            sw_vault::EncStringType::AesCbc256HmacSha256B64,
            key,
        )
        .unwrap();
        let enc_user = sw_vault::encrypt_with(
            username.as_bytes(),
            sw_vault::EncStringType::AesCbc256HmacSha256B64,
            key,
        )
        .unwrap();
        let enc_pass = sw_vault::encrypt_with(
            password.as_bytes(),
            sw_vault::EncStringType::AesCbc256HmacSha256B64,
            key,
        )
        .unwrap();

        sw_vault::Cipher {
            id: Some(uuid::Uuid::new_v4()),
            r#type: sw_vault::CipherType::Login,
            name: enc_name,
            favorite: false,
            reprompt: 0,
            fields: vec![],
            login: Some(sw_vault::LoginCipher {
                username: Some(enc_user),
                password: Some(enc_pass),
                uri: None,
                uris: vec![],
                totp: None,
            }),
            ..Default::default()
        }
    }

    fn temp_state() -> (AgentState, tempfile::TempDir) {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let (agent, _) = test_agent(42);
        let state = AgentState::new(ConfigFile::default())
            .with_config_directory(temp_dir.path())
            .with_vault_agent(agent);
        (state, temp_dir)
    }

    fn mock_api_client(base_url: &str) -> Arc<sw_bitwarden_api::AuthenticatedClient> {
        let token = sw_config::LoginToken {
            access_token: "mock_access_token".to_string(),
            expires_in: 3600,
            token_type: "Bearer".to_string(),
            refresh_token: "mock_refresh_token".to_string(),
            key: "mock_key".to_string(),
            kdf: None,
            kdf_iterations: None,
            kdf_memory: None,
            kdf_parallelism: None,
        };
        Arc::new(
            sw_bitwarden_api::AuthenticatedClient::from_token_with_options(
                format!("{base_url}/identity"),
                format!("{base_url}/api"),
                token,
                true,
            ),
        )
    }

    // ====================================================================
    // FASE 1 — Tests de handle_sync
    // ====================================================================

    #[tokio::test]
    async fn test_handle_sync_locked_returns_error() {
        let (mut state, _tmp) = temp_state();
        state.is_locked = true;
        let res = handle_sync(&mut state, &serde_json::json!({})).await;
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("Bóveda bloqueada"));
    }

    #[tokio::test]
    async fn test_handle_sync_without_session_returns_error() {
        let (mut state, _tmp) = temp_state();
        state.is_locked = false;
        state.config.encrypted_token = String::new();
        state.api_client = None;
        let res = handle_sync(&mut state, &serde_json::json!({})).await;
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err(),
            "No hay sesión iniciada. Ejecuta 'silverwarden login' primero."
        );
    }

    #[tokio::test]
    async fn test_handle_sync_payload_updates_config_and_summary() {
        let (mut state, _tmp) = temp_state();
        state.is_locked = false;
        let (_, key) = test_agent(42);

        let vault = state.vault_agent.as_ref().unwrap().vault();
        // Insert 2 logins, 1 ssh key, 1 note
        vault
            .insert(encrypted_login("Login1", "u1", "p1", &key))
            .await;
        vault
            .insert(encrypted_login("Login2", "u2", "p2", &key))
            .await;
        let enc_ssh_name = sw_vault::encrypt_with(
            b"enc_ssh",
            sw_vault::EncStringType::AesCbc256HmacSha256B64,
            &key,
        )
        .unwrap();
        let enc_note_name = sw_vault::encrypt_with(
            b"enc_note",
            sw_vault::EncStringType::AesCbc256HmacSha256B64,
            &key,
        )
        .unwrap();
        vault
            .insert(sw_vault::Cipher {
                id: Some(uuid::Uuid::new_v4()),
                r#type: sw_vault::CipherType::SshKey,
                name: enc_ssh_name,
                ..Default::default()
            })
            .await;
        vault
            .insert(sw_vault::Cipher {
                id: Some(uuid::Uuid::new_v4()),
                r#type: sw_vault::CipherType::Note,
                name: enc_note_name,
                ..Default::default()
            })
            .await;

        let payload = serde_json::json!({
            "encrypted_token": "enc_tok_payload",
            "encrypted_user_symmetric_key": "enc_sym_payload",
            "identity_url": "https://identity.test",
            "api_url": "https://api.test",
            "danger_accept_invalid_certs": true,
        });

        let res = handle_sync(&mut state, &payload)
            .await
            .expect("sync should succeed");
        assert_eq!(state.config.encrypted_token, "enc_tok_payload");
        assert_eq!(state.config.encrypted_user_symmetric_key, "enc_sym_payload");
        assert_eq!(state.config.identity_url, "https://identity.test");
        assert_eq!(state.config.api_url, "https://api.test");
        assert!(state.config.danger_accept_invalid_certs);

        assert_eq!(res["status"], "synced");
        assert_eq!(res["total"], 4);
        assert_eq!(res["logins"], 2);
        assert_eq!(res["ssh_keys"], 1);
    }

    #[tokio::test]
    async fn test_handle_sync_disk_config_fallback() {
        let (mut state, tmp) = temp_state();
        state.is_locked = false;
        state.config.encrypted_token = String::new();
        state.api_client = None;

        let disk_cfg = ConfigFile {
            encrypted_token: "disk_enc_token".to_string(),
            encrypted_user_symmetric_key: "disk_enc_sym".to_string(),
            identity_url: "https://disk-ident.test".to_string(),
            api_url: "https://disk-api.test".to_string(),
            danger_accept_invalid_certs: true,
            ..Default::default()
        };
        save_config_file(&disk_cfg, &tmp.path().join("goldwarden.json")).unwrap();

        let res = handle_sync(&mut state, &serde_json::json!({}))
            .await
            .expect("sync fallback should succeed");
        assert_eq!(state.config.encrypted_token, "disk_enc_token");
        assert_eq!(state.config.encrypted_user_symmetric_key, "disk_enc_sym");
        assert_eq!(state.config.identity_url, "https://disk-ident.test");
        assert_eq!(state.config.api_url, "https://disk-api.test");
        assert_eq!(res["status"], "synced");
    }

    #[tokio::test]
    async fn test_handle_sync_api_success_persists_vault() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let profile_id = uuid::Uuid::new_v4();
        let valid_enc = "2.aXZfMTZfYnl0ZXNfbG9uZw==|Y2lwaGVydGV4dF9ieXRlcw==|bWFjXzMyX2J5dGVzX2xvbmdfaGFzaF9zdHJpbmchIQ==";
        let sync_response = serde_json::json!({
            "profile": {
                "id": profile_id.to_string(),
                "name": "Test User",
                "email": "test@example.com"
            },
            "folders": [],
            "ciphers": [
                {
                    "id": uuid::Uuid::new_v4().to_string(),
                    "type": 1,
                    "name": valid_enc,
                    "login": {
                        "username": valid_enc,
                        "password": valid_enc
                    }
                },
                {
                    "id": uuid::Uuid::new_v4().to_string(),
                    "type": 5,
                    "name": valid_enc
                }
            ]
        });

        Mock::given(method("GET"))
            .and(path("/api/sync"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&sync_response))
            .mount(&server)
            .await;

        let (mut state, tmp) = temp_state();
        state.is_locked = false;
        state.api_client = Some(mock_api_client(&server.uri()));

        let res = handle_sync(&mut state, &serde_json::json!({}))
            .await
            .expect("sync should succeed");
        assert_eq!(res["status"], "synced");
        assert_eq!(res["total"], 2);
        assert_eq!(res["logins"], 1);
        assert_eq!(res["ssh_keys"], 1);

        // Verify vault.json was persisted on disk in tmp
        let vault_file = tmp.path().join("vault.json");
        assert!(vault_file.exists());
        let loaded = sw_vault::load_vault(&vault_file).expect("load vault from disk");
        assert_eq!(loaded.ciphers.len(), 2);
        assert_eq!(loaded.profile.id, Some(profile_id));
    }

    #[tokio::test]
    async fn test_handle_sync_api_rate_limit() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/sync"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&server)
            .await;

        let (mut state, _tmp) = temp_state();
        state.is_locked = false;
        state.api_client = Some(mock_api_client(&server.uri()));

        let err = handle_sync(&mut state, &serde_json::json!({}))
            .await
            .unwrap_err();
        assert!(err.contains("El servidor ha bloqueado temporalmente tu IP"));
    }

    #[tokio::test]
    async fn test_handle_sync_api_server_error() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/sync"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let (mut state, _tmp) = temp_state();
        state.is_locked = false;
        state.api_client = Some(mock_api_client(&server.uri()));

        let err = handle_sync(&mut state, &serde_json::json!({}))
            .await
            .unwrap_err();
        assert!(err.contains("Error al sincronizar con el servidor"));
    }

    #[tokio::test]
    async fn test_handle_sync_token_payload_builds_api_client() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let sync_response = serde_json::json!({
            "profile": {
                "id": uuid::Uuid::new_v4().to_string(),
                "name": "User",
                "email": "u@test.com",
            },
            "folders": [],
            "collections": [],
            "ciphers": [],
        });

        Mock::given(method("GET"))
            .and(path("/api/sync"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&sync_response))
            .mount(&server)
            .await;

        let (mut state, _tmp) = temp_state();
        state.is_locked = false;
        assert!(state.api_client.is_none());

        let payload = serde_json::json!({
            "identity_url": format!("{}/identity", server.uri()),
            "api_url": format!("{}/api", server.uri()),
            "danger_accept_invalid_certs": true,
            "token": {
                "access_token": "valid_token_xyz",
                "expires_in": 3600,
                "token_type": "Bearer",
                "refresh_token": "valid_refresh_xyz",
                "key": "valid_key_xyz"
            }
        });

        let res = handle_sync(&mut state, &payload)
            .await
            .expect("sync with token payload should succeed");
        assert_eq!(res["status"], "synced");
        assert!(state.api_client.is_some());
    }

    // ====================================================================
    // FASE 2 — Tests de logins
    // ====================================================================

    #[tokio::test]
    async fn test_handle_list_logins_filters_and_locked() {
        let (mut state, _tmp) = temp_state();
        let (agent, key) = test_agent(50);
        state.vault_agent = Some(agent.clone());

        // 1. Locked -> returns error
        state.is_locked = true;
        let err = handle_list_logins(&state).await.unwrap_err();
        assert!(err.contains("Bóveda bloqueada"));

        // 2. Unlocked
        agent.unlock(key.try_clone().unwrap()).await;
        state.is_locked = false;

        let vault = agent.vault();
        // 1 active login
        let mut active_login = encrypted_login("ActiveLogin", "alice", "pass123", &key);
        active_login.deleted_date = None;
        vault.insert(active_login).await;

        // 1 note
        let note_enc_name = sw_vault::encrypt_with(
            b"NoteName",
            sw_vault::EncStringType::AesCbc256HmacSha256B64,
            &key,
        )
        .unwrap();
        vault
            .insert(sw_vault::Cipher {
                id: Some(uuid::Uuid::new_v4()),
                r#type: sw_vault::CipherType::Note,
                name: note_enc_name,
                ..Default::default()
            })
            .await;

        // 1 deleted login
        let mut deleted_login = encrypted_login("DeletedLogin", "bob", "pass456", &key);
        deleted_login.deleted_date = Some("2026-01-01T00:00:00Z".to_string());
        vault.insert(deleted_login).await;

        let res = handle_list_logins(&state)
            .await
            .expect("list logins succeeds");
        let list = res.as_array().expect("array result");
        assert_eq!(list.len(), 1);
        assert_eq!(list[0]["name"], "ActiveLogin");
        assert_eq!(list[0]["username"], "alice");
    }

    #[tokio::test]
    async fn test_handle_get_login_found_not_found_locked() {
        let (mut state, _tmp) = temp_state();
        let (agent, key) = test_agent(51);
        state.vault_agent = Some(agent.clone());

        // Locked error
        state.is_locked = true;
        assert!(
            handle_get_login(&state, &serde_json::json!({ "name": "GitHub" }))
                .await
                .is_err()
        );

        // Unlock
        agent.unlock(key.try_clone().unwrap()).await;
        state.is_locked = false;

        let login = encrypted_login("GitHub", "octocat", "super_secret", &key);
        agent.vault().insert(login).await;

        // Found exact
        let res_exact = handle_get_login(&state, &serde_json::json!({ "name": "GitHub" }))
            .await
            .unwrap();
        assert_eq!(res_exact["name"], "GitHub");
        assert_eq!(res_exact["username"], "octocat");
        assert_eq!(res_exact["password"], "super_secret");

        // Found case-insensitive
        let res_case = handle_get_login(&state, &serde_json::json!({ "name": "github" }))
            .await
            .unwrap();
        assert_eq!(res_case["name"], "GitHub");

        // Found from primitive string payload
        let res_str = handle_get_login(&state, &serde_json::json!("GITHUB"))
            .await
            .unwrap();
        assert_eq!(res_str["name"], "GitHub");

        // Not found
        let err_not_found = handle_get_login(&state, &serde_json::json!({ "name": "GitLab" }))
            .await
            .unwrap_err();
        assert!(err_not_found.contains("No se encontró ningún acceso con el nombre 'GitLab'"));

        // Missing name in payload
        let err_missing = handle_get_login(&state, &serde_json::json!({}))
            .await
            .unwrap_err();
        assert!(err_missing.contains("Campo 'name' requerido"));
    }

    #[tokio::test]
    async fn test_handle_delete_login_local_and_not_found() {
        let (mut state, _tmp) = temp_state();
        let (agent, key) = test_agent(52);
        state.vault_agent = Some(agent.clone());
        state.is_locked = false;
        agent.unlock(key.try_clone().unwrap()).await;

        let login = encrypted_login("Twitter", "bird_user", "tweet123", &key);
        agent.vault().insert(login).await;

        assert_eq!(agent.vault().all().await.len(), 1);

        // Delete existing
        let res = handle_delete_login(&mut state, &serde_json::json!({ "name": "Twitter" }))
            .await
            .unwrap();
        assert_eq!(res["status"], "deleted");
        assert_eq!(res["name"], "Twitter");
        assert_eq!(agent.vault().all().await.len(), 0);

        // Delete not found
        let err = handle_delete_login(&mut state, &serde_json::json!({ "name": "Twitter" }))
            .await
            .unwrap_err();
        assert!(err.contains("No se encontró ningún acceso con el nombre 'Twitter'"));
    }

    #[tokio::test]
    async fn test_handle_delete_login_server_error_is_tolerated() {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path_regex(r"^/api/ciphers/.*"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let (mut state, _tmp) = temp_state();
        let (agent, key) = test_agent(53);
        state.vault_agent = Some(agent.clone());
        state.is_locked = false;
        agent.unlock(key.try_clone().unwrap()).await;
        state.api_client = Some(mock_api_client(&server.uri()));

        let login = encrypted_login("Reddit", "redditor", "upvote_all", &key);
        agent.vault().insert(login).await;

        let res = handle_delete_login(&mut state, &serde_json::json!({ "name": "Reddit" }))
            .await
            .unwrap();
        assert_eq!(res["status"], "deleted");
        assert_eq!(res["name"], "Reddit");
        assert_eq!(agent.vault().all().await.len(), 0);
    }

    #[tokio::test]
    async fn test_handle_create_login_validations() {
        let (mut state, _tmp) = temp_state();
        let (agent, key) = test_agent(54);
        state.vault_agent = Some(agent.clone());

        // 1. Locked
        state.is_locked = true;
        let err_locked = handle_create_login(&mut state, &serde_json::json!({}))
            .await
            .unwrap_err();
        assert!(err_locked.contains("Bóveda bloqueada"));

        state.is_locked = false;
        agent.unlock(key).await;

        // 2. Non-object payload
        let err_non_obj = handle_create_login(&mut state, &serde_json::json!("not-an-object"))
            .await
            .unwrap_err();
        assert!(err_non_obj.contains("El payload debe ser un objeto JSON"));

        // 3. Missing fields
        assert!(handle_create_login(
            &mut state,
            &serde_json::json!({ "username": "u", "password": "p" })
        )
        .await
        .unwrap_err()
        .contains("Campo 'name' requerido"));
        assert!(handle_create_login(
            &mut state,
            &serde_json::json!({ "name": "n", "password": "p" })
        )
        .await
        .unwrap_err()
        .contains("Campo 'username' requerido"));
        assert!(handle_create_login(
            &mut state,
            &serde_json::json!({ "name": "n", "username": "u" })
        )
        .await
        .unwrap_err()
        .contains("Campo 'password' requerido"));

        // 4. Empty strings
        assert!(handle_create_login(
            &mut state,
            &serde_json::json!({ "name": "  ", "username": "u", "password": "p" })
        )
        .await
        .unwrap_err()
        .contains("El campo 'name' no puede estar vacío"));
        assert!(handle_create_login(
            &mut state,
            &serde_json::json!({ "name": "n", "username": "  ", "password": "p" })
        )
        .await
        .unwrap_err()
        .contains("El campo 'username' no puede estar vacío"));
        assert!(handle_create_login(
            &mut state,
            &serde_json::json!({ "name": "n", "username": "u", "password": "  " })
        )
        .await
        .unwrap_err()
        .contains("El campo 'password' no puede estar vacío"));

        // 5. No profile synced
        let err_no_profile = handle_create_login(
            &mut state,
            &serde_json::json!({ "name": "n", "username": "u", "password": "p" }),
        )
        .await
        .unwrap_err();
        assert!(err_no_profile
            .contains("No se ha sincronizado el perfil. Ejecuta 'silverwarden sync' primero."));

        // 6. Profile present, but no api_client
        agent
            .vault()
            .load_sync_data(sw_vault::SyncData {
                profile: sw_vault::Profile {
                    id: Some(uuid::Uuid::new_v4()),
                    ..Default::default()
                },
                ..Default::default()
            })
            .await;
        state.api_client = None;
        let err_no_session = handle_create_login(
            &mut state,
            &serde_json::json!({ "name": "n", "username": "u", "password": "p" }),
        )
        .await
        .unwrap_err();
        assert!(err_no_session.contains("No hay sesión iniciada en el servidor"));
    }

    #[tokio::test]
    async fn test_handle_create_login_success() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let server_cipher_id = uuid::Uuid::new_v4();
        let profile_id = uuid::Uuid::new_v4();

        let valid_enc = "2.aXZfMTZfYnl0ZXNfbG9uZw==|Y2lwaGVydGV4dF9ieXRlcw==|bWFjXzMyX2J5dGVzX2xvbmdfaGFzaF9zdHJpbmchIQ==";
        let response_cipher = serde_json::json!({
            "id": server_cipher_id.to_string(),
            "type": 1,
            "name": valid_enc,
            "encryptedFor": profile_id.to_string(),
            "login": {
                "username": valid_enc,
                "password": valid_enc
            }
        });

        Mock::given(method("POST"))
            .and(path("/api/ciphers"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_cipher))
            .mount(&server)
            .await;

        let (mut state, _tmp) = temp_state();
        let (agent, key) = test_agent(55);
        state.vault_agent = Some(agent.clone());
        state.is_locked = false;
        agent.unlock(key).await;

        // Set profile in vault
        agent
            .vault()
            .load_sync_data(sw_vault::SyncData {
                profile: sw_vault::Profile {
                    id: Some(profile_id),
                    ..Default::default()
                },
                ..Default::default()
            })
            .await;

        state.api_client = Some(mock_api_client(&server.uri()));

        let payload = serde_json::json!({
            "name": "Google",
            "username": "user@gmail.com",
            "password": "secretpassword"
        });

        let res = handle_create_login(&mut state, &payload)
            .await
            .expect("create login should succeed");
        assert_eq!(res["status"], "created");
        assert_eq!(res["id"], server_cipher_id.to_string());
        assert_eq!(res["name"], "Google");

        // Verify inserted into vault
        let all = agent.vault().all().await;
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].id, Some(server_cipher_id));
    }

    // ====================================================================
    // FASE 3 — Tests de sesión y registry
    // ====================================================================

    #[tokio::test]
    async fn test_handle_set_session_persists_and_unlocks() {
        use base64::Engine;

        let (mut state, tmp) = temp_state();
        let key_bytes = [77u8; 64];
        let key_b64 = base64::engine::general_purpose::STANDARD.encode(key_bytes);

        let payload = serde_json::json!({
            "identity_url": "https://ident.custom.test",
            "api_url": "https://api.custom.test",
            "notifications_url": "https://notif.custom.test",
            "danger_accept_invalid_certs": true,
            "encrypted_token": "enc_tok_sample",
            "encrypted_user_symmetric_key": "enc_sym_sample",
            "token": {
                "access_token": "bearer_abc",
                "expires_in": 3600,
                "token_type": "Bearer",
                "refresh_token": "refr_123",
                "key": "key_123"
            },
            "user_symmetric_key": key_b64,
        });

        let res = handle_set_session(&mut state, &payload)
            .await
            .expect("set session should succeed");
        assert_eq!(res["status"], "session_saved");

        // Config updated in memory
        assert_eq!(state.config.identity_url, "https://ident.custom.test");
        assert_eq!(state.config.api_url, "https://api.custom.test");
        assert_eq!(state.config.notifications_url, "https://notif.custom.test");
        assert!(state.config.danger_accept_invalid_certs);
        assert_eq!(state.config.encrypted_token, "enc_tok_sample");
        assert_eq!(state.config.encrypted_user_symmetric_key, "enc_sym_sample");

        // api_client created
        assert!(state.api_client.is_some());

        // vault unlocked
        assert!(!state.vault_agent.as_ref().unwrap().is_locked());

        // config file persisted
        let config_file = tmp.path().join("goldwarden.json");
        assert!(config_file.exists());
        let saved_content = std::fs::read_to_string(config_file).unwrap();
        assert!(saved_content.contains("https://ident.custom.test"));
    }

    #[tokio::test]
    async fn test_handle_set_session_invalid_key_does_not_panic() {
        let (mut state, _tmp) = temp_state();

        // 1. Invalid base64
        let payload1 = serde_json::json!({
            "user_symmetric_key": "not-valid-base64-%%%$$$",
        });
        let res1 = handle_set_session(&mut state, &payload1).await;
        assert!(res1.is_ok());

        // 2. Valid base64 but wrong length (3 bytes instead of 64)
        let payload2 = serde_json::json!({
            "user_symmetric_key": "AQID",
        });
        let res2 = handle_set_session(&mut state, &payload2).await;
        assert!(res2.is_ok());
    }

    #[tokio::test]
    async fn test_handle_sync_data_invalid_payload() {
        let (mut state, _tmp) = temp_state();
        let err = handle_sync_data(&mut state, &serde_json::json!("not-a-syncdata-object"))
            .await
            .unwrap_err();
        assert!(err.contains("Error deserializando SyncData"));
    }

    #[tokio::test]
    async fn test_handle_sync_data_success() {
        let (mut state, tmp) = temp_state();
        let (_, key) = test_agent(60);
        let valid_sync = sw_vault::SyncData {
            profile: sw_vault::Profile {
                id: Some(uuid::Uuid::new_v4()),
                ..Default::default()
            },
            ciphers: vec![
                encrypted_login("LoginSync", "usr", "pwd", &key),
                sw_vault::Cipher {
                    id: Some(uuid::Uuid::new_v4()),
                    r#type: sw_vault::CipherType::SshKey,
                    name: sw_vault::encrypt_with(
                        b"ssh_sync",
                        sw_vault::EncStringType::AesCbc256HmacSha256B64,
                        &key,
                    )
                    .unwrap(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };

        let payload = serde_json::to_value(&valid_sync).unwrap();
        let res = handle_sync_data(&mut state, &payload)
            .await
            .expect("sync data should succeed");
        assert_eq!(res["status"], "synced");
        assert_eq!(res["total"], 2);
        assert_eq!(res["logins"], 1);
        assert_eq!(res["ssh_keys"], 1);

        // Vault file on disk
        let vault_file = tmp.path().join("vault.json");
        assert!(vault_file.exists());
    }

    #[tokio::test]
    async fn test_agent_state_helpers_and_config_path_variants() {
        let temp_dir = tempfile::tempdir().unwrap();
        let direct_file = temp_dir.path().join("goldwarden.json");
        let state = AgentState::new(ConfigFile::default()).with_config_directory(&direct_file);
        assert_eq!(state.config_path(), Some(direct_file));

        let mock_client = mock_api_client("http://localhost:1234");
        let state_with_client = state.with_api_client(mock_client);
        assert!(state_with_client.api_client.is_some());
    }

    #[tokio::test]
    async fn test_registry_login_actions_wire_handlers() {
        let registry = default_registry();
        let (mut state, _tmp) = temp_state();
        let ctx = test_ctx();

        // Locked state: these actions must return their specific locked/validation error, not "Acción no reconocida"
        let res_sync = registry
            .execute("Sync", &mut state, &ctx, &serde_json::json!({}))
            .await;
        assert_eq!(
            res_sync.unwrap_err(),
            "Bóveda bloqueada. Desbloquea con 'silverwarden unlock' primero."
        );

        let res_list = registry
            .execute("ListLogins", &mut state, &ctx, &serde_json::json!({}))
            .await;
        assert_eq!(
            res_list.unwrap_err(),
            "Bóveda bloqueada. Desbloquea con 'silverwarden unlock' primero."
        );

        let res_get = registry
            .execute(
                "GetLogin",
                &mut state,
                &ctx,
                &serde_json::json!({ "name": "test" }),
            )
            .await;
        assert_eq!(
            res_get.unwrap_err(),
            "Bóveda bloqueada. Desbloquea con 'silverwarden unlock' primero."
        );

        let res_create = registry
            .execute("CreateLogin", &mut state, &ctx, &serde_json::json!({}))
            .await;
        assert_eq!(
            res_create.unwrap_err(),
            "Bóveda bloqueada. Desbloquea con 'silverwarden unlock' primero."
        );

        let res_del = registry
            .execute("DeleteLogin", &mut state, &ctx, &serde_json::json!({}))
            .await;
        assert_eq!(
            res_del.unwrap_err(),
            "Bóveda bloqueada. Desbloquea con 'silverwarden unlock' primero."
        );

        let res_set = registry
            .execute("SetSession", &mut state, &ctx, &serde_json::json!({}))
            .await;
        assert_eq!(res_set.unwrap()["status"], "session_saved");

        let res_login = registry
            .execute("Login", &mut state, &ctx, &serde_json::json!({}))
            .await;
        assert_eq!(res_login.unwrap()["status"], "session_saved");

        let sync_empty = serde_json::to_value(sw_vault::SyncData::default()).unwrap();
        let res_sd = registry
            .execute("SyncData", &mut state, &ctx, &sync_empty)
            .await;
        assert_eq!(res_sd.unwrap()["status"], "synced");

        let res_rv = registry
            .execute("ReloadVault", &mut state, &ctx, &sync_empty)
            .await;
        assert_eq!(res_rv.unwrap()["status"], "synced");
    }

    #[tokio::test]
    async fn test_pin_cache_store_and_get() {
        let mut cache = PinCache::new(Duration::from_secs(900));
        assert!(!cache.is_valid());
        assert!(cache.get().is_none());
        assert!(cache.remaining().is_none());

        let key = [55u8; 32];
        cache.store(&key);

        assert!(cache.is_valid());
        assert!(cache.remaining().is_some());
        let retrieved = cache.get();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap(), [55u8; 32]);
    }

    #[tokio::test]
    async fn test_pin_cache_expires_after_ttl() {
        let ttl = Duration::from_millis(50);
        let mut cache = PinCache::new(ttl);
        let key = [42u8; 32];
        cache.store(&key);
        assert!(cache.is_valid());

        tokio::time::sleep(Duration::from_millis(70)).await;

        assert!(!cache.is_valid());
        assert!(cache.get().is_none());
        assert!(cache.remaining().is_none());
    }

    #[tokio::test]
    async fn test_pin_cache_ttl_resets_on_get() {
        let ttl = Duration::from_millis(60);
        let mut cache = PinCache::new(ttl);
        let key = [77u8; 32];
        cache.store(&key);

        // Esperar la mitad del TTL (30ms)
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(cache.is_valid());
        let rem1 = cache.remaining().unwrap();
        assert!(rem1 <= Duration::from_millis(40));

        // get() reinicia el TTL a 60ms
        let ret = cache.get();
        assert!(ret.is_some());

        // Esperar 40ms más (total 70ms desde store, pero 40ms desde get)
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert!(cache.is_valid());
        assert!(cache.get().is_some());

        // Esperar 70ms más -> ahora expira
        tokio::time::sleep(Duration::from_millis(70)).await;
        assert!(!cache.is_valid());
        assert!(cache.get().is_none());
    }

    #[tokio::test]
    async fn test_pin_cache_clear() {
        let mut cache = PinCache::new(Duration::from_secs(900));
        let key = [88u8; 32];
        cache.store(&key);
        assert!(cache.is_valid());

        cache.clear();
        assert!(!cache.is_valid());
        assert!(cache.get().is_none());
        assert!(cache.remaining().is_none());
    }

    #[tokio::test]
    async fn test_unlock_uses_pin_cache_when_valid() {
        let registry = default_registry();
        let (_state, temp_dir) = temp_state();
        let mut state = AgentState::new(ConfigFile {
            device_uuid: "test-dev-uuid".to_string(),
            ..Default::default()
        })
        .with_config_directory(temp_dir.path());
        let ctx = test_ctx();

        // 1. Configurar PIN
        let set_res = registry
            .execute(
                "PinSet",
                &mut state,
                &ctx,
                &serde_json::json!({ "pin": "cache_pin_123" }),
            )
            .await
            .unwrap();
        assert_eq!(set_res["status"], "pin_set");

        // 2. Primer Unlock con PIN: cache miss
        let unlock1 = registry
            .execute(
                "Unlock",
                &mut state,
                &ctx,
                &serde_json::json!({ "pin": "cache_pin_123" }),
            )
            .await
            .unwrap();
        assert_eq!(unlock1["status"], "unlocked");
        assert_eq!(unlock1["from_cache"], false);
        assert!(state.pin_cache.is_valid());

        // Simulamos bloqueo del agente sin llamar a Lock (ej. bloqueo por inactividad o cambio de bandera)
        state.is_locked = true;

        // 3. Segundo Unlock sin PIN: cache hit (no ejecuta Argon2i)
        let unlock2 = registry
            .execute("Unlock", &mut state, &ctx, &serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(unlock2["status"], "unlocked");
        assert_eq!(unlock2["from_cache"], true);
        assert!(!state.is_locked);
    }

    #[tokio::test]
    async fn test_unlock_falls_back_to_argon2_when_cache_miss() {
        let registry = default_registry();
        let (_state, temp_dir) = temp_state();
        let mut state = AgentState::new(ConfigFile {
            device_uuid: "test-dev-uuid".to_string(),
            ..Default::default()
        })
        .with_config_directory(temp_dir.path());
        let ctx = test_ctx();

        registry
            .execute(
                "PinSet",
                &mut state,
                &ctx,
                &serde_json::json!({ "pin": "my_pin_456" }),
            )
            .await
            .unwrap();

        // Limpiamos explícitamente el caché para forzar cache miss
        state.pin_cache.clear();
        assert!(!state.pin_cache.is_valid());

        // Intento de Unlock sin PIN debe fallar al no haber caché
        let err_no_pin = registry
            .execute("Unlock", &mut state, &ctx, &serde_json::json!({}))
            .await
            .unwrap_err();
        assert_eq!(
            err_no_pin,
            "Campo 'pin' requerido en payload (no hay caché válido)"
        );

        // Unlock con PIN ejecuta Argon2i y llena el caché
        let unlock_res = registry
            .execute(
                "Unlock",
                &mut state,
                &ctx,
                &serde_json::json!({ "pin": "my_pin_456" }),
            )
            .await
            .unwrap();
        assert_eq!(unlock_res["status"], "unlocked");
        assert_eq!(unlock_res["from_cache"], false);
        assert!(state.pin_cache.is_valid());
    }

    #[tokio::test]
    async fn test_lock_clears_pin_cache() {
        let registry = default_registry();
        let (_state, temp_dir) = temp_state();
        let mut state = AgentState::new(ConfigFile {
            device_uuid: "test-dev-uuid".to_string(),
            ..Default::default()
        })
        .with_config_directory(temp_dir.path());
        let ctx = test_ctx();

        registry
            .execute(
                "PinSet",
                &mut state,
                &ctx,
                &serde_json::json!({ "pin": "lock_pin_789" }),
            )
            .await
            .unwrap();

        let unlock = registry
            .execute(
                "Unlock",
                &mut state,
                &ctx,
                &serde_json::json!({ "pin": "lock_pin_789" }),
            )
            .await
            .unwrap();
        assert_eq!(unlock["status"], "unlocked");
        assert!(state.pin_cache.is_valid());

        // Lock debe limpiar el pin_cache por seguridad
        let lock_res = registry
            .execute("Lock", &mut state, &ctx, &serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(lock_res["status"], "locked");
        assert!(!state.pin_cache.is_valid());
        assert!(state.pin_cache.get().is_none());

        // Posterior Unlock sin PIN falla porque el caché fue limpiado
        let unlock_fail = registry
            .execute("Unlock", &mut state, &ctx, &serde_json::json!({}))
            .await;
        assert!(unlock_fail.is_err());
    }

    #[tokio::test]
    async fn test_pin_update_clears_and_stores_new() {
        let registry = default_registry();
        let (_state, temp_dir) = temp_state();
        let mut state = AgentState::new(ConfigFile {
            device_uuid: "test-dev-uuid".to_string(),
            ..Default::default()
        })
        .with_config_directory(temp_dir.path());
        let ctx = test_ctx();

        registry
            .execute(
                "PinSet",
                &mut state,
                &ctx,
                &serde_json::json!({ "pin": "old_pin_111" }),
            )
            .await
            .unwrap();

        let _ = registry
            .execute(
                "Unlock",
                &mut state,
                &ctx,
                &serde_json::json!({ "pin": "old_pin_111" }),
            )
            .await
            .unwrap();
        assert!(state.pin_cache.is_valid());

        // PinUpdate debe limpiar el caché previo y almacenar la nueva clave derivada
        let update_res = registry
            .execute(
                "PinUpdate",
                &mut state,
                &ctx,
                &serde_json::json!({
                    "old_pin": "old_pin_111",
                    "new_pin": "new_pin_222"
                }),
            )
            .await
            .unwrap();
        assert_eq!(update_res["status"], "pin_updated");
        assert!(state.pin_cache.is_valid());

        // El nuevo PIN está en caché y permite Unlock inmediato sin enviar PIN
        state.is_locked = true;
        let unlock_cache = registry
            .execute("Unlock", &mut state, &ctx, &serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(unlock_cache["status"], "unlocked");
        assert_eq!(unlock_cache["from_cache"], true);
    }

    #[tokio::test]
    async fn test_status_reports_pin_cached() {
        let registry = default_registry();
        let (_state, temp_dir) = temp_state();
        let mut state = AgentState::new(ConfigFile {
            device_uuid: "test-dev-uuid".to_string(),
            ..Default::default()
        })
        .with_config_directory(temp_dir.path());
        let ctx = test_ctx();

        // Status inicial antes de configurar PIN
        let st_init = registry
            .execute("Status", &mut state, &ctx, &serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(st_init["pin_cached"], false);
        assert_eq!(st_init["pin_cached_remaining_secs"], 0);

        registry
            .execute(
                "PinSet",
                &mut state,
                &ctx,
                &serde_json::json!({ "pin": "status_pin_333" }),
            )
            .await
            .unwrap();

        let _ = registry
            .execute(
                "Unlock",
                &mut state,
                &ctx,
                &serde_json::json!({ "pin": "status_pin_333" }),
            )
            .await
            .unwrap();

        let st_after = registry
            .execute("Status", &mut state, &ctx, &serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(st_after["pin_cached"], true);
        let remaining = st_after["pin_cached_remaining_secs"].as_u64().unwrap();
        assert!(remaining > 0 && remaining <= 900);
    }

    #[tokio::test]
    async fn test_pin_cache_constant_time_no_panic() {
        let mut cache = PinCache::new(Duration::from_secs(900));

        // Intento de almacenar clave de tamaño incorrecto (ej. 64 bytes o 16 bytes)
        cache.store(&[1u8; 64]);
        assert!(!cache.is_valid());
        assert!(cache.get().is_none());

        cache.store(&[1u8; 16]);
        assert!(!cache.is_valid());
        assert!(cache.get().is_none());

        // Con clave válida de 32 bytes
        let valid_key = [9u8; 32];
        cache.store(&valid_key);
        assert!(cache.is_valid());

        let retrieved = cache.get();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap(), [9u8; 32]);
    }

    #[tokio::test]
    async fn test_unlock_cache_hit_decrypts_token_and_symmetric_key() {
        let registry = default_registry();
        let (_state, temp_dir) = temp_state();
        let ctx = test_ctx();

        let device_uuid = "test-device-uuid-1234";
        let pin = "correct_secret_pin";
        let config_key =
            sw_config::derive_config_key_with_params(pin, device_uuid, AGENT_KDF_MEMORY_KIB)
                .unwrap();
        let config_key_hash = sw_config::hash_config_key(&config_key);

        // Preparamos token sintético y lo ciframos con config_key
        let original_token = sw_config::LoginToken {
            access_token: "mock_access_token_123".to_string(),
            expires_in: 3600,
            token_type: "Bearer".to_string(),
            refresh_token: "mock_refresh_token_456".to_string(),
            key: "mock_key_789".to_string(),
            ..Default::default()
        };
        let token_json = serde_json::to_string(&original_token).unwrap();
        let enc_token = sw_config::encrypt_string(&token_json, &config_key).unwrap();

        // Preparamos clave simétrica de usuario (64 bytes) y la ciframos con config_key
        use base64::Engine;
        let original_user_sym_key = [77u8; 64];
        let user_sym_b64 = base64::engine::general_purpose::STANDARD.encode(original_user_sym_key);
        let enc_user_sym = sw_config::encrypt_string(&user_sym_b64, &config_key).unwrap();

        let (va, _) = test_agent(1);
        let cfg = ConfigFile {
            device_uuid: device_uuid.to_string(),
            config_key_hash,
            encrypted_token: enc_token,
            encrypted_user_symmetric_key: enc_user_sym,
            identity_url: "https://identity.bitwarden.test".to_string(),
            api_url: "https://api.bitwarden.test".to_string(),
            ..Default::default()
        };

        let mut state = AgentState::new(cfg).with_config_directory(temp_dir.path());
        state.vault_agent = Some(va.clone());

        // 1. Primer Unlock con PIN: cache miss
        let unlock1 = registry
            .execute(
                "Unlock",
                &mut state,
                &ctx,
                &serde_json::json!({ "pin": pin }),
            )
            .await
            .unwrap();
        assert_eq!(unlock1["status"], "unlocked");
        assert_eq!(unlock1["from_cache"], false);
        assert!(!va.is_locked());
        assert!(state.api_client.is_some());

        // 2. Simular bloqueo del agente
        state.is_locked = true;
        va.lock().await;
        assert!(va.is_locked());

        // 3. Segundo Unlock sin PIN: cache hit. Debe descifrar token y user_symmetric_key idénticos
        let unlock2 = registry
            .execute("Unlock", &mut state, &ctx, &serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(unlock2["status"], "unlocked");
        assert_eq!(unlock2["from_cache"], true);
        assert!(!state.is_locked);
        assert!(!va.is_locked());

        // Verificar que el token descifrado coincide exactamente
        let cached_cfg_key = state.pin_cache.get().unwrap();
        let decrypted_token = state.config.decrypt_token(&cached_cfg_key).unwrap();
        assert_eq!(decrypted_token.access_token, original_token.access_token);
        assert_eq!(decrypted_token.refresh_token, original_token.refresh_token);

        // Verificar que la user_symmetric_key descifrada coincide exactamente
        let dec_user_sym_b64 =
            sw_config::decrypt_string(&state.config.encrypted_user_symmetric_key, &cached_cfg_key)
                .unwrap();
        let dec_user_sym_bytes = base64::engine::general_purpose::STANDARD
            .decode(dec_user_sym_b64.trim())
            .unwrap();
        assert_eq!(dec_user_sym_bytes, original_user_sym_key);
    }

    #[tokio::test]
    async fn test_unlock_cache_hit_empty_encrypted_token() {
        let registry = default_registry();
        let (_state, temp_dir) = temp_state();
        let ctx = test_ctx();

        let device_uuid = "test-device-uuid-empty-tok";
        let pin = "correct_secret_pin";
        let config_key =
            sw_config::derive_config_key_with_params(pin, device_uuid, AGENT_KDF_MEMORY_KIB)
                .unwrap();
        let config_key_hash = sw_config::hash_config_key(&config_key);

        use base64::Engine;
        let original_user_sym_key = [77u8; 64];
        let user_sym_b64 = base64::engine::general_purpose::STANDARD.encode(original_user_sym_key);
        let enc_user_sym = sw_config::encrypt_string(&user_sym_b64, &config_key).unwrap();

        let (va, _) = test_agent(1);
        let cfg = ConfigFile {
            device_uuid: device_uuid.to_string(),
            config_key_hash,
            encrypted_token: String::new(),
            encrypted_user_symmetric_key: enc_user_sym,
            ..Default::default()
        };

        let mut state = AgentState::new(cfg).with_config_directory(temp_dir.path());
        state.vault_agent = Some(va.clone());

        // 1. Primer Unlock con PIN (cache miss): encrypted_token está vacío -> no crea api_client
        let unlock1 = registry
            .execute(
                "Unlock",
                &mut state,
                &ctx,
                &serde_json::json!({ "pin": pin }),
            )
            .await
            .unwrap();
        assert_eq!(unlock1["status"], "unlocked");
        assert_eq!(unlock1["from_cache"], false);
        assert!(!va.is_locked());
        assert!(state.api_client.is_none());

        // 2. Simular bloqueo
        state.is_locked = true;
        va.lock().await;
        assert!(va.is_locked());

        // 3. Segundo Unlock sin PIN (cache hit): encrypted_token sigue vacío -> api_client permanece None
        let unlock2 = registry
            .execute("Unlock", &mut state, &ctx, &serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(unlock2["status"], "unlocked");
        assert_eq!(unlock2["from_cache"], true);
        assert!(!state.is_locked);
        assert!(!va.is_locked());
        assert!(state.api_client.is_none());
    }

    #[tokio::test]
    async fn test_unlock_cache_hit_empty_encrypted_user_symmetric_key() {
        let registry = default_registry();
        let (_state, temp_dir) = temp_state();
        let ctx = test_ctx();

        let device_uuid = "test-device-uuid-empty-sym";
        let pin = "correct_secret_pin";
        let config_key =
            sw_config::derive_config_key_with_params(pin, device_uuid, AGENT_KDF_MEMORY_KIB)
                .unwrap();
        let config_key_hash = sw_config::hash_config_key(&config_key);

        let (va, _) = test_agent(1);
        let cfg = ConfigFile {
            device_uuid: device_uuid.to_string(),
            config_key_hash,
            encrypted_token: String::new(),
            encrypted_user_symmetric_key: String::new(),
            ..Default::default()
        };

        let mut state = AgentState::new(cfg).with_config_directory(temp_dir.path());
        state.vault_agent = Some(va.clone());

        // 1. Primer Unlock con PIN (cache miss): enc_sym vacío -> fallback a from_parts
        let unlock1 = registry
            .execute(
                "Unlock",
                &mut state,
                &ctx,
                &serde_json::json!({ "pin": pin }),
            )
            .await
            .unwrap();
        assert_eq!(unlock1["status"], "unlocked");
        assert_eq!(unlock1["from_cache"], false);
        assert!(!va.is_locked());

        // 2. Simular bloqueo
        state.is_locked = true;
        va.lock().await;
        assert!(va.is_locked());

        // 3. Segundo Unlock sin PIN (cache hit): enc_sym vacío -> fallback a from_parts
        let unlock2 = registry
            .execute("Unlock", &mut state, &ctx, &serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(unlock2["status"], "unlocked");
        assert_eq!(unlock2["from_cache"], true);
        assert!(!state.is_locked);
        assert!(!va.is_locked());
    }

    #[tokio::test]
    async fn test_unlock_cache_hit_decrypt_string_fails() {
        let registry = default_registry();
        let (_state, temp_dir) = temp_state();
        let ctx = test_ctx();

        let device_uuid = "test-device-uuid-corrupt-sym";
        let pin = "correct_secret_pin";
        let config_key =
            sw_config::derive_config_key_with_params(pin, device_uuid, AGENT_KDF_MEMORY_KIB)
                .unwrap();
        let config_key_hash = sw_config::hash_config_key(&config_key);

        // Generar un EncString válido y corromperlo cambiando el último carácter (MAC inválida)
        let valid_enc =
            sw_config::encrypt_string("dummy_user_symmetric_key_payload", &config_key).unwrap();
        let mut chars: Vec<char> = valid_enc.chars().collect();
        let last_idx = chars.len() - 1;
        chars[last_idx] = if chars[last_idx] == 'A' { 'B' } else { 'A' };
        let corrupted_enc: String = chars.into_iter().collect();

        let (va, _) = test_agent(1);
        let cfg = ConfigFile {
            device_uuid: device_uuid.to_string(),
            config_key_hash,
            encrypted_token: String::new(),
            encrypted_user_symmetric_key: corrupted_enc,
            ..Default::default()
        };

        let mut state = AgentState::new(cfg).with_config_directory(temp_dir.path());
        state.vault_agent = Some(va.clone());

        // 1. Primer Unlock con PIN (cache miss): decrypt_string falla -> fallback a from_parts
        let unlock1 = registry
            .execute(
                "Unlock",
                &mut state,
                &ctx,
                &serde_json::json!({ "pin": pin }),
            )
            .await
            .unwrap();
        assert_eq!(unlock1["status"], "unlocked");
        assert_eq!(unlock1["from_cache"], false);
        assert!(!va.is_locked());

        // 2. Simular bloqueo
        state.is_locked = true;
        va.lock().await;
        assert!(va.is_locked());

        // 3. Segundo Unlock sin PIN (cache hit): decrypt_string falla -> fallback a from_parts sin pánico
        let unlock2 = registry
            .execute("Unlock", &mut state, &ctx, &serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(unlock2["status"], "unlocked");
        assert_eq!(unlock2["from_cache"], true);
        assert!(!state.is_locked);
        assert!(!va.is_locked());
    }

    #[tokio::test]
    async fn test_unlock_cache_hit_base64_decode_fails() {
        let registry = default_registry();
        let (_state, temp_dir) = temp_state();
        let ctx = test_ctx();

        let device_uuid = "test-device-uuid-bad-b64";
        let pin = "correct_secret_pin";
        let config_key =
            sw_config::derive_config_key_with_params(pin, device_uuid, AGENT_KDF_MEMORY_KIB)
                .unwrap();
        let config_key_hash = sw_config::hash_config_key(&config_key);

        // 1. Cifrar un string que se descifra correctamente pero NO es base64 válido
        let not_base64 = "this string is definitely NOT valid base64!!! @@##";
        let enc_not_b64 = sw_config::encrypt_string(not_base64, &config_key).unwrap();

        let (va, _) = test_agent(1);
        let cfg = ConfigFile {
            device_uuid: device_uuid.to_string(),
            config_key_hash,
            encrypted_token: String::new(),
            encrypted_user_symmetric_key: enc_not_b64,
            ..Default::default()
        };

        let mut state = AgentState::new(cfg).with_config_directory(temp_dir.path());
        state.vault_agent = Some(va.clone());

        // Unlock con PIN (cache miss): base64 decode falla -> fallback a from_parts
        let unlock1 = registry
            .execute(
                "Unlock",
                &mut state,
                &ctx,
                &serde_json::json!({ "pin": pin }),
            )
            .await
            .unwrap();
        assert_eq!(unlock1["status"], "unlocked");
        assert_eq!(unlock1["from_cache"], false);
        assert!(!va.is_locked());

        // Simular bloqueo
        state.is_locked = true;
        va.lock().await;
        assert!(va.is_locked());

        // Unlock sin PIN (cache hit): base64 decode falla -> fallback a from_parts
        let unlock2 = registry
            .execute("Unlock", &mut state, &ctx, &serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(unlock2["status"], "unlocked");
        assert_eq!(unlock2["from_cache"], true);
        assert!(!state.is_locked);
        assert!(!va.is_locked());

        // 2. Probar rama adicional: base64 decode es válido pero longitud no es 64 bytes (falla from_bytes)
        use base64::Engine;
        let short_key_b64 = base64::engine::general_purpose::STANDARD.encode([42u8; 16]);
        let enc_short_key = sw_config::encrypt_string(&short_key_b64, &config_key).unwrap();
        state.config.encrypted_user_symmetric_key = enc_short_key;

        // Simular bloqueo
        state.is_locked = true;
        va.lock().await;
        assert!(va.is_locked());

        // Unlock sin PIN (cache hit): decode ok, from_bytes falla (16 != 64) -> fallback a from_parts
        let unlock3 = registry
            .execute("Unlock", &mut state, &ctx, &serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(unlock3["status"], "unlocked");
        assert_eq!(unlock3["from_cache"], true);
        assert!(!state.is_locked);
        assert!(!va.is_locked());
    }

    #[tokio::test]
    async fn test_unlock_cache_hit_no_vault_agent() {
        let registry = default_registry();
        let (_state, temp_dir) = temp_state();
        let ctx = test_ctx();

        let device_uuid = "test-device-uuid-no-va";
        let pin = "correct_secret_pin";
        let config_key =
            sw_config::derive_config_key_with_params(pin, device_uuid, AGENT_KDF_MEMORY_KIB)
                .unwrap();
        let config_key_hash = sw_config::hash_config_key(&config_key);

        let cfg = ConfigFile {
            device_uuid: device_uuid.to_string(),
            config_key_hash,
            encrypted_token: String::new(),
            encrypted_user_symmetric_key: String::new(),
            ..Default::default()
        };

        let mut state = AgentState::new(cfg).with_config_directory(temp_dir.path());
        state.vault_agent = None; // Sin vault_agent

        // 1. Unlock con PIN: cache miss sin vault_agent
        let unlock1 = registry
            .execute(
                "Unlock",
                &mut state,
                &ctx,
                &serde_json::json!({ "pin": pin }),
            )
            .await
            .unwrap();
        assert_eq!(unlock1["status"], "unlocked");
        assert_eq!(unlock1["from_cache"], false);
        assert!(!state.is_locked);
        assert!(state.vault_agent.is_none());

        // 2. Simular bloqueo
        state.is_locked = true;

        // 3. Unlock sin PIN: cache hit sin vault_agent
        let unlock2 = registry
            .execute("Unlock", &mut state, &ctx, &serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(unlock2["status"], "unlocked");
        assert_eq!(unlock2["from_cache"], true);
        assert!(!state.is_locked);
        assert!(state.vault_agent.is_none());
    }

    #[tokio::test]
    async fn test_lock_notifies_via_notifier() {
        let registry = default_registry();
        let (state, _temp_dir) = temp_state();
        let mock_notifier = Arc::new(sw_notify::MockNotifier::new());
        let mut state = state.with_notifier(mock_notifier.clone());
        let ctx = test_ctx();

        let lock_res = registry
            .execute("Lock", &mut state, &ctx, &serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(lock_res["status"], "locked");
        assert!(state.is_locked);

        let notifs = mock_notifier.notifications();
        assert_eq!(notifs.len(), 1);
        assert_eq!(
            notifs[0],
            ("SilverWarden".to_string(), "Bóveda bloqueada".to_string())
        );
    }

    #[tokio::test]
    async fn test_lock_succeeds_even_if_notifier_fails() {
        let registry = default_registry();
        let (state, _temp_dir) = temp_state();
        let mock_notifier = Arc::new(sw_notify::MockNotifier::failing());
        let mut state = state.with_notifier(mock_notifier.clone());
        let ctx = test_ctx();

        let lock_res = registry
            .execute("Lock", &mut state, &ctx, &serde_json::json!({}))
            .await
            .expect("Lock should succeed even if notifier fails (silent fallback)");
        assert_eq!(lock_res["status"], "locked");
        assert!(state.is_locked);
        assert!(mock_notifier.notifications().is_empty());
    }

    #[tokio::test]
    async fn test_last_activity_updates_on_ipc() {
        let (mut state, _temp_dir) = temp_state();
        state.is_locked = false;
        let daemon = AgentDaemon::with_state(state);
        let ctx = test_ctx();

        let past = tokio::time::Instant::now() - Duration::from_secs(60);
        *daemon.state.read().await.last_activity.write().await = past;

        let idle_before = daemon.state.read().await.idle_duration().await;
        assert!(idle_before >= Duration::from_secs(59));

        let msg = IpcMessage::new("Status", serde_json::json!({}));
        let _ = daemon.handle_message(&ctx, msg).await;

        let idle_after = daemon.state.read().await.idle_duration().await;
        assert!(idle_after < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn test_idle_monitor_locks_after_ttl() {
        let (mut state, _temp_dir) = temp_state();
        state.is_locked = false;
        let mock_notifier = Arc::new(sw_notify::MockNotifier::new());
        state.notifier = mock_notifier.clone();
        state.config.runtime_config.idle_ttl_secs = 10;
        let state_arc = Arc::new(RwLock::new(state));

        let past = tokio::time::Instant::now() - Duration::from_secs(20);
        *state_arc.read().await.last_activity.write().await = past;

        let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
        let monitor_handle = spawn_idle_monitor(
            state_arc.clone(),
            shutdown_tx.subscribe(),
            Duration::from_millis(10),
        );

        tokio::time::sleep(Duration::from_millis(40)).await;
        let _ = shutdown_tx.send(());
        let _ = monitor_handle.await;

        assert!(state_arc.read().await.is_locked);
        let notifs = mock_notifier.notifications();
        assert_eq!(notifs.len(), 1);
        assert_eq!(
            notifs[0],
            (
                "SilverWarden".to_string(),
                "Bóveda bloqueada por inactividad".to_string()
            )
        );
    }

    #[tokio::test]
    async fn test_idle_monitor_resets_on_activity() {
        let (mut state, _temp_dir) = temp_state();
        state.is_locked = false;
        let mock_notifier = Arc::new(sw_notify::MockNotifier::new());
        state.notifier = mock_notifier.clone();
        state.config.runtime_config.idle_ttl_secs = 100;
        let state_arc = Arc::new(RwLock::new(state));

        *state_arc.read().await.last_activity.write().await =
            tokio::time::Instant::now() - Duration::from_secs(50);

        state_arc.read().await.touch_activity().await;

        let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
        let monitor_handle = spawn_idle_monitor(
            state_arc.clone(),
            shutdown_tx.subscribe(),
            Duration::from_millis(10),
        );

        tokio::time::sleep(Duration::from_millis(30)).await;
        let _ = shutdown_tx.send(());
        let _ = monitor_handle.await;

        assert!(!state_arc.read().await.is_locked);
        assert!(mock_notifier.notifications().is_empty());
    }

    #[tokio::test]
    async fn test_logind_prepare_for_sleep_locks() {
        let (mut state, _temp_dir) = temp_state();
        state.is_locked = false;
        let mock_notifier = Arc::new(sw_notify::MockNotifier::new());
        state.notifier = mock_notifier.clone();
        let state_arc = Arc::new(RwLock::new(state));

        // PrepareForSleep(false) should not lock
        handle_logind_event(&state_arc, LogindEvent::PrepareForSleep(false)).await;
        assert!(!state_arc.read().await.is_locked);
        assert!(mock_notifier.notifications().is_empty());

        // PrepareForSleep(true) should lock
        handle_logind_event(&state_arc, LogindEvent::PrepareForSleep(true)).await;
        assert!(state_arc.read().await.is_locked);
        let notifs = mock_notifier.notifications();
        assert_eq!(notifs.len(), 1);
        assert_eq!(
            notifs[0],
            (
                "SilverWarden".to_string(),
                "Bóveda bloqueada por suspensión del sistema".to_string()
            )
        );
    }

    #[tokio::test]
    async fn test_logind_lock_signal_locks() {
        let (mut state, _temp_dir) = temp_state();
        state.is_locked = false;
        let mock_notifier = Arc::new(sw_notify::MockNotifier::new());
        state.notifier = mock_notifier.clone();
        let state_arc = Arc::new(RwLock::new(state));

        handle_logind_event(&state_arc, LogindEvent::Lock).await;
        assert!(state_arc.read().await.is_locked);
        let notifs = mock_notifier.notifications();
        assert_eq!(notifs.len(), 1);
        assert_eq!(
            notifs[0],
            (
                "SilverWarden".to_string(),
                "Bóveda bloqueada por bloqueo de pantalla".to_string()
            )
        );
    }

    #[tokio::test]
    async fn test_idle_monitor_does_not_lock_when_already_locked() {
        let (mut state, _temp_dir) = temp_state();
        state.is_locked = true;
        let mock_notifier = Arc::new(sw_notify::MockNotifier::new());
        state.notifier = mock_notifier.clone();
        state.config.runtime_config.idle_ttl_secs = 1;
        let state_arc = Arc::new(RwLock::new(state));

        *state_arc.read().await.last_activity.write().await =
            tokio::time::Instant::now() - Duration::from_secs(10);

        let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
        let monitor_handle = spawn_idle_monitor(
            state_arc.clone(),
            shutdown_tx.subscribe(),
            Duration::from_millis(10),
        );
        tokio::time::sleep(Duration::from_millis(30)).await;
        let _ = shutdown_tx.send(());
        let _ = monitor_handle.await;

        handle_logind_event(&state_arc, LogindEvent::Lock).await;
        handle_logind_event(&state_arc, LogindEvent::PrepareForSleep(true)).await;

        assert!(state_arc.read().await.is_locked);
        assert!(mock_notifier.notifications().is_empty());
    }

    #[tokio::test]
    async fn test_spawn_logind_monitor_shutdown() {
        let state = Arc::new(RwLock::new(AgentState::default()));
        let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
        let handle = spawn_logind_monitor(state, shutdown_tx.subscribe());
        let _ = shutdown_tx.send(());
        let res = tokio::time::timeout(Duration::from_secs(2), handle).await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_biometrics_trait_mock_ok() {
        use sw_systemauth::biometrics::{Biometrics, MockBiometrics};
        let mock = MockBiometrics::new(true);
        let ctx = test_ctx();
        let res = mock.authenticate("test", &ctx).await;
        assert!(res.unwrap());
        assert_eq!(mock.call_count(), 1);
    }

    #[tokio::test]
    async fn test_biometrics_trait_mock_fail() {
        use sw_systemauth::biometrics::{Biometrics, BiometricsError, MockBiometrics};
        let mock = MockBiometrics::failing();
        let ctx = test_ctx();
        let res = mock.authenticate("test", &ctx).await;
        assert!(matches!(res, Err(BiometricsError::Failed(_))));
        assert_eq!(mock.call_count(), 1);
    }

    #[tokio::test]
    async fn test_unlock_with_biometrics_success() {
        let registry = default_registry();
        let (state, _temp_dir) = temp_state();
        let mock_bio = Arc::new(sw_systemauth::biometrics::MockBiometrics::new(true));
        let mut state = state.with_biometrics(mock_bio.clone());
        state.config.runtime_config.biometrics_enabled = true;
        let ctx = test_ctx();
        let pin = "bio_pin_123";

        let _ = registry
            .execute(
                "PinSet",
                &mut state,
                &ctx,
                &serde_json::json!({ "pin": pin }),
            )
            .await
            .unwrap();

        let unlock1 = registry
            .execute(
                "Unlock",
                &mut state,
                &ctx,
                &serde_json::json!({ "pin": pin }),
            )
            .await
            .unwrap();
        assert_eq!(unlock1["status"], "unlocked");
        assert_eq!(mock_bio.call_count(), 0);

        state.is_locked = true;

        let unlock2 = registry
            .execute("Unlock", &mut state, &ctx, &serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(unlock2["status"], "unlocked");
        assert_eq!(unlock2["from_cache"], true);
        assert_eq!(unlock2["biometrics"], true);
        assert!(!state.is_locked);
        assert_eq!(mock_bio.call_count(), 1);
    }

    #[tokio::test]
    async fn test_unlock_with_biometrics_denied() {
        let registry = default_registry();
        let (state, _temp_dir) = temp_state();
        let mock_bio = Arc::new(sw_systemauth::biometrics::MockBiometrics::new(false));
        let mut state = state.with_biometrics(mock_bio.clone());
        state.config.runtime_config.biometrics_enabled = true;
        let ctx = test_ctx();
        let pin = "bio_pin_denied";

        let _ = registry
            .execute(
                "PinSet",
                &mut state,
                &ctx,
                &serde_json::json!({ "pin": pin }),
            )
            .await
            .unwrap();

        let _ = registry
            .execute(
                "Unlock",
                &mut state,
                &ctx,
                &serde_json::json!({ "pin": pin }),
            )
            .await
            .unwrap();

        state.is_locked = true;

        let err = registry
            .execute("Unlock", &mut state, &ctx, &serde_json::json!({}))
            .await
            .unwrap_err();
        assert_eq!(err, "Biometría cancelada o fallida");
        assert!(state.is_locked);
        assert_eq!(mock_bio.call_count(), 1);
    }

    #[tokio::test]
    async fn test_unlock_with_biometrics_disabled() {
        let registry = default_registry();
        let (state, _temp_dir) = temp_state();
        let mock_bio = Arc::new(sw_systemauth::biometrics::MockBiometrics::new(true));
        let mut state = state.with_biometrics(mock_bio.clone());
        state.config.runtime_config.biometrics_enabled = false;
        let ctx = test_ctx();
        let pin = "bio_pin_disabled";

        let _ = registry
            .execute(
                "PinSet",
                &mut state,
                &ctx,
                &serde_json::json!({ "pin": pin }),
            )
            .await
            .unwrap();

        let _ = registry
            .execute(
                "Unlock",
                &mut state,
                &ctx,
                &serde_json::json!({ "pin": pin }),
            )
            .await
            .unwrap();

        state.is_locked = true;

        let unlock2 = registry
            .execute("Unlock", &mut state, &ctx, &serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(unlock2["status"], "unlocked");
        assert_eq!(unlock2["from_cache"], true);
        assert_eq!(unlock2["biometrics"], false);
        assert!(!state.is_locked);
        assert_eq!(mock_bio.call_count(), 0);
    }

    #[tokio::test]
    async fn test_status_logged_in_false_when_locked() {
        let registry = default_registry();
        let (mut state, _temp_dir) = temp_state();
        let ctx = test_ctx();

        // Configurado como logueado
        state.config.encrypted_token = "some_encrypted_token".into();

        // 1. Desbloqueado: Status reporta logged_in: true
        state.is_locked = false;
        let st_unlocked = registry
            .execute("Status", &mut state, &ctx, &serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(st_unlocked["locked"], false);
        assert_eq!(st_unlocked["logged_in"], true);

        // 2. Ejecutar Lock
        let lock_res = registry
            .execute("Lock", &mut state, &ctx, &serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(lock_res["status"], "locked");
        assert!(state.is_locked);

        // 3. Bloqueado: Status reporta logged_in: false aunque config.encrypted_token exista
        let st_locked = registry
            .execute("Status", &mut state, &ctx, &serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(st_locked["locked"], true);
        assert_eq!(st_locked["logged_in"], false);
    }
}
