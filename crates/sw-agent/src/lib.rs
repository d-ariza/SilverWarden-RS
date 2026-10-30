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
            vault_agent: None,
            config_directory: None,
            api_client: None,
        }
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

    let agent = state
        .vault_agent
        .as_ref()
        .ok_or_else(|| "Vault agent no configurado".to_string())?;

    let client = state.api_client.as_ref().or_else(|| agent.api_client());
    if let Some(c) = client {
        match c.sync().await {
            Ok(sync_data) => {
                agent.vault().load_sync_data(sync_data).await;
            }
            Err(sw_bitwarden_api::ApiError::RateLimitExceeded) => {
                return Err("El servidor ha bloqueado temporalmente tu IP por demasiados intentos de login. Espera unos minutos o cambia de red (por ejemplo, usa datos móviles).".to_string());
            }
            Err(e) => return Err(format!("Error al sincronizar con el servidor: {e}")),
        }
    }

    let logins = agent
        .vault()
        .all()
        .await
        .into_iter()
        .filter(|c| c.r#type == sw_vault::CipherType::Login && c.deleted_date.is_none())
        .count();

    Ok(serde_json::json!({
        "status": "synced",
        "logins": logins,
    }))
}

async fn handle_list_logins(state: &AgentState) -> Result<serde_json::Value, String> {
    if state.is_locked {
        return Err("Bóveda bloqueada. Desbloquea con 'silverwarden unlock' primero.".to_string());
    }
    let agent = state
        .vault_agent
        .as_ref()
        .ok_or_else(|| "Vault agent no configurado".to_string())?;
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

    let agent = state
        .vault_agent
        .as_ref()
        .ok_or_else(|| "Vault agent no configurado".to_string())?;
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

    let agent = state
        .vault_agent
        .as_ref()
        .ok_or_else(|| "Vault agent no configurado".to_string())?;
    let sym_key = agent
        .get_symmetric_key()
        .await
        .ok_or_else(|| "Bóveda bloqueada".to_string())?;

    let cipher_id = uuid::Uuid::new_v4();
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
        id: Some(cipher_id),
        r#type: sw_vault::CipherType::Login,
        name: enc_name,
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

    let agent = state
        .vault_agent
        .as_ref()
        .ok_or_else(|| "Vault agent no configurado".to_string())?;
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

    // Status: devuelve { locked, has_pin, logged_in, version }
    registry.register(
        "Status",
        |state: &mut AgentState, _ctx: &CallingContext, _payload: &serde_json::Value| {
            let logged_in = state.config.is_logged_in() || state.api_client.is_some();
            Ok(serde_json::json!({
                "locked": state.is_locked,
                "has_pin": state.has_pin,
                "logged_in": logged_in,
                "version": env!("CARGO_PKG_VERSION"),
            }))
        },
    );

    // Unlock: recibe { pin }, verifica contra sw-config, actualiza estado, crea sesión Pin
    registry.register_async(
        "Unlock",
        |state: &mut AgentState, ctx: &CallingContext, payload: &serde_json::Value| {
            #[rustfmt::skip]
            let pin = match payload {
                serde_json::Value::Object(map) => match map.get("pin").and_then(|v| v.as_str()) {
                    Some(p) => p.to_string(),
                    None => return Box::pin(async { Err("Campo 'pin' requerido en payload".to_string()) }),
                },
                serde_json::Value::String(s) => s.clone(),
                _ => return Box::pin(async { Err("Payload inválido para Unlock: se esperaba objeto con 'pin' o string".to_string()) }),
            };

            // Sync from payload if present
            if let Some(map) = payload.as_object() {
                if let Some(enc_tok) = map.get("encrypted_token").and_then(|v| v.as_str()) {
                    if !enc_tok.is_empty() {
                        state.config.encrypted_token = enc_tok.to_string();
                    }
                }
                if let Some(enc_sym) = map.get("encrypted_user_symmetric_key").and_then(|v| v.as_str()) {
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
                                state.config.encrypted_user_symmetric_key = disk_cfg.encrypted_user_symmetric_key;
                            }
                            state.config.identity_url = disk_cfg.identity_url;
                            state.config.api_url = disk_cfg.api_url;
                            state.config.notifications_url = disk_cfg.notifications_url;
                            state.config.danger_accept_invalid_certs = disk_cfg.danger_accept_invalid_certs;
                        }
                    }
                }
            }

            if !state.has_pin {
                return Box::pin(async { Err("No hay PIN configurado en el agente".to_string()) });
            }

            let (verified, memory_kib) =
                match state.config.verify_pin_with_params(&pin, AGENT_KDF_MEMORY_KIB) {
                    Ok(true) => (true, AGENT_KDF_MEMORY_KIB),
                    Ok(false) => {
                        match state
                            .config
                            .verify_pin_with_params(&pin, sw_config::KDF_MEMORY_KIB_TEST)
                        {
                            Ok(true) => (true, sw_config::KDF_MEMORY_KIB_TEST),
                            Ok(false) => (false, AGENT_KDF_MEMORY_KIB),
                            Err(e) => {
                                return Box::pin(async move {
                                    Err(format!("Error al verificar PIN: {e}"))
                                })
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
            state.sessions.create_session(ctx, SessionType::Pin, Duration::from_secs(3600));
            state.sessions.create_session(ctx, SessionType::AccessVault, Duration::from_secs(3600));
            let va = state.vault_agent.clone();
            let enc_sym = state.config.encrypted_user_symmetric_key.clone();
            let key_res = sw_config::derive_config_key_with_params(&pin, &state.config.device_uuid, memory_kib);

            if let Ok(key) = &key_res {
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
                                if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(dec.trim()) {
                                    sw_crypto::SymmetricKey::from_bytes(&bytes)
                                        .or_else(|_| sw_crypto::SymmetricKey::from_parts(&key, &key))
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
                Ok(serde_json::json!({ "status": "unlocked" }))
            })
        },
    );

    // Lock: borra la clave de memoria y wipea sesiones
    registry.register_async(
        "Lock",
        |state: &mut AgentState, _ctx: &CallingContext, _payload: &serde_json::Value| {
            state.is_locked = true;
            state.sessions.wipe();
            let va = state.vault_agent.clone();
            Box::pin(async move {
                if let Some(agent) = va {
                    agent.lock().await;
                }
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

            state
                .config
                .update_pin_with_params(old_pin, new_pin, AGENT_KDF_MEMORY_KIB)
                .map_err(|e| format!("Error al actualizar PIN: {e}"))?;

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
        state.config.encrypted_token = "some_encrypted_token".into();
        let st = registry
            .execute("Status", &mut state, &ctx, &serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(st["logged_in"], true);

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
}
