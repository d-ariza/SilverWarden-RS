use crate::handlers::sync::populate_keyring;
use crate::state::AgentState;
use crate::AgentError;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use sw_config::ConfigFile;
use sw_ipc::dto::{AgentStatus, ConfigView, OperationAck, PinChangeResult};
use sw_systemauth::{CallingContext, SessionType};

#[cfg(not(test))]
pub const AGENT_KDF_MEMORY_KIB: u32 = sw_config::KDF_MEMORY_KIB;
#[cfg(test)]
pub const AGENT_KDF_MEMORY_KIB: u32 = sw_config::KDF_MEMORY_KIB_TEST;

/// Typed parameters for `handle_set_session_params`.
#[derive(Default)]
pub struct SessionUpdate<'a> {
    pub token: Option<&'a serde_json::Value>,
    pub encrypted_token: Option<&'a str>,
    pub encrypted_user_symmetric_key: Option<&'a str>,
    pub user_symmetric_key: Option<&'a str>,
    pub identity_url: Option<&'a str>,
    pub api_url: Option<&'a str>,
    pub notifications_url: Option<&'a str>,
    pub danger_accept_invalid_certs: Option<bool>,
}

pub async fn handle_set_session_params(
    state: &mut AgentState,
    params: SessionUpdate<'_>,
) -> Result<OperationAck, AgentError> {
    if let Some(ident) = params.identity_url {
        state.services.config.identity_url = ident.to_string();
    }
    if let Some(api) = params.api_url {
        state.services.config.api_url = api.to_string();
    }
    if let Some(notif) = params.notifications_url {
        state.services.config.notifications_url = notif.to_string();
    }
    if let Some(insecure) = params.danger_accept_invalid_certs {
        state.services.config.danger_accept_invalid_certs = insecure;
    }

    if let Some(enc_tok) = params.encrypted_token {
        if !enc_tok.is_empty() {
            state.services.config.encrypted_token = enc_tok.to_string();
        }
    }
    if let Some(enc_sym) = params.encrypted_user_symmetric_key {
        if !enc_sym.is_empty() {
            state.services.config.encrypted_user_symmetric_key = enc_sym.to_string();
        }
    }

    if let Some(token_val) = params.token {
        if let Ok(token) = serde_json::from_value::<sw_config::LoginToken>(token_val.clone()) {
            let identity_url = state.services.config.identity_url.clone();
            let api_url = state.services.config.api_url.clone();
            let client = Arc::new(
                sw_bitwarden_api::AuthenticatedClient::from_token_with_options(
                    identity_url,
                    api_url,
                    token,
                    state.services.config.danger_accept_invalid_certs,
                ),
            );
            state.services.api_client = Some(client);
        }
    }

    if let Some(sym_key_b64) = params.user_symmetric_key {
        use base64::Engine;
        if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(sym_key_b64.trim()) {
            if let Ok(sym_key) = sw_crypto::SymmetricKey::from_bytes(&bytes) {
                state.services.vault_agent.unlock(sym_key).await;
            }
        }
    }

    if let Some(path) = state.config_path() {
        let _ = save_config_file(&state.services.config, &path);
    }

    Ok(OperationAck::status("session_saved"))
}

pub async fn handle_set_session(
    state: &mut AgentState,
    payload: &serde_json::Value,
) -> Result<serde_json::Value, AgentError> {
    let params = SessionUpdate {
        token: payload.get("token"),
        encrypted_token: payload.get("encrypted_token").and_then(|v| v.as_str()),
        encrypted_user_symmetric_key: payload
            .get("encrypted_user_symmetric_key")
            .and_then(|v| v.as_str()),
        user_symmetric_key: payload.get("user_symmetric_key").and_then(|v| v.as_str()),
        identity_url: payload.get("identity_url").and_then(|v| v.as_str()),
        api_url: payload.get("api_url").and_then(|v| v.as_str()),
        notifications_url: payload.get("notifications_url").and_then(|v| v.as_str()),
        danger_accept_invalid_certs: payload
            .get("danger_accept_invalid_certs")
            .and_then(|v| v.as_bool()),
    };
    let ack = handle_set_session_params(state, params).await?;
    serde_json::to_value(ack).map_err(|e| AgentError::ServerError(e.to_string()))
}

pub(crate) fn set_permissions_unix(path: &Path, mode: u32) -> Result<(), std::io::Error> {
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

pub async fn handle_status(
    state: &mut AgentState,
    _ctx: &CallingContext,
) -> Result<AgentStatus, AgentError> {
    let logged_in = !state.session.is_locked
        && (state.services.config.is_logged_in() || state.services.api_client.is_some());
    Ok(AgentStatus {
        locked: state.session.is_locked,
        has_pin: state.session.has_pin,
        logged_in,
        version: env!("CARGO_PKG_VERSION").to_string(),
        pin_cached: state.security.pin_cache.is_valid(),
        pin_cached_remaining_secs: state
            .security
            .pin_cache
            .remaining()
            .map(|d| d.as_secs())
            .unwrap_or(0),
    })
}

pub async fn handle_unlock_pin(
    state: &mut AgentState,
    ctx: &CallingContext,
    pin_opt: Option<&str>,
    encrypted_token: Option<&str>,
    encrypted_user_symmetric_key: Option<&str>,
) -> Result<OperationAck, AgentError> {
    if let Some(enc_tok) = encrypted_token {
        if !enc_tok.is_empty() {
            state.services.config.encrypted_token = enc_tok.to_string();
        }
    }
    if let Some(enc_sym) = encrypted_user_symmetric_key {
        if !enc_sym.is_empty() {
            state.services.config.encrypted_user_symmetric_key = enc_sym.to_string();
        }
    }

    // Sync from config file on disk if available
    if let Some(path) = state.config_path() {
        if path.exists() {
            if let Ok(content) = std::fs::read_to_string(&path) {
                if let Ok(disk_cfg) = serde_json::from_str::<ConfigFile>(&content) {
                    if !disk_cfg.config_key_hash.is_empty() {
                        state.services.config.config_key_hash = disk_cfg.config_key_hash;
                        state.session.has_pin = true;
                    }
                    if !disk_cfg.encrypted_token.is_empty() {
                        state.services.config.encrypted_token = disk_cfg.encrypted_token;
                    }
                    if !disk_cfg.encrypted_user_symmetric_key.is_empty() {
                        state.services.config.encrypted_user_symmetric_key =
                            disk_cfg.encrypted_user_symmetric_key;
                    }
                    state.services.config.identity_url = disk_cfg.identity_url;
                    state.services.config.api_url = disk_cfg.api_url;
                    state.services.config.notifications_url = disk_cfg.notifications_url;
                    state.services.config.danger_accept_invalid_certs =
                        disk_cfg.danger_accept_invalid_certs;
                }
            }
        }
    }

    if !state.session.has_pin {
        return Err(AgentError::Unauthorized(
            "No hay PIN configurado en el agente".to_string(),
        ));
    }

    // 1. Si no hay PIN en el payload: intentar cache hit (evita Argon2i)
    if pin_opt.is_none() {
        if let Some(config_key) = state.security.pin_cache.get() {
            let biometrics_enabled = state.services.config.runtime_config.biometrics_enabled;
            if biometrics_enabled {
                match state
                    .security
                    .biometrics
                    .authenticate("Desbloquear SilverWarden", ctx)
                    .await
                {
                    Ok(true) => {}
                    _ => {
                        return Err(AgentError::Unauthorized(
                            "Biometría cancelada o fallida".to_string(),
                        ))
                    }
                }
            }

            state.session.is_locked = false;
            state
                .session
                .sessions
                .create_session(ctx, SessionType::Pin, Duration::from_secs(3600));
            state.session.sessions.create_session(
                ctx,
                SessionType::AccessVault,
                Duration::from_secs(3600),
            );

            if state.services.api_client.is_none()
                && !state.services.config.encrypted_token.is_empty()
            {
                if let Ok(token) = state.services.config.decrypt_token(&config_key) {
                    state.services.api_client = Some(Arc::new(
                        sw_bitwarden_api::AuthenticatedClient::from_token_with_options(
                            state.services.config.identity_url.clone(),
                            state.services.config.api_url.clone(),
                            token,
                            state.services.config.danger_accept_invalid_certs,
                        ),
                    ));
                }
            }

            let agent = &state.services.vault_agent;
            let sym_key = if !state
                .services
                .config
                .encrypted_user_symmetric_key
                .is_empty()
            {
                if let Ok(dec) = sw_config::decrypt_string(
                    &state.services.config.encrypted_user_symmetric_key,
                    &config_key,
                ) {
                    use base64::Engine;
                    if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(dec.trim())
                    {
                        sw_crypto::SymmetricKey::from_bytes(&bytes).or_else(|_| {
                            sw_crypto::SymmetricKey::from_parts(&config_key, &config_key)
                        })
                    } else {
                        sw_crypto::SymmetricKey::from_parts(&config_key, &config_key)
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
            if agent.vault().is_empty().await {
                if let Some(vault_path) = state.vault_path() {
                    if vault_path.exists() {
                        if let Ok(sync_data) = sw_vault::load_vault(&vault_path) {
                            agent.vault().load_sync_data(sync_data).await;
                        }
                    }
                }
            }
            if let Some(sk) = agent.get_symmetric_key().await {
                populate_keyring(&state.security.keyring, agent.vault(), &sk).await;
            }

            return Ok(OperationAck::unlocked(true, Some(biometrics_enabled)));
        } else {
            return Err(AgentError::Validation(
                "Campo 'pin' requerido en payload (no hay caché válido)".to_string(),
            ));
        }
    }

    // 2. Si hay PIN en el payload: se valida el PIN con KDF y se actualiza el caché
    let pin = pin_opt.unwrap();

    let (verified, memory_kib) = match state
        .services
        .config
        .verify_pin_with_params(pin, AGENT_KDF_MEMORY_KIB)
    {
        Ok(true) => (true, AGENT_KDF_MEMORY_KIB),
        Ok(false) => {
            match state
                .services
                .config
                .verify_pin_with_params(pin, sw_config::KDF_MEMORY_KIB_TEST)
            {
                Ok(true) => (true, sw_config::KDF_MEMORY_KIB_TEST),
                Ok(false) => (false, AGENT_KDF_MEMORY_KIB),
                Err(e) => {
                    return Err(AgentError::ServerError(format!(
                        "Error al verificar PIN: {e}"
                    )))
                }
            }
        }
        Err(e) => {
            return Err(AgentError::ServerError(format!(
                "Error al verificar PIN: {e}"
            )))
        }
    };

    if !verified {
        return Err(AgentError::InvalidPin);
    }

    state.session.is_locked = false;
    state
        .session
        .sessions
        .create_session(ctx, SessionType::Pin, Duration::from_secs(3600));
    state
        .session
        .sessions
        .create_session(ctx, SessionType::AccessVault, Duration::from_secs(3600));

    let key_res = sw_config::derive_config_key_with_params(
        pin,
        &state.services.config.device_uuid,
        memory_kib,
    );

    if let Ok(key) = &key_res {
        state.security.pin_cache.store(key);

        if state.services.api_client.is_none() && !state.services.config.encrypted_token.is_empty()
        {
            if let Ok(token) = state.services.config.decrypt_token(key) {
                state.services.api_client = Some(Arc::new(
                    sw_bitwarden_api::AuthenticatedClient::from_token_with_options(
                        state.services.config.identity_url.clone(),
                        state.services.config.api_url.clone(),
                        token,
                        state.services.config.danger_accept_invalid_certs,
                    ),
                ));
            }
        }
    }

    let agent = &state.services.vault_agent;
    if let Ok(key) = key_res {
        let sym_key = if !state
            .services
            .config
            .encrypted_user_symmetric_key
            .is_empty()
        {
            if let Ok(dec) =
                sw_config::decrypt_string(&state.services.config.encrypted_user_symmetric_key, &key)
            {
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
    if agent.vault().is_empty().await {
        if let Some(vault_path) = state.vault_path() {
            if vault_path.exists() {
                if let Ok(sync_data) = sw_vault::load_vault(&vault_path) {
                    agent.vault().load_sync_data(sync_data).await;
                }
            }
        }
    }
    if let Some(sk) = agent.get_symmetric_key().await {
        populate_keyring(&state.security.keyring, agent.vault(), &sk).await;
    }

    Ok(OperationAck::unlocked(false, None))
}

pub async fn handle_unlock(
    state: &mut AgentState,
    ctx: &CallingContext,
    payload: &serde_json::Value,
) -> Result<serde_json::Value, AgentError> {
    let pin_opt = match payload {
        serde_json::Value::Object(map) => map.get("pin").and_then(|v| v.as_str()),
        serde_json::Value::String(s) => Some(s.as_str()),
        _ => None,
    };
    let enc_tok = payload.get("encrypted_token").and_then(|v| v.as_str());
    let enc_sym = payload
        .get("encrypted_user_symmetric_key")
        .and_then(|v| v.as_str());
    let ack = handle_unlock_pin(state, ctx, pin_opt, enc_tok, enc_sym).await?;
    serde_json::to_value(ack).map_err(|e| AgentError::ServerError(e.to_string()))
}

pub async fn handle_lock_typed(
    state: &mut AgentState,
    _ctx: &CallingContext,
) -> Result<OperationAck, AgentError> {
    state.security.pin_cache.clear();
    state.session.is_locked = true;
    state.session.sessions.wipe();
    let va = state.services.vault_agent.clone();
    let notifier = state.security.notifier.clone();
    let state_kr = state.security.keyring.clone();
    va.lock().await;
    state_kr.write().await.lock();
    let _ = notifier.notify("SilverWarden", "Bóveda bloqueada").await;
    Ok(OperationAck::status("locked"))
}

pub async fn handle_lock(
    state: &mut AgentState,
    ctx: &CallingContext,
) -> Result<serde_json::Value, AgentError> {
    let ack = handle_lock_typed(state, ctx).await?;
    serde_json::to_value(ack).map_err(|e| AgentError::ServerError(e.to_string()))
}

pub fn handle_pin_set_value(
    state: &mut AgentState,
    pin: &str,
) -> Result<PinChangeResult, AgentError> {
    if state.session.has_pin {
        return Err(AgentError::Validation(
            "El PIN ya está configurado. Usa PinUpdate para cambiarlo.".to_string(),
        ));
    }

    let key = sw_config::derive_config_key_with_params(
        pin,
        &state.services.config.device_uuid,
        AGENT_KDF_MEMORY_KIB,
    )
    .map_err(|e| AgentError::ServerError(format!("Error al derivar clave de PIN: {e}")))?;
    state.services.config.config_key_hash = sw_config::hash_config_key(&key);
    state.session.has_pin = true;
    state.security.pin_cache.store(&key);

    if let Some(path) = state.config_path() {
        let _ = save_config_file(&state.services.config, &path);
    }

    Ok(PinChangeResult {
        updated: true,
        status: "pin_set".to_string(),
    })
}

pub fn handle_pin_set(
    state: &mut AgentState,
    payload: &serde_json::Value,
) -> Result<PinChangeResult, AgentError> {
    let pin = match payload {
        serde_json::Value::Object(map) => {
            map.get("pin").and_then(|v| v.as_str()).ok_or_else(|| {
                AgentError::Validation("Campo 'pin' requerido en payload".to_string())
            })?
        }
        serde_json::Value::String(s) => s.as_str(),
        _ => {
            return Err(AgentError::Validation(
                "Payload inválido para PinSet: se esperaba objeto con 'pin'".to_string(),
            ))
        }
    };
    handle_pin_set_value(state, pin)
}

pub fn handle_pin_update_values(
    state: &mut AgentState,
    old_pin: &str,
    new_pin: &str,
) -> Result<PinChangeResult, AgentError> {
    if !state.session.has_pin {
        return Err(AgentError::Validation(
            "El PIN no está configurado. Usa PinSet.".to_string(),
        ));
    }

    state.security.pin_cache.clear();

    state
        .services
        .config
        .update_pin_with_params(old_pin, new_pin, AGENT_KDF_MEMORY_KIB)
        .map_err(|e| match e {
            sw_config::ConfigError::InvalidPin => AgentError::InvalidPin,
            other => AgentError::ServerError(format!("Error al actualizar PIN: {other}")),
        })?;

    if let Ok(new_key) = sw_config::derive_config_key_with_params(
        new_pin,
        &state.services.config.device_uuid,
        AGENT_KDF_MEMORY_KIB,
    ) {
        state.security.pin_cache.store(&new_key);
    }

    if let Some(path) = state.config_path() {
        let _ = save_config_file(&state.services.config, &path);
    }

    Ok(PinChangeResult {
        updated: true,
        status: "pin_updated".to_string(),
    })
}

pub fn handle_pin_update(
    state: &mut AgentState,
    payload: &serde_json::Value,
) -> Result<PinChangeResult, AgentError> {
    let (old_pin, new_pin) =
        match payload {
            serde_json::Value::Object(map) => {
                let old = map.get("old_pin").and_then(|v| v.as_str()).ok_or_else(|| {
                    AgentError::Validation("Campo 'old_pin' requerido".to_string())
                })?;
                let new = map.get("new_pin").and_then(|v| v.as_str()).ok_or_else(|| {
                    AgentError::Validation("Campo 'new_pin' requerido".to_string())
                })?;
                (old, new)
            }
            _ => {
                return Err(AgentError::Validation(
                    "Payload inválido para PinUpdate: se esperaba objeto con 'old_pin' y 'new_pin'"
                        .to_string(),
                ))
            }
        };
    handle_pin_update_values(state, old_pin, new_pin)
}

pub fn handle_agent_shutdown_typed(state: &mut AgentState) -> Result<OperationAck, AgentError> {
    if let Some(tx) = &state.services.shutdown_sender {
        let _ = tx.try_send(());
    }
    Ok(OperationAck::status("shutting_down"))
}

pub fn handle_agent_shutdown(state: &mut AgentState) -> Result<serde_json::Value, AgentError> {
    let ack = handle_agent_shutdown_typed(state)?;
    serde_json::to_value(ack).map_err(|e| AgentError::ServerError(e.to_string()))
}

pub fn handle_get_config(state: &AgentState) -> ConfigView {
    ConfigView {
        api_url: state.services.config.api_url.clone(),
        identity_url: state.services.config.identity_url.clone(),
        notifications_url: state.services.config.notifications_url.clone(),
        danger_accept_invalid_certs: state.services.config.danger_accept_invalid_certs,
    }
}

pub fn handle_set_config(
    state: &mut AgentState,
    view: &ConfigView,
) -> Result<ConfigView, AgentError> {
    let api_url = view.api_url.trim();
    let identity_url = view.identity_url.trim();
    let notifications_url = view.notifications_url.trim();
    if api_url.is_empty() || identity_url.is_empty() {
        return Err(AgentError::Validation(
            "api_url e identity_url no pueden estar vacíos".to_string(),
        ));
    }

    state.services.config.api_url = api_url.to_string();
    state.services.config.identity_url = identity_url.to_string();
    state.services.config.notifications_url = notifications_url.to_string();
    state.services.config.danger_accept_invalid_certs = view.danger_accept_invalid_certs;

    if let Some(path) = state.config_path() {
        save_config_file(&state.services.config, &path)?;
    }

    Ok(handle_get_config(state))
}
