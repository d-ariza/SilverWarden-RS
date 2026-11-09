use crate::state::AgentState;
use crate::AgentError;
use std::sync::Arc;

pub async fn populate_keyring(
    keyring: &tokio::sync::RwLock<sw_crypto::Keyring>,
    vault: &sw_vault::VaultStore,
    user_sym_key: &sw_crypto::SymmetricKey,
) {
    if let Some(profile) = vault.profile().await {
        let mut org_keys = std::collections::HashMap::new();
        for org in profile.organizations {
            if let (Some(id), Some(key)) = (org.id, org.key) {
                org_keys.insert(id.to_string(), key);
            }
        }
        let priv_key = profile.private_key.unwrap_or_default();
        let mut kr = keyring.write().await;
        let _ = sw_crypto::init_keyring_from_user_symmetric_key(
            &mut kr,
            user_sym_key.clone(),
            &priv_key,
            org_keys,
        );
    } else {
        let mut kr = keyring.write().await;
        kr.unlock_with_account_key(user_sym_key.clone());
    }
}

pub async fn handle_sync(
    state: &mut AgentState,
    payload: &serde_json::Value,
) -> Result<serde_json::Value, AgentError> {
    if state.session.is_locked {
        return Err(AgentError::Locked);
    }

    // 1. Sync config fields from payload if provided
    if let Some(map) = payload.as_object() {
        if let Some(enc_tok) = map.get("encrypted_token").and_then(|v| v.as_str()) {
            if !enc_tok.is_empty() {
                state.services.config.encrypted_token = enc_tok.to_string();
            }
        }
        if let Some(enc_sym) = map
            .get("encrypted_user_symmetric_key")
            .and_then(|v| v.as_str())
        {
            if !enc_sym.is_empty() {
                state.services.config.encrypted_user_symmetric_key = enc_sym.to_string();
            }
        }
        if let Some(id_url) = map.get("identity_url").and_then(|v| v.as_str()) {
            state.services.config.identity_url = id_url.to_string();
        }
        if let Some(api_url) = map.get("api_url").and_then(|v| v.as_str()) {
            state.services.config.api_url = api_url.to_string();
        }
        if let Some(insecure) = map
            .get("danger_accept_invalid_certs")
            .and_then(|v| v.as_bool())
        {
            state.services.config.danger_accept_invalid_certs = insecure;
        }
        if let Some(token_val) = map.get("token") {
            if let Ok(token) = serde_json::from_value::<sw_config::LoginToken>(token_val.clone()) {
                let client = Arc::new(
                    sw_bitwarden_api::AuthenticatedClient::from_token_with_options(
                        state.services.config.identity_url.clone(),
                        state.services.config.api_url.clone(),
                        token,
                        state.services.config.danger_accept_invalid_certs,
                    ),
                );
                state.services.api_client = Some(client);
            }
        }
    }

    // 2. If still not logged in according to state.services.config and api_client is missing, check disk config
    if !state.services.config.is_logged_in() && state.services.api_client.is_none() {
        if let Some(path) = state.config_path() {
            if path.exists() {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if let Ok(disk_cfg) = serde_json::from_str::<sw_config::ConfigFile>(&content) {
                        if disk_cfg.is_logged_in() {
                            state.services.config.encrypted_token = disk_cfg.encrypted_token;
                            state.services.config.encrypted_user_symmetric_key =
                                disk_cfg.encrypted_user_symmetric_key;
                            state.services.config.identity_url = disk_cfg.identity_url;
                            state.services.config.api_url = disk_cfg.api_url;
                            state.services.config.notifications_url = disk_cfg.notifications_url;
                            state.services.config.danger_accept_invalid_certs =
                                disk_cfg.danger_accept_invalid_certs;
                        }
                    }
                }
            }
        }
    }

    // Si aún no tenemos api_client pero tenemos token encriptado y caché de clave, descifrarlo
    if state.services.api_client.is_none() && !state.services.config.encrypted_token.is_empty() {
        if let Some(config_key) = state.security.pin_cache.get() {
            if let Ok(token) = state.services.config.decrypt_token(&config_key) {
                let client = Arc::new(
                    sw_bitwarden_api::AuthenticatedClient::from_token_with_options(
                        state.services.config.identity_url.clone(),
                        state.services.config.api_url.clone(),
                        token,
                        state.services.config.danger_accept_invalid_certs,
                    ),
                );
                state.services.api_client = Some(client);
            }
        }
    }

    if !state.services.config.is_logged_in() && state.services.api_client.is_none() {
        return Err(AgentError::Unauthorized(
            "No hay sesión iniciada. Ejecuta 'silverwarden login' primero.".to_string(),
        ));
    }

    let agent = state.services.vault_agent.clone();

    let client = state.services.api_client.as_ref().or_else(|| agent.api_client());
    if let Some(c) = client {
        match c.sync().await {
            Ok(sync_data) => {
                if let Some(vp) = state.vault_path() {
                    let _ = sw_vault::save_vault(&vp, &sync_data);
                }
                agent.vault().load_sync_data(sync_data).await;
            }
            Err(sw_bitwarden_api::ApiError::RateLimitExceeded) => {
                return Err(AgentError::ServerError("El servidor ha bloqueado temporalmente tu IP por demasiados intentos de login. Espera unos minutos o cambia de red (por ejemplo, usa datos móviles).".to_string()));
            }
            Err(e) => {
                return Err(AgentError::ServerError(format!(
                    "Error al sincronizar con el servidor: {e}"
                )))
            }
        }
    } else {
        // Fallback: recargar desde el vault.json guardado en disco
        let vp = state.vault_path().or_else(|| {
            sw_vault::VaultPaths::default_paths()
                .ok()
                .map(|p| p.vault_file())
        });
        if let Some(path) = vp {
            if path.exists() {
                if let Ok(sync_data) = sw_vault::load_vault(&path) {
                    agent.vault().load_sync_data(sync_data).await;
                }
            }
        }
    }

    if let Some(sym_key) = agent.get_symmetric_key().await {
        populate_keyring(&state.security.keyring, agent.vault(), &sym_key).await;
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

pub async fn handle_sync_data(
    state: &mut AgentState,
    payload: &serde_json::Value,
) -> Result<serde_json::Value, AgentError> {
    let sync_data: sw_vault::SyncData = serde_json::from_value(payload.clone())
        .map_err(|e| AgentError::Validation(format!("Error deserializando SyncData: {e}")))?;

    if let Some(vp) = state.vault_path() {
        let _ = sw_vault::save_vault(&vp, &sync_data);
    }

    let agent = state.services.vault_agent.clone();

    // Load sync data into the agent's VaultStore without modifying existing user_symmetric_key in memory
    agent.vault().load_sync_data(sync_data).await;

    if let Some(sym_key) = agent.get_symmetric_key().await {
        populate_keyring(&state.security.keyring, agent.vault(), &sym_key).await;
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
