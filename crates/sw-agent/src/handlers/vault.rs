use crate::handlers::sync::populate_keyring;
use crate::state::AgentState;
use crate::AgentError;

pub async fn handle_list_logins(state: &AgentState) -> Result<serde_json::Value, AgentError> {
    if state.session.is_locked {
        return Err(AgentError::Locked);
    }
    let agent = state.services.vault_agent.clone();
    let sym_key = agent.get_symmetric_key().await.ok_or(AgentError::Locked)?;

    {
        let kr = state.security.keyring.read().await;
        if kr.is_locked() || kr.account_key().is_none() {
            drop(kr);
            populate_keyring(&state.security.keyring, agent.vault(), &sym_key).await;
        }
    }

    let kr = state.security.keyring.read().await;
    let all = agent.vault().all().await;
    let mut list = Vec::new();
    for c in all {
        if c.r#type == sw_vault::CipherType::Login && c.deleted_date.is_none() {
            let base_key = if let Some(ref org_id) = c.organization_id {
                kr.get_symmetric_key_for_organization(&org_id.to_string())
                    .ok()
            } else {
                None
            };
            let effective_base_key = base_key.as_ref().unwrap_or(&sym_key);

            let cipher_key_owned = if let Some(ref enc_k) = c.key {
                if !enc_k.is_null() {
                    match sw_crypto::decrypt_with(enc_k, effective_base_key) {
                        Ok(kb) => sw_crypto::SymmetricKey::from_bytes(&kb).ok(),
                        Err(_) => None,
                    }
                } else {
                    None
                }
            } else {
                None
            };
            let item_key = cipher_key_owned.as_ref().unwrap_or(effective_base_key);

            let name = if !c.name.is_null() {
                sw_crypto::decrypt_with(&c.name, item_key)
                    .ok()
                    .and_then(|b| String::from_utf8(b).ok())
                    .unwrap_or_else(|| "Error al descifrar".to_string())
            } else {
                "Sin nombre".to_string()
            };

            let username = c
                .login
                .as_ref()
                .and_then(|l| l.username.as_ref())
                .filter(|u| !u.is_null())
                .and_then(|u| {
                    sw_crypto::decrypt_with(u, item_key)
                        .ok()
                        .and_then(|b| String::from_utf8(b).ok())
                })
                .unwrap_or_default();

            list.push(serde_json::json!({
                "id": c.id,
                "name": name,
                "username": username,
            }));
        }
    }
    Ok(serde_json::json!(list))
}

pub async fn handle_get_login(
    state: &AgentState,
    payload: &serde_json::Value,
) -> Result<serde_json::Value, AgentError> {
    if state.session.is_locked {
        return Err(AgentError::Locked);
    }
    let target_name = payload
        .get("name")
        .and_then(|v| v.as_str())
        .or_else(|| payload.as_str())
        .ok_or_else(|| AgentError::Validation("Campo 'name' requerido".to_string()))?;

    let agent = state.services.vault_agent.clone();
    let sym_key = agent.get_symmetric_key().await.ok_or(AgentError::Locked)?;

    {
        let kr = state.security.keyring.read().await;
        if kr.is_locked() || kr.account_key().is_none() {
            drop(kr);
            populate_keyring(&state.security.keyring, agent.vault(), &sym_key).await;
        }
    }

    let kr = state.security.keyring.read().await;
    let all = agent.vault().all().await;
    for c in all {
        if c.r#type == sw_vault::CipherType::Login && c.deleted_date.is_none() {
            let base_key = if let Some(ref org_id) = c.organization_id {
                kr.get_symmetric_key_for_organization(&org_id.to_string())
                    .ok()
            } else {
                None
            };
            let effective_base_key = base_key.as_ref().unwrap_or(&sym_key);

            if let Ok(dec) = sw_vault::VaultStore::decrypt_cipher(&c, effective_base_key) {
                if dec.name.eq_ignore_ascii_case(target_name)
                    || c.id.map(|u| u.to_string()).as_deref() == Some(target_name)
                {
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
    Err(AgentError::NotFound(format!(
        "No se encontró ningún acceso con el nombre '{target_name}'"
    )))
}

pub async fn handle_create_login(
    state: &mut AgentState,
    payload: &serde_json::Value,
) -> Result<serde_json::Value, AgentError> {
    if state.session.is_locked {
        return Err(AgentError::Locked);
    }
    let obj = payload
        .as_object()
        .ok_or_else(|| AgentError::Validation("El payload debe ser un objeto JSON".to_string()))?;

    let name = obj
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AgentError::Validation("Campo 'name' requerido".to_string()))?;
    let username = obj
        .get("username")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AgentError::Validation("Campo 'username' requerido".to_string()))?;
    let password = obj
        .get("password")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AgentError::Validation("Campo 'password' requerido".to_string()))?;

    if name.trim().is_empty() {
        return Err(AgentError::Validation(
            "El campo 'name' no puede estar vacío".to_string(),
        ));
    }
    if username.trim().is_empty() {
        return Err(AgentError::Validation(
            "El campo 'username' no puede estar vacío".to_string(),
        ));
    }
    if password.trim().is_empty() {
        return Err(AgentError::Validation(
            "El campo 'password' no puede estar vacío".to_string(),
        ));
    }

    let agent = state.services.vault_agent.clone();

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
            return Err(AgentError::Validation(
                "No se ha sincronizado el perfil. Ejecuta 'silverwarden sync' primero.".to_string(),
            ));
        }
    };

    let sym_key = agent.get_symmetric_key().await.ok_or(AgentError::Locked)?;

    let enc_name = sw_vault::encrypt_with(
        name.as_bytes(),
        sw_vault::EncStringType::AesCbc256HmacSha256B64,
        &sym_key,
    )
    .map_err(|e| AgentError::ServerError(format!("Error al cifrar nombre: {e}")))?;
    let enc_user = sw_vault::encrypt_with(
        username.as_bytes(),
        sw_vault::EncStringType::AesCbc256HmacSha256B64,
        &sym_key,
    )
    .map_err(|e| AgentError::ServerError(format!("Error al cifrar usuario: {e}")))?;
    let enc_pass = sw_vault::encrypt_with(
        password.as_bytes(),
        sw_vault::EncStringType::AesCbc256HmacSha256B64,
        &sym_key,
    )
    .map_err(|e| AgentError::ServerError(format!("Error al cifrar contraseña: {e}")))?;

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

    let client = state
        .services
        .api_client
        .as_ref()
        .or_else(|| agent.api_client());
    let client = client.ok_or_else(|| {
        AgentError::Unauthorized("No hay sesión iniciada en el servidor. Inicia sesión con 'silverwarden login' primero.".to_string())
    })?;

    let created_cipher = client
        .post_cipher(&cipher)
        .await
        .map_err(|e| AgentError::ServerError(format!("Error del servidor al crear acceso: {e}")))?;

    let server_id = created_cipher.id.ok_or_else(|| {
        AgentError::ServerError("El servidor no devolvió un ID para el acceso creado".to_string())
    })?;

    agent.vault().insert(created_cipher).await;

    Ok(serde_json::json!({
        "status": "created",
        "id": server_id.to_string(),
        "name": name,
    }))
}

pub async fn handle_delete_login(
    state: &mut AgentState,
    payload: &serde_json::Value,
) -> Result<serde_json::Value, AgentError> {
    if state.session.is_locked {
        return Err(AgentError::Locked);
    }
    let target_name = payload
        .get("name")
        .and_then(|v| v.as_str())
        .or_else(|| payload.as_str())
        .ok_or_else(|| AgentError::Validation("Campo 'name' requerido".to_string()))?;

    let agent = state.services.vault_agent.clone();
    let sym_key = agent.get_symmetric_key().await.ok_or(AgentError::Locked)?;

    let all = agent.vault().all().await;
    let mut to_delete = None;
    let kr = state.security.keyring.read().await;
    for c in all {
        if c.r#type == sw_vault::CipherType::Login && c.deleted_date.is_none() {
            let base_key = if let Some(ref org_id) = c.organization_id {
                kr.get_symmetric_key_for_organization(&org_id.to_string())
                    .ok()
            } else {
                None
            };
            let effective_base_key = base_key.as_ref().unwrap_or(&sym_key);

            if let Ok(dec) = sw_vault::VaultStore::decrypt_cipher(&c, effective_base_key) {
                if dec.name.eq_ignore_ascii_case(target_name)
                    || c.id.map(|u| u.to_string()).as_deref() == Some(target_name)
                {
                    to_delete = Some((c.id, dec.name));
                    break;
                }
            }
        }
    }

    let (id_opt, found_name) = to_delete.ok_or_else(|| {
        AgentError::NotFound(format!(
            "No se encontró ningún acceso con el nombre '{target_name}'"
        ))
    })?;

    if let Some(id) = id_opt {
        let client = state
            .services
            .api_client
            .as_ref()
            .or_else(|| agent.api_client());
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
