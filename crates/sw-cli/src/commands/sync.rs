use crate::*;

pub async fn handle<P>(cli: &Cli, mut prompt_fn: P) -> Result<String, CliError>
where
    P: FnMut(&str) -> Result<String, CliError>,
{
    let socket_path = resolve_socket_path(cli.socket.clone())?;
    let config_path = resolve_config_path(cli.config.clone())?;
    let config = if config_path.exists() {
        sw_config::ConfigFile::load_from_file(&config_path)
            .map_err(|e| CliError::Config(e.to_string()))?
    } else {
        sw_config::ConfigFile::default()
    };

    if !config.is_logged_in() {
        return Err(CliError::Other(
            "No hay sesión iniciada. Ejecuta 'silverwarden login' primero.".to_string(),
        ));
    }

    let config_key = if config.config_key_hash.is_empty() {
        sw_config::derive_config_key_with_params("", &config.device_uuid, CLI_KDF_MEMORY_KIB)
            .or_else(|_| {
                sw_config::derive_config_key_with_params(
                    "",
                    &config.device_uuid,
                    sw_config::KDF_MEMORY_KIB_TEST,
                )
            })
            .map_err(|e| CliError::Config(e.to_string()))?
    } else {
        let pin = prompt_fn("Introduce tu PIN de SilverWarden para sincronizar: ")?;
        config
            .unlock_with_params(&pin, CLI_KDF_MEMORY_KIB)
            .or_else(|_| config.unlock_with_params(&pin, sw_config::KDF_MEMORY_KIB_TEST))
            .map_err(|e| CliError::Config(format!("PIN incorrecto: {e}")))?
    };

    let token = config
        .decrypt_token(&config_key)
        .map_err(|e| CliError::Config(e.to_string()))?;

    let active_identity_url = config.identity_url.clone();
    let active_api_url = config.api_url.clone();
    let mut active_insecure = config.danger_accept_invalid_certs;
    if cli.insecure {
        active_insecure = true;
    }

    let client = sw_bitwarden_api::AuthenticatedClient::from_token_with_options(
        &active_identity_url,
        &active_api_url,
        token,
        active_insecure,
    );

    let sync_data = client
                .sync()
                .await
                .map_err(|e| match e {
                    sw_bitwarden_api::ApiError::RateLimitExceeded => CliError::Other(
                        "El servidor ha bloqueado temporalmente tu IP por demasiados intentos de login. Espera unos minutos o cambia de red (por ejemplo, usa datos móviles).".to_string(),
                    ),
                    _ => CliError::Other(format!("Error al sincronizar con el servidor: {e}")),
                })?;

    let vault_path = if let Some(ref cfg_path) = cli.config {
        cfg_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join("vault.json")
    } else {
        sw_vault::VaultPaths::default_paths()
            .map_err(|e| CliError::Other(e.to_string()))?
            .vault_file()
    };
    let _ = sw_vault::save_vault(&vault_path, &sync_data);

    let non_deleted: Vec<_> = sync_data
        .ciphers
        .iter()
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
    let notes = non_deleted
        .iter()
        .filter(|c| c.r#type == sw_vault::CipherType::Note)
        .count();
    let cards = non_deleted
        .iter()
        .filter(|c| c.r#type == sw_vault::CipherType::Card)
        .count();
    let identities = non_deleted
        .iter()
        .filter(|c| c.r#type == sw_vault::CipherType::Identity)
        .count();

    if socket_path.exists() {
        if let Ok(payload) = serde_json::to_value(&sync_data) {
            let _ = AgentClient::new(&socket_path)
                .call(Request::SyncData(payload))
                .await;
        }
    }

    Ok(format_sync_summary(
        total, logins, ssh_keys, notes, cards, identities,
    ))
}
