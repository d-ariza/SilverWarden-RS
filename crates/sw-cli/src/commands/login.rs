use crate::*;

#[allow(clippy::too_many_arguments)]
pub async fn handle<P>(
    cli: &Cli,
    email: &Option<String>,
    password: &Option<String>,
    server: &Option<String>,
    apikey: &bool,
    client_id: &Option<String>,
    client_secret: &Option<String>,
    mut prompt_fn: P,
) -> Result<String, CliError>
where
    P: FnMut(&str) -> Result<String, CliError>,
{
    let socket_path = resolve_socket_path(cli.socket.clone())?;
    let config_path = resolve_config_path(cli.config.clone())?;
    let mut config = if config_path.exists() {
        sw_config::ConfigFile::load_from_file(&config_path)
            .map_err(|e| CliError::Config(e.to_string()))?
    } else {
        sw_config::ConfigFile::default()
    };

    // Read saved configuration directly. CLI flags only override for this execution without mutating saved URLs.
    let mut active_identity_url = config.identity_url.clone();
    let mut active_api_url = config.api_url.clone();
    let mut active_insecure = config.danger_accept_invalid_certs;

    if let Some(srv) = server {
        if srv.trim().is_empty() {
            return Err(CliError::Other(
                "La URL del servidor no puede estar vacía.".to_string(),
            ));
        }
        let (derived_id, derived_api, _) = sw_config::derive_server_urls(srv);
        active_identity_url = derived_id;
        active_api_url = derived_api;
        if config.identity_url == sw_config::ConfigFile::default().identity_url
            || config.identity_url.is_empty()
        {
            config.identity_url = active_identity_url.clone();
            config.api_url = active_api_url.clone();
        }
    }

    if cli.insecure {
        active_insecure = true;
    }

    let client = sw_bitwarden_api::AuthenticatedClient::from_token_with_options(
        &active_identity_url,
        &active_api_url,
        Default::default(),
        active_insecure,
    );

    let (token, user_symmetric_key, display_user, resolved_client_id, resolved_client_secret) =
        if *apikey {
            let cid = match client_id {
                Some(c) => c.clone(),
                None => match std::env::var("BW_CLIENTID") {
                    Ok(val) if !val.trim().is_empty() => val,
                    _ => prompt_fn("Introduce tu client_id de Bitwarden: ")?,
                },
            };
            let csecret = match client_secret {
                Some(s) => s.clone(),
                None => match std::env::var("BW_CLIENTSECRET") {
                    Ok(val) if !val.trim().is_empty() => val,
                    _ => prompt_fn("Introduce tu client_secret de Bitwarden: ")?,
                },
            };
            let email_val = match email {
                Some(e) => e.clone(),
                None => match std::env::var("BW_EMAIL") {
                    Ok(val) if !val.trim().is_empty() => val,
                    _ => prompt_fn("Introduce tu email de Bitwarden: ")?,
                },
            };
            let password_val = match password {
                Some(p) => p.clone(),
                None => match std::env::var("BW_PASSWORD") {
                    Ok(val) if !val.trim().is_empty() => val,
                    _ => prompt_fn("Introduce tu contraseña maestra: ")?,
                },
            };

            let (token, sym_key) = client
                .login_api_key(
                    &cid,
                    &csecret,
                    &email_val,
                    &password_val,
                    &config.device_uuid,
                )
                .await
                .map_err(|e| CliError::Other(e.to_string()))?;

            (token, sym_key, email_val, Some(cid), Some(csecret))
        } else {
            let email_val = match email {
                Some(e) => e.clone(),
                None => match std::env::var("BW_EMAIL") {
                    Ok(val) if !val.trim().is_empty() => val,
                    _ => prompt_fn("Introduce tu email de Bitwarden: ")?,
                },
            };
            let password_val = match password {
                Some(p) => p.clone(),
                None => match std::env::var("BW_PASSWORD") {
                    Ok(val) if !val.trim().is_empty() => val,
                    _ => prompt_fn("Introduce tu contraseña maestra: ")?,
                },
            };

            let login_res = client
                .login(&email_val, &password_val, &config.device_uuid)
                .await;

            let (token, sym_key) = match login_res {
                Ok(pair) => pair,
                Err(sw_bitwarden_api::ApiError::TwoFactorRequired {
                    providers,
                    token: two_factor_token,
                }) => {
                    println!("El servidor requiere autenticación en dos pasos.");
                    println!("Métodos disponibles:");
                    let mut opt_strs = Vec::new();
                    if providers.is_empty() || providers.contains(&0) {
                        println!("  0) TOTP (App autenticadora)");
                        opt_strs.push("0");
                    }
                    if providers.contains(&1) {
                        println!("  1) Email (código enviado a tu correo)");
                        opt_strs.push("1");
                    }
                    if opt_strs.is_empty() {
                        println!("  0) TOTP (App autenticadora)");
                        opt_strs.push("0");
                    }

                    let prompt_msg = format!("Selecciona un método [{}]: ", opt_strs.join("/"));
                    let choice = prompt_fn(&prompt_msg)?.trim().to_string();
                    let selected_provider: i32 = match choice.as_str() {
                        "1" if opt_strs.contains(&"1") => 1,
                        "0" | "" => 0,
                        other => other.parse().unwrap_or(0),
                    };

                    if selected_provider == 1 {
                        println!("Enviando código de verificación a tu correo...");
                        if let Err(e) = client
                            .send_two_factor_email_login(&email_val, &config.device_uuid)
                            .await
                        {
                            eprintln!("Aviso al solicitar código por correo: {e}");
                        }
                    }

                    let code = prompt_fn("Introduce el código de verificación de 6 dígitos: ")?;
                    client
                        .complete_2fa(
                            &email_val,
                            &password_val,
                            &two_factor_token,
                            code.trim(),
                            selected_provider,
                            &config.device_uuid,
                        )
                        .await
                        .map_err(|e| CliError::Other(e.to_string()))?
                }
                Err(e) => return Err(CliError::Other(e.to_string())),
            };

            (token, sym_key, email_val, None, None)
        };

    let config_key = if config.config_key_hash.is_empty() {
        sw_config::derive_config_key_with_params("", &config.device_uuid, CLI_KDF_MEMORY_KIB)
            .map_err(|e| CliError::Config(e.to_string()))?
    } else {
        let pin = prompt_fn("Introduce tu PIN de SilverWarden para guardar la sesión: ")?;
        config
            .unlock_with_params(&pin, CLI_KDF_MEMORY_KIB)
            .map_err(|e| CliError::Config(format!("PIN incorrecto: {e}")))?
    };

    config
        .set_token(&token, &config_key)
        .map_err(|e| CliError::Config(e.to_string()))?;
    config
        .set_user_symmetric_key(&user_symmetric_key, &config_key)
        .map_err(|e| CliError::Config(e.to_string()))?;

    if let Some(cid) = resolved_client_id {
        config
            .set_client_id(&cid, &config_key)
            .map_err(|e| CliError::Config(e.to_string()))?;
    }
    if let Some(csecret) = resolved_client_secret {
        config
            .set_client_secret(&csecret, &config_key)
            .map_err(|e| CliError::Config(e.to_string()))?;
    }

    config
        .save_to_file(&config_path)
        .map_err(|e| CliError::Io(e.to_string()))?;

    if socket_path.exists() {
        use base64::Engine;
        let b64_sym_key = base64::engine::general_purpose::STANDARD.encode(&user_symmetric_key);
        let _ = AgentClient::new(&socket_path)
            .call(Request::SetSession {
                token: Some(serde_json::to_value(&token).unwrap_or_default()),
                encrypted_token: Some(config.encrypted_token.clone()),
                encrypted_user_symmetric_key: Some(config.encrypted_user_symmetric_key.clone()),
                user_symmetric_key: Some(b64_sym_key),
                identity_url: Some(active_identity_url),
                api_url: Some(active_api_url),
                notifications_url: Some(config.notifications_url.clone()),
                danger_accept_invalid_certs: Some(active_insecure),
            })
            .await;
    }

    Ok(format!("Sesión iniciada con éxito para {display_user}."))
}
