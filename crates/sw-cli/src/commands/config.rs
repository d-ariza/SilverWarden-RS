use crate::*;

pub async fn handle<P>(
    cli: &Cli,
    action: &ConfigCommands,
    mut prompt_fn: P,
) -> Result<String, CliError>
where
    P: FnMut(&str) -> Result<String, CliError>,
{
    let config_path = resolve_config_path(cli.config.clone())?;
    let mut config = if config_path.exists() {
        sw_config::ConfigFile::load_from_file(&config_path)
            .map_err(|e| CliError::Config(e.to_string()))?
    } else {
        sw_config::ConfigFile::default()
    };

    match action {
        ConfigCommands::Get => {
            let status_login = if config.is_logged_in() { "Sí" } else { "No" };
            let status_insecure = if config.danger_accept_invalid_certs {
                "Sí"
            } else {
                "No"
            };
            Ok(format!(
                        "Configuración actual:\n  Identity URL:      {}\n  API URL:           {}\n  Notifications URL: {}\n  Aceptar certs inv: {}\n  Sesión iniciada:   {}",
                        config.identity_url,
                        config.api_url,
                        config.notifications_url,
                        status_insecure,
                        status_login
                    ))
        }
        ConfigCommands::Setup => {
            setup_config_flow(&mut prompt_fn, &mut config)?;
            config
                .save_to_file(&config_path)
                .map_err(|e| CliError::Io(e.to_string()))?;
            let status_insecure = if config.danger_accept_invalid_certs {
                "Sí"
            } else {
                "No"
            };
            Ok(format!(
                        "Configuración guardada exitosamente:\n  Identity URL:      {}\n  API URL:           {}\n  Notifications URL: {}\n  Aceptar certs inv: {}",
                        config.identity_url,
                        config.api_url,
                        config.notifications_url,
                        status_insecure
                    ))
        }
        ConfigCommands::SetServer { url } => {
            if url.trim().is_empty() {
                return Err(CliError::Other(
                    "La URL del servidor no puede estar vacía.".to_string(),
                ));
            }
            config.set_server(url);
            if cli.insecure {
                config.danger_accept_invalid_certs = true;
            }
            config
                .save_to_file(&config_path)
                .map_err(|e| CliError::Io(e.to_string()))?;
            Ok(format!(
                        "Servidor configurado a {url}.\n  Identity URL:      {}\n  API URL:           {}\n  Notifications URL: {}",
                        config.identity_url, config.api_url, config.notifications_url
                    ))
        }
        ConfigCommands::SetIdentity { url } => {
            if url.trim().is_empty() {
                return Err(CliError::Other(
                    "La URL de identity no puede estar vacía.".to_string(),
                ));
            }
            config.identity_url = url.clone();
            config
                .save_to_file(&config_path)
                .map_err(|e| CliError::Io(e.to_string()))?;
            Ok(format!("Identity URL actualizada a {url}."))
        }
        ConfigCommands::SetApi { url } => {
            if url.trim().is_empty() {
                return Err(CliError::Other(
                    "La URL de API no puede estar vacía.".to_string(),
                ));
            }
            config.api_url = url.clone();
            config
                .save_to_file(&config_path)
                .map_err(|e| CliError::Io(e.to_string()))?;
            Ok(format!("API URL actualizada a {url}."))
        }
        ConfigCommands::SetNotifications { url } => {
            if url.trim().is_empty() {
                return Err(CliError::Other(
                    "La URL de notifications no puede estar vacía.".to_string(),
                ));
            }
            config.notifications_url = url.clone();
            config
                .save_to_file(&config_path)
                .map_err(|e| CliError::Io(e.to_string()))?;
            Ok(format!("Notifications URL actualizada a {url}."))
        }
    }
}
