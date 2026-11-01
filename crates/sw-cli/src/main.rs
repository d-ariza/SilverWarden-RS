use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use sw_ipc::IpcMessage;

#[cfg(not(test))]
pub const CLI_KDF_MEMORY_KIB: u32 = sw_config::KDF_MEMORY_KIB;
#[cfg(test)]
pub const CLI_KDF_MEMORY_KIB: u32 = sw_config::KDF_MEMORY_KIB_TEST;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CliError {
    #[error(
        "El agente no está corriendo o el socket no existe. Ejecuta 'silverwarden agent start'."
    )]
    SocketNotFound(PathBuf),

    #[error(
        "El agente no está corriendo o el socket no existe. Ejecuta 'silverwarden agent start'."
    )]
    ConnectionFailed(PathBuf, String),

    #[error("Error al enviar mensaje al agente: {0}")]
    SendFailed(String),

    #[error("Error al recibir respuesta del agente: {0}")]
    ReceiveFailed(String),

    #[error("{0}")]
    AgentError(String),

    #[error("Error de E/S o terminal: {0}")]
    Io(String),

    #[error("Error de configuración: {0}")]
    Config(String),

    #[error("{0}")]
    Other(String),
}

#[derive(Parser, Debug, PartialEq, Eq)]
#[command(name = "silverwarden")]
#[command(author = "silverWarden-rs contributors")]
#[command(version = "0.1.0")]
#[command(
    about = "CLI client for silverWarden Bitwarden-compatible vault and SSH agent",
    long_about = None
)]
pub struct Cli {
    /// Custom path to the SilverWarden agent Unix socket
    #[arg(long, global = true)]
    pub socket: Option<PathBuf>,

    /// Custom path to the SilverWarden configuration file
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,

    /// Accept invalid/self-signed SSL/TLS certificates (insecure)
    #[arg(long, global = true, alias = "danger-accept-invalid-certs")]
    pub insecure: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug, PartialEq, Eq)]
pub enum Commands {
    /// Manage the background agent daemon
    Agent {
        #[command(subcommand)]
        action: AgentCommands,
    },
    /// Check daemon status and vault lock state
    Status,
    /// Unlock the vault with PIN
    Unlock {
        #[arg(short, long)]
        pin: Option<String>,
    },
    /// Lock the vault immediately and clear sessions
    Lock,
    /// Configure or update master PIN
    Pin {
        #[command(subcommand)]
        action: PinCommands,
    },
    /// Login to Bitwarden server
    Login {
        /// Bitwarden account email
        #[arg(short, long)]
        email: Option<String>,

        /// Master password (interactive prompt if not provided)
        #[arg(short, long)]
        password: Option<String>,

        /// Base server URL (e.g. http://localhost:8080)
        #[arg(long)]
        server: Option<String>,

        /// Login using API Key (client_id and client_secret)
        #[arg(long = "apikey", alias = "api-key")]
        apikey: bool,

        /// Bitwarden API Key Client ID
        #[arg(long = "client-id")]
        client_id: Option<String>,

        /// Bitwarden API Key Client Secret
        #[arg(long = "client-secret")]
        client_secret: Option<String>,
    },
    /// Force vault synchronization with server
    Sync,
    /// Query or list logins from vault
    Logins {
        #[command(subcommand)]
        action: Option<LoginsCommands>,

        #[arg(short, long)]
        filter: Option<String>,
    },
    /// Manage SSH keys and agent
    Ssh {
        #[command(subcommand)]
        ssh_command: SshCommands,
    },
    /// View or configure server URLs
    Config {
        #[command(subcommand)]
        action: ConfigCommands,
    },
    /// Migrate existing Goldwarden configuration and vault from Go installation
    Migrate {
        #[arg(long, default_value = "~/.config/goldwarden/goldwarden.json")]
        source: String,
    },
}

#[derive(Subcommand, Debug, PartialEq, Eq)]
pub enum ConfigCommands {
    /// Show current configuration URLs and login status
    Get,
    /// Interactively setup server connection and URLs
    Setup,
    /// Set base server URL (derives identity, api, and notifications URLs)
    SetServer { url: String },
    /// Set identity URL manually
    SetIdentity { url: String },
    /// Set API URL manually
    SetApi { url: String },
    /// Set notifications URL manually
    SetNotifications { url: String },
}

#[derive(Subcommand, Debug, PartialEq, Eq)]
pub enum LoginsCommands {
    /// List all logins in vault
    List,
    /// Get details for a specific login
    Get {
        /// Name of the login
        name: String,
    },
    /// Create a new login entry
    Create {
        /// Login entry name
        #[arg(short, long)]
        name: String,
        /// Login username
        #[arg(short, long)]
        username: String,
        /// Login password
        #[arg(short, long)]
        password: String,
    },
    /// Delete a login entry
    Delete {
        /// Name of the login to delete
        name: String,
    },
}

#[derive(Subcommand, Debug, PartialEq, Eq)]
pub enum AgentCommands {
    /// Start the agent daemon in the foreground
    Start {
        /// Do not start the SSH agent server
        #[arg(long)]
        no_ssh: bool,
    },
}

#[derive(Subcommand, Debug, PartialEq, Eq)]
pub enum PinCommands {
    /// Set a new initial PIN
    Set {
        #[arg(short, long)]
        pin: Option<String>,
    },
    /// Update existing PIN
    Update {
        #[arg(long)]
        old_pin: Option<String>,
        #[arg(long)]
        new_pin: Option<String>,
    },
}

#[derive(Subcommand, Debug, PartialEq, Eq)]
pub enum CommandsSsh {
    /// List keys in agent
    List,
    /// Add key to agent
    Add { key_id: String },
}

pub type SshCommands = CommandsSsh;

/// Sends a request message to the running agent daemon over the Unix socket.
pub async fn send_command(
    socket_path: &Path,
    action: &str,
    payload: serde_json::Value,
) -> Result<IpcMessage, CliError> {
    if !socket_path.exists() {
        return Err(CliError::SocketNotFound(socket_path.to_path_buf()));
    }

    let mut stream = tokio::net::UnixStream::connect(socket_path)
        .await
        .map_err(|e| CliError::ConnectionFailed(socket_path.to_path_buf(), e.to_string()))?;

    let message = IpcMessage::new(action, payload);
    sw_ipc::write_message(&mut stream, &message)
        .await
        .map_err(|e| CliError::SendFailed(e.to_string()))?;

    let response = sw_ipc::read_message(&mut stream)
        .await
        .map_err(|e| CliError::ReceiveFailed(e.to_string()))?;

    if response.action == "Error" {
        let err_msg = match &response.payload {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Object(obj) => obj
                .get("error")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| response.payload.to_string()),
            other => other.to_string(),
        };
        return Err(CliError::AgentError(err_msg));
    }

    Ok(response)
}

/// Resolves the socket path, prioritizing the custom CLI flag or user default.
pub fn resolve_socket_path(custom: Option<PathBuf>) -> Result<PathBuf, CliError> {
    match custom {
        Some(p) => Ok(p),
        None => sw_agent::default_socket_path().map_err(|e| CliError::Other(e.to_string())),
    }
}

/// Resolves the SSH agent socket path, respecting custom paths or default `~/.silverwarden-ssh-agent.sock`.
pub fn resolve_ssh_socket_path(main_socket: &Path) -> PathBuf {
    if let Some(parent) = main_socket.parent() {
        let is_home = std::env::var("HOME")
            .map(|h| PathBuf::from(h) == parent)
            .unwrap_or(false);
        if !is_home {
            return parent.join(".silverwarden-ssh-agent.sock");
        }
    }
    sw_ssh_agent::default_ssh_agent_socket_path()
        .unwrap_or_else(|_| PathBuf::from(".silverwarden-ssh-agent.sock"))
}

/// Emits a warning if a running Goldwarden Go instance socket is detected.
pub fn check_goldwarden_go_conflict() -> bool {
    if let Ok(home) = std::env::var("HOME") {
        let go_sock = PathBuf::from(home).join(".goldwarden.sock");
        if go_sock.exists() {
            eprintln!("ADVERTENCIA: Goldwarden Go está corriendo (~/.goldwarden.sock activo). Te recomendamos detenerlo para evitar conflictos de estado.");
            return true;
        }
    }
    false
}

/// Resolves the configuration file path, supporting custom flag or SILVERWARDEN_CONFIG_PATH override.
pub fn resolve_config_path(custom: Option<PathBuf>) -> Result<PathBuf, CliError> {
    if let Some(p) = custom {
        return Ok(p);
    }
    if let Ok(path) = std::env::var("SILVERWARDEN_CONFIG_PATH") {
        return Ok(PathBuf::from(path));
    }
    let home = std::env::var("HOME")
        .map_err(|e| CliError::Config(format!("No se pudo determinar $HOME: {e}")))?;
    Ok(sw_config::get_new_config_path(Path::new(&home)))
}

/// Helper to parse affirmative or negative user input for boolean prompts.
pub fn parse_yes_no(input: &str) -> bool {
    let lower = input.trim().to_lowercase();
    matches!(lower.as_str(), "s" | "si" | "sí" | "y" | "yes")
}

/// Helper to read prompts from an arbitrary `BufRead` stream (mockable for tests).
pub fn prompt_from_io<R: std::io::BufRead, W: std::io::Write>(
    reader: &mut R,
    writer: &mut W,
    msg: &str,
) -> Result<String, CliError> {
    write!(writer, "{}", msg).map_err(|e| CliError::Io(e.to_string()))?;
    writer.flush().map_err(|e| CliError::Io(e.to_string()))?;
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|e| CliError::Io(e.to_string()))?;
    Ok(line.trim_end_matches(&['\r', '\n'][..]).to_string())
}

/// Interactive guided configuration setup flow.
pub fn setup_config_flow<P>(
    mut prompt_fn: P,
    config: &mut sw_config::ConfigFile,
) -> Result<(), CliError>
where
    P: FnMut(&str) -> Result<String, CliError>,
{
    let menu = "¿A qué tipo de servidor deseas conectarte?\n  1) Bitwarden Oficial (Nube)\n  2) Vaultwarden / Autoalojado (Local o propio)\n  3) Configuración Manual (Avanzado)\nSelecciona una opción [1/2/3]: ";
    let choice = prompt_fn(menu)?;
    let choice_trimmed = choice.trim().trim_matches(|c: char| !c.is_numeric());

    match choice_trimmed {
        "1" => {
            let id_prompt = "Identity URL (por defecto: https://vault.bitwarden.com/identity): ";
            let id_input = prompt_fn(id_prompt)?;
            config.identity_url = if id_input.trim().is_empty() {
                "https://vault.bitwarden.com/identity".to_string()
            } else {
                id_input.trim().to_string()
            };

            let api_prompt = "API URL (por defecto: https://api.bitwarden.com): ";
            let api_input = prompt_fn(api_prompt)?;
            config.api_url = if api_input.trim().is_empty() {
                "https://api.bitwarden.com".to_string()
            } else {
                api_input.trim().to_string()
            };

            let notif_prompt =
                "Notifications URL (por defecto: https://notifications.bitwarden.com): ";
            let notif_input = prompt_fn(notif_prompt)?;
            config.notifications_url = if notif_input.trim().is_empty() {
                "https://notifications.bitwarden.com".to_string()
            } else {
                notif_input.trim().to_string()
            };

            config.danger_accept_invalid_certs = false;
        }
        "2" => {
            let base_prompt =
                "URL base de tu servidor (ej. https://localhost o https://mi-vaultwarden.com): ";
            let base_input = prompt_fn(base_prompt)?;
            let base = base_input.trim();
            if base.is_empty() {
                return Err(CliError::Other(
                    "La URL del servidor no puede estar vacía.".to_string(),
                ));
            }
            config.set_server(base);

            let cert_prompt = "¿Usas un certificado autofirmado (self-signed)? (s/N): ";
            let cert_ans = prompt_fn(cert_prompt)?;
            config.danger_accept_invalid_certs = parse_yes_no(&cert_ans);
        }
        "3" => {
            let id_prompt = "Identity URL: ";
            let id_input = prompt_fn(id_prompt)?;
            let id_trimmed = id_input.trim();
            if id_trimmed.is_empty() {
                return Err(CliError::Other(
                    "La Identity URL no puede estar vacía.".to_string(),
                ));
            }
            config.identity_url = id_trimmed.to_string();

            let api_prompt = "API URL: ";
            let api_input = prompt_fn(api_prompt)?;
            let api_trimmed = api_input.trim();
            if api_trimmed.is_empty() {
                return Err(CliError::Other(
                    "La API URL no puede estar vacía.".to_string(),
                ));
            }
            config.api_url = api_trimmed.to_string();

            let notif_prompt = "Notifications URL: ";
            let notif_input = prompt_fn(notif_prompt)?;
            let notif_trimmed = notif_input.trim();
            if notif_trimmed.is_empty() {
                return Err(CliError::Other(
                    "La Notifications URL no puede estar vacía.".to_string(),
                ));
            }
            config.notifications_url = notif_trimmed.to_string();

            let cert_prompt = "¿Usas un certificado autofirmado (self-signed)? (s/N): ";
            let cert_ans = prompt_fn(cert_prompt)?;
            config.danger_accept_invalid_certs = parse_yes_no(&cert_ans);
        }
        _ => {
            return Err(CliError::Other(
                "Opción inválida. Selecciona 1, 2 o 3.".to_string(),
            ));
        }
    }

    Ok(())
}

/// Formats the human-readable summary of synchronized items by type.
pub fn format_sync_summary(
    total: usize,
    logins: usize,
    ssh_keys: usize,
    notes: usize,
    cards: usize,
    identities: usize,
) -> String {
    if total == 0 {
        return "Sincronización completada: 0 elementos.".to_string();
    }

    let mut parts = Vec::new();
    if logins > 0 {
        parts.push(if logins == 1 {
            "1 login".to_string()
        } else {
            format!("{logins} logins")
        });
    }
    if ssh_keys > 0 {
        parts.push(if ssh_keys == 1 {
            "1 clave SSH".to_string()
        } else {
            format!("{ssh_keys} claves SSH")
        });
    }
    if notes > 0 {
        parts.push(if notes == 1 {
            "1 nota".to_string()
        } else {
            format!("{notes} notas")
        });
    }
    if cards > 0 {
        parts.push(if cards == 1 {
            "1 tarjeta".to_string()
        } else {
            format!("{cards} tarjetas")
        });
    }
    if identities > 0 {
        parts.push(if identities == 1 {
            "1 identidad".to_string()
        } else {
            format!("{identities} identidades")
        });
    }

    let elem_str = if total == 1 { "elemento" } else { "elementos" };
    if parts.is_empty() {
        format!("Sincronización completada: {total} {elem_str}.")
    } else {
        format!(
            "Sincronización completada: {total} {elem_str} ({}).",
            parts.join(", ")
        )
    }
}

/// Executes a CLI command, returning human-readable output or an error.
pub async fn handle_command<P>(cli: &Cli, mut prompt_fn: P) -> Result<String, CliError>
where
    P: FnMut(&str) -> Result<String, CliError>,
{
    let socket_path = resolve_socket_path(cli.socket.clone())?;

    match &cli.command {
        Commands::Agent { action } => match action {
            AgentCommands::Start { no_ssh } => {
                println!(
                    "Iniciando el agente SilverWarden en {}...",
                    socket_path.display()
                );
                let ssh_socket_path = resolve_ssh_socket_path(&socket_path);

                let agent_sock = socket_path.clone();
                let agent_handle =
                    tokio::spawn(async move { sw_agent::run_agent(&agent_sock).await });

                let ssh_handle = if !*no_ssh {
                    println!(
                        "Iniciando el servidor SSH agent en {}...",
                        ssh_socket_path.display()
                    );
                    let ssh_sock = ssh_socket_path.clone();
                    let ssh_server = sw_ssh_agent::SshAgentServer::for_shared_agent(&ssh_sock);
                    Some(tokio::spawn(async move { ssh_server.serve().await }))
                } else {
                    None
                };

                tokio::select! {
                    // llvm-cov: ignore -- Real SIGINT / ctrl_c signal cannot be simulated in unit test runner without terminating the runner
                    _ = tokio::signal::ctrl_c() => {
                        println!("Señal de parada recibida (Ctrl+C). Deteniendo servicios...");
                    }
                    res = agent_handle => {
                        if let Ok(Err(e)) = res {
                            eprintln!("Error en el daemon principal: {e}");
                        }
                    }
                    res = async {
                        if let Some(h) = ssh_handle {
                            h.await
                        } else {
                            std::future::pending().await
                        }
                    } => {
                        if let Ok(Err(e)) = res {
                            eprintln!("Error en el servidor SSH agent: {e}");
                        }
                    }
                }

                if socket_path.exists() {
                    let _ = std::fs::remove_file(&socket_path);
                }
                if !*no_ssh && ssh_socket_path.exists() {
                    let _ = std::fs::remove_file(&ssh_socket_path);
                }

                Ok(format!("Agente finalizado en {}", socket_path.display()))
            }
        },
        Commands::Status => {
            let resp = send_command(&socket_path, "Status", serde_json::json!({})).await?;
            let locked = resp
                .payload
                .get("locked")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            let has_pin = resp
                .payload
                .get("has_pin")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let logged_in = resp
                .payload
                .get("logged_in")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let version = resp
                .payload
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");

            Ok(format!(
                "Estado del Agente SilverWarden (v{version}):\n  Bloqueado:        {}\n  PIN configurado:  {}\n  Sesión iniciada:  {}",
                if locked { "Sí" } else { "No" },
                if has_pin { "Sí" } else { "No" },
                if logged_in { "Sí" } else { "No" }
            ))
        }
        Commands::Unlock { pin } => {
            let pin_val = match pin {
                Some(p) => p.clone(),
                None => prompt_fn("Introduce el PIN de desbloqueo: ")?,
            };
            let config_path = resolve_config_path(cli.config.clone())?;
            let config = if config_path.exists() {
                sw_config::ConfigFile::load_from_file(&config_path).ok()
            } else {
                None
            };
            let mut payload = serde_json::json!({ "pin": pin_val });
            if let Some(cfg) = config {
                if let Some(obj) = payload.as_object_mut() {
                    obj.insert(
                        "encrypted_token".into(),
                        serde_json::Value::String(cfg.encrypted_token),
                    );
                    obj.insert(
                        "encrypted_user_symmetric_key".into(),
                        serde_json::Value::String(cfg.encrypted_user_symmetric_key),
                    );
                }
            }
            send_command(&socket_path, "Unlock", payload).await?;
            Ok("Bóveda desbloqueada con éxito.".to_string())
        }
        Commands::Lock => {
            send_command(&socket_path, "Lock", serde_json::json!({})).await?;
            Ok("Bóveda bloqueada y sesiones en memoria eliminadas.".to_string())
        }
        Commands::Pin { action } => match action {
            PinCommands::Set { pin } => {
                let pin_val = match pin {
                    Some(p) => p.clone(),
                    None => prompt_fn("Introduce el nuevo PIN: ")?,
                };
                send_command(
                    &socket_path,
                    "PinSet",
                    serde_json::json!({ "pin": pin_val }),
                )
                .await?;
                Ok("PIN configurado exitosamente.".to_string())
            }
            PinCommands::Update { old_pin, new_pin } => {
                let old_val = match old_pin {
                    Some(p) => p.clone(),
                    None => prompt_fn("Introduce el PIN actual: ")?,
                };
                let new_val = match new_pin {
                    Some(p) => p.clone(),
                    None => prompt_fn("Introduce el nuevo PIN: ")?,
                };
                send_command(
                    &socket_path,
                    "PinUpdate",
                    serde_json::json!({ "old_pin": old_val, "new_pin": new_val }),
                )
                .await?;
                Ok("PIN actualizado exitosamente.".to_string())
            }
        },
        Commands::Login {
            email,
            password,
            server,
            apikey,
            client_id,
            client_secret,
        } => {
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

            let (
                token,
                user_symmetric_key,
                display_user,
                resolved_client_id,
                resolved_client_secret,
            ) = if *apikey {
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
                sw_config::derive_config_key_with_params(
                    "",
                    &config.device_uuid,
                    CLI_KDF_MEMORY_KIB,
                )
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
                let b64_sym_key =
                    base64::engine::general_purpose::STANDARD.encode(&user_symmetric_key);
                let _ = send_command(
                    &socket_path,
                    "SetSession",
                    serde_json::json!({
                        "token": token,
                        "encrypted_token": config.encrypted_token,
                        "encrypted_user_symmetric_key": config.encrypted_user_symmetric_key,
                        "user_symmetric_key": b64_sym_key,
                        "identity_url": active_identity_url,
                        "api_url": active_api_url,
                        "notifications_url": config.notifications_url,
                        "danger_accept_invalid_certs": active_insecure,
                    }),
                )
                .await;
            }

            Ok(format!("Sesión iniciada con éxito para {display_user}."))
        }
        Commands::Sync => {
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
                sw_config::derive_config_key_with_params(
                    "",
                    &config.device_uuid,
                    CLI_KDF_MEMORY_KIB,
                )
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
                    let _ = send_command(&socket_path, "SyncData", payload).await;
                }
            }

            Ok(format_sync_summary(
                total, logins, ssh_keys, notes, cards, identities,
            ))
        }
        Commands::Logins { action, filter } => match action {
            None | Some(LoginsCommands::List) => {
                let resp = send_command(&socket_path, "ListLogins", serde_json::json!({})).await?;
                let items = resp.payload.as_array().cloned().unwrap_or_default();
                let filter_str = filter.as_deref().unwrap_or("").to_lowercase();
                let filtered: Vec<_> = items
                    .into_iter()
                    .filter(|item| {
                        if filter_str.is_empty() {
                            return true;
                        }
                        let name = item.get("name").and_then(|v| v.as_str()).unwrap_or("");
                        let username = item.get("username").and_then(|v| v.as_str()).unwrap_or("");
                        name.to_lowercase().contains(&filter_str)
                            || username.to_lowercase().contains(&filter_str)
                    })
                    .collect();

                if filtered.is_empty() {
                    return Ok("No se encontraron accesos guardados.".to_string());
                }

                let mut out = format!("{:<30} | {}\n", "Nombre", "Usuario");
                out.push_str(&format!(
                    "{:-<30}-+------------------------------------\n",
                    ""
                ));
                for item in filtered {
                    let name = item.get("name").and_then(|v| v.as_str()).unwrap_or("");
                    let username = item.get("username").and_then(|v| v.as_str()).unwrap_or("");
                    out.push_str(&format!("{:<30} | {}\n", name, username));
                }
                Ok(out.trim_end().to_string())
            }
            Some(LoginsCommands::Get { name }) => {
                if name.trim().is_empty() {
                    return Err(CliError::Other(
                        "El nombre no puede estar vacío.".to_string(),
                    ));
                }
                let resp = send_command(
                    &socket_path,
                    "GetLogin",
                    serde_json::json!({ "name": name }),
                )
                .await?;
                let password = resp
                    .payload
                    .get("password")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let totp = resp
                    .payload
                    .get("totp")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                Ok(format!("Contraseña: {password}\nTOTP: {totp}"))
            }
            Some(LoginsCommands::Create {
                name,
                username,
                password,
            }) => {
                if name.trim().is_empty() {
                    return Err(CliError::Other(
                        "El nombre no puede estar vacío.".to_string(),
                    ));
                }
                let resp = send_command(
                    &socket_path,
                    "CreateLogin",
                    serde_json::json!({
                        "name": name,
                        "username": username,
                        "password": password
                    }),
                )
                .await?;

                if let Some(status) = resp.payload.get("status").and_then(|v| v.as_str()) {
                    if status == "error" {
                        let err_msg = resp
                            .payload
                            .get("error")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Error al crear el acceso");
                        return Err(CliError::AgentError(err_msg.to_string()));
                    }
                }

                Ok(format!("Acceso '{name}' creado exitosamente."))
            }
            Some(LoginsCommands::Delete { name }) => {
                if name.trim().is_empty() {
                    return Err(CliError::Other(
                        "El nombre no puede estar vacío.".to_string(),
                    ));
                }
                send_command(
                    &socket_path,
                    "DeleteLogin",
                    serde_json::json!({ "name": name }),
                )
                .await?;
                Ok(format!("Acceso '{name}' eliminado exitosamente."))
            }
        },
        Commands::Ssh { ssh_command } => match ssh_command {
            SshCommands::List => Ok("Listando claves SSH registradas...".to_string()),
            SshCommands::Add { key_id } => {
                if key_id.trim().is_empty() {
                    return Err(CliError::Other(
                        "El nombre de la clave SSH no puede estar vacío.".to_string(),
                    ));
                }
                Ok(format!("Registrando clave SSH {key_id}"))
            }
        },
        Commands::Config { action } => {
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
        Commands::Migrate { source: _ } => {
            sw_config::run_migration().map_err(|e| CliError::Config(e.to_string()))
        }
    }
}

// llvm-cov: ignore -- Binary entrypoint not invoked by the unit test runner
#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    check_goldwarden_go_conflict();

    let prompt = |msg: &str| -> Result<String, CliError> {
        let is_secret = msg.to_lowercase().contains("contraseña")
            || msg.to_lowercase().contains("password")
            || msg.to_lowercase().contains("pin");
        if is_secret {
            rpassword::prompt_password(msg).map_err(|e| CliError::Io(e.to_string()))
        } else {
            use std::io::{self, Write};
            print!("{msg}");
            io::stdout()
                .flush()
                .map_err(|e| CliError::Io(e.to_string()))?;
            let mut input = String::new();
            io::stdin()
                .read_line(&mut input)
                .map_err(|e| CliError::Io(e.to_string()))?;
            Ok(input.trim_end_matches(&['\r', '\n'][..]).to_string())
        }
    };

    match handle_command(&cli, prompt).await {
        Ok(msg) => {
            if !msg.is_empty() {
                println!("{msg}");
            }
        }
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UnixListener;

    #[test]
    fn test_cli_parse_migrate_default() {
        let cli = Cli::try_parse_from(["silverwarden", "migrate"]).expect("Should parse migrate");
        match cli.command {
            Commands::Migrate { source } => {
                assert_eq!(source, "~/.config/goldwarden/goldwarden.json");
            }
            _ => panic!("Expected Migrate command"),
        }
    }

    #[test]
    fn test_cli_parse_status() {
        let cli = Cli::try_parse_from(["silverwarden", "status"]).expect("Should parse status");
        assert_eq!(cli.command, Commands::Status);
    }

    #[test]
    fn test_cli_parse_agent_start() {
        let cli = Cli::try_parse_from(["silverwarden", "agent", "start"])
            .expect("Should parse agent start");
        assert_eq!(
            cli.command,
            Commands::Agent {
                action: AgentCommands::Start { no_ssh: false },
            }
        );
    }

    #[test]
    fn test_cli_parse_agent_start_no_ssh() {
        let cli = Cli::try_parse_from(["silverwarden", "agent", "start", "--no-ssh"])
            .expect("Should parse agent start --no-ssh");
        assert_eq!(
            cli.command,
            Commands::Agent {
                action: AgentCommands::Start { no_ssh: true },
            }
        );
    }

    #[test]
    fn test_cli_parse_unlock_with_pin() {
        let cli = Cli::try_parse_from(["silverwarden", "unlock", "--pin", "123456"])
            .expect("Should parse unlock with pin");
        assert_eq!(
            cli.command,
            Commands::Unlock {
                pin: Some("123456".to_string())
            }
        );
    }

    #[test]
    fn test_cli_parse_unlock_without_pin() {
        let cli = Cli::try_parse_from(["silverwarden", "unlock"])
            .expect("Should parse unlock without pin");
        assert_eq!(cli.command, Commands::Unlock { pin: None });
    }

    #[test]
    fn test_cli_parse_lock() {
        let cli = Cli::try_parse_from(["silverwarden", "lock"]).expect("Should parse lock");
        assert_eq!(cli.command, Commands::Lock);
    }

    #[test]
    fn test_cli_parse_pin_set() {
        let cli = Cli::try_parse_from(["silverwarden", "pin", "set", "--pin", "987654"])
            .expect("Should parse pin set");
        assert_eq!(
            cli.command,
            Commands::Pin {
                action: PinCommands::Set {
                    pin: Some("987654".to_string())
                }
            }
        );
    }

    #[test]
    fn test_cli_parse_pin_set_interactive() {
        let cli =
            Cli::try_parse_from(["silverwarden", "pin", "set"]).expect("Should parse pin set");
        assert_eq!(
            cli.command,
            Commands::Pin {
                action: PinCommands::Set { pin: None }
            }
        );
    }

    #[test]
    fn test_cli_parse_pin_update() {
        let cli = Cli::try_parse_from([
            "silverwarden",
            "pin",
            "update",
            "--old-pin",
            "123",
            "--new-pin",
            "456",
        ])
        .expect("Should parse pin update");
        assert_eq!(
            cli.command,
            Commands::Pin {
                action: PinCommands::Update {
                    old_pin: Some("123".to_string()),
                    new_pin: Some("456".to_string()),
                }
            }
        );
    }

    #[test]
    fn test_cli_custom_socket_flag() {
        let cli = Cli::try_parse_from(["silverwarden", "--socket", "/tmp/custom.sock", "status"])
            .expect("Should parse custom socket");
        assert_eq!(cli.socket, Some(PathBuf::from("/tmp/custom.sock")));
        assert_eq!(cli.command, Commands::Status);
    }

    #[test]
    fn test_cli_parse_login() {
        let cli = Cli::try_parse_from([
            "silverwarden",
            "login",
            "--email",
            "test@test.com",
            "--password",
            "mypass",
        ])
        .expect("Should parse login");
        assert_eq!(
            cli.command,
            Commands::Login {
                email: Some("test@test.com".to_string()),
                password: Some("mypass".to_string()),
                server: None,
                apikey: false,
                client_id: None,
                client_secret: None,
            }
        );
    }

    #[test]
    fn test_cli_parse_login_with_server() {
        let cli = Cli::try_parse_from([
            "silverwarden",
            "login",
            "--email",
            "user@vaultwarden.local",
            "--server",
            "http://localhost:8080",
        ])
        .expect("Should parse login with server");
        assert_eq!(
            cli.command,
            Commands::Login {
                email: Some("user@vaultwarden.local".to_string()),
                password: None,
                server: Some("http://localhost:8080".to_string()),
                apikey: false,
                client_id: None,
                client_secret: None,
            }
        );
    }

    #[test]
    fn test_cli_parse_login_with_apikey() {
        let cli = Cli::try_parse_from([
            "silverwarden",
            "login",
            "--apikey",
            "--client-id",
            "user.123",
            "--client-secret",
            "secret456",
        ])
        .expect("Should parse login with apikey");
        assert_eq!(
            cli.command,
            Commands::Login {
                email: None,
                password: None,
                server: None,
                apikey: true,
                client_id: Some("user.123".to_string()),
                client_secret: Some("secret456".to_string()),
            }
        );
    }

    #[test]
    fn test_cli_parse_config_subcommands() {
        let cli_get = Cli::try_parse_from(["silverwarden", "config", "get"])
            .expect("Should parse config get");
        assert_eq!(
            cli_get.command,
            Commands::Config {
                action: ConfigCommands::Get
            }
        );

        let cli_set_srv = Cli::try_parse_from([
            "silverwarden",
            "config",
            "set-server",
            "http://localhost:8080",
        ])
        .expect("Should parse config set-server");
        assert_eq!(
            cli_set_srv.command,
            Commands::Config {
                action: ConfigCommands::SetServer {
                    url: "http://localhost:8080".to_string()
                }
            }
        );

        let cli_set_id = Cli::try_parse_from([
            "silverwarden",
            "config",
            "set-identity",
            "https://id.bitwarden.com",
        ])
        .expect("Should parse config set-identity");
        assert_eq!(
            cli_set_id.command,
            Commands::Config {
                action: ConfigCommands::SetIdentity {
                    url: "https://id.bitwarden.com".to_string()
                }
            }
        );

        let cli_set_api = Cli::try_parse_from([
            "silverwarden",
            "config",
            "set-api",
            "https://api.bitwarden.com",
        ])
        .expect("Should parse config set-api");
        assert_eq!(
            cli_set_api.command,
            Commands::Config {
                action: ConfigCommands::SetApi {
                    url: "https://api.bitwarden.com".to_string()
                }
            }
        );

        let cli_set_notif = Cli::try_parse_from([
            "silverwarden",
            "config",
            "set-notifications",
            "https://notifications.bitwarden.com",
        ])
        .expect("Should parse config set-notifications");
        assert_eq!(
            cli_set_notif.command,
            Commands::Config {
                action: ConfigCommands::SetNotifications {
                    url: "https://notifications.bitwarden.com".to_string()
                }
            }
        );
    }

    #[test]
    fn test_cli_parse_logins_list() {
        let cli = Cli::try_parse_from(["silverwarden", "logins", "list"])
            .expect("Should parse logins list");
        assert_eq!(
            cli.command,
            Commands::Logins {
                action: Some(LoginsCommands::List),
                filter: None,
            }
        );
    }

    #[test]
    fn test_cli_parse_logins_get() {
        let cli = Cli::try_parse_from(["silverwarden", "logins", "get", "MyLogin"])
            .expect("Should parse logins get");
        assert_eq!(
            cli.command,
            Commands::Logins {
                action: Some(LoginsCommands::Get {
                    name: "MyLogin".to_string()
                }),
                filter: None,
            }
        );
    }

    #[test]
    fn test_cli_parse_logins_create() {
        let cli = Cli::try_parse_from([
            "silverwarden",
            "logins",
            "create",
            "--name",
            "MyLogin",
            "--username",
            "myuser",
            "--password",
            "mypassword",
        ])
        .expect("Should parse logins create");
        assert_eq!(
            cli.command,
            Commands::Logins {
                action: Some(LoginsCommands::Create {
                    name: "MyLogin".to_string(),
                    username: "myuser".to_string(),
                    password: "mypassword".to_string(),
                }),
                filter: None,
            }
        );
    }

    #[test]
    fn test_cli_parse_logins_delete() {
        let cli = Cli::try_parse_from(["silverwarden", "logins", "delete", "MyLogin"])
            .expect("Should parse logins delete");
        assert_eq!(
            cli.command,
            Commands::Logins {
                action: Some(LoginsCommands::Delete {
                    name: "MyLogin".to_string()
                }),
                filter: None,
            }
        );
    }

    #[tokio::test]
    async fn test_send_command_socket_not_found() {
        let non_existent = PathBuf::from("/tmp/non_existent_silverwarden_socket_12345.sock");
        let res = send_command(&non_existent, "Status", serde_json::json!({})).await;
        assert_eq!(res, Err(CliError::SocketNotFound(non_existent)));
    }

    #[tokio::test]
    async fn test_send_command_receive_failed() {
        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("server_drops.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();

        // Server accepts connection and immediately drops stream without replying
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                drop(stream);
            }
        });

        let res = send_command(&socket_path, "Status", serde_json::json!({})).await;
        assert!(matches!(res, Err(CliError::ReceiveFailed(_))));
    }

    #[tokio::test]
    async fn test_send_command_agent_error() {
        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("error_server.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();

        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let _req = sw_ipc::read_message(&mut stream).await.unwrap();
                let err_resp =
                    IpcMessage::new("Error", serde_json::Value::String("PIN incorrecto".into()));
                sw_ipc::write_message(&mut stream, &err_resp).await.unwrap();
            }
        });

        let res = send_command(
            &socket_path,
            "Unlock",
            serde_json::json!({ "pin": "bad_pin" }),
        )
        .await;
        assert_eq!(res, Err(CliError::AgentError("PIN incorrecto".into())));
    }

    #[tokio::test]
    async fn test_send_command_success() {
        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("success_server.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();

        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let req = sw_ipc::read_message(&mut stream).await.unwrap();
                assert_eq!(req.action, "Status");
                let ok_resp = IpcMessage::new(
                    "Ok",
                    serde_json::json!({
                        "locked": false,
                        "has_pin": true,
                        "logged_in": true,
                        "version": "0.1.0"
                    }),
                );
                sw_ipc::write_message(&mut stream, &ok_resp).await.unwrap();
            }
        });

        let res = send_command(&socket_path, "Status", serde_json::json!({})).await;
        assert!(res.is_ok());
        let msg = res.unwrap();
        assert_eq!(msg.action, "Ok");
        assert_eq!(msg.payload["locked"], false);
    }

    fn test_cli(socket: Option<PathBuf>, command: Commands) -> Cli {
        Cli {
            socket,
            config: None,
            insecure: false,
            command,
        }
    }

    #[tokio::test]
    async fn test_handle_command_status_and_status_locked() {
        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("status.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();

        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let _ = sw_ipc::read_message(&mut stream).await.unwrap();
                let ok_resp = IpcMessage::new(
                    "Ok",
                    serde_json::json!({
                        "locked": true,
                        "has_pin": false,
                        "logged_in": false,
                        "version": "0.1.0"
                    }),
                );
                sw_ipc::write_message(&mut stream, &ok_resp).await.unwrap();
            }
        });

        let cli = test_cli(Some(socket_path), Commands::Status);

        let output = handle_command(&cli, |_| Ok("unused".into())).await.unwrap();
        assert!(output.contains("Bloqueado:        Sí"));
        assert!(output.contains("PIN configurado:  No"));
        assert!(output.contains("Sesión iniciada:  No"));
    }

    #[tokio::test]
    async fn test_handle_command_unlock_with_pin_and_interactive() {
        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("unlock.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();

        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let req = sw_ipc::read_message(&mut stream).await.unwrap();
                assert_eq!(req.action, "Unlock");
                let resp = IpcMessage::new("Ok", serde_json::json!({ "status": "unlocked" }));
                sw_ipc::write_message(&mut stream, &resp).await.unwrap();
            }
        });

        // 1. With --pin flag
        let cli_flag = test_cli(
            Some(socket_path.clone()),
            Commands::Unlock {
                pin: Some("secret123".into()),
            },
        );
        let out_flag = handle_command(&cli_flag, |_| unreachable!()).await.unwrap();
        assert!(out_flag.contains("Bóveda desbloqueada con éxito."));

        // 2. Interactive prompt
        let cli_prompt = test_cli(Some(socket_path), Commands::Unlock { pin: None });
        let out_prompt = handle_command(&cli_prompt, |msg| {
            assert!(msg.contains("PIN"));
            Ok("prompted_secret".into())
        })
        .await
        .unwrap();
        assert!(out_prompt.contains("Bóveda desbloqueada con éxito."));
    }

    #[tokio::test]
    async fn test_handle_command_lock() {
        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("lock.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();

        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let req = sw_ipc::read_message(&mut stream).await.unwrap();
                assert_eq!(req.action, "Lock");
                let resp = IpcMessage::new("Ok", serde_json::json!({ "status": "locked" }));
                sw_ipc::write_message(&mut stream, &resp).await.unwrap();
            }
        });

        let cli = test_cli(Some(socket_path), Commands::Lock);
        let output = handle_command(&cli, |_| unreachable!()).await.unwrap();
        assert!(output.contains("Bóveda bloqueada"));
    }

    #[tokio::test]
    async fn test_handle_command_pin_set_and_update() {
        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("pin.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();

        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let req = sw_ipc::read_message(&mut stream).await.unwrap();
                match req.action.as_str() {
                    "PinSet" => {
                        let resp =
                            IpcMessage::new("Ok", serde_json::json!({ "status": "pin_set" }));
                        sw_ipc::write_message(&mut stream, &resp).await.unwrap();
                    }
                    "PinUpdate" => {
                        let resp =
                            IpcMessage::new("Ok", serde_json::json!({ "status": "pin_updated" }));
                        sw_ipc::write_message(&mut stream, &resp).await.unwrap();
                    }
                    _ => panic!("Unexpected action {}", req.action),
                }
            }
        });

        // PinSet flag
        let cli_set = test_cli(
            Some(socket_path.clone()),
            Commands::Pin {
                action: PinCommands::Set {
                    pin: Some("pin_123".into()),
                },
            },
        );
        let out_set = handle_command(&cli_set, |_| unreachable!()).await.unwrap();
        assert!(out_set.contains("PIN configurado exitosamente."));

        // PinSet interactive
        let cli_set_interactive = test_cli(
            Some(socket_path.clone()),
            Commands::Pin {
                action: PinCommands::Set { pin: None },
            },
        );
        let out_set_interactive = handle_command(&cli_set_interactive, |_| Ok("pin_inter".into()))
            .await
            .unwrap();
        assert!(out_set_interactive.contains("PIN configurado exitosamente."));

        // PinUpdate flags
        let cli_update = test_cli(
            Some(socket_path.clone()),
            Commands::Pin {
                action: PinCommands::Update {
                    old_pin: Some("old".into()),
                    new_pin: Some("new".into()),
                },
            },
        );
        let out_update = handle_command(&cli_update, |_| unreachable!())
            .await
            .unwrap();
        assert!(out_update.contains("PIN actualizado exitosamente."));

        // PinUpdate interactive
        let mut prompts = vec!["new_inter", "old_inter"];
        let cli_update_interactive = test_cli(
            Some(socket_path),
            Commands::Pin {
                action: PinCommands::Update {
                    old_pin: None,
                    new_pin: None,
                },
            },
        );
        let out_update_interactive = handle_command(&cli_update_interactive, |_| {
            Ok(prompts.pop().unwrap().to_string())
        })
        .await
        .unwrap();
        assert!(out_update_interactive.contains("PIN actualizado exitosamente."));
    }

    #[tokio::test]
    async fn test_handle_command_local_subcommands() {
        let dummy_socket = PathBuf::from("/tmp/dummy.sock");

        // SSH List
        let cli_ssh_list = test_cli(
            Some(dummy_socket.clone()),
            Commands::Ssh {
                ssh_command: SshCommands::List,
            },
        );
        assert!(handle_command(&cli_ssh_list, |_| unreachable!())
            .await
            .unwrap()
            .contains("Listando claves SSH"));

        // SSH Add
        let cli_ssh_add = test_cli(
            Some(dummy_socket),
            Commands::Ssh {
                ssh_command: SshCommands::Add {
                    key_id: "id_ed25519".into(),
                },
            },
        );
        assert!(handle_command(&cli_ssh_add, |_| unreachable!())
            .await
            .unwrap()
            .contains("Registrando clave SSH id_ed25519"));
    }

    #[tokio::test]
    async fn test_cli_login_success() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let base_url = mock_server.uri();

        let email = "test@example.com";
        let password = "super_master_password";

        // Prelogin endpoint returns KdfInformation
        Mock::given(method("POST"))
            .and(path("/accounts/prelogin"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "kdf": 0,
                "kdfIterations": 10
            })))
            .mount(&mock_server)
            .await;

        // Derive expected encKey
        let kdf_config = sw_crypto::KdfConfig {
            kdf_type: sw_crypto::KdfType::Pbkdf2,
            iterations: 10,
            memory: None,
            parallelism: None,
        };
        let master_key =
            sw_crypto::derive_master_key(password.as_bytes(), email, &kdf_config).unwrap();
        let stretched = sw_crypto::stretch_key(&master_key).unwrap();
        let synthetic_sym_key = [7u8; 64];
        let enc_key_wire = sw_crypto::encrypt_with_to_string(
            &synthetic_sym_key,
            sw_crypto::EncStringType::AesCbc256HmacSha256B64,
            &stretched,
        )
        .unwrap();

        // Token endpoint
        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "mock_token_abc123",
                "expires_in": 3600,
                "token_type": "Bearer",
                "refresh_token": "mock_refresh_token_xyz",
                "key": enc_key_wire
            })))
            .mount(&mock_server)
            .await;

        let temp_dir = tempfile::tempdir().unwrap();
        let config_file_path = temp_dir.path().join("silverwarden.json");
        std::env::set_var("SILVERWARDEN_CONFIG_PATH", &config_file_path);

        // Pre-create initial config pointing to mock server
        let initial_cfg = sw_config::ConfigFile {
            identity_url: base_url.clone(),
            api_url: base_url.clone(),
            ..Default::default()
        };
        initial_cfg.save_to_file(&config_file_path).unwrap();

        let cli = Cli {
            socket: Some(temp_dir.path().join("dummy.sock")),
            config: Some(config_file_path.clone()),
            insecure: false,
            command: Commands::Login {
                email: Some(email.to_string()),
                password: Some(password.to_string()),
                server: None,
                apikey: false,
                client_id: None,
                client_secret: None,
            },
        };

        let result = handle_command(&cli, |_| unreachable!()).await;
        assert!(
            result.is_ok(),
            "Login command should succeed: {:?}",
            result.err()
        );
        let msg = result.unwrap();
        assert!(msg.contains("Sesión iniciada con éxito"));

        // Verify config on disk
        let saved_cfg = sw_config::ConfigFile::load_from_file(&config_file_path).unwrap();
        assert!(saved_cfg.is_logged_in());
        assert!(!saved_cfg.encrypted_token.is_empty());
        assert!(!saved_cfg.encrypted_user_symmetric_key.is_empty());
    }

    #[tokio::test]
    async fn test_cli_sync_without_login_fails() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config_file_path = temp_dir.path().join("silverwarden.json");

        let empty_cfg = sw_config::ConfigFile::default();
        empty_cfg.save_to_file(&config_file_path).unwrap();

        let cli = Cli {
            socket: Some(temp_dir.path().join("dummy.sock")),
            config: Some(config_file_path),
            insecure: false,
            command: Commands::Sync,
        };

        let result = handle_command(&cli, |_| unreachable!()).await;
        match result {
            Err(CliError::Other(msg)) => {
                assert_eq!(
                    msg,
                    "No hay sesión iniciada. Ejecuta 'silverwarden login' primero."
                );
            }
            other => panic!("Expected CliError::Other, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_cli_sync_success() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let base_url = mock_server.uri();

        let ciphers = (0..5)
            .map(|_| sw_vault::Cipher {
                id: Some(sw_vault::Uuid::new_v4()),
                r#type: sw_vault::CipherType::Login,
                name: sw_crypto::EncString::default(),
                ..Default::default()
            })
            .collect::<Vec<_>>();
        let sync_data = sw_vault::SyncData {
            ciphers,
            ..Default::default()
        };

        Mock::given(method("GET"))
            .and(path("/sync"))
            .respond_with(ResponseTemplate::new(200).set_body_json(sync_data))
            .mount(&mock_server)
            .await;

        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("sync_success.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();

        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let req = sw_ipc::read_message(&mut stream).await.unwrap();
                assert_eq!(req.action, "SyncData");
                let resp = IpcMessage::new(
                    "Ok",
                    serde_json::json!({
                        "status": "synced",
                        "logins": 5
                    }),
                );
                sw_ipc::write_message(&mut stream, &resp).await.unwrap();
            }
        });

        let config_file_path = temp_dir.path().join("silverwarden.json");

        let mut logged_in_cfg = sw_config::ConfigFile {
            identity_url: base_url.clone(),
            api_url: base_url,
            ..Default::default()
        };
        let config_key = sw_config::derive_config_key_with_params(
            "",
            &logged_in_cfg.device_uuid,
            sw_config::KDF_MEMORY_KIB_TEST,
        )
        .unwrap();
        let token = sw_config::LoginToken {
            access_token: "test_token".to_string(),
            ..Default::default()
        };
        logged_in_cfg.set_token(&token, &config_key).unwrap();
        logged_in_cfg.save_to_file(&config_file_path).unwrap();

        let cli = Cli {
            socket: Some(socket_path),
            config: Some(config_file_path),
            insecure: false,
            command: Commands::Sync,
        };

        let output = handle_command(&cli, |_| unreachable!()).await.unwrap();
        assert!(output.contains("Sincronización completada: 5 elementos (5 logins)."));
    }

    #[tokio::test]
    async fn test_cli_sync_without_agent_running() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let base_url = mock_server.uri();

        let ciphers = (0..3)
            .map(|_| sw_vault::Cipher {
                id: Some(sw_vault::Uuid::new_v4()),
                r#type: sw_vault::CipherType::Login,
                name: sw_crypto::EncString::default(),
                ..Default::default()
            })
            .collect::<Vec<_>>();
        let sync_data = sw_vault::SyncData {
            ciphers,
            ..Default::default()
        };

        Mock::given(method("GET"))
            .and(path("/sync"))
            .respond_with(ResponseTemplate::new(200).set_body_json(sync_data))
            .mount(&mock_server)
            .await;

        let temp_dir = tempfile::tempdir().unwrap();
        let nonexistent_socket = temp_dir.path().join("no_agent.sock");
        let config_file_path = temp_dir.path().join("silverwarden.json");

        let mut logged_in_cfg = sw_config::ConfigFile {
            identity_url: base_url.clone(),
            api_url: base_url,
            ..Default::default()
        };
        let config_key = sw_config::derive_config_key_with_params(
            "",
            &logged_in_cfg.device_uuid,
            sw_config::KDF_MEMORY_KIB_TEST,
        )
        .unwrap();
        let token = sw_config::LoginToken {
            access_token: "test_token".to_string(),
            ..Default::default()
        };
        logged_in_cfg.set_token(&token, &config_key).unwrap();
        logged_in_cfg.save_to_file(&config_file_path).unwrap();

        let cli = Cli {
            socket: Some(nonexistent_socket),
            config: Some(config_file_path),
            insecure: false,
            command: Commands::Sync,
        };

        let output = handle_command(&cli, |_| unreachable!()).await.unwrap();
        assert!(output.contains("Sincronización completada: 3 elementos (3 logins)."));
    }

    #[tokio::test]
    async fn test_cli_sync_e2e_agent_receives_sync_data_and_ssh_add_lists_keys() {
        use std::sync::Arc;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let base_url = mock_server.uri();

        let sym_key = sw_crypto::SymmetricKey::from_bytes(&[0x42u8; 64]).unwrap();
        let (priv_1, pub_1) = sw_ssh_agent::generate_test_ed25519(1, "work-laptop");
        let enc_name_1 = sw_crypto::encrypt_with(
            b"work-laptop",
            sw_crypto::EncStringType::AesCbc256HmacSha256B64,
            &sym_key,
        )
        .unwrap();
        let enc_priv_1 = sw_crypto::encrypt_with(
            priv_1.as_bytes(),
            sw_crypto::EncStringType::AesCbc256HmacSha256B64,
            &sym_key,
        )
        .unwrap();
        let enc_pub_1 = sw_crypto::encrypt_with(
            pub_1.as_bytes(),
            sw_crypto::EncStringType::AesCbc256HmacSha256B64,
            &sym_key,
        )
        .unwrap();

        let cipher_ssh = sw_vault::Cipher {
            id: Some(sw_vault::Uuid::new_v4()),
            r#type: sw_vault::CipherType::SshKey,
            name: enc_name_1,
            ssh_key: Some(sw_vault::SSHKeyCipher {
                private_key: Some(enc_priv_1),
                public_key: Some(enc_pub_1),
                key_fingerprint: None,
            }),
            ..Default::default()
        };

        let sync_data = sw_vault::SyncData {
            ciphers: vec![cipher_ssh],
            ..Default::default()
        };

        Mock::given(method("GET"))
            .and(path("/sync"))
            .respond_with(ResponseTemplate::new(200).set_body_json(sync_data))
            .mount(&mock_server)
            .await;

        let temp_dir = tempfile::tempdir().unwrap();
        let agent_socket_path = temp_dir.path().join("agent.sock");
        let config_file_path = temp_dir.path().join("silverwarden.json");

        // 1. Setup VaultAgentServer unlocked with sym_key, but starting with empty VaultStore
        let vault_store = Arc::new(sw_vault::VaultStore::new());
        let vault_agent = Arc::new(sw_ssh_agent::VaultAgentServer::with_key(
            vault_store.clone(),
            sym_key.try_clone().unwrap(),
        ));

        // Verify SSH agent currently has 0 keys
        let identities_before = vault_agent.request_identities().await.unwrap();
        assert_eq!(identities_before.len(), 0);

        // 2. Start agent daemon with this vault_agent
        let mut agent_state = sw_agent::AgentState::default().with_vault_agent(vault_agent.clone());
        agent_state.config_directory = Some(temp_dir.path().to_path_buf());
        let daemon = sw_agent::AgentDaemon::with_vault_agent(agent_state, vault_agent.clone());

        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
        let a_sock = agent_socket_path.clone();
        let mut rx = shutdown_rx;
        let daemon_handle = tokio::spawn(async move {
            let _ = sw_agent::run_agent_daemon_with_shutdown(&a_sock, daemon, async move {
                let _ = rx.recv().await;
            })
            .await;
        });

        // Wait until agent socket is ready
        for _ in 0..50 {
            if agent_socket_path.exists() {
                break;
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }
        assert!(agent_socket_path.exists());

        // 3. Write CLI config
        let mut logged_in_cfg = sw_config::ConfigFile {
            identity_url: base_url.clone(),
            api_url: base_url,
            ..Default::default()
        };
        let config_key = sw_config::derive_config_key_with_params(
            "",
            &logged_in_cfg.device_uuid,
            sw_config::KDF_MEMORY_KIB_TEST,
        )
        .unwrap();
        let token = sw_config::LoginToken {
            access_token: "test_token".to_string(),
            ..Default::default()
        };
        logged_in_cfg.set_token(&token, &config_key).unwrap();
        logged_in_cfg.save_to_file(&config_file_path).unwrap();

        // 4. Run CLI sync command
        let cli = Cli {
            socket: Some(agent_socket_path.clone()),
            config: Some(config_file_path),
            insecure: false,
            command: Commands::Sync,
        };

        let output = handle_command(&cli, |_| unreachable!()).await.unwrap();
        assert!(output.contains("Sincronización completada: 1 elemento (1 clave SSH)."));

        // 5. Query SSH identities from vault_agent: it should now have "work-laptop"!
        let identities_after = vault_agent.request_identities().await.unwrap();
        assert_eq!(identities_after.len(), 1);
        match &identities_after[0] {
            sw_ssh_agent::AgentIdentity::PublicKey { comment, .. } => {
                assert_eq!(comment, "work-laptop");
            }
            sw_ssh_agent::AgentIdentity::Certificate { comment, .. } => {
                assert_eq!(comment, "work-laptop");
            }
        }

        // Cleanup
        let _ = shutdown_tx.send(());
        let _ = daemon_handle.await;
    }

    #[tokio::test]
    async fn test_cli_logins_list() {
        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("logins_list.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();

        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let req = sw_ipc::read_message(&mut stream).await.unwrap();
                assert_eq!(req.action, "ListLogins");
                let resp = IpcMessage::new(
                    "Ok",
                    serde_json::json!([
                        { "id": "111", "name": "GitHub", "username": "octocat" },
                        { "id": "222", "name": "Google", "username": "admin@gmail.com" }
                    ]),
                );
                sw_ipc::write_message(&mut stream, &resp).await.unwrap();
            }
        });

        let cli = test_cli(
            Some(socket_path),
            Commands::Logins {
                action: Some(LoginsCommands::List),
                filter: None,
            },
        );

        let output = handle_command(&cli, |_| unreachable!()).await.unwrap();
        assert!(output.contains("Nombre"));
        assert!(output.contains("Usuario"));
        assert!(output.contains("GitHub"));
        assert!(output.contains("octocat"));
        assert!(output.contains("Google"));
        assert!(output.contains("admin@gmail.com"));
    }

    #[tokio::test]
    async fn test_cli_logins_create() {
        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("logins_create.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();

        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let req = sw_ipc::read_message(&mut stream).await.unwrap();
                assert_eq!(req.action, "CreateLogin");
                assert_eq!(req.payload["name"], "AWS Console");
                assert_eq!(req.payload["username"], "root");
                assert_eq!(req.payload["password"], "hunter2");
                let resp = IpcMessage::new(
                    "Ok",
                    serde_json::json!({
                        "status": "created",
                        "id": "uuid-1234",
                        "name": "AWS Console"
                    }),
                );
                sw_ipc::write_message(&mut stream, &resp).await.unwrap();
            }
        });

        let cli = test_cli(
            Some(socket_path),
            Commands::Logins {
                action: Some(LoginsCommands::Create {
                    name: "AWS Console".into(),
                    username: "root".into(),
                    password: "hunter2".into(),
                }),
                filter: None,
            },
        );

        let output = handle_command(&cli, |_| unreachable!()).await.unwrap();
        assert!(output.contains("Acceso 'AWS Console' creado exitosamente."));
    }

    #[tokio::test]
    async fn test_cli_logins_get_and_delete() {
        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("logins_get_delete.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();

        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let req = sw_ipc::read_message(&mut stream).await.unwrap();
                match req.action.as_str() {
                    "GetLogin" => {
                        assert_eq!(req.payload["name"], "GitHub");
                        let resp = IpcMessage::new(
                            "Ok",
                            serde_json::json!({
                                "name": "GitHub",
                                "username": "octocat",
                                "password": "supersecretpass",
                                "totp": "123456"
                            }),
                        );
                        sw_ipc::write_message(&mut stream, &resp).await.unwrap();
                    }
                    "DeleteLogin" => {
                        assert_eq!(req.payload["name"], "GitHub");
                        let resp = IpcMessage::new(
                            "Ok",
                            serde_json::json!({
                                "status": "deleted",
                                "name": "GitHub"
                            }),
                        );
                        sw_ipc::write_message(&mut stream, &resp).await.unwrap();
                    }
                    other => panic!("Unexpected action {other}"),
                }
            }
        });

        // GetLogin
        let cli_get = test_cli(
            Some(socket_path.clone()),
            Commands::Logins {
                action: Some(LoginsCommands::Get {
                    name: "GitHub".into(),
                }),
                filter: None,
            },
        );
        let out_get = handle_command(&cli_get, |_| unreachable!()).await.unwrap();
        assert!(out_get.contains("Contraseña: supersecretpass"));
        assert!(out_get.contains("TOTP: 123456"));

        // DeleteLogin
        let cli_del = test_cli(
            Some(socket_path),
            Commands::Logins {
                action: Some(LoginsCommands::Delete {
                    name: "GitHub".into(),
                }),
                filter: None,
            },
        );
        let out_del = handle_command(&cli_del, |_| unreachable!()).await.unwrap();
        assert!(out_del.contains("Acceso 'GitHub' eliminado exitosamente."));
    }

    #[test]
    fn test_resolve_socket_path() {
        let custom = PathBuf::from("/custom/path.sock");
        assert_eq!(resolve_socket_path(Some(custom.clone())).unwrap(), custom);

        if let Ok(home) = std::env::var("HOME") {
            let default_path = resolve_socket_path(None).unwrap();
            assert_eq!(default_path, PathBuf::from(home).join(".silverwarden.sock"));
        }
    }

    static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static ASYNC_ENV_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    struct EnvGuard {
        key: String,
        old_val: Option<String>,
    }

    impl EnvGuard {
        fn new(key: &str) -> Self {
            Self {
                key: key.to_string(),
                old_val: std::env::var(key).ok(),
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            unsafe {
                match &self.old_val {
                    Some(val) => std::env::set_var(&self.key, val),
                    None => std::env::remove_var(&self.key),
                }
            }
        }
    }

    #[test]
    fn test_check_goldwarden_go_conflict() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let _guard = EnvGuard::new("HOME");
        let temp_dir = tempfile::tempdir().unwrap();
        let home_fake = temp_dir.path().to_path_buf();
        unsafe {
            std::env::set_var("HOME", &home_fake);
        }

        // Absent
        assert!(!check_goldwarden_go_conflict());

        // Present
        let go_sock = home_fake.join(".goldwarden.sock");
        std::fs::write(&go_sock, b"").unwrap();
        assert!(check_goldwarden_go_conflict());
    }

    #[test]
    fn test_format_sync_summary_breakdown() {
        assert_eq!(
            format_sync_summary(8, 3, 2, 1, 1, 1),
            "Sincronización completada: 8 elementos (3 logins, 2 claves SSH, 1 nota, 1 tarjeta, 1 identidad)."
        );
        assert_eq!(
            format_sync_summary(0, 0, 0, 0, 0, 0),
            "Sincronización completada: 0 elementos."
        );
        assert_eq!(
            format_sync_summary(1, 1, 0, 0, 0, 0),
            "Sincronización completada: 1 elemento (1 login)."
        );
    }

    #[test]
    fn test_cli_error_display() {
        let p = PathBuf::from("/tmp/test.sock");
        assert!(CliError::SocketNotFound(p.clone())
            .to_string()
            .contains("El agente no está corriendo o el socket no existe"));
        assert!(CliError::ConnectionFailed(p, "conn err".into())
            .to_string()
            .contains("El agente no está corriendo o el socket no existe"));
        assert!(CliError::SendFailed("send err".into())
            .to_string()
            .contains("Error al enviar"));
        assert!(CliError::ReceiveFailed("recv err".into())
            .to_string()
            .contains("Error al recibir"));
        assert_eq!(
            CliError::AgentError("agent err".into()).to_string(),
            "agent err"
        );
        assert!(CliError::Io("io err".into())
            .to_string()
            .contains("Error de E/S"));
        assert!(CliError::Config("cfg err".into())
            .to_string()
            .contains("Error de configuración"));
        assert_eq!(CliError::Other("other err".into()).to_string(), "other err");
    }

    #[tokio::test]
    async fn test_agent_start_launches_both_sockets() {
        let temp_dir = tempfile::tempdir().expect("Failed to create tempdir");
        let main_sock = temp_dir.path().join(".silverwarden.sock");
        let ssh_sock = temp_dir.path().join(".silverwarden-ssh-agent.sock");

        let cli = test_cli(
            Some(main_sock.clone()),
            Commands::Agent {
                action: AgentCommands::Start { no_ssh: false },
            },
        );

        let handle = tokio::spawn(async move {
            let _ = handle_command(&cli, |_| Ok(String::new())).await;
        });

        // Wait up to 5 seconds for both sockets to appear
        let mut both_exist = false;
        for _ in 0..50 {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            if main_sock.exists() && ssh_sock.exists() {
                both_exist = true;
                break;
            }
        }
        assert!(both_exist, "Both sockets should exist after agent start");

        // Verify ssh-add -L against the SSH agent socket responds with "no identities" (exit code 1)
        let output = tokio::process::Command::new("ssh-add")
            .arg("-L")
            .env("SSH_AUTH_SOCK", &ssh_sock)
            .output()
            .await
            .expect("Failed to execute ssh-add");

        assert_eq!(output.status.code(), Some(1));
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stderr.contains("The agent has no identities.")
                || stdout.contains("The agent has no identities.")
        );

        handle.abort();
    }

    #[tokio::test]
    async fn test_agent_start_no_ssh() {
        let temp_dir = tempfile::tempdir().expect("Failed to create tempdir");
        let main_sock = temp_dir.path().join(".silverwarden.sock");
        let ssh_sock = temp_dir.path().join(".silverwarden-ssh-agent.sock");

        let cli = test_cli(
            Some(main_sock.clone()),
            Commands::Agent {
                action: AgentCommands::Start { no_ssh: true },
            },
        );

        let handle = tokio::spawn(async move {
            let _ = handle_command(&cli, |_| Ok(String::new())).await;
        });

        // Wait up to 2 seconds for main socket to appear
        let mut main_exists = false;
        for _ in 0..20 {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            if main_sock.exists() {
                main_exists = true;
                break;
            }
        }
        assert!(main_exists, "Main socket should exist");
        // SSH socket should NOT exist
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(
            !ssh_sock.exists(),
            "SSH socket should NOT exist with --no-ssh"
        );

        handle.abort();
    }

    #[tokio::test]
    async fn test_login_rate_limit_error() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let base_url = mock_server.uri();

        let email = "ratelimit@example.com";
        let password = "super_master_password";

        Mock::given(method("POST"))
            .and(path("/accounts/prelogin"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "kdf": 0,
                "kdfIterations": 10
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&mock_server)
            .await;

        let temp_dir = tempfile::tempdir().unwrap();
        let config_file_path = temp_dir.path().join("silverwarden.json");

        let initial_cfg = sw_config::ConfigFile {
            identity_url: base_url.clone(),
            api_url: base_url,
            ..Default::default()
        };
        initial_cfg.save_to_file(&config_file_path).unwrap();

        let cli = Cli {
            socket: Some(temp_dir.path().join("dummy.sock")),
            config: Some(config_file_path),
            insecure: false,
            command: Commands::Login {
                email: Some(email.to_string()),
                password: Some(password.to_string()),
                server: None,
                apikey: false,
                client_id: None,
                client_secret: None,
            },
        };

        let err = handle_command(&cli, |_| unreachable!()).await.unwrap_err();
        assert!(err.to_string().contains(
            "El servidor ha bloqueado temporalmente tu IP por demasiados intentos de login"
        ));
    }

    #[tokio::test]
    async fn test_login_invalid_credentials() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let base_url = mock_server.uri();

        let email = "invalid@example.com";
        let password = "wrong_password";

        Mock::given(method("POST"))
            .and(path("/accounts/prelogin"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "kdf": 0,
                "kdfIterations": 10
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "error": "invalid_grant",
                "error_description": "Invalid username or password."
            })))
            .mount(&mock_server)
            .await;

        let temp_dir = tempfile::tempdir().unwrap();
        let config_file_path = temp_dir.path().join("silverwarden.json");

        let initial_cfg = sw_config::ConfigFile {
            identity_url: base_url.clone(),
            api_url: base_url,
            ..Default::default()
        };
        initial_cfg.save_to_file(&config_file_path).unwrap();

        let cli = Cli {
            socket: Some(temp_dir.path().join("dummy.sock")),
            config: Some(config_file_path),
            insecure: false,
            command: Commands::Login {
                email: Some(email.to_string()),
                password: Some(password.to_string()),
                server: None,
                apikey: false,
                client_id: None,
                client_secret: None,
            },
        };

        let err = handle_command(&cli, |_| unreachable!()).await.unwrap_err();
        assert!(err
            .to_string()
            .contains("Credenciales inválidas. Comprueba tu correo y contraseña maestra."));
    }

    #[tokio::test]
    async fn test_unlock_wrong_pin() {
        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("unlock_wrong_pin.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();

        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let req = sw_ipc::read_message(&mut stream).await.unwrap();
                assert_eq!(req.action, "Unlock");
                assert_eq!(req.payload["pin"], "999999");
                let resp = IpcMessage::new("Error", serde_json::json!("PIN incorrecto"));
                sw_ipc::write_message(&mut stream, &resp).await.unwrap();
            }
        });

        let cli = test_cli(
            Some(socket_path),
            Commands::Unlock {
                pin: Some("999999".into()),
            },
        );

        let err = handle_command(&cli, |_| unreachable!()).await.unwrap_err();
        assert_eq!(err, CliError::AgentError("PIN incorrecto".to_string()));
        assert_eq!(err.to_string(), "PIN incorrecto");
    }

    #[tokio::test]
    async fn test_create_empty_name_fails() {
        let temp_dir = tempfile::tempdir().unwrap();
        let dummy_socket = temp_dir.path().join("dummy.sock");

        let cli = test_cli(
            Some(dummy_socket),
            Commands::Logins {
                action: Some(LoginsCommands::Create {
                    name: "   ".into(),
                    username: "user".into(),
                    password: "pass".into(),
                }),
                filter: None,
            },
        );

        let err = handle_command(&cli, |_| unreachable!()).await.unwrap_err();
        assert_eq!(
            err,
            CliError::Other("El nombre no puede estar vacío.".to_string())
        );
        assert_eq!(err.to_string(), "El nombre no puede estar vacío.");
    }

    #[tokio::test]
    async fn test_delete_nonexistent_fails() {
        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("delete_nonexistent.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();

        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let req = sw_ipc::read_message(&mut stream).await.unwrap();
                assert_eq!(req.action, "DeleteLogin");
                assert_eq!(req.payload["name"], "NonExistent");
                let resp = IpcMessage::new(
                    "Error",
                    serde_json::json!("No se encontró ningún acceso con el nombre 'NonExistent'"),
                );
                sw_ipc::write_message(&mut stream, &resp).await.unwrap();
            }
        });

        let cli = test_cli(
            Some(socket_path),
            Commands::Logins {
                action: Some(LoginsCommands::Delete {
                    name: "NonExistent".into(),
                }),
                filter: None,
            },
        );

        let err = handle_command(&cli, |_| unreachable!()).await.unwrap_err();
        assert_eq!(
            err,
            CliError::AgentError(
                "No se encontró ningún acceso con el nombre 'NonExistent'".to_string()
            )
        );
        assert_eq!(
            err.to_string(),
            "No se encontró ningún acceso con el nombre 'NonExistent'"
        );
    }

    #[tokio::test]
    async fn test_cli_config_commands_flow() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config_path = temp_dir.path().join("silverwarden.json");

        // 1. Initial config get (returns default URLs and not logged in)
        let cli_get = Cli {
            socket: None,
            config: Some(config_path.clone()),
            insecure: false,
            command: Commands::Config {
                action: ConfigCommands::Get,
            },
        };
        let out_get = handle_command(&cli_get, |_| unreachable!()).await.unwrap();
        assert!(out_get.contains("Identity URL:      https://identity.bitwarden.com"));
        assert!(out_get.contains("Sesión iniciada:   No"));

        // 2. Set server URL
        let cli_set_server = Cli {
            socket: None,
            config: Some(config_path.clone()),
            insecure: false,
            command: Commands::Config {
                action: ConfigCommands::SetServer {
                    url: "http://localhost:8080".to_string(),
                },
            },
        };
        let out_srv = handle_command(&cli_set_server, |_| unreachable!())
            .await
            .unwrap();
        assert!(out_srv.contains("Servidor configurado a http://localhost:8080."));
        assert!(out_srv.contains("Identity URL:      http://localhost:8080/identity"));
        assert!(out_srv.contains("API URL:           http://localhost:8080/api"));
        assert!(out_srv.contains("Notifications URL: http://localhost:8080/notifications"));

        // 3. Verify get reflects the server URLs
        let out_get2 = handle_command(&cli_get, |_| unreachable!()).await.unwrap();
        assert!(out_get2.contains("Identity URL:      http://localhost:8080/identity"));
        assert!(out_get2.contains("API URL:           http://localhost:8080/api"));

        // 4. Set individual URLs
        let cli_set_id = Cli {
            socket: None,
            config: Some(config_path.clone()),
            insecure: false,
            command: Commands::Config {
                action: ConfigCommands::SetIdentity {
                    url: "https://id.custom.com".to_string(),
                },
            },
        };
        handle_command(&cli_set_id, |_| unreachable!())
            .await
            .unwrap();

        let cli_set_api = Cli {
            socket: None,
            config: Some(config_path.clone()),
            insecure: false,
            command: Commands::Config {
                action: ConfigCommands::SetApi {
                    url: "https://api.custom.com".to_string(),
                },
            },
        };
        handle_command(&cli_set_api, |_| unreachable!())
            .await
            .unwrap();

        let cli_set_notif = Cli {
            socket: None,
            config: Some(config_path.clone()),
            insecure: false,
            command: Commands::Config {
                action: ConfigCommands::SetNotifications {
                    url: "https://notif.custom.com".to_string(),
                },
            },
        };
        handle_command(&cli_set_notif, |_| unreachable!())
            .await
            .unwrap();

        // 5. Verify get reflects individual changes
        let out_get3 = handle_command(&cli_get, |_| unreachable!()).await.unwrap();
        assert!(out_get3.contains("Identity URL:      https://id.custom.com"));
        assert!(out_get3.contains("API URL:           https://api.custom.com"));
        assert!(out_get3.contains("Notifications URL: https://notif.custom.com"));

        // 6. Validation error on empty URLs
        let cli_empty_srv = Cli {
            socket: None,
            config: Some(config_path),
            insecure: false,
            command: Commands::Config {
                action: ConfigCommands::SetServer {
                    url: "   ".to_string(),
                },
            },
        };
        let err = handle_command(&cli_empty_srv, |_| unreachable!())
            .await
            .unwrap_err();
        assert_eq!(err.to_string(), "La URL del servidor no puede estar vacía.");
    }

    #[tokio::test]
    async fn test_cli_login_with_server_flag() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let base_url = mock_server.uri();

        let email = "vaultwarden_user@example.com";
        let password = "super_vaultwarden_password";

        // Prelogin endpoint (derived as {base_url}/identity/accounts/prelogin)
        Mock::given(method("POST"))
            .and(path("/identity/accounts/prelogin"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "kdf": 0,
                "kdfIterations": 10
            })))
            .mount(&mock_server)
            .await;

        let kdf_config = sw_crypto::KdfConfig {
            kdf_type: sw_crypto::KdfType::Pbkdf2,
            iterations: 10,
            memory: None,
            parallelism: None,
        };
        let master_key =
            sw_crypto::derive_master_key(password.as_bytes(), email, &kdf_config).unwrap();
        let stretched = sw_crypto::stretch_key(&master_key).unwrap();
        let synthetic_sym_key = [42u8; 64];
        let enc_key_wire = sw_crypto::encrypt_with_to_string(
            &synthetic_sym_key,
            sw_crypto::EncStringType::AesCbc256HmacSha256B64,
            &stretched,
        )
        .unwrap();

        // Token endpoint on {base_url}/identity/connect/token
        Mock::given(method("POST"))
            .and(path("/identity/connect/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "mock_vw_token",
                "expires_in": 3600,
                "token_type": "Bearer",
                "refresh_token": "mock_vw_refresh",
                "key": enc_key_wire
            })))
            .mount(&mock_server)
            .await;

        let temp_dir = tempfile::tempdir().unwrap();
        let config_file_path = temp_dir.path().join("silverwarden.json");

        let initial_cfg = sw_config::ConfigFile {
            identity_url: "https://initial.vault/identity".to_string(),
            api_url: "https://initial.vault/api".to_string(),
            notifications_url: "https://initial.vault/notifications".to_string(),
            ..Default::default()
        };
        initial_cfg.save_to_file(&config_file_path).unwrap();

        let cli = Cli {
            socket: Some(temp_dir.path().join("dummy.sock")),
            config: Some(config_file_path.clone()),
            insecure: false,
            command: Commands::Login {
                email: Some(email.to_string()),
                password: Some(password.to_string()),
                server: Some(base_url.clone()),
                apikey: false,
                client_id: None,
                client_secret: None,
            },
        };

        let result = handle_command(&cli, |_| unreachable!()).await;
        assert!(
            result.is_ok(),
            "Login with --server should succeed: {:?}",
            result.err()
        );

        // Verify config file was NOT overwritten with server URLs (flag only applies for execution)
        let saved_config = sw_config::ConfigFile::load_from_file(&config_file_path).unwrap();
        assert_eq!(saved_config.identity_url, "https://initial.vault/identity");
        assert_eq!(saved_config.api_url, "https://initial.vault/api");
        assert_eq!(
            saved_config.notifications_url,
            "https://initial.vault/notifications"
        );
        assert!(saved_config.is_logged_in());
    }

    #[test]
    fn test_cli_parse_insecure_flags() {
        let cli1 = Cli::try_parse_from(["silverwarden", "--insecure", "status"])
            .expect("Should parse --insecure before subcommand");
        assert!(cli1.insecure);
        assert_eq!(cli1.command, Commands::Status);

        let cli2 = Cli::try_parse_from(["silverwarden", "status", "--insecure"])
            .expect("Should parse --insecure after subcommand");
        assert!(cli2.insecure);

        let cli3 = Cli::try_parse_from(["silverwarden", "login", "--danger-accept-invalid-certs"])
            .expect("Should parse alias --danger-accept-invalid-certs");
        assert!(cli3.insecure);

        let cli_default = Cli::try_parse_from(["silverwarden", "status"])
            .expect("Should parse status without insecure");
        assert!(!cli_default.insecure);
    }

    #[tokio::test]
    async fn test_cli_login_with_insecure_flag() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let base_url = mock_server.uri();

        let email = "insecure_user@example.com";
        let password = "super_insecure_password";

        Mock::given(method("POST"))
            .and(path("/accounts/prelogin"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "kdf": 0,
                "kdfIterations": 10
            })))
            .mount(&mock_server)
            .await;

        let kdf_config = sw_crypto::KdfConfig {
            kdf_type: sw_crypto::KdfType::Pbkdf2,
            iterations: 10,
            memory: None,
            parallelism: None,
        };
        let master_key =
            sw_crypto::derive_master_key(password.as_bytes(), email, &kdf_config).unwrap();
        let stretched = sw_crypto::stretch_key(&master_key).unwrap();
        let synthetic_sym_key = [99u8; 64];
        let enc_key_wire = sw_crypto::encrypt_with_to_string(
            &synthetic_sym_key,
            sw_crypto::EncStringType::AesCbc256HmacSha256B64,
            &stretched,
        )
        .unwrap();

        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "mock_insecure_token",
                "expires_in": 3600,
                "token_type": "Bearer",
                "refresh_token": "mock_insecure_refresh",
                "key": enc_key_wire
            })))
            .mount(&mock_server)
            .await;

        let temp_dir = tempfile::tempdir().unwrap();
        let config_file_path = temp_dir.path().join("silverwarden.json");

        let initial_cfg = sw_config::ConfigFile {
            identity_url: base_url.clone(),
            api_url: base_url,
            danger_accept_invalid_certs: false,
            ..Default::default()
        };
        initial_cfg.save_to_file(&config_file_path).unwrap();

        let cli = Cli {
            socket: Some(temp_dir.path().join("dummy.sock")),
            config: Some(config_file_path.clone()),
            insecure: true,
            command: Commands::Login {
                email: Some(email.to_string()),
                password: Some(password.to_string()),
                server: None,
                apikey: false,
                client_id: None,
                client_secret: None,
            },
        };

        let result = handle_command(&cli, |_| unreachable!()).await;
        assert!(result.is_ok(), "Login with --insecure should succeed");

        let saved = sw_config::ConfigFile::load_from_file(&config_file_path).unwrap();
        assert!(!saved.danger_accept_invalid_certs);
        assert!(saved.is_logged_in());
    }

    #[test]
    fn test_config_setup_option1_bitwarden_defaults() {
        let input_bytes = b"1\n\n\n\n";
        let mut reader = std::io::Cursor::new(input_bytes);
        let mut writer = Vec::new();

        let mut config = sw_config::ConfigFile::default();
        let prompt_fn = |msg: &str| prompt_from_io(&mut reader, &mut writer, msg);

        setup_config_flow(prompt_fn, &mut config).expect("Option 1 setup should succeed");

        assert_eq!(config.identity_url, "https://vault.bitwarden.com/identity");
        assert_eq!(config.api_url, "https://api.bitwarden.com");
        assert_eq!(
            config.notifications_url,
            "https://notifications.bitwarden.com"
        );
        assert!(!config.danger_accept_invalid_certs);
    }

    #[test]
    fn test_config_setup_option1_bitwarden_custom_urls() {
        let input_bytes = b"1\nhttps://custom.vault/identity\nhttps://custom.vault/api\nhttps://custom.vault/notifications\n";
        let mut reader = std::io::Cursor::new(input_bytes);
        let mut writer = Vec::new();

        let mut config = sw_config::ConfigFile::default();
        let prompt_fn = |msg: &str| prompt_from_io(&mut reader, &mut writer, msg);

        setup_config_flow(prompt_fn, &mut config).expect("Option 1 custom setup should succeed");

        assert_eq!(config.identity_url, "https://custom.vault/identity");
        assert_eq!(config.api_url, "https://custom.vault/api");
        assert_eq!(
            config.notifications_url,
            "https://custom.vault/notifications"
        );
        assert!(!config.danger_accept_invalid_certs);
    }

    #[test]
    fn test_config_setup_option2_vaultwarden_self_signed() {
        let input_bytes = b"2\nhttps://vw.local:8443\ns\n";
        let mut reader = std::io::Cursor::new(input_bytes);
        let mut writer = Vec::new();

        let mut config = sw_config::ConfigFile::default();
        let prompt_fn = |msg: &str| prompt_from_io(&mut reader, &mut writer, msg);

        setup_config_flow(prompt_fn, &mut config).expect("Option 2 setup should succeed");

        assert_eq!(config.identity_url, "https://vw.local:8443/identity");
        assert_eq!(config.api_url, "https://vw.local:8443/api");
        assert_eq!(
            config.notifications_url,
            "https://vw.local:8443/notifications"
        );
        assert!(config.danger_accept_invalid_certs);
    }

    #[test]
    fn test_config_setup_option2_vaultwarden_official_certs() {
        let input_bytes = b"2\nhttps://vw.example.com\nn\n";
        let mut reader = std::io::Cursor::new(input_bytes);
        let mut writer = Vec::new();

        let mut config = sw_config::ConfigFile::default();
        let prompt_fn = |msg: &str| prompt_from_io(&mut reader, &mut writer, msg);

        setup_config_flow(prompt_fn, &mut config).expect("Option 2 setup should succeed");

        assert_eq!(config.identity_url, "https://vw.example.com/identity");
        assert_eq!(config.api_url, "https://vw.example.com/api");
        assert_eq!(
            config.notifications_url,
            "https://vw.example.com/notifications"
        );
        assert!(!config.danger_accept_invalid_certs);
    }

    #[test]
    fn test_config_setup_option3_manual() {
        let input_bytes =
            b"3\nhttps://auth.company.lan\nhttps://api.company.lan\nhttps://ws.company.lan\ns\n";
        let mut reader = std::io::Cursor::new(input_bytes);
        let mut writer = Vec::new();

        let mut config = sw_config::ConfigFile::default();
        let prompt_fn = |msg: &str| prompt_from_io(&mut reader, &mut writer, msg);

        setup_config_flow(prompt_fn, &mut config).expect("Option 3 setup should succeed");

        assert_eq!(config.identity_url, "https://auth.company.lan");
        assert_eq!(config.api_url, "https://api.company.lan");
        assert_eq!(config.notifications_url, "https://ws.company.lan");
        assert!(config.danger_accept_invalid_certs);
    }

    #[tokio::test]
    async fn test_cli_config_setup_and_get_integration() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config_file_path = temp_dir.path().join("silverwarden.json");

        let input_bytes = b"2\nhttps://vault.company.lan\ns\n";
        let mut reader = std::io::Cursor::new(input_bytes);
        let mut writer = Vec::new();

        let cli_setup = Cli {
            socket: Some(temp_dir.path().join("dummy.sock")),
            config: Some(config_file_path.clone()),
            insecure: false,
            command: Commands::Config {
                action: ConfigCommands::Setup,
            },
        };

        let output = handle_command(&cli_setup, |msg| {
            prompt_from_io(&mut reader, &mut writer, msg)
        })
        .await
        .expect("config setup should succeed");

        assert!(output.contains("Configuración guardada exitosamente:"));
        assert!(output.contains("Identity URL:      https://vault.company.lan/identity"));
        assert!(output.contains("Aceptar certs inv: Sí"));

        // Now run config get to verify full display of URLs and certs
        let cli_get = Cli {
            socket: Some(temp_dir.path().join("dummy.sock")),
            config: Some(config_file_path),
            insecure: false,
            command: Commands::Config {
                action: ConfigCommands::Get,
            },
        };

        let get_output = handle_command(&cli_get, |_| unreachable!())
            .await
            .expect("config get should succeed");

        assert!(get_output.contains("Configuración actual:"));
        assert!(get_output.contains("Identity URL:      https://vault.company.lan/identity"));
        assert!(get_output.contains("API URL:           https://vault.company.lan/api"));
        assert!(get_output.contains("Notifications URL: https://vault.company.lan/notifications"));
        assert!(get_output.contains("Aceptar certs inv: Sí"));
        assert!(get_output.contains("Sesión iniciada:   No"));
    }

    #[tokio::test]
    async fn test_cli_login_unlock_sync_integration_sequence() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let base_url = mock_server.uri();

        let email = "integration_user@example.com";
        let password = "super_integration_password";
        let pin = "4321";

        // 1. Mock endpoints
        // Prelogin
        Mock::given(method("POST"))
            .and(path("/identity/accounts/prelogin"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "kdf": 0,
                "kdfIterations": 10
            })))
            .mount(&mock_server)
            .await;

        let kdf_config = sw_crypto::KdfConfig {
            kdf_type: sw_crypto::KdfType::Pbkdf2,
            iterations: 10,
            memory: None,
            parallelism: None,
        };
        let master_key =
            sw_crypto::derive_master_key(password.as_bytes(), email, &kdf_config).unwrap();
        let stretched = sw_crypto::stretch_key(&master_key).unwrap();
        let synthetic_sym_key = [88u8; 64];
        let enc_key_wire = sw_crypto::encrypt_with_to_string(
            &synthetic_sym_key,
            sw_crypto::EncStringType::AesCbc256HmacSha256B64,
            &stretched,
        )
        .unwrap();

        // Connect token
        Mock::given(method("POST"))
            .and(path("/identity/connect/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "mock_seq_token",
                "expires_in": 3600,
                "token_type": "Bearer",
                "refresh_token": "mock_seq_refresh",
                "key": enc_key_wire
            })))
            .mount(&mock_server)
            .await;

        // Sync
        Mock::given(method("GET"))
            .and(path("/api/sync"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "profile": {},
                "folders": [],
                "collections": [],
                "ciphers": []
            })))
            .mount(&mock_server)
            .await;

        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("seq_agent.sock");
        let config_file_path = temp_dir.path().join("silverwarden.json");

        // Pre-configure PIN in initial config
        let mut initial_config = sw_config::ConfigFile::default();
        let config_key = sw_config::derive_config_key_with_params(
            pin,
            &initial_config.device_uuid,
            CLI_KDF_MEMORY_KIB,
        )
        .unwrap();
        initial_config.config_key_hash = sw_config::hash_config_key(&config_key);
        initial_config.save_to_file(&config_file_path).unwrap();

        let agent_state = sw_agent::AgentState::new(initial_config.clone())
            .with_config_directory(temp_dir.path().to_path_buf());
        let va = sw_ssh_agent::shared_vault_agent();
        let daemon = sw_agent::AgentDaemon::with_vault_agent(agent_state, va);

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let sock_clone = socket_path.clone();
        tokio::spawn(async move {
            let _ = sw_agent::run_agent_daemon_with_shutdown(&sock_clone, daemon, async {
                let _ = shutdown_rx.await;
            })
            .await;
        });

        // Wait until agent socket is ready
        for _ in 0..50 {
            if socket_path.exists() {
                break;
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
        }

        // --- Sequence Step 1: Login ---
        let cli_login = Cli {
            socket: Some(socket_path.clone()),
            config: Some(config_file_path.clone()),
            insecure: false,
            command: Commands::Login {
                email: Some(email.to_string()),
                password: Some(password.to_string()),
                server: Some(base_url.clone()),
                apikey: false,
                client_id: None,
                client_secret: None,
            },
        };

        let login_res = handle_command(&cli_login, |msg| {
            if msg.contains("PIN") {
                Ok(pin.to_string())
            } else {
                Ok("".to_string())
            }
        })
        .await
        .expect("Login step should succeed");
        assert!(login_res.contains("Sesión iniciada con éxito"));

        // --- Sequence Step 2: Unlock ---
        let cli_unlock = Cli {
            socket: Some(socket_path.clone()),
            config: Some(config_file_path.clone()),
            insecure: false,
            command: Commands::Unlock {
                pin: Some(pin.to_string()),
            },
        };

        let unlock_res = handle_command(&cli_unlock, |_| unreachable!())
            .await
            .expect("Unlock step should succeed");
        assert!(unlock_res.contains("Bóveda desbloqueada con éxito"));

        // --- Sequence Step 3: Sync ---
        let cli_sync = Cli {
            socket: Some(socket_path.clone()),
            config: Some(config_file_path.clone()),
            insecure: false,
            command: Commands::Sync,
        };

        let sync_res = handle_command(&cli_sync, |msg| {
            if msg.contains("PIN") {
                Ok(pin.to_string())
            } else {
                Ok("".to_string())
            }
        })
        .await
        .expect("Sync step should succeed without state error");
        assert!(sync_res.contains("Sincronización completada"));

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn test_cli_logins_create_server_failure_propagates_error() {
        use std::sync::Arc;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        // Mock failure on POST /ciphers and /api/ciphers
        Mock::given(method("POST"))
            .and(path("/ciphers"))
            .respond_with(
                ResponseTemplate::new(500)
                    .set_body_string("Internal server error from Vaultwarden"),
            )
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/ciphers"))
            .respond_with(
                ResponseTemplate::new(500)
                    .set_body_string("Internal server error from Vaultwarden"),
            )
            .mount(&mock_server)
            .await;

        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("failing_create.sock");

        let sym_key = sw_crypto::SymmetricKey::from_bytes(&[0x42u8; 64]).unwrap();
        let va = Arc::new(sw_ssh_agent::VaultAgentServer::default());
        va.unlock(sym_key).await;
        va.vault()
            .load_sync_data(sw_vault::SyncData {
                profile: sw_vault::Profile {
                    id: Some(sw_vault::Uuid::new_v4()),
                    ..Default::default()
                },
                ..Default::default()
            })
            .await;

        let client = Arc::new(
            sw_bitwarden_api::AuthenticatedClient::from_token_with_options(
                mock_server.uri(),
                mock_server.uri(),
                sw_config::LoginToken::default(),
                false,
            ),
        );

        let mut agent_state = sw_agent::AgentState::new(sw_config::ConfigFile::default())
            .with_config_directory(temp_dir.path().to_path_buf());
        agent_state.is_locked = false;
        agent_state.api_client = Some(client);

        let daemon = sw_agent::AgentDaemon::with_vault_agent(agent_state, va.clone());

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let sock_clone = socket_path.clone();
        tokio::spawn(async move {
            let _ = sw_agent::run_agent_daemon_with_shutdown(&sock_clone, daemon, async {
                let _ = shutdown_rx.await;
            })
            .await;
        });

        for _ in 0..50 {
            if socket_path.exists() {
                break;
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
        }

        let cli = Cli {
            socket: Some(socket_path),
            config: None,
            insecure: false,
            command: Commands::Logins {
                action: Some(LoginsCommands::Create {
                    name: "FailingSite".into(),
                    username: "admin".into(),
                    password: "password123".into(),
                }),
                filter: None,
            },
        };

        let res = handle_command(&cli, |_| unreachable!()).await;
        assert!(res.is_err(), "Creation should fail when server returns 500");
        let err_msg = res.unwrap_err().to_string();
        assert!(
            err_msg.contains("Error del servidor al crear acceso"),
            "Error message should mention server failure: {err_msg}"
        );
        assert!(
            err_msg.contains("500"),
            "Error message should contain HTTP 500 status: {err_msg}"
        );
        assert!(
            !err_msg.contains("creado exitosamente"),
            "Error message must NOT say created successfully"
        );

        // Verify the item was NOT inserted into the local vault
        let vault_items = va.vault().all().await;
        assert!(
            vault_items.is_empty(),
            "Local vault must not contain the item when server rejects creation"
        );

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn test_cli_logins_create_server_success_inserts_item() {
        use std::sync::Arc;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let returned_id = sw_vault::Uuid::new_v4();
        let returned_cipher = sw_vault::Cipher {
            id: Some(returned_id),
            r#type: sw_vault::CipherType::Login,
            ..Default::default()
        };

        let profile_id = sw_vault::Uuid::new_v4();

        // Mock success on POST /ciphers requiring encryptedFor matching profile_id
        Mock::given(method("POST"))
            .and(path("/ciphers"))
            .and(wiremock::matchers::body_string_contains(format!(
                "\"encryptedFor\":\"{profile_id}\""
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(&returned_cipher))
            .mount(&mock_server)
            .await;

        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("success_create.sock");

        let sym_key = sw_crypto::SymmetricKey::from_bytes(&[0x42u8; 64]).unwrap();
        let va = Arc::new(sw_ssh_agent::VaultAgentServer::default());
        va.unlock(sym_key).await;
        va.vault()
            .load_sync_data(sw_vault::SyncData {
                profile: sw_vault::Profile {
                    id: Some(profile_id),
                    ..Default::default()
                },
                ..Default::default()
            })
            .await;

        let client = Arc::new(
            sw_bitwarden_api::AuthenticatedClient::from_token_with_options(
                mock_server.uri(),
                mock_server.uri(),
                sw_config::LoginToken::default(),
                false,
            ),
        );

        let mut agent_state = sw_agent::AgentState::new(sw_config::ConfigFile::default())
            .with_config_directory(temp_dir.path().to_path_buf());
        agent_state.is_locked = false;
        agent_state.api_client = Some(client);

        let daemon = sw_agent::AgentDaemon::with_vault_agent(agent_state, va.clone());

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let sock_clone = socket_path.clone();
        tokio::spawn(async move {
            let _ = sw_agent::run_agent_daemon_with_shutdown(&sock_clone, daemon, async {
                let _ = shutdown_rx.await;
            })
            .await;
        });

        for _ in 0..50 {
            if socket_path.exists() {
                break;
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
        }

        let cli = Cli {
            socket: Some(socket_path),
            config: None,
            insecure: false,
            command: Commands::Logins {
                action: Some(LoginsCommands::Create {
                    name: "SuccessfulSite".into(),
                    username: "admin".into(),
                    password: "password123".into(),
                }),
                filter: None,
            },
        };

        let res = handle_command(&cli, |_| unreachable!()).await;
        assert!(
            res.is_ok(),
            "Creation should succeed when server returns 200 with id: {:?}",
            res.err()
        );
        let success_msg = res.unwrap();
        assert!(
            success_msg.contains("Acceso 'SuccessfulSite' creado exitosamente."),
            "Success message should be displayed: {success_msg}"
        );

        // Verify the item was inserted into the local vault with the server ID
        let vault_items = va.vault().all().await;
        assert_eq!(vault_items.len(), 1);
        assert_eq!(vault_items[0].id, Some(returned_id));

        // Verify wiremock received the POST request with encryptedFor
        let requests = mock_server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        let req_body: serde_json::Value =
            serde_json::from_slice(&requests[0].body).expect("Valid JSON request body");
        assert_eq!(req_body["encryptedFor"], profile_id.to_string());

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn test_cli_logins_create_fails_when_profile_not_synced() {
        use std::sync::Arc;

        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("no_profile_create.sock");

        let sym_key = sw_crypto::SymmetricKey::from_bytes(&[0x42u8; 64]).unwrap();
        let va = Arc::new(sw_ssh_agent::VaultAgentServer::default());
        va.unlock(sym_key).await;
        // Profile is not loaded into va.vault()

        let mut agent_state = sw_agent::AgentState::new(sw_config::ConfigFile::default())
            .with_config_directory(temp_dir.path().to_path_buf());
        agent_state.is_locked = false;

        let daemon = sw_agent::AgentDaemon::with_vault_agent(agent_state, va.clone());

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let sock_clone = socket_path.clone();
        tokio::spawn(async move {
            let _ = sw_agent::run_agent_daemon_with_shutdown(&sock_clone, daemon, async {
                let _ = shutdown_rx.await;
            })
            .await;
        });

        for _ in 0..50 {
            if socket_path.exists() {
                break;
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
        }

        let cli = Cli {
            socket: Some(socket_path),
            config: None,
            insecure: false,
            command: Commands::Logins {
                action: Some(LoginsCommands::Create {
                    name: "SiteWithoutProfile".into(),
                    username: "user".into(),
                    password: "pass".into(),
                }),
                filter: None,
            },
        };

        let res = handle_command(&cli, |_| unreachable!()).await;
        assert!(
            res.is_err(),
            "Should return error when profile is not synced"
        );
        let err_msg = res.unwrap_err().to_string();
        assert!(
            err_msg
                .contains("No se ha sincronizado el perfil. Ejecuta 'silverwarden sync' primero."),
            "Expected profile sync error message, got: {err_msg}"
        );

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn test_cli_login_interactive_2fa_totp_success() {
        use wiremock::matchers::{body_string_contains, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let base_url = mock_server.uri();

        let email = "user2fa@example.com";
        let password = "password123";

        // Prelogin endpoint
        Mock::given(method("POST"))
            .and(path("/accounts/prelogin"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "kdf": 0,
                "kdfIterations": 10
            })))
            .mount(&mock_server)
            .await;

        let kdf_config = sw_crypto::KdfConfig {
            kdf_type: sw_crypto::KdfType::Pbkdf2,
            iterations: 10,
            memory: None,
            parallelism: None,
        };
        let master_key =
            sw_crypto::derive_master_key(password.as_bytes(), email, &kdf_config).unwrap();
        let stretched = sw_crypto::stretch_key(&master_key).unwrap();
        let synthetic_sym_key = [7u8; 64];
        let enc_key_wire = sw_crypto::encrypt_with_to_string(
            &synthetic_sym_key,
            sw_crypto::EncStringType::AesCbc256HmacSha256B64,
            &stretched,
        )
        .unwrap();

        // 1. Initial login fails with 2FA required challenge
        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .and(body_string_contains("grant_type=password"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "invalid_grant",
                "error_description": "Two-step verification required.",
                "TwoFactorProviders2": {
                    "0": {}
                },
                "twoFactorToken": "challenge_token_2fa_xyz"
            })))
            .up_to_n_times(1)
            .mount(&mock_server)
            .await;

        // 2. 2FA completion returns access token with encrypted key
        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .and(body_string_contains("twoFactorProvider=0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "mock_2fa_access_token_123",
                "expires_in": 3600,
                "token_type": "Bearer",
                "refresh_token": "mock_2fa_refresh_token_456",
                "key": enc_key_wire
            })))
            .mount(&mock_server)
            .await;

        let temp_dir = tempfile::tempdir().unwrap();
        let config_file_path = temp_dir.path().join("silverwarden.json");

        let initial_cfg = sw_config::ConfigFile {
            identity_url: base_url.clone(),
            api_url: base_url.clone(),
            ..Default::default()
        };
        initial_cfg.save_to_file(&config_file_path).unwrap();

        let cli = Cli {
            socket: Some(temp_dir.path().join("dummy.sock")),
            config: Some(config_file_path.clone()),
            insecure: false,
            command: Commands::Login {
                email: Some(email.to_string()),
                password: Some(password.to_string()),
                server: None,
                apikey: false,
                client_id: None,
                client_secret: None,
            },
        };

        let result = handle_command(&cli, |prompt_str| {
            if prompt_str.contains("Selecciona un método") {
                Ok("0".to_string())
            } else if prompt_str.contains("código de verificación") {
                Ok("123456".to_string())
            } else {
                Ok("".to_string())
            }
        })
        .await;

        assert!(
            result.is_ok(),
            "Interactive 2FA login should succeed: {:?}",
            result.err()
        );
        let msg = result.unwrap();
        assert!(msg.contains("Sesión iniciada con éxito"));

        let saved_cfg = sw_config::ConfigFile::load_from_file(&config_file_path).unwrap();
        assert!(saved_cfg.is_logged_in());
        assert!(!saved_cfg.encrypted_token.is_empty());
        assert!(!saved_cfg.encrypted_user_symmetric_key.is_empty());
    }

    #[tokio::test]
    async fn test_cli_login_api_key_success() {
        use wiremock::matchers::{body_string_contains, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let base_url = mock_server.uri();

        let email = "apiuser@example.com";
        let password = "masterpassword123";
        let client_id = "user.api_client_test";
        let client_secret = "secret_api_key_value";

        Mock::given(method("POST"))
            .and(path("/accounts/prelogin"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "kdf": 0,
                "kdfIterations": 10
            })))
            .mount(&mock_server)
            .await;

        let kdf_config = sw_crypto::KdfConfig {
            kdf_type: sw_crypto::KdfType::Pbkdf2,
            iterations: 10,
            memory: None,
            parallelism: None,
        };
        let master_key =
            sw_crypto::derive_master_key(password.as_bytes(), email, &kdf_config).unwrap();
        let stretched = sw_crypto::stretch_key(&master_key).unwrap();
        let synthetic_sym_key = [9u8; 64];
        let enc_key_wire = sw_crypto::encrypt_with_to_string(
            &synthetic_sym_key,
            sw_crypto::EncStringType::AesCbc256HmacSha256B64,
            &stretched,
        )
        .unwrap();

        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .and(body_string_contains("grant_type=client_credentials"))
            .and(body_string_contains("scope=api"))
            .and(body_string_contains("client_id=user.api_client_test"))
            .and(body_string_contains("client_secret=secret_api_key_value"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "mock_api_access_token",
                "expires_in": 3600,
                "token_type": "Bearer",
                "refresh_token": "mock_api_refresh_token",
                "key": enc_key_wire
            })))
            .mount(&mock_server)
            .await;

        let temp_dir = tempfile::tempdir().unwrap();
        let config_file_path = temp_dir.path().join("silverwarden.json");

        let initial_cfg = sw_config::ConfigFile {
            identity_url: base_url.clone(),
            api_url: base_url.clone(),
            ..Default::default()
        };
        initial_cfg.save_to_file(&config_file_path).unwrap();

        let cli = Cli {
            socket: Some(temp_dir.path().join("dummy.sock")),
            config: Some(config_file_path.clone()),
            insecure: false,
            command: Commands::Login {
                email: Some(email.to_string()),
                password: Some(password.to_string()),
                server: None,
                apikey: true,
                client_id: Some(client_id.to_string()),
                client_secret: Some(client_secret.to_string()),
            },
        };

        let result = handle_command(&cli, |_| unreachable!()).await;
        assert!(
            result.is_ok(),
            "API key login should succeed: {:?}",
            result.err()
        );
        let msg = result.unwrap();
        assert!(msg.contains("Sesión iniciada con éxito"));

        let saved_cfg = sw_config::ConfigFile::load_from_file(&config_file_path).unwrap();
        assert!(saved_cfg.is_logged_in());
        assert!(!saved_cfg.encrypted_token.is_empty());
        assert!(!saved_cfg.encrypted_user_symmetric_key.is_empty());

        let config_key = sw_config::derive_config_key_with_params(
            "",
            &saved_cfg.device_uuid,
            CLI_KDF_MEMORY_KIB,
        )
        .unwrap();
        assert_eq!(saved_cfg.decrypt_client_id(&config_key).unwrap(), client_id);
        assert_eq!(
            saved_cfg.decrypt_client_secret(&config_key).unwrap(),
            client_secret
        );
    }

    struct FailingReader;

    impl std::io::Read for FailingReader {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("simulated read failure"))
        }
    }

    impl std::io::BufRead for FailingReader {
        fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
            Err(std::io::Error::other("simulated read failure"))
        }

        fn consume(&mut self, _amt: usize) {}

        fn read_line(&mut self, _buf: &mut String) -> std::io::Result<usize> {
            Err(std::io::Error::other("simulated read failure"))
        }
    }

    struct FailingWriter;

    impl std::io::Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("simulated write failure"))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::other("simulated flush failure"))
        }
    }

    #[test]
    fn test_resolve_ssh_socket_path_non_home_parent() {
        let temp_dir = tempfile::tempdir().unwrap();
        let main_socket = temp_dir.path().join(".silverwarden.sock");
        let expected = temp_dir.path().join(".silverwarden-ssh-agent.sock");
        let resolved = resolve_ssh_socket_path(&main_socket);
        assert_eq!(resolved, expected);
        if let Ok(default_ssh) = sw_ssh_agent::default_ssh_agent_socket_path() {
            assert_ne!(resolved, default_ssh);
        }
    }

    #[test]
    fn test_resolve_ssh_socket_path_home_parent() {
        let home = match std::env::var("HOME") {
            Ok(h) => PathBuf::from(h),
            Err(_) => return,
        };
        let main_socket = home.join(".silverwarden.sock");
        let resolved = resolve_ssh_socket_path(&main_socket);
        let expected = sw_ssh_agent::default_ssh_agent_socket_path()
            .unwrap_or_else(|_| PathBuf::from(".silverwarden-ssh-agent.sock"));
        assert_eq!(resolved, expected);
    }

    #[test]
    fn test_resolve_config_path_env_override() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let _guard = EnvGuard::new("SILVERWARDEN_CONFIG_PATH");
        unsafe {
            std::env::set_var("SILVERWARDEN_CONFIG_PATH", "/tmp/test_override_config.json");
        }
        let resolved = resolve_config_path(None).expect("Should resolve override config path");
        assert_eq!(resolved, PathBuf::from("/tmp/test_override_config.json"));
    }

    #[test]
    fn test_parse_yes_no_variants() {
        let positive = [
            "s", "S", "si", "SI", "sí", "SÍ", "y", "Y", "yes", "YES", "Yes", " S ",
        ];
        for val in positive {
            assert!(parse_yes_no(val), "Expected '{val}' to parse as true");
        }

        let negative = ["n", "N", "no", "NO", "No", "", " ", "xyz", "true", "false"];
        for val in negative {
            assert!(!parse_yes_no(val), "Expected '{val}' to parse as false");
        }
    }

    #[test]
    fn test_prompt_from_io_read_error() {
        let mut reader = FailingReader;
        let mut writer = Vec::<u8>::new();
        let result = prompt_from_io(&mut reader, &mut writer, "Prompt: ");
        match result {
            Err(CliError::Io(msg)) => {
                assert!(msg.contains("simulated read failure"));
            }
            other => panic!("Expected CliError::Io, got: {:?}", other),
        }
        assert_eq!(String::from_utf8(writer).unwrap(), "Prompt: ");
    }

    #[test]
    fn test_resolve_config_path_missing_home() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let _cfg_guard = EnvGuard::new("SILVERWARDEN_CONFIG_PATH");
        let _home_guard = EnvGuard::new("HOME");

        unsafe {
            std::env::remove_var("SILVERWARDEN_CONFIG_PATH");
            std::env::remove_var("HOME");
        }

        let result = resolve_config_path(None);
        match result {
            Err(CliError::Config(msg)) => {
                assert!(msg.contains("No se pudo determinar $HOME"));
            }
            other => panic!(
                "Expected CliError::Config when HOME is missing, got: {:?}",
                other
            ),
        }
    }

    #[test]
    fn test_prompt_from_io_write_error() {
        let mut reader = std::io::Cursor::new(b"input\n");
        let mut writer = FailingWriter;
        let result = prompt_from_io(&mut reader, &mut writer, "Prompt: ");
        match result {
            Err(CliError::Io(msg)) => {
                assert!(msg.contains("simulated write failure"));
            }
            other => panic!("Expected CliError::Io, got: {:?}", other),
        }
    }

    #[test]
    fn test_resolve_config_path_custom_provided() {
        let custom = PathBuf::from("/custom/config/path.json");
        let resolved = resolve_config_path(Some(custom.clone())).unwrap();
        assert_eq!(resolved, custom);
    }

    #[test]
    fn test_resolve_ssh_socket_path_no_parent() {
        let path = Path::new("socket_without_parent");
        let resolved = resolve_ssh_socket_path(path);
        assert_eq!(resolved, PathBuf::from(".silverwarden-ssh-agent.sock"));
    }

    #[test]
    fn test_check_goldwarden_go_conflict_no_home() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let _home_guard = EnvGuard::new("HOME");
        unsafe {
            std::env::remove_var("HOME");
        }
        assert!(!check_goldwarden_go_conflict());
    }

    #[test]
    fn test_setup_config_flow_validation_errors() {
        let mut cfg = sw_config::ConfigFile::default();

        // Opción inválida
        let res = setup_config_flow(|_| Ok("99".to_string()), &mut cfg);
        assert!(res.is_err());
        match res.unwrap_err() {
            CliError::Other(msg) => assert!(msg.contains("Opción inválida")),
            e => panic!("Unexpected error: {:?}", e),
        }

        // Opción 2 con URL vacía
        let mut step = 0;
        let res = setup_config_flow(
            |_| {
                step += 1;
                if step == 1 {
                    Ok("2".to_string())
                } else {
                    Ok("   ".to_string())
                }
            },
            &mut cfg,
        );
        assert!(res.is_err());
        match res.unwrap_err() {
            CliError::Other(msg) => assert!(msg.contains("URL del servidor no puede estar vacía")),
            e => panic!("Unexpected error: {:?}", e),
        }

        // Opción 3 con Identity URL vacía
        let mut step3 = 0;
        let res = setup_config_flow(
            |_| {
                step3 += 1;
                if step3 == 1 {
                    Ok("3".to_string())
                } else {
                    Ok("".to_string())
                }
            },
            &mut cfg,
        );
        assert!(res.is_err());
        match res.unwrap_err() {
            CliError::Other(msg) => assert!(msg.contains("Identity URL no puede estar vacía")),
            e => panic!("Unexpected error: {:?}", e),
        }

        // Opción 3 con API URL vacía
        let mut step3_api = 0;
        let res = setup_config_flow(
            |_| {
                step3_api += 1;
                match step3_api {
                    1 => Ok("3".to_string()),
                    2 => Ok("https://identity.example.com".to_string()),
                    _ => Ok("".to_string()),
                }
            },
            &mut cfg,
        );
        assert!(res.is_err());
        match res.unwrap_err() {
            CliError::Other(msg) => assert!(msg.contains("API URL no puede estar vacía")),
            e => panic!("Unexpected error: {:?}", e),
        }

        // Opción 3 con Notifications URL vacía
        let mut step3_notif = 0;
        let res = setup_config_flow(
            |_| {
                step3_notif += 1;
                match step3_notif {
                    1 => Ok("3".to_string()),
                    2 => Ok("https://identity.example.com".to_string()),
                    3 => Ok("https://api.example.com".to_string()),
                    _ => Ok("".to_string()),
                }
            },
            &mut cfg,
        );
        assert!(res.is_err());
        match res.unwrap_err() {
            CliError::Other(msg) => {
                assert!(msg.contains("Notifications URL no puede estar vacía"))
            }
            e => panic!("Unexpected error: {:?}", e),
        }
    }

    #[test]
    fn test_format_sync_summary_additional_combinations() {
        assert_eq!(
            format_sync_summary(1, 0, 0, 1, 0, 0),
            "Sincronización completada: 1 elemento (1 nota)."
        );
        assert_eq!(
            format_sync_summary(1, 0, 0, 0, 1, 0),
            "Sincronización completada: 1 elemento (1 tarjeta)."
        );
        assert_eq!(
            format_sync_summary(1, 0, 0, 0, 0, 1),
            "Sincronización completada: 1 elemento (1 identidad)."
        );
        assert_eq!(
            format_sync_summary(2, 0, 0, 0, 0, 2),
            "Sincronización completada: 2 elementos (2 identidades)."
        );
        assert_eq!(
            format_sync_summary(2, 0, 0, 2, 0, 0),
            "Sincronización completada: 2 elementos (2 notas)."
        );
        assert_eq!(
            format_sync_summary(5, 0, 2, 0, 3, 0),
            "Sincronización completada: 5 elementos (2 claves SSH, 3 tarjetas)."
        );
        assert_eq!(
            format_sync_summary(3, 0, 0, 0, 0, 0),
            "Sincronización completada: 3 elementos."
        );
        assert_eq!(
            format_sync_summary(1, 0, 0, 0, 0, 0),
            "Sincronización completada: 1 elemento."
        );
    }

    #[tokio::test]
    async fn test_agent_start_terminates_on_agent_bind_failure() {
        let invalid_sock = PathBuf::from("/nonexistent/directory/never_exists/agent.sock");
        let cli = test_cli(
            Some(invalid_sock.clone()),
            Commands::Agent {
                action: AgentCommands::Start { no_ssh: true },
            },
        );
        let res = handle_command(&cli, |_| Ok(String::new())).await;
        assert!(res.is_ok());
        let msg = res.unwrap();
        assert!(msg.contains("Agente finalizado en"));
    }

    #[tokio::test]
    async fn test_agent_start_terminates_on_agent_and_ssh_failure() {
        let invalid_sock = PathBuf::from("/nonexistent/directory/never_exists/agent.sock");
        let cli = test_cli(
            Some(invalid_sock.clone()),
            Commands::Agent {
                action: AgentCommands::Start { no_ssh: false },
            },
        );
        let res = handle_command(&cli, |_| Ok(String::new())).await;
        assert!(res.is_ok());
        let msg = res.unwrap();
        assert!(msg.contains("Agente finalizado en"));
    }

    #[tokio::test]
    async fn test_config_set_empty_urls_validation() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cfg_path = temp_dir.path().join("silverwarden.json");

        let cli_srv = Cli {
            socket: None,
            config: Some(cfg_path.clone()),
            insecure: false,
            command: Commands::Config {
                action: ConfigCommands::SetServer {
                    url: "   ".to_string(),
                },
            },
        };
        let err_srv = handle_command(&cli_srv, |_| Ok(String::new()))
            .await
            .unwrap_err();
        match err_srv {
            CliError::Other(msg) => {
                assert!(msg.contains("La URL del servidor no puede estar vacía"))
            }
            other => panic!("Unexpected error: {:?}", other),
        }

        let cli_id = Cli {
            socket: None,
            config: Some(cfg_path.clone()),
            insecure: false,
            command: Commands::Config {
                action: ConfigCommands::SetIdentity {
                    url: "".to_string(),
                },
            },
        };
        let err_id = handle_command(&cli_id, |_| Ok(String::new()))
            .await
            .unwrap_err();
        match err_id {
            CliError::Other(msg) => {
                assert!(msg.contains("La URL de identity no puede estar vacía"))
            }
            other => panic!("Unexpected error: {:?}", other),
        }

        let cli_api = Cli {
            socket: None,
            config: Some(cfg_path.clone()),
            insecure: false,
            command: Commands::Config {
                action: ConfigCommands::SetApi {
                    url: "  ".to_string(),
                },
            },
        };
        let err_api = handle_command(&cli_api, |_| Ok(String::new()))
            .await
            .unwrap_err();
        match err_api {
            CliError::Other(msg) => assert!(msg.contains("La URL de API no puede estar vacía")),
            other => panic!("Unexpected error: {:?}", other),
        }

        let cli_notif = Cli {
            socket: None,
            config: Some(cfg_path.clone()),
            insecure: false,
            command: Commands::Config {
                action: ConfigCommands::SetNotifications {
                    url: "".to_string(),
                },
            },
        };
        let err_notif = handle_command(&cli_notif, |_| Ok(String::new()))
            .await
            .unwrap_err();
        match err_notif {
            CliError::Other(msg) => {
                assert!(msg.contains("La URL de notifications no puede estar vacía"))
            }
            other => panic!("Unexpected error: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_ssh_subcommands() {
        let cli_list = Cli {
            socket: None,
            config: None,
            insecure: false,
            command: Commands::Ssh {
                ssh_command: SshCommands::List,
            },
        };
        let res_list = handle_command(&cli_list, |_| Ok(String::new()))
            .await
            .unwrap();
        assert!(res_list.contains("Listando claves SSH"));

        let cli_add_empty = Cli {
            socket: None,
            config: None,
            insecure: false,
            command: Commands::Ssh {
                ssh_command: SshCommands::Add {
                    key_id: "  ".to_string(),
                },
            },
        };
        let err_add = handle_command(&cli_add_empty, |_| Ok(String::new()))
            .await
            .unwrap_err();
        match err_add {
            CliError::Other(msg) => {
                assert!(msg.contains("El nombre de la clave SSH no puede estar vacío"))
            }
            other => panic!("Unexpected error: {:?}", other),
        }

        let cli_add_ok = Cli {
            socket: None,
            config: None,
            insecure: false,
            command: Commands::Ssh {
                ssh_command: SshCommands::Add {
                    key_id: "id_ed25519".to_string(),
                },
            },
        };
        let res_add = handle_command(&cli_add_ok, |_| Ok(String::new()))
            .await
            .unwrap();
        assert!(res_add.contains("Registrando clave SSH id_ed25519"));
    }

    #[tokio::test]
    async fn test_cli_login_2fa_email_provider_success() {
        use wiremock::matchers::{body_string_contains, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let base_url = mock_server.uri();

        let email = "user_email_2fa@example.com";
        let password = "password123";

        Mock::given(method("POST"))
            .and(path("/accounts/prelogin"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "kdf": 0,
                "kdfIterations": 10
            })))
            .mount(&mock_server)
            .await;

        let kdf_config = sw_crypto::KdfConfig {
            kdf_type: sw_crypto::KdfType::Pbkdf2,
            iterations: 10,
            memory: None,
            parallelism: None,
        };
        let master_key =
            sw_crypto::derive_master_key(password.as_bytes(), email, &kdf_config).unwrap();
        let stretched = sw_crypto::stretch_key(&master_key).unwrap();
        let synthetic_sym_key = [7u8; 64];
        let enc_key_wire = sw_crypto::encrypt_with_to_string(
            &synthetic_sym_key,
            sw_crypto::EncStringType::AesCbc256HmacSha256B64,
            &stretched,
        )
        .unwrap();

        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .and(body_string_contains("grant_type=password"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "invalid_grant",
                "error_description": "Two-step verification required.",
                "TwoFactorProviders2": {
                    "0": {},
                    "1": {}
                },
                "twoFactorToken": "challenge_token_email_2fa"
            })))
            .up_to_n_times(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/two-factor/send-email-login"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .and(body_string_contains("twoFactorProvider=1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "mock_email_2fa_access_token",
                "expires_in": 3600,
                "token_type": "Bearer",
                "refresh_token": "mock_email_2fa_refresh",
                "key": enc_key_wire
            })))
            .mount(&mock_server)
            .await;

        let temp_dir = tempfile::tempdir().unwrap();
        let config_file_path = temp_dir.path().join("silverwarden.json");

        let initial_cfg = sw_config::ConfigFile {
            identity_url: base_url.clone(),
            api_url: base_url.clone(),
            ..Default::default()
        };
        initial_cfg.save_to_file(&config_file_path).unwrap();

        let cli = Cli {
            socket: Some(temp_dir.path().join("dummy.sock")),
            config: Some(config_file_path.clone()),
            insecure: false,
            command: Commands::Login {
                email: Some(email.to_string()),
                password: Some(password.to_string()),
                server: None,
                apikey: false,
                client_id: None,
                client_secret: None,
            },
        };

        let result = handle_command(&cli, |prompt_str| {
            if prompt_str.contains("Selecciona un método") {
                Ok("1".to_string())
            } else if prompt_str.contains("código de verificación") {
                Ok("654321".to_string())
            } else {
                Ok("".to_string())
            }
        })
        .await;

        assert!(result.is_ok(), "Email 2FA login failed: {:?}", result.err());
    }

    #[tokio::test]
    async fn test_cli_login_2fa_email_send_fails_but_continues() {
        use wiremock::matchers::{body_string_contains, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let base_url = mock_server.uri();

        let email = "user_email_send_fail@example.com";
        let password = "password123";

        Mock::given(method("POST"))
            .and(path("/accounts/prelogin"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "kdf": 0,
                "kdfIterations": 10
            })))
            .mount(&mock_server)
            .await;

        let kdf_config = sw_crypto::KdfConfig {
            kdf_type: sw_crypto::KdfType::Pbkdf2,
            iterations: 10,
            memory: None,
            parallelism: None,
        };
        let master_key =
            sw_crypto::derive_master_key(password.as_bytes(), email, &kdf_config).unwrap();
        let stretched = sw_crypto::stretch_key(&master_key).unwrap();
        let synthetic_sym_key = [7u8; 64];
        let enc_key_wire = sw_crypto::encrypt_with_to_string(
            &synthetic_sym_key,
            sw_crypto::EncStringType::AesCbc256HmacSha256B64,
            &stretched,
        )
        .unwrap();

        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .and(body_string_contains("grant_type=password"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "invalid_grant",
                "error_description": "Two-step verification required.",
                "TwoFactorProviders2": {
                    "1": {}
                },
                "twoFactorToken": "challenge_token_email_fail"
            })))
            .up_to_n_times(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/two-factor/send-email-login"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal error sending mail"))
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .and(body_string_contains("twoFactorProvider=1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "mock_token",
                "expires_in": 3600,
                "token_type": "Bearer",
                "refresh_token": "mock_refresh",
                "key": enc_key_wire
            })))
            .mount(&mock_server)
            .await;

        let temp_dir = tempfile::tempdir().unwrap();
        let config_file_path = temp_dir.path().join("silverwarden.json");

        let initial_cfg = sw_config::ConfigFile {
            identity_url: base_url.clone(),
            api_url: base_url.clone(),
            ..Default::default()
        };
        initial_cfg.save_to_file(&config_file_path).unwrap();

        let cli = Cli {
            socket: Some(temp_dir.path().join("dummy.sock")),
            config: Some(config_file_path.clone()),
            insecure: false,
            command: Commands::Login {
                email: Some(email.to_string()),
                password: Some(password.to_string()),
                server: None,
                apikey: false,
                client_id: None,
                client_secret: None,
            },
        };

        let result = handle_command(&cli, |prompt_str| {
            if prompt_str.contains("Selecciona un método") {
                Ok("1".to_string())
            } else if prompt_str.contains("código de verificación") {
                Ok("111222".to_string())
            } else {
                Ok("".to_string())
            }
        })
        .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_cli_login_2fa_invalid_provider_falls_back_to_totp() {
        use wiremock::matchers::{body_string_contains, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let base_url = mock_server.uri();

        let email = "user_fallback@example.com";
        let password = "password123";

        Mock::given(method("POST"))
            .and(path("/accounts/prelogin"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "kdf": 0,
                "kdfIterations": 10
            })))
            .mount(&mock_server)
            .await;

        let kdf_config = sw_crypto::KdfConfig {
            kdf_type: sw_crypto::KdfType::Pbkdf2,
            iterations: 10,
            memory: None,
            parallelism: None,
        };
        let master_key =
            sw_crypto::derive_master_key(password.as_bytes(), email, &kdf_config).unwrap();
        let stretched = sw_crypto::stretch_key(&master_key).unwrap();
        let synthetic_sym_key = [7u8; 64];
        let enc_key_wire = sw_crypto::encrypt_with_to_string(
            &synthetic_sym_key,
            sw_crypto::EncStringType::AesCbc256HmacSha256B64,
            &stretched,
        )
        .unwrap();

        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .and(body_string_contains("grant_type=password"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "invalid_grant",
                "error_description": "Two-step verification required.",
                "TwoFactorProviders2": {
                    "0": {}
                },
                "twoFactorToken": "challenge_token_fallback"
            })))
            .up_to_n_times(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .and(body_string_contains("twoFactorProvider=0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "mock_token",
                "expires_in": 3600,
                "token_type": "Bearer",
                "refresh_token": "mock_refresh",
                "key": enc_key_wire
            })))
            .mount(&mock_server)
            .await;

        let temp_dir = tempfile::tempdir().unwrap();
        let config_file_path = temp_dir.path().join("silverwarden.json");

        let initial_cfg = sw_config::ConfigFile {
            identity_url: base_url.clone(),
            api_url: base_url.clone(),
            ..Default::default()
        };
        initial_cfg.save_to_file(&config_file_path).unwrap();

        let cli = Cli {
            socket: Some(temp_dir.path().join("dummy.sock")),
            config: Some(config_file_path.clone()),
            insecure: false,
            command: Commands::Login {
                email: Some(email.to_string()),
                password: Some(password.to_string()),
                server: None,
                apikey: false,
                client_id: None,
                client_secret: None,
            },
        };

        let result = handle_command(&cli, |prompt_str| {
            if prompt_str.contains("Selecciona un método") {
                Ok("invalid_provider".to_string())
            } else if prompt_str.contains("código de verificación") {
                Ok("123456".to_string())
            } else {
                Ok("".to_string())
            }
        })
        .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_cli_login_2fa_code_invalid() {
        use wiremock::matchers::{body_string_contains, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let base_url = mock_server.uri();

        let email = "user_bad_code@example.com";
        let password = "password123";

        Mock::given(method("POST"))
            .and(path("/accounts/prelogin"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "kdf": 0,
                "kdfIterations": 10
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .and(body_string_contains("grant_type=password"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "invalid_grant",
                "error_description": "Two-step verification required.",
                "TwoFactorProviders2": {
                    "0": {}
                },
                "twoFactorToken": "challenge_token_bad_code"
            })))
            .up_to_n_times(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .and(body_string_contains("twoFactorProvider=0"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "invalid_grant",
                "error_description": "Invalid two-step verification code."
            })))
            .mount(&mock_server)
            .await;

        let temp_dir = tempfile::tempdir().unwrap();
        let config_file_path = temp_dir.path().join("silverwarden.json");

        let initial_cfg = sw_config::ConfigFile {
            identity_url: base_url.clone(),
            api_url: base_url.clone(),
            ..Default::default()
        };
        initial_cfg.save_to_file(&config_file_path).unwrap();

        let cli = Cli {
            socket: Some(temp_dir.path().join("dummy.sock")),
            config: Some(config_file_path.clone()),
            insecure: false,
            command: Commands::Login {
                email: Some(email.to_string()),
                password: Some(password.to_string()),
                server: None,
                apikey: false,
                client_id: None,
                client_secret: None,
            },
        };

        let result = handle_command(&cli, |prompt_str| {
            if prompt_str.contains("Selecciona un método") {
                Ok("0".to_string())
            } else if prompt_str.contains("código de verificación") {
                Ok("000000".to_string())
            } else {
                Ok("".to_string())
            }
        })
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_cli_login_empty_server_flag() {
        let cli = Cli {
            socket: None,
            config: None,
            insecure: false,
            command: Commands::Login {
                email: Some("test@example.com".to_string()),
                password: Some("password".to_string()),
                server: Some("   ".to_string()),
                apikey: false,
                client_id: None,
                client_secret: None,
            },
        };
        let res = handle_command(&cli, |_| Ok(String::new())).await;
        assert!(res.is_err());
        match res.unwrap_err() {
            CliError::Other(msg) => {
                assert!(msg.contains("La URL del servidor no puede estar vacía"))
            }
            other => panic!("Unexpected error: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_cli_login_apikey_from_env_vars() {
        use wiremock::matchers::{body_string_contains, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let _lock = ASYNC_ENV_MUTEX.lock().await;
        let _g_cid = EnvGuard::new("BW_CLIENTID");
        let _g_csec = EnvGuard::new("BW_CLIENTSECRET");
        let _g_em = EnvGuard::new("BW_EMAIL");
        let _g_pw = EnvGuard::new("BW_PASSWORD");

        unsafe {
            std::env::set_var("BW_CLIENTID", "user.env_cid");
            std::env::set_var("BW_CLIENTSECRET", "env_secret_123");
            std::env::set_var("BW_EMAIL", "env_user@example.com");
            std::env::set_var("BW_PASSWORD", "env_password_456");
        }

        let mock_server = MockServer::start().await;
        let base_url = mock_server.uri();

        Mock::given(method("POST"))
            .and(path("/accounts/prelogin"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "kdf": 0,
                "kdfIterations": 10
            })))
            .mount(&mock_server)
            .await;

        let kdf_config = sw_crypto::KdfConfig {
            kdf_type: sw_crypto::KdfType::Pbkdf2,
            iterations: 10,
            memory: None,
            parallelism: None,
        };
        let master_key =
            sw_crypto::derive_master_key(b"env_password_456", "env_user@example.com", &kdf_config)
                .unwrap();
        let stretched = sw_crypto::stretch_key(&master_key).unwrap();
        let synthetic_sym_key = [9u8; 64];
        let enc_key_wire = sw_crypto::encrypt_with_to_string(
            &synthetic_sym_key,
            sw_crypto::EncStringType::AesCbc256HmacSha256B64,
            &stretched,
        )
        .unwrap();

        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .and(body_string_contains("grant_type=client_credentials"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "apikey_access_token_env",
                "expires_in": 3600,
                "token_type": "Bearer",
                "refresh_token": "apikey_refresh_token_env",
                "key": enc_key_wire
            })))
            .mount(&mock_server)
            .await;

        let temp_dir = tempfile::tempdir().unwrap();
        let config_file_path = temp_dir.path().join("silverwarden.json");

        let initial_cfg = sw_config::ConfigFile {
            identity_url: base_url.clone(),
            api_url: base_url.clone(),
            ..Default::default()
        };
        initial_cfg.save_to_file(&config_file_path).unwrap();

        let cli = Cli {
            socket: Some(temp_dir.path().join("dummy.sock")),
            config: Some(config_file_path.clone()),
            insecure: false,
            command: Commands::Login {
                email: None,
                password: None,
                server: None,
                apikey: true,
                client_id: None,
                client_secret: None,
            },
        };

        let result = handle_command(&cli, |_| unreachable!()).await;
        assert!(
            result.is_ok(),
            "ApiKey login from env failed: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_cli_login_apikey_prompts_missing_credentials() {
        use wiremock::matchers::{body_string_contains, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let _lock = ASYNC_ENV_MUTEX.lock().await;
        let _g_cid = EnvGuard::new("BW_CLIENTID");
        let _g_csec = EnvGuard::new("BW_CLIENTSECRET");
        let _g_em = EnvGuard::new("BW_EMAIL");
        let _g_pw = EnvGuard::new("BW_PASSWORD");

        unsafe {
            std::env::remove_var("BW_CLIENTID");
            std::env::remove_var("BW_CLIENTSECRET");
            std::env::remove_var("BW_EMAIL");
            std::env::remove_var("BW_PASSWORD");
        }

        let mock_server = MockServer::start().await;
        let base_url = mock_server.uri();

        Mock::given(method("POST"))
            .and(path("/accounts/prelogin"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "kdf": 0,
                "kdfIterations": 10
            })))
            .mount(&mock_server)
            .await;

        let kdf_config = sw_crypto::KdfConfig {
            kdf_type: sw_crypto::KdfType::Pbkdf2,
            iterations: 10,
            memory: None,
            parallelism: None,
        };
        let master_key =
            sw_crypto::derive_master_key(b"prompt_pwd", "prompt_user@example.com", &kdf_config)
                .unwrap();
        let stretched = sw_crypto::stretch_key(&master_key).unwrap();
        let synthetic_sym_key = [3u8; 64];
        let enc_key_wire = sw_crypto::encrypt_with_to_string(
            &synthetic_sym_key,
            sw_crypto::EncStringType::AesCbc256HmacSha256B64,
            &stretched,
        )
        .unwrap();

        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .and(body_string_contains("grant_type=client_credentials"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "apikey_access_token_prompt",
                "expires_in": 3600,
                "token_type": "Bearer",
                "refresh_token": "apikey_refresh_token_prompt",
                "key": enc_key_wire
            })))
            .mount(&mock_server)
            .await;

        let temp_dir = tempfile::tempdir().unwrap();
        let config_file_path = temp_dir.path().join("silverwarden.json");

        let initial_cfg = sw_config::ConfigFile {
            identity_url: base_url.clone(),
            api_url: base_url.clone(),
            ..Default::default()
        };
        initial_cfg.save_to_file(&config_file_path).unwrap();

        let cli = Cli {
            socket: Some(temp_dir.path().join("dummy.sock")),
            config: Some(config_file_path.clone()),
            insecure: false,
            command: Commands::Login {
                email: None,
                password: None,
                server: None,
                apikey: true,
                client_id: None,
                client_secret: None,
            },
        };

        let result = handle_command(&cli, |prompt_str| {
            if prompt_str.contains("client_id") {
                Ok("prompt_cid".to_string())
            } else if prompt_str.contains("client_secret") {
                Ok("prompt_csec".to_string())
            } else if prompt_str.contains("email") {
                Ok("prompt_user@example.com".to_string())
            } else if prompt_str.contains("contraseña") {
                Ok("prompt_pwd".to_string())
            } else {
                Ok("".to_string())
            }
        })
        .await;

        assert!(
            result.is_ok(),
            "ApiKey login with prompts failed: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_cli_login_with_existing_pin_unlocks_config_or_fails() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let base_url = mock_server.uri();

        Mock::given(method("POST"))
            .and(path("/accounts/prelogin"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "kdf": 0,
                "kdfIterations": 10
            })))
            .mount(&mock_server)
            .await;

        let kdf_config = sw_crypto::KdfConfig {
            kdf_type: sw_crypto::KdfType::Pbkdf2,
            iterations: 10,
            memory: None,
            parallelism: None,
        };
        let master_key =
            sw_crypto::derive_master_key(b"password", "user@example.com", &kdf_config).unwrap();
        let stretched = sw_crypto::stretch_key(&master_key).unwrap();
        let synthetic_sym_key = [4u8; 64];
        let enc_key_wire = sw_crypto::encrypt_with_to_string(
            &synthetic_sym_key,
            sw_crypto::EncStringType::AesCbc256HmacSha256B64,
            &stretched,
        )
        .unwrap();

        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "access_token_pin",
                "expires_in": 3600,
                "token_type": "Bearer",
                "refresh_token": "refresh_pin",
                "key": enc_key_wire
            })))
            .mount(&mock_server)
            .await;

        let temp_dir = tempfile::tempdir().unwrap();
        let config_file_path = temp_dir.path().join("silverwarden.json");

        let mut initial_cfg = sw_config::ConfigFile {
            identity_url: base_url.clone(),
            api_url: base_url.clone(),
            ..Default::default()
        };
        let pin_key = sw_config::derive_config_key_with_params(
            "1234",
            &initial_cfg.device_uuid,
            CLI_KDF_MEMORY_KIB,
        )
        .unwrap();
        initial_cfg.config_key_hash = sw_config::hash_config_key(&pin_key);
        initial_cfg.save_to_file(&config_file_path).unwrap();

        let cli = Cli {
            socket: Some(temp_dir.path().join("dummy.sock")),
            config: Some(config_file_path.clone()),
            insecure: false,
            command: Commands::Login {
                email: Some("user@example.com".to_string()),
                password: Some("password".to_string()),
                server: None,
                apikey: false,
                client_id: None,
                client_secret: None,
            },
        };

        let res_err = handle_command(&cli, |_| Ok("wrong_pin".to_string())).await;
        assert!(res_err.is_err());
        match res_err.unwrap_err() {
            CliError::Config(msg) => assert!(msg.contains("PIN incorrecto")),
            other => panic!("Unexpected error: {:?}", other),
        }

        let res_ok = handle_command(&cli, |_| Ok("1234".to_string())).await;
        assert!(res_ok.is_ok());
    }

    #[tokio::test]
    async fn test_cli_sync_rate_limit_exceeded() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let base_url = mock_server.uri();

        Mock::given(method("GET"))
            .and(path("/sync"))
            .respond_with(ResponseTemplate::new(429).set_body_string("Rate limit exceeded"))
            .mount(&mock_server)
            .await;

        let temp_dir = tempfile::tempdir().unwrap();
        let config_file_path = temp_dir.path().join("silverwarden.json");

        let mut cfg = sw_config::ConfigFile {
            identity_url: base_url.clone(),
            api_url: base_url.clone(),
            ..Default::default()
        };
        let config_key =
            sw_config::derive_config_key_with_params("", &cfg.device_uuid, CLI_KDF_MEMORY_KIB)
                .unwrap();
        cfg.set_token(
            &sw_config::LoginToken {
                access_token: "test_token".to_string(),
                expires_in: 3600,
                token_type: "Bearer".to_string(),
                refresh_token: "refresh".to_string(),
                ..Default::default()
            },
            &config_key,
        )
        .unwrap();
        cfg.save_to_file(&config_file_path).unwrap();

        let cli = Cli {
            socket: Some(temp_dir.path().join("dummy.sock")),
            config: Some(config_file_path),
            insecure: true,
            command: Commands::Sync,
        };

        let res = handle_command(&cli, |_| unreachable!()).await;
        assert!(res.is_err());
        match res.unwrap_err() {
            CliError::Other(msg) => assert!(msg.contains("bloqueado temporalmente")),
            other => panic!("Unexpected error: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_cli_sync_server_error() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let base_url = mock_server.uri();

        Mock::given(method("GET"))
            .and(path("/sync"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal server error"))
            .mount(&mock_server)
            .await;

        let temp_dir = tempfile::tempdir().unwrap();
        let config_file_path = temp_dir.path().join("silverwarden.json");

        let mut cfg = sw_config::ConfigFile {
            identity_url: base_url.clone(),
            api_url: base_url.clone(),
            ..Default::default()
        };
        let config_key =
            sw_config::derive_config_key_with_params("", &cfg.device_uuid, CLI_KDF_MEMORY_KIB)
                .unwrap();
        cfg.set_token(
            &sw_config::LoginToken {
                access_token: "test_token".to_string(),
                expires_in: 3600,
                token_type: "Bearer".to_string(),
                refresh_token: "refresh".to_string(),
                ..Default::default()
            },
            &config_key,
        )
        .unwrap();
        cfg.save_to_file(&config_file_path).unwrap();

        let cli = Cli {
            socket: Some(temp_dir.path().join("dummy.sock")),
            config: Some(config_file_path),
            insecure: true,
            command: Commands::Sync,
        };

        let res = handle_command(&cli, |_| unreachable!()).await;
        assert!(res.is_err());
        match res.unwrap_err() {
            CliError::Other(msg) => assert!(msg.contains("Error al sincronizar con el servidor")),
            other => panic!("Unexpected error: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_cli_sync_with_pin_prompt_wrong_and_correct() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let base_url = mock_server.uri();

        Mock::given(method("GET"))
            .and(path("/sync"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "profile": { "id": "22cadb2c-d706-471a-a3e9-9fb725925639", "email": "test@test.com" },
                "ciphers": []
            })))
            .mount(&mock_server)
            .await;

        let temp_dir = tempfile::tempdir().unwrap();
        let config_file_path = temp_dir.path().join("silverwarden.json");

        let mut cfg = sw_config::ConfigFile {
            identity_url: base_url.clone(),
            api_url: base_url.clone(),
            ..Default::default()
        };
        let config_key =
            sw_config::derive_config_key_with_params("4321", &cfg.device_uuid, CLI_KDF_MEMORY_KIB)
                .unwrap();
        cfg.config_key_hash = sw_config::hash_config_key(&config_key);
        cfg.set_token(
            &sw_config::LoginToken {
                access_token: "test_token".to_string(),
                expires_in: 3600,
                token_type: "Bearer".to_string(),
                refresh_token: "refresh".to_string(),
                ..Default::default()
            },
            &config_key,
        )
        .unwrap();
        cfg.save_to_file(&config_file_path).unwrap();

        let cli = Cli {
            socket: Some(temp_dir.path().join("dummy.sock")),
            config: Some(config_file_path),
            insecure: true,
            command: Commands::Sync,
        };

        let res_err = handle_command(&cli, |_| Ok("wrong".to_string())).await;
        assert!(res_err.is_err());
        match res_err.unwrap_err() {
            CliError::Config(msg) => assert!(msg.contains("PIN incorrecto")),
            other => panic!("Unexpected error: {:?}", other),
        }

        let res_ok = handle_command(&cli, |_| Ok("4321".to_string())).await;
        assert!(res_ok.is_ok());
    }

    #[tokio::test]
    async fn test_cli_logins_empty_name_validations() {
        let cli_get = Cli {
            socket: None,
            config: None,
            insecure: false,
            command: Commands::Logins {
                action: Some(LoginsCommands::Get {
                    name: "   ".to_string(),
                }),
                filter: None,
            },
        };
        let err_get = handle_command(&cli_get, |_| Ok(String::new()))
            .await
            .unwrap_err();
        match err_get {
            CliError::Other(msg) => assert!(msg.contains("El nombre no puede estar vacío")),
            other => panic!("Unexpected error: {:?}", other),
        }

        let cli_del = Cli {
            socket: None,
            config: None,
            insecure: false,
            command: Commands::Logins {
                action: Some(LoginsCommands::Delete {
                    name: "".to_string(),
                }),
                filter: None,
            },
        };
        let err_del = handle_command(&cli_del, |_| Ok(String::new()))
            .await
            .unwrap_err();
        match err_del {
            CliError::Other(msg) => assert!(msg.contains("El nombre no puede estar vacío")),
            other => panic!("Unexpected error: {:?}", other),
        }

        let cli_create = Cli {
            socket: None,
            config: None,
            insecure: false,
            command: Commands::Logins {
                action: Some(LoginsCommands::Create {
                    name: "  ".to_string(),
                    username: "u".to_string(),
                    password: "p".to_string(),
                }),
                filter: None,
            },
        };
        let err_create = handle_command(&cli_create, |_| Ok(String::new()))
            .await
            .unwrap_err();
        match err_create {
            CliError::Other(msg) => assert!(msg.contains("El nombre no puede estar vacío")),
            other => panic!("Unexpected error: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_cli_logins_create_error_payload_propagates() {
        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("agent.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();

        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                if let Ok(msg) = sw_ipc::read_message(&mut stream).await {
                    assert_eq!(msg.action, "CreateLogin");
                    let resp = IpcMessage::new(
                        "CreateLogin",
                        serde_json::json!({
                            "status": "error",
                            "error": "Error interno al crear cipher"
                        }),
                    );
                    let _ = sw_ipc::write_message(&mut stream, &resp).await;
                }
            }
        });

        let cli = Cli {
            socket: Some(socket_path),
            config: None,
            insecure: false,
            command: Commands::Logins {
                action: Some(LoginsCommands::Create {
                    name: "test".to_string(),
                    username: "user".to_string(),
                    password: "pwd".to_string(),
                }),
                filter: None,
            },
        };

        let err = handle_command(&cli, |_| Ok(String::new()))
            .await
            .unwrap_err();
        match err {
            CliError::AgentError(msg) => assert!(msg.contains("Error interno al crear cipher")),
            other => panic!("Unexpected error: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_cli_logins_list_filter_matches_and_no_matches() {
        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("agent.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();

        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                if let Ok(msg) = sw_ipc::read_message(&mut stream).await {
                    if msg.action == "ListLogins" {
                        let resp = IpcMessage::new(
                            "ListLogins",
                            serde_json::json!([
                                { "name": "GitHub", "username": "octocat" },
                                { "name": "Google", "username": "alice@gmail.com" }
                            ]),
                        );
                        let _ = sw_ipc::write_message(&mut stream, &resp).await;
                    }
                }
            }
        });

        let cli_match = Cli {
            socket: Some(socket_path.clone()),
            config: None,
            insecure: false,
            command: Commands::Logins {
                action: Some(LoginsCommands::List),
                filter: Some("octocat".to_string()),
            },
        };
        let out_match = handle_command(&cli_match, |_| Ok(String::new()))
            .await
            .unwrap();
        assert!(out_match.contains("GitHub"));
        assert!(!out_match.contains("Google"));

        let cli_match_name = Cli {
            socket: Some(socket_path.clone()),
            config: None,
            insecure: false,
            command: Commands::Logins {
                action: Some(LoginsCommands::List),
                filter: Some("goog".to_string()),
            },
        };
        let out_match_name = handle_command(&cli_match_name, |_| Ok(String::new()))
            .await
            .unwrap();
        assert!(out_match_name.contains("Google"));
        assert!(!out_match_name.contains("GitHub"));

        let cli_no_match = Cli {
            socket: Some(socket_path),
            config: None,
            insecure: false,
            command: Commands::Logins {
                action: Some(LoginsCommands::List),
                filter: Some("nonexistent".to_string()),
            },
        };
        let out_no_match = handle_command(&cli_no_match, |_| Ok(String::new()))
            .await
            .unwrap();
        assert!(out_no_match.contains("No se encontraron accesos guardados."));
    }

    #[tokio::test]
    async fn test_cli_unlock_with_corrupt_config_ignores_and_proceeds() {
        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("agent.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();

        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                if let Ok(msg) = sw_ipc::read_message(&mut stream).await {
                    assert_eq!(msg.action, "Unlock");
                    assert_eq!(msg.payload.get("pin").unwrap(), "1234");
                    assert!(msg.payload.get("encrypted_token").is_none());
                    let resp = IpcMessage::new("Unlock", serde_json::json!({ "unlocked": true }));
                    let _ = sw_ipc::write_message(&mut stream, &resp).await;
                }
            }
        });

        let config_file_path = temp_dir.path().join("silverwarden.json");
        std::fs::write(&config_file_path, b"INVALID JSON CONTENT { [ }").unwrap();

        let cli = Cli {
            socket: Some(socket_path),
            config: Some(config_file_path),
            insecure: false,
            command: Commands::Unlock {
                pin: Some("1234".to_string()),
            },
        };

        let res = handle_command(&cli, |_| Ok(String::new())).await;
        assert!(res.is_ok());
        assert!(res.unwrap().contains("Bóveda desbloqueada con éxito"));
    }

    #[tokio::test]
    async fn test_cli_pin_commands_interactive_prompts() {
        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("agent.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();

        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                if let Ok(msg) = sw_ipc::read_message(&mut stream).await {
                    if msg.action == "PinSet" {
                        assert_eq!(msg.payload.get("pin").unwrap(), "5555");
                        let resp =
                            IpcMessage::new("PinSet", serde_json::json!({ "success": true }));
                        let _ = sw_ipc::write_message(&mut stream, &resp).await;
                    } else if msg.action == "PinUpdate" {
                        assert_eq!(msg.payload.get("old_pin").unwrap(), "5555");
                        assert_eq!(msg.payload.get("new_pin").unwrap(), "6666");
                        let resp =
                            IpcMessage::new("PinUpdate", serde_json::json!({ "success": true }));
                        let _ = sw_ipc::write_message(&mut stream, &resp).await;
                    }
                }
            }
        });

        let cli_set = Cli {
            socket: Some(socket_path.clone()),
            config: None,
            insecure: false,
            command: Commands::Pin {
                action: PinCommands::Set { pin: None },
            },
        };
        let res_set = handle_command(&cli_set, |_| Ok("5555".to_string()))
            .await
            .unwrap();
        assert!(res_set.contains("PIN configurado exitosamente"));

        let cli_upd = Cli {
            socket: Some(socket_path),
            config: None,
            insecure: false,
            command: Commands::Pin {
                action: PinCommands::Update {
                    old_pin: None,
                    new_pin: None,
                },
            },
        };
        let mut upd_count = 0;
        let res_upd = handle_command(&cli_upd, |_| {
            upd_count += 1;
            if upd_count == 1 {
                Ok("5555".to_string())
            } else {
                Ok("6666".to_string())
            }
        })
        .await
        .unwrap();
        assert!(res_upd.contains("PIN actualizado exitosamente"));
    }

    #[tokio::test]
    async fn test_send_command_agent_error_primitive_payload() {
        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("agent.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();

        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                if sw_ipc::read_message(&mut stream).await.is_ok() {
                    let resp = IpcMessage::new("Error", serde_json::json!(500));
                    let _ = sw_ipc::write_message(&mut stream, &resp).await;
                }
            }
        });

        let res = send_command(&socket_path, "Ping", serde_json::json!({})).await;
        assert!(res.is_err());
        match res.unwrap_err() {
            CliError::AgentError(msg) => assert_eq!(msg, "500"),
            other => panic!("Unexpected error: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_cli_login_with_env_email_and_password() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let _lock = ASYNC_ENV_MUTEX.lock().await;
        let _g_em = EnvGuard::new("BW_EMAIL");
        let _g_pw = EnvGuard::new("BW_PASSWORD");

        unsafe {
            std::env::set_var("BW_EMAIL", "env_login_user@example.com");
            std::env::set_var("BW_PASSWORD", "env_login_pwd_123");
        }

        let mock_server = MockServer::start().await;
        let base_url = mock_server.uri();

        Mock::given(method("POST"))
            .and(path("/accounts/prelogin"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "kdf": 0,
                "kdfIterations": 10
            })))
            .mount(&mock_server)
            .await;

        let kdf_config = sw_crypto::KdfConfig {
            kdf_type: sw_crypto::KdfType::Pbkdf2,
            iterations: 10,
            memory: None,
            parallelism: None,
        };
        let master_key = sw_crypto::derive_master_key(
            b"env_login_pwd_123",
            "env_login_user@example.com",
            &kdf_config,
        )
        .unwrap();
        let stretched = sw_crypto::stretch_key(&master_key).unwrap();
        let synthetic_sym_key = [1u8; 64];
        let enc_key_wire = sw_crypto::encrypt_with_to_string(
            &synthetic_sym_key,
            sw_crypto::EncStringType::AesCbc256HmacSha256B64,
            &stretched,
        )
        .unwrap();

        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "mock_env_token",
                "expires_in": 3600,
                "token_type": "Bearer",
                "refresh_token": "mock_refresh",
                "key": enc_key_wire
            })))
            .mount(&mock_server)
            .await;

        let temp_dir = tempfile::tempdir().unwrap();
        let config_file_path = temp_dir.path().join("silverwarden.json");

        let initial_cfg = sw_config::ConfigFile {
            identity_url: base_url.clone(),
            api_url: base_url.clone(),
            ..Default::default()
        };
        initial_cfg.save_to_file(&config_file_path).unwrap();

        let cli = Cli {
            socket: Some(temp_dir.path().join("dummy.sock")),
            config: Some(config_file_path),
            insecure: false,
            command: Commands::Login {
                email: None,
                password: None,
                server: None,
                apikey: false,
                client_id: None,
                client_secret: None,
            },
        };

        let res = handle_command(&cli, |_| unreachable!()).await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_cli_login_config_file_not_found_creates_default() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let base_url = mock_server.uri();

        Mock::given(method("POST"))
            .and(path("/identity/accounts/prelogin"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "kdf": 0,
                "kdfIterations": 10
            })))
            .mount(&mock_server)
            .await;

        let kdf_config = sw_crypto::KdfConfig {
            kdf_type: sw_crypto::KdfType::Pbkdf2,
            iterations: 10,
            memory: None,
            parallelism: None,
        };
        let master_key =
            sw_crypto::derive_master_key(b"password", "user_fresh@example.com", &kdf_config)
                .unwrap();
        let stretched = sw_crypto::stretch_key(&master_key).unwrap();
        let synthetic_sym_key = [1u8; 64];
        let enc_key_wire = sw_crypto::encrypt_with_to_string(
            &synthetic_sym_key,
            sw_crypto::EncStringType::AesCbc256HmacSha256B64,
            &stretched,
        )
        .unwrap();

        Mock::given(method("POST"))
            .and(path("/identity/connect/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "mock_token_fresh",
                "expires_in": 3600,
                "token_type": "Bearer",
                "refresh_token": "mock_refresh",
                "key": enc_key_wire
            })))
            .mount(&mock_server)
            .await;

        let temp_dir = tempfile::tempdir().unwrap();
        let config_file_path = temp_dir.path().join("non_existing_silverwarden.json");

        let cli = Cli {
            socket: Some(temp_dir.path().join("dummy.sock")),
            config: Some(config_file_path.clone()),
            insecure: false,
            command: Commands::Login {
                email: Some("user_fresh@example.com".to_string()),
                password: Some("password".to_string()),
                server: Some(base_url),
                apikey: false,
                client_id: None,
                client_secret: None,
            },
        };

        let res = handle_command(&cli, |_| unreachable!()).await;
        assert!(res.is_ok());
        assert!(config_file_path.exists());
    }

    #[tokio::test]
    async fn test_cli_login_2fa_empty_providers_list() {
        use wiremock::matchers::{body_string_contains, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let base_url = mock_server.uri();

        let email = "user_empty_prov@example.com";
        let password = "password123";

        Mock::given(method("POST"))
            .and(path("/accounts/prelogin"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "kdf": 0,
                "kdfIterations": 10
            })))
            .mount(&mock_server)
            .await;

        let kdf_config = sw_crypto::KdfConfig {
            kdf_type: sw_crypto::KdfType::Pbkdf2,
            iterations: 10,
            memory: None,
            parallelism: None,
        };
        let master_key =
            sw_crypto::derive_master_key(password.as_bytes(), email, &kdf_config).unwrap();
        let stretched = sw_crypto::stretch_key(&master_key).unwrap();
        let synthetic_sym_key = [7u8; 64];
        let enc_key_wire = sw_crypto::encrypt_with_to_string(
            &synthetic_sym_key,
            sw_crypto::EncStringType::AesCbc256HmacSha256B64,
            &stretched,
        )
        .unwrap();

        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .and(body_string_contains("grant_type=password"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "invalid_grant",
                "error_description": "Two-step verification required.",
                "TwoFactorProviders2": {},
                "twoFactorToken": "challenge_token_empty_providers"
            })))
            .up_to_n_times(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .and(body_string_contains("twoFactorProvider=0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "mock_token",
                "expires_in": 3600,
                "token_type": "Bearer",
                "refresh_token": "mock_refresh",
                "key": enc_key_wire
            })))
            .mount(&mock_server)
            .await;

        let temp_dir = tempfile::tempdir().unwrap();
        let config_file_path = temp_dir.path().join("silverwarden.json");

        let initial_cfg = sw_config::ConfigFile {
            identity_url: base_url.clone(),
            api_url: base_url.clone(),
            ..Default::default()
        };
        initial_cfg.save_to_file(&config_file_path).unwrap();

        let cli = Cli {
            socket: Some(temp_dir.path().join("dummy.sock")),
            config: Some(config_file_path),
            insecure: false,
            command: Commands::Login {
                email: Some(email.to_string()),
                password: Some(password.to_string()),
                server: None,
                apikey: false,
                client_id: None,
                client_secret: None,
            },
        };

        let result = handle_command(&cli, |prompt_str| {
            if prompt_str.contains("Selecciona un método") {
                Ok("0".to_string())
            } else if prompt_str.contains("código de verificación") {
                Ok("123456".to_string())
            } else {
                Ok("".to_string())
            }
        })
        .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_config_set_server_insecure_flag() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cfg_path = temp_dir.path().join("silverwarden.json");

        let cli = Cli {
            socket: None,
            config: Some(cfg_path.clone()),
            insecure: true,
            command: Commands::Config {
                action: ConfigCommands::SetServer {
                    url: "https://vaultwarden.local".to_string(),
                },
            },
        };
        let res = handle_command(&cli, |_| Ok(String::new())).await.unwrap();
        assert!(res.contains("Servidor configurado a https://vaultwarden.local"));

        let saved = sw_config::ConfigFile::load_from_file(&cfg_path).unwrap();
        assert!(saved.danger_accept_invalid_certs);
    }

    #[tokio::test]
    async fn test_handle_command_migrate() {
        let cli = Cli {
            socket: None,
            config: None,
            insecure: false,
            command: Commands::Migrate {
                source: "dummy".to_string(),
            },
        };
        let _ = handle_command(&cli, |_| Ok(String::new())).await;
    }

    #[tokio::test]
    async fn test_cli_config_setup_command_with_self_signed() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cfg_path = temp_dir.path().join("silverwarden.json");

        let cli = Cli {
            socket: None,
            config: Some(cfg_path.clone()),
            insecure: false,
            command: Commands::Config {
                action: ConfigCommands::Setup,
            },
        };

        let mut step = 0;
        let res = handle_command(&cli, |_| {
            step += 1;
            match step {
                1 => Ok("2".to_string()),
                2 => Ok("https://vaultwarden.lan".to_string()),
                _ => Ok("s".to_string()),
            }
        })
        .await
        .unwrap();

        assert!(res.contains("Configuración guardada exitosamente"));
        assert!(res.contains("Aceptar certs inv: Sí"));

        let saved = sw_config::ConfigFile::load_from_file(&cfg_path).unwrap();
        assert!(saved.danger_accept_invalid_certs);
    }

    #[tokio::test]
    async fn test_cli_sync_with_default_vault_paths() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let _lock = ASYNC_ENV_MUTEX.lock().await;
        let _g_cfg = EnvGuard::new("SILVERWARDEN_CONFIG_PATH");
        let _g_home = EnvGuard::new("HOME");

        let mock_server = MockServer::start().await;
        let base_url = mock_server.uri();

        Mock::given(method("GET"))
            .and(path("/sync"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "profile": { "id": "22cadb2c-d706-471a-a3e9-9fb725925639", "email": "test@test.com" },
                "ciphers": []
            })))
            .mount(&mock_server)
            .await;

        let temp_dir = tempfile::tempdir().unwrap();
        let config_file_path = temp_dir.path().join("silverwarden.json");
        let fake_home = temp_dir.path().join("fake_home");
        std::fs::create_dir_all(&fake_home).unwrap();

        let mut cfg = sw_config::ConfigFile {
            identity_url: base_url.clone(),
            api_url: base_url.clone(),
            ..Default::default()
        };
        let config_key =
            sw_config::derive_config_key_with_params("", &cfg.device_uuid, CLI_KDF_MEMORY_KIB)
                .unwrap();
        cfg.set_token(
            &sw_config::LoginToken {
                access_token: "test_token".to_string(),
                expires_in: 3600,
                token_type: "Bearer".to_string(),
                refresh_token: "refresh".to_string(),
                ..Default::default()
            },
            &config_key,
        )
        .unwrap();
        cfg.save_to_file(&config_file_path).unwrap();

        unsafe {
            std::env::set_var(
                "SILVERWARDEN_CONFIG_PATH",
                config_file_path.to_str().unwrap(),
            );
            std::env::set_var("HOME", fake_home.to_str().unwrap());
        }

        let cli = Cli {
            socket: Some(temp_dir.path().join("dummy.sock")),
            config: None,
            insecure: true,
            command: Commands::Sync,
        };

        let res = handle_command(&cli, |_| unreachable!()).await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_cli_logins_create_status_ok_payload() {
        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("agent.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();

        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                if let Ok(msg) = sw_ipc::read_message(&mut stream).await {
                    assert_eq!(msg.action, "CreateLogin");
                    let resp = IpcMessage::new(
                        "CreateLogin",
                        serde_json::json!({
                            "status": "ok",
                            "cipher_id": "test_id"
                        }),
                    );
                    let _ = sw_ipc::write_message(&mut stream, &resp).await;
                }
            }
        });

        let cli = Cli {
            socket: Some(socket_path),
            config: None,
            insecure: false,
            command: Commands::Logins {
                action: Some(LoginsCommands::Create {
                    name: "my_site".to_string(),
                    username: "user".to_string(),
                    password: "pwd".to_string(),
                }),
                filter: None,
            },
        };

        let res = handle_command(&cli, |_| Ok(String::new())).await.unwrap();
        assert!(res.contains("Acceso 'my_site' creado exitosamente"));
    }
}
