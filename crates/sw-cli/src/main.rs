use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use sw_ipc::IpcMessage;

#[cfg(not(test))]
pub const CLI_KDF_MEMORY_KIB: u32 = sw_config::KDF_MEMORY_KIB;
#[cfg(test)]
pub const CLI_KDF_MEMORY_KIB: u32 = sw_config::KDF_MEMORY_KIB_TEST;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CliError {
    #[error("El archivo de socket no existe: {0}")]
    SocketNotFound(PathBuf),

    #[error("No se pudo conectar al socket del agente en {0}: {1}")]
    ConnectionFailed(PathBuf, String),

    #[error("Error al enviar mensaje al agente: {0}")]
    SendFailed(String),

    #[error("Error al recibir respuesta del agente: {0}")]
    ReceiveFailed(String),

    #[error("Error del agente: {0}")]
    AgentError(String),

    #[error("Error de E/S o terminal: {0}")]
    Io(String),

    #[error("Error de configuración: {0}")]
    Config(String),

    #[error("Error: {0}")]
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
    /// Migrate existing Goldwarden configuration and vault from Go installation
    Migrate {
        #[arg(long, default_value = "~/.config/goldwarden/goldwarden.json")]
        source: String,
    },
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
            send_command(
                &socket_path,
                "Unlock",
                serde_json::json!({ "pin": pin_val }),
            )
            .await?;
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
        Commands::Login { email, password } => {
            let email_val = match email {
                Some(e) => e.clone(),
                None => prompt_fn("Introduce tu email de Bitwarden: ")?,
            };
            let password_val = match password {
                Some(p) => p.clone(),
                None => prompt_fn("Introduce tu contraseña maestra: ")?,
            };

            let config_path = resolve_config_path(cli.config.clone())?;
            let mut config = if config_path.exists() {
                sw_config::ConfigFile::load_from_file(&config_path)
                    .map_err(|e| CliError::Config(e.to_string()))?
            } else {
                sw_config::ConfigFile::default()
            };

            let client = sw_bitwarden_api::AuthenticatedClient::from_token(
                &config.identity_url,
                &config.api_url,
                Default::default(),
            );
            let (token, user_symmetric_key) = client
                .login(&email_val, &password_val, &config.device_uuid)
                .await
                .map_err(|e| CliError::Other(e.to_string()))?;

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
                        "user_symmetric_key": b64_sym_key
                    }),
                )
                .await;
            }

            Ok(format!("Sesión iniciada con éxito para {email_val}."))
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

            let resp = send_command(&socket_path, "Sync", serde_json::json!({})).await?;
            let logins = resp
                .payload
                .get("logins")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            Ok(format!(
                "Sincronización completada ({logins} logins descargados)."
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
                send_command(
                    &socket_path,
                    "CreateLogin",
                    serde_json::json!({
                        "name": name,
                        "username": username,
                        "password": password
                    }),
                )
                .await?;
                Ok(format!("Acceso '{name}' creado exitosamente."))
            }
            Some(LoginsCommands::Delete { name }) => {
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
            SshCommands::Add { key_id } => Ok(format!("Registrando clave SSH {key_id}")),
        },
        Commands::Migrate { source: _ } => {
            sw_config::run_migration().map_err(|e| CliError::Config(e.to_string()))
        }
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    check_goldwarden_go_conflict();

    let prompt =
        |msg: &str| rpassword::prompt_password(msg).map_err(|e| CliError::Io(e.to_string()));

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
            .and(path("/api/accounts/prelogin"))
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
            command: Commands::Login {
                email: Some(email.to_string()),
                password: Some(password.to_string()),
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
        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("sync_success.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();

        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let req = sw_ipc::read_message(&mut stream).await.unwrap();
                assert_eq!(req.action, "Sync");
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

        let logged_in_cfg = sw_config::ConfigFile {
            encrypted_token: "some_encrypted_token".to_string(),
            ..Default::default()
        };
        logged_in_cfg.save_to_file(&config_file_path).unwrap();

        let cli = Cli {
            socket: Some(socket_path),
            config: Some(config_file_path),
            command: Commands::Sync,
        };

        let output = handle_command(&cli, |_| unreachable!()).await.unwrap();
        assert!(output.contains("Sincronización completada (5 logins descargados)."));
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

    #[test]
    fn test_check_goldwarden_go_conflict() {
        let temp_dir = tempfile::tempdir().unwrap();
        let home_fake = temp_dir.path().to_path_buf();
        std::env::set_var("HOME", &home_fake);

        // Absent
        assert!(!check_goldwarden_go_conflict());

        // Present
        let go_sock = home_fake.join(".goldwarden.sock");
        std::fs::write(&go_sock, b"").unwrap();
        assert!(check_goldwarden_go_conflict());
    }

    #[test]
    fn test_cli_error_display() {
        let p = PathBuf::from("/tmp/test.sock");
        assert!(CliError::SocketNotFound(p.clone())
            .to_string()
            .contains("no existe"));
        assert!(CliError::ConnectionFailed(p, "conn err".into())
            .to_string()
            .contains("No se pudo conectar"));
        assert!(CliError::SendFailed("send err".into())
            .to_string()
            .contains("Error al enviar"));
        assert!(CliError::ReceiveFailed("recv err".into())
            .to_string()
            .contains("Error al recibir"));
        assert!(CliError::AgentError("agent err".into())
            .to_string()
            .contains("Error del agente"));
        assert!(CliError::Io("io err".into())
            .to_string()
            .contains("Error de E/S"));
        assert!(CliError::Config("cfg err".into())
            .to_string()
            .contains("Error de configuración"));
        assert!(CliError::Other("other err".into())
            .to_string()
            .contains("Error: other err"));
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
}
