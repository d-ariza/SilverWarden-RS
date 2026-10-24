use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use sw_ipc::IpcMessage;

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
    /// Force vault synchronization with server
    Sync,
    /// Query or list logins from vault
    Logins {
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
pub enum AgentCommands {
    /// Start the agent daemon in the foreground
    Start,
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

/// Executes a CLI command, returning human-readable output or an error.
pub async fn handle_command<P>(cli: &Cli, mut prompt_fn: P) -> Result<String, CliError>
where
    P: FnMut(&str) -> Result<String, CliError>,
{
    let socket_path = resolve_socket_path(cli.socket.clone())?;

    match &cli.command {
        Commands::Agent { action } => match action {
            AgentCommands::Start => {
                println!(
                    "Iniciando el agente SilverWarden en {}...",
                    socket_path.display()
                );
                sw_agent::run_agent(&socket_path)
                    .await
                    .map_err(|e| CliError::Other(e.to_string()))?;
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
        Commands::Sync => Ok("Sincronizando bóveda...".to_string()),
        Commands::Logins { filter: _ } => Ok("Listando accesos guardados...".to_string()),
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
                action: AgentCommands::Start
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

        let cli = Cli {
            socket: Some(socket_path),
            command: Commands::Status,
        };

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
        let cli_flag = Cli {
            socket: Some(socket_path.clone()),
            command: Commands::Unlock {
                pin: Some("secret123".into()),
            },
        };
        let out_flag = handle_command(&cli_flag, |_| unreachable!()).await.unwrap();
        assert!(out_flag.contains("Bóveda desbloqueada con éxito."));

        // 2. Interactive prompt
        let cli_prompt = Cli {
            socket: Some(socket_path),
            command: Commands::Unlock { pin: None },
        };
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

        let cli = Cli {
            socket: Some(socket_path),
            command: Commands::Lock,
        };
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
        let cli_set = Cli {
            socket: Some(socket_path.clone()),
            command: Commands::Pin {
                action: PinCommands::Set {
                    pin: Some("pin_123".into()),
                },
            },
        };
        let out_set = handle_command(&cli_set, |_| unreachable!()).await.unwrap();
        assert!(out_set.contains("PIN configurado exitosamente."));

        // PinSet interactive
        let cli_set_interactive = Cli {
            socket: Some(socket_path.clone()),
            command: Commands::Pin {
                action: PinCommands::Set { pin: None },
            },
        };
        let out_set_interactive = handle_command(&cli_set_interactive, |_| Ok("pin_inter".into()))
            .await
            .unwrap();
        assert!(out_set_interactive.contains("PIN configurado exitosamente."));

        // PinUpdate flags
        let cli_update = Cli {
            socket: Some(socket_path.clone()),
            command: Commands::Pin {
                action: PinCommands::Update {
                    old_pin: Some("old".into()),
                    new_pin: Some("new".into()),
                },
            },
        };
        let out_update = handle_command(&cli_update, |_| unreachable!())
            .await
            .unwrap();
        assert!(out_update.contains("PIN actualizado exitosamente."));

        // PinUpdate interactive
        let mut prompts = vec!["new_inter", "old_inter"];
        let cli_update_interactive = Cli {
            socket: Some(socket_path),
            command: Commands::Pin {
                action: PinCommands::Update {
                    old_pin: None,
                    new_pin: None,
                },
            },
        };
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

        // Sync
        let cli_sync = Cli {
            socket: Some(dummy_socket.clone()),
            command: Commands::Sync,
        };
        assert!(handle_command(&cli_sync, |_| unreachable!())
            .await
            .unwrap()
            .contains("Sincronizando"));

        // Logins
        let cli_logins = Cli {
            socket: Some(dummy_socket.clone()),
            command: Commands::Logins { filter: None },
        };
        assert!(handle_command(&cli_logins, |_| unreachable!())
            .await
            .unwrap()
            .contains("Listando accesos"));

        // SSH List
        let cli_ssh_list = Cli {
            socket: Some(dummy_socket.clone()),
            command: Commands::Ssh {
                ssh_command: SshCommands::List,
            },
        };
        assert!(handle_command(&cli_ssh_list, |_| unreachable!())
            .await
            .unwrap()
            .contains("Listando claves SSH"));

        // SSH Add
        let cli_ssh_add = Cli {
            socket: Some(dummy_socket),
            command: Commands::Ssh {
                ssh_command: SshCommands::Add {
                    key_id: "id_ed25519".into(),
                },
            },
        };
        assert!(handle_command(&cli_ssh_add, |_| unreachable!())
            .await
            .unwrap()
            .contains("Registrando clave SSH id_ed25519"));
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
}
