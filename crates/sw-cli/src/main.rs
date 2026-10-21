use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use sw_ipc::IpcMessage;

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
async fn send_ipc_message(
    socket_path: &Path,
    message: IpcMessage,
) -> Result<IpcMessage, anyhow::Error> {
    let mut stream = tokio::net::UnixStream::connect(socket_path).await.map_err(|e| {
        anyhow::anyhow!(
            "No se pudo conectar al socket del agente en {}: {e}.\n¿Está el agente ejecutándose? Puedes iniciarlo con 'silverwarden agent start'.",
            socket_path.display()
        )
    })?;

    sw_ipc::write_message(&mut stream, &message).await?;
    let response = sw_ipc::read_message(&mut stream).await?;
    Ok(response)
}

fn resolve_socket_path(custom: Option<PathBuf>) -> Result<PathBuf, anyhow::Error> {
    match custom {
        Some(p) => Ok(p),
        None => sw_agent::default_socket_path().map_err(|e| anyhow::anyhow!("{e}")),
    }
}

fn check_goldwarden_go_conflict() {
    if let Ok(home) = std::env::var("HOME") {
        let go_sock = PathBuf::from(home).join(".goldwarden.sock");
        if go_sock.exists() {
            eprintln!("ADVERTENCIA: Goldwarden Go está corriendo (~/.goldwarden.sock activo). Te recomendamos detenerlo para evitar conflictos de estado.");
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let socket_path = cli.socket.clone();

    check_goldwarden_go_conflict();

    match cli.command {
        Commands::Agent { action } => match action {
            AgentCommands::Start => {
                let path = resolve_socket_path(socket_path)?;
                println!("Iniciando el agente SilverWarden en {}...", path.display());
                sw_agent::run_agent(&path).await?;
            }
        },
        Commands::Status => {
            let path = resolve_socket_path(socket_path)?;
            let msg = IpcMessage::new("Status", serde_json::json!({}));
            match send_ipc_message(&path, msg).await {
                Ok(resp) => {
                    if resp.action == "Ok" {
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

                        println!("Estado del Agente SilverWarden (v{version}):");
                        println!("  Bloqueado:        {}", if locked { "Sí" } else { "No" });
                        println!("  PIN configurado:  {}", if has_pin { "Sí" } else { "No" });
                        println!(
                            "  Sesión iniciada:  {}",
                            if logged_in { "Sí" } else { "No" }
                        );
                    } else {
                        eprintln!("Error al consultar estado: {}", resp.payload);
                    }
                }
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            }
        }
        Commands::Unlock { pin } => {
            let pin_val = match pin {
                Some(p) => p,
                None => rpassword::prompt_password("Introduce el PIN de desbloqueo: ")?,
            };
            let path = resolve_socket_path(socket_path)?;
            let msg = IpcMessage::new("Unlock", serde_json::json!({ "pin": pin_val }));
            match send_ipc_message(&path, msg).await {
                Ok(resp) => {
                    if resp.action == "Ok" {
                        println!("Bóveda desbloqueada con éxito.");
                    } else {
                        eprintln!("Fallo al desbloquear: {}", resp.payload);
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            }
        }
        Commands::Lock => {
            let path = resolve_socket_path(socket_path)?;
            let msg = IpcMessage::new("Lock", serde_json::json!({}));
            match send_ipc_message(&path, msg).await {
                Ok(resp) => {
                    if resp.action == "Ok" {
                        println!("Bóveda bloqueada y sesiones en memoria eliminadas.");
                    } else {
                        eprintln!("Error al bloquear: {}", resp.payload);
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            }
        }
        Commands::Pin { action } => match action {
            PinCommands::Set { pin } => {
                let pin_val = match pin {
                    Some(p) => p,
                    None => rpassword::prompt_password("Introduce el nuevo PIN: ")?,
                };
                let path = resolve_socket_path(socket_path)?;
                let msg = IpcMessage::new("PinSet", serde_json::json!({ "pin": pin_val }));
                match send_ipc_message(&path, msg).await {
                    Ok(resp) => {
                        if resp.action == "Ok" {
                            println!("PIN configurado exitosamente.");
                        } else {
                            eprintln!("Error al configurar PIN: {}", resp.payload);
                            std::process::exit(1);
                        }
                    }
                    Err(e) => {
                        eprintln!("{e}");
                        std::process::exit(1);
                    }
                }
            }
            PinCommands::Update { old_pin, new_pin } => {
                let old_val = match old_pin {
                    Some(p) => p,
                    None => rpassword::prompt_password("Introduce el PIN actual: ")?,
                };
                let new_val = match new_pin {
                    Some(p) => p,
                    None => rpassword::prompt_password("Introduce el nuevo PIN: ")?,
                };
                let path = resolve_socket_path(socket_path)?;
                let msg = IpcMessage::new(
                    "PinUpdate",
                    serde_json::json!({ "old_pin": old_val, "new_pin": new_val }),
                );
                match send_ipc_message(&path, msg).await {
                    Ok(resp) => {
                        if resp.action == "Ok" {
                            println!("PIN actualizado exitosamente.");
                        } else {
                            eprintln!("Error al actualizar PIN: {}", resp.payload);
                            std::process::exit(1);
                        }
                    }
                    Err(e) => {
                        eprintln!("{e}");
                        std::process::exit(1);
                    }
                }
            }
        },
        Commands::Sync => {
            println!("Sincronizando bóveda...");
        }
        Commands::Logins { filter: _ } => {
            println!("Listando accesos guardados...");
        }
        Commands::Ssh { ssh_command } => match ssh_command {
            SshCommands::List => println!("Listando claves SSH registradas..."),
            SshCommands::Add { key_id } => println!("Registrando clave SSH {}", key_id),
        },
        Commands::Migrate { source: _ } => match sw_config::run_migration() {
            Ok(msg) => println!("{msg}"),
            Err(e) => {
                eprintln!("Error en migración: {e}");
                std::process::exit(1);
            }
        },
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
