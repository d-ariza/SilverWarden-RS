use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
pub use sw_client::{AgentClient, AgentConnection, ClientError};
pub use sw_ipc::{Request, Response};

pub mod systemd;

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
    /// Install systemd user service and Polkit policy, and enable the agent
    SetupSystemd {
        /// Print the generated files but do not install them
        #[arg(long)]
        dry_run: bool,
        /// Do not run systemctl enable/start after installing
        #[arg(long)]
        no_enable: bool,
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

impl From<ClientError> for CliError {
    fn from(err: ClientError) -> Self {
        match err {
            ClientError::SocketNotFound(p) => CliError::SocketNotFound(p),
            ClientError::ConnectionFailed(p, msg) => CliError::ConnectionFailed(p, msg),
            ClientError::SendFailed(msg) => CliError::SendFailed(msg),
            ClientError::ReceiveFailed(msg) => CliError::ReceiveFailed(msg),
            ClientError::InvalidPin => {
                CliError::AgentError("El PIN es incorrecto, inténtalo de nuevo.".to_string())
            }
            ClientError::Locked => CliError::AgentError(
                "Bóveda bloqueada. Desbloquea con 'silverwarden unlock' primero.".to_string(),
            ),
            ClientError::NotFound(msg) => CliError::AgentError(msg),
            ClientError::Unauthorized(msg) => CliError::AgentError(msg),
            ClientError::ServerError(msg) => CliError::AgentError(msg),
            ClientError::Validation(msg) => CliError::AgentError(msg),
            ClientError::AgentError { message, .. } => CliError::AgentError(message),
            ClientError::Io(msg) => CliError::Io(msg),
        }
    }
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
pub mod commands;

pub async fn handle_command<P>(cli: &Cli, mut prompt_fn: P) -> Result<String, CliError>
where
    P: FnMut(&str) -> Result<String, CliError>,
{
    match &cli.command {
        Commands::Agent { action } => commands::agent::handle(cli, action).await,
        Commands::Status => commands::status::handle(cli).await,
        Commands::Unlock { pin } => commands::unlock::handle(cli, pin, &mut prompt_fn).await,
        Commands::Lock => commands::lock::handle(cli).await,
        Commands::Pin { action } => commands::pin::handle(cli, action, &mut prompt_fn).await,
        Commands::Login {
            email,
            password,
            server,
            apikey,
            client_id,
            client_secret,
        } => {
            commands::login::handle(
                cli,
                email,
                password,
                server,
                apikey,
                client_id,
                client_secret,
                &mut prompt_fn,
            )
            .await
        }
        Commands::Sync => commands::sync::handle(cli, &mut prompt_fn).await,
        Commands::Logins { action, filter } => commands::logins::handle(cli, action, filter).await,
        Commands::Ssh { ssh_command } => commands::ssh::handle(cli, ssh_command).await,
        Commands::Config { action } => commands::config::handle(cli, action, &mut prompt_fn).await,
        Commands::Migrate { source } => commands::migrate::handle(source).await,
        Commands::SetupSystemd { dry_run, no_enable } => {
            commands::setup_systemd::handle(dry_run, no_enable).await
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
mod tests;
