use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "silverwarden")]
#[command(author = "silverWarden-rs contributors")]
#[command(version = "0.1.0")]
#[command(about = "CLI client for silverWarden Bitwarden-compatible vault and SSH agent", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Check daemon status and vault lock state
    Status,
    /// Unlock the vault with PIN
    Unlock {
        #[arg(short, long)]
        pin: Option<String>,
    },
    /// Lock the vault immediately
    Lock,
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

#[derive(Subcommand, Debug)]
enum CommandsSsh {
    /// List keys in agent
    List,
    /// Add key to agent
    Add { key_id: String },
}

type SshCommands = CommandsSsh;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Status => {
            println!("silverWarden CLI v0.1.0 (MVP)");
            println!("Daemon: Not running (use 'silverwarden-agent' to start)");
        }
        Commands::Unlock { pin: _ } => {
            println!("Unlocking vault...");
        }
        Commands::Lock => {
            println!("Vault locked.");
        }
        Commands::Sync => {
            println!("Synchronizing vault...");
        }
        Commands::Logins { filter: _ } => {
            println!("Listing logins...");
        }
        Commands::Ssh { ssh_command } => match ssh_command {
            SshCommands::List => println!("Listing SSH keys..."),
            SshCommands::Add { key_id } => println!("Adding SSH key {}", key_id),
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
        assert!(matches!(cli.command, Commands::Status));
    }
}
