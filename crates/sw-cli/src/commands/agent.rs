use crate::*;
use std::sync::Arc;

pub async fn handle(cli: &Cli, action: &AgentCommands) -> Result<String, CliError> {
    let socket_path = resolve_socket_path(cli.socket.clone())?;
    match action {
        AgentCommands::Start { no_ssh } => {
            println!(
                "Iniciando el agente SilverWarden en {}...",
                socket_path.display()
            );
            let ssh_socket_path = match &cli.socket {
                Some(_) => sw_config::ssh_agent_socket_path_next_to(&socket_path),
                None => sw_config::default_ssh_agent_socket_path()
                    .unwrap_or_else(|_| sw_config::ssh_agent_socket_path_next_to(&socket_path)),
            };

            let vault_agent = Arc::new(sw_vault_agent::VaultAgentServer::default());
            let agent_sock = socket_path.clone();
            let va_clone = vault_agent.clone();
            let agent_handle =
                tokio::spawn(async move { sw_agent::run_agent(&agent_sock, va_clone).await });

            let ssh_handle = if !*no_ssh {
                println!(
                    "Iniciando el servidor SSH agent en {}...",
                    ssh_socket_path.display()
                );
                let ssh_sock = ssh_socket_path.clone();
                let ssh_server =
                    sw_ssh_agent::SshAgentServer::new(&ssh_sock, (*vault_agent).clone());
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
    }
}
