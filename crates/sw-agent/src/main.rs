use std::sync::Arc;
use sw_vault_agent::VaultAgentServer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    tracing::info!("Starting silverWarden agent daemon...");

    let socket_path = sw_config::default_socket_path()?;
    let vault_agent = Arc::new(VaultAgentServer::default());
    sw_agent::run_agent(&socket_path, vault_agent).await?;

    Ok(())
}
