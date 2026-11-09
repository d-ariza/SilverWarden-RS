use sw_agent::AgentDaemon;
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    info!("Starting silverWarden agent daemon...");

    let _daemon = AgentDaemon::default();
    info!("silverWarden daemon initialized successfully");

    Ok(())
}
