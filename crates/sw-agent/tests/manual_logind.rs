use std::sync::Arc;
use std::time::Duration;
use sw_agent::{spawn_logind_monitor, AgentState};
use tokio::sync::RwLock;

#[tokio::test]
#[ignore]
async fn test_logind_monitor_smoke() {
    let state = Arc::new(RwLock::new(AgentState::default()));
    let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);

    let handle = spawn_logind_monitor(state.clone(), shutdown_tx.subscribe());

    // Allow connection attempt to system D-Bus
    tokio::time::sleep(Duration::from_millis(100)).await;

    let _ = shutdown_tx.send(());
    let res = tokio::time::timeout(Duration::from_secs(2), handle).await;
    assert!(res.is_ok(), "logind monitor should shutdown cleanly");
}
