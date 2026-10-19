use std::sync::Arc;
use sw_config::ConfigFile;
use sw_ipc::{IpcRequest, IpcResponse};
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct AgentState {
    pub is_locked: bool,
    pub config: ConfigFile,
}

impl Default for AgentState {
    fn default() -> Self {
        Self {
            is_locked: true,
            config: ConfigFile::default(),
        }
    }
}

pub struct AgentDaemon {
    pub state: Arc<RwLock<AgentState>>,
}

impl AgentDaemon {
    pub fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(AgentState::default())),
        }
    }

    pub async fn handle_request(&self, request: IpcRequest) -> IpcResponse {
        match request {
            IpcRequest::Status => {
                let state = self.state.read().await;
                IpcResponse::Ok(serde_json::json!({
                    "locked": state.is_locked,
                    "version": env!("CARGO_PKG_VERSION"),
                }))
            }
            IpcRequest::Unlock { pin: _ } => {
                let mut state = self.state.write().await;
                state.is_locked = false;
                IpcResponse::Ok(serde_json::json!({ "status": "unlocked" }))
            }
            IpcRequest::Lock => {
                let mut state = self.state.write().await;
                state.is_locked = true;
                IpcResponse::Ok(serde_json::json!({ "status": "locked" }))
            }
            IpcRequest::Sync => IpcResponse::Ok(serde_json::json!({ "status": "synced" })),
            IpcRequest::GetLogins { filter: _ } => IpcResponse::Ok(serde_json::json!([])),
        }
    }
}

impl Default for AgentDaemon {
    fn default() -> Self {
        Self::new()
    }
}
