use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CallingContext {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub process_name: String,
}

#[derive(Debug)]
pub struct AuthSession {
    pub session_type: SessionType,
    pub created_at: Instant,
    pub ttl: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionType {
    AccessVault,
    SSHKey,
    Pin,
}

impl AuthSession {
    pub fn new(session_type: SessionType, ttl_secs: u64) -> Self {
        Self {
            session_type,
            created_at: Instant::now(),
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    pub fn is_valid(&self) -> bool {
        self.created_at.elapsed() < self.ttl
    }
}
