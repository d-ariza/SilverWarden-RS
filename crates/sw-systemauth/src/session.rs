use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

/// Context identifying the caller process that connected to the agent socket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallingContext {
    pub username: String,
    pub process_name: String,
    pub parent_process_name: String,
    pub grandparent_process_name: String,
    pub process_pid: u32,
    pub parent_process_pid: u32,
    pub grandparent_process_pid: u32,
    pub error: bool,
    pub authenticated: bool,
}

impl Default for CallingContext {
    fn default() -> Self {
        Self {
            username: "unknown".to_string(),
            process_name: "unknown".to_string(),
            parent_process_name: "unknown".to_string(),
            grandparent_process_name: "unknown".to_string(),
            process_pid: 0,
            parent_process_pid: 0,
            grandparent_process_pid: 0,
            error: true,
            authenticated: false,
        }
    }
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

/// A hardened authentication session tied to process lineage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    pub pid: u32,
    pub ppid: u32,
    pub grand_ppid: u32,
    pub expires_at: std::time::SystemTime,
    pub session_type: SessionType,
}

impl Session {
    /// Checks whether this session has expired relative to the current system time.
    pub fn is_expired(&self) -> bool {
        std::time::SystemTime::now() >= self.expires_at
    }
}

/// In-memory store for active authentication sessions with strict process-tree hardening.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionStore {
    pub(crate) sessions: Vec<Session>,
}

impl SessionStore {
    /// Creates a new empty session store.
    pub fn new() -> Self {
        Self {
            sessions: Vec::new(),
        }
    }

    /// Creates and registers an authentication session for the calling context with a specified TTL.
    pub fn create_session(
        &mut self,
        ctx: &CallingContext,
        session_type: SessionType,
        ttl: Duration,
    ) -> Session {
        let session = Session {
            pid: ctx.process_pid,
            ppid: ctx.parent_process_pid,
            grand_ppid: ctx.grandparent_process_pid,
            expires_at: std::time::SystemTime::now() + ttl,
            session_type,
        };
        self.sessions.push(session.clone());
        session
    }

    /// Verifies if an active, unexpired session exists for the given calling context.
    ///
    /// Hardening rules:
    /// - If `ctx.error` is true or `ctx.authenticated` is false, verification always fails.
    /// - For `AccessVault` and `Pin`: requires an exact match of (pid, ppid, grand_ppid).
    /// - For `SSHKey`: if `ctx.process_name` is "ssh", "ssh-keygen", or "git",
    ///   permits matching by session type (any valid unexpired SSHKey session is accepted).
    ///   Otherwise, requires an exact match of (pid, ppid, grand_ppid).
    pub fn verify_session(&self, ctx: &CallingContext, session_type: SessionType) -> bool {
        if ctx.error || !ctx.authenticated {
            return false;
        }

        let is_git_ssh_context = ctx.process_name == "ssh"
            || ctx.process_name == "ssh-keygen"
            || ctx.process_name == "git";

        for s in &self.sessions {
            if s.session_type != session_type || s.is_expired() {
                continue;
            }

            match session_type {
                SessionType::AccessVault | SessionType::Pin => {
                    if s.pid == ctx.process_pid
                        && s.ppid == ctx.parent_process_pid
                        && s.grand_ppid == ctx.grandparent_process_pid
                    {
                        return true;
                    }
                }
                SessionType::SSHKey => {
                    if is_git_ssh_context {
                        return true;
                    }
                    if s.pid == ctx.process_pid
                        && s.ppid == ctx.parent_process_pid
                        && s.grand_ppid == ctx.grandparent_process_pid
                    {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Wipes and clears all stored sessions (invoked when locking the vault).
    pub fn wipe(&mut self) {
        self.sessions.clear();
    }

    /// Prunes expired sessions from the store.
    pub fn prune_expired(&mut self) {
        self.sessions.retain(|s| !s.is_expired());
    }

    /// Returns the number of sessions currently stored.
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Checks if the session store is empty.
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}
