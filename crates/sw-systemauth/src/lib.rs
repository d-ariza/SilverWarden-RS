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
    sessions: Vec<Session>,
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

/// Lightweight container for process name and parent PID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    pub name: String,
    pub ppid: u32,
}

/// Resolves the username corresponding to a given system UID.
pub fn resolve_username(uid: u32) -> Option<String> {
    // 1. Try reading /etc/passwd directly
    if let Ok(content) = std::fs::read_to_string("/etc/passwd") {
        for line in content.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 3 {
                if let Ok(entry_uid) = parts[2].parse::<u32>() {
                    if entry_uid == uid {
                        return Some(parts[0].to_string());
                    }
                }
            }
        }
    }

    // 2. Fallback via sysinfo Users list
    use sysinfo::Users;
    let users = Users::new_with_refreshed_list();
    for user in users.list() {
        if user.id().to_string() == uid.to_string() {
            return Some(user.name().to_string());
        }
    }

    None
}

/// Parses the executable name (comm) and PPID from `/proc/<pid>/stat` content.
pub fn parse_proc_stat(stat_content: &str) -> Option<ProcessInfo> {
    let open_paren = stat_content.find('(')?;
    let close_paren = stat_content.rfind(')')?;
    if close_paren <= open_paren {
        return None;
    }
    let comm = &stat_content[open_paren + 1..close_paren];
    let after_paren = &stat_content[close_paren + 1..];
    let tokens: Vec<&str> = after_paren.split_whitespace().collect();
    // Tokens after ')' are:
    // 0: state (char)
    // 1: ppid (integer)
    let ppid: u32 = tokens.get(1)?.parse().ok()?;

    Some(ProcessInfo {
        name: comm.to_string(),
        ppid,
    })
}

/// Retrieves process information for a given PID.
pub fn get_process_info(pid: u32) -> Option<ProcessInfo> {
    if pid == 0 {
        return None;
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(stat_content) = std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            if let Some(info) = parse_proc_stat(&stat_content) {
                return Some(info);
            }
        }
    }

    // Fallback using sysinfo
    use sysinfo::{Pid, System};
    let mut sys = System::new();
    let sys_pid = Pid::from_u32(pid);
    sys.refresh_process(sys_pid);
    let process = sys.process(sys_pid)?;
    Some(ProcessInfo {
        name: process.name().to_string(),
        ppid: process.parent().map(|p| p.as_u32()).unwrap_or(0),
    })
}

/// Resolves the full `CallingContext` given a UID, PID, username and process lookup function.
pub fn resolve_calling_context_with_lookup<F>(
    uid: u32,
    pid: u32,
    username: Option<String>,
    lookup_proc: F,
) -> CallingContext
where
    F: Fn(u32) -> Option<ProcessInfo>,
{
    let error_context = CallingContext {
        error: true,
        authenticated: false,
        ..Default::default()
    };

    // Root is not allowed to interact with the agent
    if uid == 0 || pid == 0 {
        return error_context;
    }

    let username = match username {
        Some(u) => u,
        None => return error_context,
    };

    let mut current_pid = pid;
    let mut current_proc = match lookup_proc(current_pid) {
        Some(p) => p,
        None => return error_context,
    };

    // Special Git case: If current process is ssh-keygen or ssh, check if PPID is git.
    // If so, anchor the context to git.
    if current_proc.name == "ssh-keygen" || current_proc.name == "ssh" {
        if let Some(parent) = lookup_proc(current_proc.ppid) {
            if parent.name == "git" {
                current_pid = current_proc.ppid;
                current_proc = parent;
            }
        }
    }

    let parent_pid = current_proc.ppid;
    let parent_proc = lookup_proc(parent_pid);
    let parent_name = parent_proc
        .as_ref()
        .map(|p| p.name.clone())
        .unwrap_or_else(|| "unknown".to_string());

    let grandparent_pid = parent_proc.as_ref().map(|p| p.ppid).unwrap_or(0);
    let grandparent_proc = if grandparent_pid > 0 {
        lookup_proc(grandparent_pid)
    } else {
        None
    };
    let grandparent_name = grandparent_proc
        .as_ref()
        .map(|p| p.name.clone())
        .unwrap_or_else(|| "unknown".to_string());

    CallingContext {
        username,
        process_name: current_proc.name,
        parent_process_name: parent_name,
        grandparent_process_name: grandparent_name,
        process_pid: current_pid,
        parent_process_pid: parent_pid,
        grandparent_process_pid: grandparent_pid,
        error: false,
        authenticated: true,
    }
}

/// Resolves the full `CallingContext` given a UID and PID using system accounts and processes.
pub fn get_calling_context_for_pid(uid: u32, pid: u32) -> CallingContext {
    resolve_calling_context_with_lookup(uid, pid, resolve_username(uid), get_process_info)
}

/// Obtains peer credentials and inspects process hierarchy from a Unix domain socket connection.
#[cfg(unix)]
pub fn get_calling_context<S: std::os::fd::AsFd>(conn: &S) -> CallingContext {
    let error_context = CallingContext {
        error: true,
        authenticated: false,
        ..Default::default()
    };

    #[cfg(target_os = "linux")]
    {
        use rustix::net::sockopt::get_socket_peercred;
        match get_socket_peercred(conn) {
            Ok(ucred) => {
                let uid = ucred.uid.as_raw();
                let pid = ucred.pid.as_raw_nonzero().get() as u32;
                get_calling_context_for_pid(uid, pid)
            }
            Err(_) => error_context,
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        // Fallback for macOS / other Unix systems: stub for M10
        error_context
    }
}

/// Non-Unix fallback stub.
#[cfg(not(unix))]
pub fn get_calling_context<T>(_conn: &T) -> CallingContext {
    CallingContext {
        error: true,
        authenticated: false,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calling_context_unix_stream_pair() {
        let (server, _client) = std::os::unix::net::UnixStream::pair().expect("Create socket pair");

        let ctx = get_calling_context(&server);
        assert!(!ctx.error, "CallingContext should not have error: {ctx:?}");
        assert!(ctx.authenticated, "CallingContext should be authenticated");
        assert_eq!(ctx.process_pid, std::process::id());
        assert!(!ctx.username.is_empty());
        assert!(!ctx.process_name.is_empty());
    }

    #[tokio::test]
    async fn test_calling_context_tokio_unix_stream_pair() {
        let (server, _client) = tokio::net::UnixStream::pair().expect("Create tokio socket pair");

        let ctx = get_calling_context(&server);
        assert!(!ctx.error);
        assert!(ctx.authenticated);
        assert_eq!(ctx.process_pid, std::process::id());
    }

    #[test]
    fn test_calling_context_fake_pid_fails() {
        let ctx = get_calling_context_for_pid(1000, 99_999_999);
        assert!(ctx.error);
        assert!(!ctx.authenticated);
        assert_eq!(ctx.process_pid, 0);
    }

    #[test]
    fn test_calling_context_root_rejected() {
        let ctx = get_calling_context_for_pid(0, std::process::id());
        assert!(ctx.error);
        assert!(!ctx.authenticated);
    }

    #[test]
    fn test_calling_context_zero_pid_rejected() {
        let ctx = get_calling_context_for_pid(1000, 0);
        assert!(ctx.error);
        assert!(!ctx.authenticated);
    }

    #[test]
    fn test_resolve_username_known_and_unknown() {
        #[cfg(unix)]
        {
            let current_uid = rustix::process::getuid().as_raw();
            let user = resolve_username(current_uid);
            assert!(user.is_some(), "Current user should resolve");
        }

        assert!(resolve_username(999_999_999).is_none());
    }

    #[test]
    fn test_parse_proc_stat() {
        // Standard stat line
        let stat_std = "1234 (bash) S 5678 1234 1234 0 -1 4194304 100 0 0 0 0 0 0 0";
        let info = parse_proc_stat(stat_std).expect("Should parse standard stat");
        assert_eq!(info.name, "bash");
        assert_eq!(info.ppid, 5678);

        // Process name with spaces
        let stat_spaces = "9999 (my process name) S 1111 9999 9999 0 -1";
        let info_spaces = parse_proc_stat(stat_spaces).expect("Should parse comm with spaces");
        assert_eq!(info_spaces.name, "my process name");
        assert_eq!(info_spaces.ppid, 1111);

        // Process name with nested parentheses
        let stat_parens = "4444 (app (worker)) S 2222 4444 4444 0 -1";
        let info_parens =
            parse_proc_stat(stat_parens).expect("Should parse comm with nested parens");
        assert_eq!(info_parens.name, "app (worker)");
        assert_eq!(info_parens.ppid, 2222);

        // Malformed stat
        assert!(parse_proc_stat("invalid stat without parens").is_none());
    }

    #[test]
    fn test_auth_session_lifecycle() {
        let session = AuthSession::new(SessionType::AccessVault, 3600);
        assert!(session.is_valid());
        assert_eq!(session.session_type, SessionType::AccessVault);

        let expired_session = AuthSession::new(SessionType::SSHKey, 0);
        std::thread::sleep(Duration::from_millis(5));
        assert!(!expired_session.is_valid());
    }

    #[test]
    fn test_git_anchoring_for_ssh_and_ssh_keygen() {
        let mock_lookup = |pid: u32| match pid {
            30 => Some(ProcessInfo {
                name: "ssh-keygen".to_string(),
                ppid: 20,
            }),
            40 => Some(ProcessInfo {
                name: "ssh".to_string(),
                ppid: 20,
            }),
            50 => Some(ProcessInfo {
                name: "ssh".to_string(),
                ppid: 10,
            }),
            20 => Some(ProcessInfo {
                name: "git".to_string(),
                ppid: 10,
            }),
            10 => Some(ProcessInfo {
                name: "zsh".to_string(),
                ppid: 1,
            }),
            1 => Some(ProcessInfo {
                name: "systemd".to_string(),
                ppid: 0,
            }),
            _ => None,
        };

        // 1. ssh-keygen with git parent should anchor to git
        let ctx_keygen = resolve_calling_context_with_lookup(
            1000,
            30,
            Some("testuser".to_string()),
            mock_lookup,
        );
        assert!(!ctx_keygen.error);
        assert!(ctx_keygen.authenticated);
        assert_eq!(ctx_keygen.process_name, "git");
        assert_eq!(ctx_keygen.process_pid, 20);
        assert_eq!(ctx_keygen.parent_process_name, "zsh");
        assert_eq!(ctx_keygen.parent_process_pid, 10);
        assert_eq!(ctx_keygen.grandparent_process_name, "systemd");
        assert_eq!(ctx_keygen.grandparent_process_pid, 1);

        // 2. ssh with git parent should also anchor to git
        let ctx_ssh_git = resolve_calling_context_with_lookup(
            1000,
            40,
            Some("testuser".to_string()),
            mock_lookup,
        );
        assert_eq!(ctx_ssh_git.process_name, "git");
        assert_eq!(ctx_ssh_git.process_pid, 20);

        // 3. ssh with zsh parent (not git) should NOT anchor, stays ssh
        let ctx_ssh_zsh = resolve_calling_context_with_lookup(
            1000,
            50,
            Some("testuser".to_string()),
            mock_lookup,
        );
        assert_eq!(ctx_ssh_zsh.process_name, "ssh");
        assert_eq!(ctx_ssh_zsh.process_pid, 50);
        assert_eq!(ctx_ssh_zsh.parent_process_name, "zsh");
        assert_eq!(ctx_ssh_zsh.parent_process_pid, 10);
    }

    #[test]
    fn test_resolve_calling_context_edge_cases() {
        // Unknown user
        let ctx_no_user = resolve_calling_context_with_lookup(1000, 10, None, |_| {
            Some(ProcessInfo {
                name: "app".into(),
                ppid: 1,
            })
        });
        assert!(ctx_no_user.error);
        assert!(!ctx_no_user.authenticated);

        // Missing parent process
        let ctx_missing_parent =
            resolve_calling_context_with_lookup(1000, 10, Some("alice".into()), |pid| {
                if pid == 10 {
                    Some(ProcessInfo {
                        name: "app".into(),
                        ppid: 9999,
                    })
                } else {
                    None
                }
            });
        assert!(!ctx_missing_parent.error);
        assert!(ctx_missing_parent.authenticated);
        assert_eq!(ctx_missing_parent.parent_process_name, "unknown");
        assert_eq!(ctx_missing_parent.grandparent_process_name, "unknown");
        assert_eq!(ctx_missing_parent.grandparent_process_pid, 0);
    }

    #[test]
    fn test_calling_context_default() {
        let def = CallingContext::default();
        assert!(def.error);
        assert!(!def.authenticated);
        assert_eq!(def.username, "unknown");
        assert_eq!(def.process_name, "unknown");
        assert_eq!(def.process_pid, 0);
    }

    #[test]
    fn test_sysinfo_fallback() {
        use sysinfo::{Pid, System};
        let mut sys = System::new();
        let current_pid = Pid::from_u32(std::process::id());
        sys.refresh_process(current_pid);
        let proc = sys.process(current_pid);
        assert!(proc.is_some());
    }

    #[test]
    fn test_session_store_create_and_verify_pin_and_vault() {
        let mut store = SessionStore::new();
        assert!(store.is_empty());

        let ctx = CallingContext {
            username: "alice".into(),
            process_name: "silverwarden".into(),
            parent_process_name: "bash".into(),
            grandparent_process_name: "systemd".into(),
            process_pid: 100,
            parent_process_pid: 50,
            grandparent_process_pid: 1,
            error: false,
            authenticated: true,
        };

        // Create Pin session
        store.create_session(&ctx, SessionType::Pin, Duration::from_secs(3600));
        assert_eq!(store.len(), 1);
        assert!(!store.is_empty());

        // Verify valid session
        assert!(store.verify_session(&ctx, SessionType::Pin));

        // Different session type should not verify
        assert!(!store.verify_session(&ctx, SessionType::AccessVault));

        // Create AccessVault session
        store.create_session(&ctx, SessionType::AccessVault, Duration::from_secs(1800));
        assert_eq!(store.len(), 2);
        assert!(store.verify_session(&ctx, SessionType::AccessVault));
    }

    #[test]
    fn test_session_store_different_pid_fails() {
        let mut store = SessionStore::new();
        let ctx = CallingContext {
            username: "alice".into(),
            process_name: "silverwarden".into(),
            parent_process_name: "bash".into(),
            grandparent_process_name: "systemd".into(),
            process_pid: 100,
            parent_process_pid: 50,
            grandparent_process_pid: 1,
            error: false,
            authenticated: true,
        };

        store.create_session(&ctx, SessionType::Pin, Duration::from_secs(3600));

        // Different PID
        let other_ctx = CallingContext {
            process_pid: 101,
            ..ctx.clone()
        };
        assert!(!store.verify_session(&other_ctx, SessionType::Pin));

        // Different PPID
        let other_ppid_ctx = CallingContext {
            parent_process_pid: 51,
            ..ctx.clone()
        };
        assert!(!store.verify_session(&other_ppid_ctx, SessionType::Pin));

        // Different Grand-PPID
        let other_grand_ppid_ctx = CallingContext {
            grandparent_process_pid: 2,
            ..ctx.clone()
        };
        assert!(!store.verify_session(&other_grand_ppid_ctx, SessionType::Pin));
    }

    #[test]
    fn test_session_store_expired_fails() {
        let mut store = SessionStore::new();
        let ctx = CallingContext {
            username: "alice".into(),
            process_name: "silverwarden".into(),
            parent_process_name: "bash".into(),
            grandparent_process_name: "systemd".into(),
            process_pid: 100,
            parent_process_pid: 50,
            grandparent_process_pid: 1,
            error: false,
            authenticated: true,
        };

        // Create session with past expiration
        let expired_session = Session {
            pid: ctx.process_pid,
            ppid: ctx.parent_process_pid,
            grand_ppid: ctx.grandparent_process_pid,
            expires_at: std::time::SystemTime::now() - Duration::from_secs(10),
            session_type: SessionType::Pin,
        };
        assert!(expired_session.is_expired());
        store.sessions.push(expired_session);

        assert!(!store.verify_session(&ctx, SessionType::Pin));

        // Pruning should remove the expired session
        store.prune_expired();
        assert!(store.is_empty());
    }

    #[test]
    fn test_session_store_sshkey_git_ssh_relaxation() {
        let mut store = SessionStore::new();

        // Session created by git command
        let git_ctx = CallingContext {
            username: "alice".into(),
            process_name: "git".into(),
            parent_process_name: "bash".into(),
            grandparent_process_name: "systemd".into(),
            process_pid: 200,
            parent_process_pid: 100,
            grandparent_process_pid: 1,
            error: false,
            authenticated: true,
        };

        store.create_session(&git_ctx, SessionType::SSHKey, Duration::from_secs(3600));

        // An ssh child process with completely different PIDs should match by type
        let ssh_child_ctx = CallingContext {
            username: "alice".into(),
            process_name: "ssh".into(),
            parent_process_name: "git".into(),
            grandparent_process_name: "bash".into(),
            process_pid: 300,
            parent_process_pid: 200,
            grandparent_process_pid: 100,
            error: false,
            authenticated: true,
        };
        assert!(store.verify_session(&ssh_child_ctx, SessionType::SSHKey));

        // ssh-keygen also matches by type
        let ssh_keygen_ctx = CallingContext {
            username: "alice".into(),
            process_name: "ssh-keygen".into(),
            parent_process_name: "git".into(),
            grandparent_process_name: "bash".into(),
            process_pid: 400,
            parent_process_pid: 200,
            grandparent_process_pid: 100,
            error: false,
            authenticated: true,
        };
        assert!(store.verify_session(&ssh_keygen_ctx, SessionType::SSHKey));

        // Non-whitelisted process (e.g. "curl") must NOT match by type; requires exact PID match
        let curl_ctx = CallingContext {
            username: "alice".into(),
            process_name: "curl".into(),
            parent_process_name: "bash".into(),
            grandparent_process_name: "systemd".into(),
            process_pid: 500,
            parent_process_pid: 100,
            grandparent_process_pid: 1,
            error: false,
            authenticated: true,
        };
        assert!(!store.verify_session(&curl_ctx, SessionType::SSHKey));

        // curl with exact PIDs matches
        let curl_exact_ctx = CallingContext {
            username: "alice".into(),
            process_name: "curl".into(),
            parent_process_name: "bash".into(),
            grandparent_process_name: "systemd".into(),
            process_pid: 200,
            parent_process_pid: 100,
            grandparent_process_pid: 1,
            error: false,
            authenticated: true,
        };
        assert!(store.verify_session(&curl_exact_ctx, SessionType::SSHKey));
    }

    #[test]
    fn test_session_store_unauthenticated_fails() {
        let mut store = SessionStore::new();
        let ctx = CallingContext {
            username: "alice".into(),
            process_name: "silverwarden".into(),
            parent_process_name: "bash".into(),
            grandparent_process_name: "systemd".into(),
            process_pid: 100,
            parent_process_pid: 50,
            grandparent_process_pid: 1,
            error: false,
            authenticated: true,
        };

        store.create_session(&ctx, SessionType::Pin, Duration::from_secs(3600));

        let err_ctx = CallingContext {
            error: true,
            ..ctx.clone()
        };
        assert!(!store.verify_session(&err_ctx, SessionType::Pin));

        let unauth_ctx = CallingContext {
            authenticated: false,
            ..ctx.clone()
        };
        assert!(!store.verify_session(&unauth_ctx, SessionType::Pin));
    }

    #[test]
    fn test_session_store_wipe_clears_all() {
        let mut store = SessionStore::new();
        let ctx = CallingContext {
            username: "alice".into(),
            process_name: "silverwarden".into(),
            parent_process_name: "bash".into(),
            grandparent_process_name: "systemd".into(),
            process_pid: 100,
            parent_process_pid: 50,
            grandparent_process_pid: 1,
            error: false,
            authenticated: true,
        };

        store.create_session(&ctx, SessionType::Pin, Duration::from_secs(3600));
        store.create_session(&ctx, SessionType::AccessVault, Duration::from_secs(3600));
        assert_eq!(store.len(), 2);

        store.wipe();
        assert!(store.is_empty());
        assert!(!store.verify_session(&ctx, SessionType::Pin));
        assert!(!store.verify_session(&ctx, SessionType::AccessVault));
    }
}
