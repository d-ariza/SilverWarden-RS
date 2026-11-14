use super::*;
use std::time::Duration;

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
    let info_parens = parse_proc_stat(stat_parens).expect("Should parse comm with nested parens");
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
    let ctx_keygen =
        resolve_calling_context_with_lookup(1000, 30, Some("testuser".to_string()), mock_lookup);
    assert!(!ctx_keygen.error);
    assert!(ctx_keygen.authenticated);
    assert_eq!(ctx_keygen.process_name, "git");
    assert_eq!(ctx_keygen.process_pid, 20);
    assert_eq!(ctx_keygen.parent_process_name, "zsh");
    assert_eq!(ctx_keygen.parent_process_pid, 10);
    assert_eq!(ctx_keygen.grandparent_process_name, "systemd");
    assert_eq!(ctx_keygen.grandparent_process_pid, 1);

    // 2. ssh with git parent should also anchor to git
    let ctx_ssh_git =
        resolve_calling_context_with_lookup(1000, 40, Some("testuser".to_string()), mock_lookup);
    assert_eq!(ctx_ssh_git.process_name, "git");
    assert_eq!(ctx_ssh_git.process_pid, 20);

    // 3. ssh with zsh parent (not git) should NOT anchor, stays ssh
    let ctx_ssh_zsh =
        resolve_calling_context_with_lookup(1000, 50, Some("testuser".to_string()), mock_lookup);
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

#[test]
fn test_get_process_start_time() {
    assert_eq!(get_process_start_time(0), 0);
    #[cfg(target_os = "linux")]
    {
        let current_pid = std::process::id();
        let start = get_process_start_time(current_pid);
        assert!(start > 0);
    }
}
