use crate::CallingContext;

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

/// Reads the process start-time (in jiffies) from `/proc/<pid>/stat` (token index 19 after ')').
pub fn get_process_start_time(pid: u32) -> u64 {
    if pid == 0 {
        return 0;
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(stat_content) = std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            if let Some(close_paren) = stat_content.rfind(')') {
                let remainder = &stat_content[close_paren + 1..];
                let tokens: Vec<&str> = remainder.split_whitespace().collect();
                if let Some(val_str) = tokens.get(19) {
                    if let Ok(val) = val_str.parse::<u64>() {
                        return val;
                    }
                }
            }
        }
    }
    0
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
