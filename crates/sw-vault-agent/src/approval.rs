use crate::error::SshAgentError;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

/// Trait abstracting approval requests (e.g., via pinentry, desktop prompt, or test mocks).
pub trait ApprovalProvider: Send + Sync {
    fn get_approval(&self, title: &str, description: &str) -> Result<bool, SshAgentError>;
}

/// Default approval provider using pinentry.
#[derive(Debug, Default, Clone)]
pub struct DefaultApprovalProvider {
    pub bypass: bool,
    pub custom_bin: Option<PathBuf>,
}

impl DefaultApprovalProvider {
    pub fn new() -> Self {
        Self {
            bypass: false,
            custom_bin: None,
        }
    }

    pub fn with_bypass() -> Self {
        Self {
            bypass: true,
            custom_bin: None,
        }
    }

    pub fn with_custom_bin(bin: PathBuf) -> Self {
        Self {
            bypass: false,
            custom_bin: Some(bin),
        }
    }
}

impl ApprovalProvider for DefaultApprovalProvider {
    fn get_approval(&self, title: &str, description: &str) -> Result<bool, SshAgentError> {
        if self.bypass {
            tracing::info!("Approval bypassed via test configuration; approving signature");
            return Ok(true);
        }

        let pinentry_bin = self.custom_bin.clone().or_else(|| {
            [
                "pinentry",
                "pinentry-curses",
                "pinentry-gnome3",
                "pinentry-qt",
                "pinentry-mac",
            ]
            .iter()
            .find_map(|bin| which_bin(bin))
        });

        let bin = match pinentry_bin {
            Some(b) => b,
            None => {
                tracing::warn!("No pinentry binary found for approval dialog");
                return Err(SshAgentError::ApprovalDenied(
                    "No pinentry binary available".into(),
                ));
            }
        };

        run_pinentry_confirm(&bin, title, description)
    }
}

pub fn which_bin(name: &str) -> Option<PathBuf> {
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let full = dir.join(name);
            if full.is_file() {
                return Some(full);
            }
        }
    }
    None
}

pub fn run_pinentry_confirm(
    bin: &Path,
    title: &str,
    description: &str,
) -> Result<bool, SshAgentError> {
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Command, Stdio};

    let mut child = Command::new(bin)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| SshAgentError::ApprovalDenied(format!("Failed to spawn pinentry: {e}")))?;

    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| SshAgentError::ApprovalDenied("Failed to open pinentry stdin".into()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| SshAgentError::ApprovalDenied("Failed to open pinentry stdout".into()))?;
    let mut reader = BufReader::new(stdout);

    // Initial OK greeting from pinentry
    let mut greeting = String::new();
    let _ = reader.read_line(&mut greeting);

    let mut send_cmd = |cmd: &str| -> Result<String, SshAgentError> {
        stdin
            .write_all(cmd.as_bytes())
            .map_err(|e| SshAgentError::ApprovalDenied(e.to_string()))?;
        stdin
            .write_all(b"\n")
            .map_err(|e| SshAgentError::ApprovalDenied(e.to_string()))?;
        stdin
            .flush()
            .map_err(|e| SshAgentError::ApprovalDenied(e.to_string()))?;

        loop {
            let mut resp = String::new();
            let bytes_read = reader
                .read_line(&mut resp)
                .map_err(|e| SshAgentError::ApprovalDenied(e.to_string()))?;
            if bytes_read == 0 {
                return Err(SshAgentError::ApprovalDenied(
                    "Pinentry closed unexpectedly".into(),
                ));
            }
            if resp.starts_with("OK") || resp.starts_with("ERR") {
                return Ok(resp);
            }
        }
    };

    let _ = send_cmd(&format!("SETTITLE {}", title.replace(['\n', '\r'], " ")));
    let _ = send_cmd(&format!(
        "SETDESC {}",
        description.replace(['\n', '\r'], " ")
    ));
    let _ = send_cmd(&format!("SETPROMPT {}", title.replace(['\n', '\r'], " ")));
    let confirm_res = send_cmd("CONFIRM")?;
    let _ = send_cmd("BYE");
    let _ = child.wait();

    if confirm_res.starts_with("OK") {
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Mock approval provider for deterministic unit and integration tests.
#[derive(Debug, Default)]
pub struct MockApprovalProvider {
    approved: AtomicBool,
    call_count: std::sync::atomic::AtomicUsize,
    last_title: std::sync::RwLock<Option<String>>,
    last_description: std::sync::RwLock<Option<String>>,
}

impl MockApprovalProvider {
    pub fn new(approved: bool) -> Self {
        Self {
            approved: AtomicBool::new(approved),
            call_count: std::sync::atomic::AtomicUsize::new(0),
            last_title: std::sync::RwLock::new(None),
            last_description: std::sync::RwLock::new(None),
        }
    }

    pub fn set_approved(&self, approved: bool) {
        self.approved.store(approved, Ordering::SeqCst);
    }

    pub fn call_count(&self) -> usize {
        self.call_count.load(Ordering::SeqCst)
    }

    pub fn last_title(&self) -> Option<String> {
        self.last_title.read().unwrap().clone()
    }

    pub fn last_description(&self) -> Option<String> {
        self.last_description.read().unwrap().clone()
    }
}

impl ApprovalProvider for MockApprovalProvider {
    fn get_approval(&self, title: &str, description: &str) -> Result<bool, SshAgentError> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        *self.last_title.write().unwrap() = Some(title.to_string());
        *self.last_description.write().unwrap() = Some(description.to_string());
        Ok(self.approved.load(Ordering::SeqCst))
    }
}
