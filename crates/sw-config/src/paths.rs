use std::path::{Path, PathBuf};

/// Returns the default agent socket path `~/.silverwarden.sock` for a specific home,
/// or falls back to the current user's `$HOME`.
pub fn socket_path_from_home(home: Option<&Path>) -> Result<PathBuf, crate::ConfigError> {
    let home = match home {
        Some(h) => h.to_path_buf(),
        None => dirs::home_dir().ok_or_else(|| {
            crate::ConfigError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "No se pudo determinar $HOME",
            ))
        })?,
    };
    Ok(home.join(".silverwarden.sock"))
}

/// Returns the default agent socket path `~/.silverwarden.sock` for the current user.
pub fn default_socket_path() -> Result<PathBuf, crate::ConfigError> {
    socket_path_from_home(None)
}

/// Returns the default SSH agent socket path `~/.silverwarden-ssh-agent.sock` for a specific home,
/// or falls back to the current user's `$HOME`.
pub fn ssh_agent_socket_path_from_home(home: Option<&Path>) -> Result<PathBuf, crate::ConfigError> {
    let home = match home {
        Some(h) => h.to_path_buf(),
        None => dirs::home_dir().ok_or_else(|| {
            crate::ConfigError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "No se pudo determinar $HOME",
            ))
        })?,
    };
    Ok(home.join(".silverwarden-ssh-agent.sock"))
}

/// Returns the default SSH agent socket path `~/.silverwarden-ssh-agent.sock` for the current user.
pub fn default_ssh_agent_socket_path() -> Result<PathBuf, crate::ConfigError> {
    ssh_agent_socket_path_from_home(None)
}

/// Returns the SSH agent socket path `.silverwarden-ssh-agent.sock` in the same directory
/// as the given main socket path.
pub fn ssh_agent_socket_path_next_to(socket_path: &Path) -> PathBuf {
    socket_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(|p| p.join(".silverwarden-ssh-agent.sock"))
        .unwrap_or_else(|| PathBuf::from(".silverwarden-ssh-agent.sock"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socket_path_from_home() {
        let path = socket_path_from_home(Some(Path::new("/custom/home"))).unwrap();
        assert_eq!(path, PathBuf::from("/custom/home/.silverwarden.sock"));
    }

    #[test]
    fn test_default_socket_path() {
        let path = default_socket_path().expect("Default socket path succeeds");
        assert!(path.ends_with(".silverwarden.sock"));
    }

    #[test]
    fn test_ssh_agent_socket_path_from_home() {
        let path = ssh_agent_socket_path_from_home(Some(Path::new("/custom/home"))).unwrap();
        assert_eq!(
            path,
            PathBuf::from("/custom/home/.silverwarden-ssh-agent.sock")
        );
    }

    #[test]
    fn test_default_ssh_agent_socket_path() {
        let path = default_ssh_agent_socket_path().expect("Default SSH agent socket path succeeds");
        assert!(path.ends_with(".silverwarden-ssh-agent.sock"));
    }

    #[test]
    fn test_ssh_agent_socket_path_next_to() {
        let with_parent = ssh_agent_socket_path_next_to(Path::new("/tmp/test/.silverwarden.sock"));
        assert_eq!(
            with_parent,
            PathBuf::from("/tmp/test/.silverwarden-ssh-agent.sock")
        );

        let without_parent = ssh_agent_socket_path_next_to(Path::new(".silverwarden.sock"));
        assert_eq!(
            without_parent,
            PathBuf::from(".silverwarden-ssh-agent.sock")
        );
    }
}
