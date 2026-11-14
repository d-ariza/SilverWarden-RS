use std::path::{Path, PathBuf};

use crate::models::{SyncData, VaultError};

/// Configurable paths for local vault caching and persistent storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultPaths {
    pub(crate) base_dir: PathBuf,
}

impl VaultPaths {
    /// Creates a `VaultPaths` with a custom base directory.
    pub fn new(base_dir: impl Into<PathBuf>) -> Self {
        Self {
            base_dir: base_dir.into(),
        }
    }

    /// Resolves the default system data directory for SilverWarden:
    /// e.g. `~/.local/share/silverwarden` on Linux via `dirs::data_dir()`.
    pub fn default_paths() -> Result<Self, VaultError> {
        let base = dirs::data_dir()
            .ok_or_else(|| {
                VaultError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "Could not determine system data directory",
                ))
            })?
            .join("silverwarden");
        Ok(Self::new(base))
    }

    /// The base directory containing the vault data.
    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    /// The path to `vault.json`.
    pub fn vault_file(&self) -> PathBuf {
        self.base_dir.join("vault.json")
    }

    /// Ensures the parent directory exists with secure permissions (0700 on Unix).
    pub fn ensure_dirs(&self) -> Result<(), VaultError> {
        if !self.base_dir.exists() {
            std::fs::create_dir_all(&self.base_dir)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(
                    &self.base_dir,
                    std::fs::Permissions::from_mode(0o700),
                );
            }
        }
        Ok(())
    }
}

impl Default for VaultPaths {
    fn default() -> Self {
        Self::default_paths().unwrap_or_else(|_| Self::new(PathBuf::from(".silverwarden")))
    }
}

/// Saves `SyncData` atomically to `path` using a temporary file and rename.
///
/// On Unix, permissions are strictly restricted to 0600 (owner read/write only).
pub fn save_vault(path: &Path, data: &SyncData) -> Result<(), VaultError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
            }
        }
    }

    let serialized = serde_json::to_vec_pretty(data)?;

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut temp_file = tempfile::NamedTempFile::new_in(parent)?;

    use std::io::Write;
    temp_file.write_all(&serialized)?;
    temp_file.flush()?;
    temp_file.as_file().sync_all()?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(temp_file.path(), perms)?;
    }

    temp_file
        .persist(path)
        .map_err(|e| VaultError::Io(e.error))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        let _ = std::fs::set_permissions(path, perms);
    }

    Ok(())
}

/// Asynchronous wrapper for `save_vault`.
pub async fn save_vault_async(path: PathBuf, data: SyncData) -> Result<(), VaultError> {
    tokio::task::spawn_blocking(move || save_vault(&path, &data))
        .await
        .map_err(|e| VaultError::Other(e.to_string()))?
}

/// Loads `SyncData` from `path`.
pub fn load_vault(path: &Path) -> Result<SyncData, VaultError> {
    if !path.exists() {
        return Err(VaultError::NotFound(path.to_path_buf()));
    }

    let file = std::fs::File::open(path)?;
    let reader = std::io::BufReader::new(file);
    let data: SyncData = serde_json::from_reader(reader)?;
    Ok(data)
}

/// Asynchronous wrapper for `load_vault`.
pub async fn load_vault_async(path: PathBuf) -> Result<SyncData, VaultError> {
    tokio::task::spawn_blocking(move || load_vault(&path))
        .await
        .map_err(|e| VaultError::Other(e.to_string()))?
}
