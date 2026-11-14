use std::path::{Path, PathBuf};

use crate::model::{ConfigError, ConfigFile};

pub const MIGRATION_SUCCESS_MSG: &str =
    "Config migrado. Ejecuta 'silverwarden sync' para descargar claves SSH y contraseñas.";

/// Returns the legacy config file path (~/.config/goldwarden.json) for a given home directory.
pub fn get_old_config_path(home: &Path) -> PathBuf {
    home.join(".config").join("goldwarden.json")
}

/// Returns the new config file path (~/.config/goldwarden/goldwarden.json) for a given home directory.
pub fn get_new_config_path(home: &Path) -> PathBuf {
    home.join(".config")
        .join("goldwarden")
        .join("goldwarden.json")
}

/// Migrates the legacy config file from ~/.config/goldwarden.json to ~/.config/goldwarden/goldwarden.json
/// for a specified home directory base.
///
/// Fixes Go bug: If old path exists and new path does not, it moves the file and returns `Ok(())`
/// (Go erroneously returned an error upon attempting to read the non-existent old path).
pub fn migrate_old_path_in(home: &Path) -> Result<(), ConfigError> {
    let old_path = get_old_config_path(home);
    let new_path = get_new_config_path(home);

    if old_path.exists() && !new_path.exists() {
        let parent_dir = new_path.parent().ok_or_else(|| {
            ConfigError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Parent directory not found",
            ))
        })?;

        if !parent_dir.exists() {
            std::fs::create_dir_all(parent_dir)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(parent_dir, std::fs::Permissions::from_mode(0o700))?;
            }
        }

        std::fs::rename(&old_path, &new_path)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&new_path, std::fs::Permissions::from_mode(0o600))?;
        }

        return Ok(());
    }

    Ok(())
}

/// Migrates legacy path using the user's HOME environment directory.
pub fn migrate_old_path() -> Result<(), ConfigError> {
    let home = std::env::var("HOME")
        .map_err(|e| ConfigError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, e)))?;
    migrate_old_path_in(Path::new(&home))
}

/// Creates a timestamped backup of the config file at `<path>.bak-<timestamp>`.
pub fn backup_config(path: &Path) -> Result<PathBuf, ConfigError> {
    if !path.exists() {
        return Err(ConfigError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Archivo a respaldar no encontrado: {}", path.display()),
        )));
    }

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("goldwarden.json");

    let backup_name = format!("{file_name}.bak-{timestamp}");
    let backup_path = path.with_file_name(backup_name);

    std::fs::copy(path, &backup_path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&backup_path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(backup_path)
}

/// Executes the full configuration migration workflow within a given home directory.
///
/// 1. Creates a backup of the existing config file before making changes.
/// 2. Migrates the file from the old path to the new path if necessary.
/// 3. Validates that the migrated config can be read and contains a non-empty `ConfigKeyHash`.
/// 4. Returns the success guidance message for M4 synchronization.
pub fn run_migration_in(home: &Path) -> Result<String, ConfigError> {
    let old_path = get_old_config_path(home);
    let new_path = get_new_config_path(home);

    if old_path.exists() {
        backup_config(&old_path)?;
    } else if new_path.exists() {
        backup_config(&new_path)?;
    } else {
        return Err(ConfigError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "No se encontró archivo de configuración para migrar en ~/.config/goldwarden.json ni ~/.config/goldwarden/goldwarden.json",
        )));
    }

    migrate_old_path_in(home)?;

    if !new_path.exists() {
        return Err(ConfigError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "El archivo migrado no existe en la ruta de destino",
        )));
    }

    let content = std::fs::read_to_string(&new_path)?;
    let cfg: ConfigFile = serde_json::from_str(&content)?;

    if cfg.config_key_hash.trim().is_empty() {
        return Err(ConfigError::Crypto(
            "ConfigKeyHash no encontrado o vacío en el archivo de configuración".to_string(),
        ));
    }

    Ok(MIGRATION_SUCCESS_MSG.to_string())
}

/// Executes the full configuration migration workflow using the user's HOME directory.
pub fn run_migration() -> Result<String, ConfigError> {
    let home = std::env::var("HOME")
        .map_err(|e| ConfigError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, e)))?;
    run_migration_in(Path::new(&home))
}
