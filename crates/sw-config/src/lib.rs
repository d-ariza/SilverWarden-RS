use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("IO error: {0}")]
    Io(#[io::source] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Configuration lock/pin error: {0}")]
    Lock(String),
}

impl From<std::io::Error> for ConfigError {
    fn from(err: std::io::Error) -> Self {
        ConfigError::Io(err)
    }
}

/// Representation of ~/.config/goldwarden/goldwarden.json
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct ConfigFile {
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub device_uuid: String,
    #[serde(default)]
    pub server_url: String,
    #[serde(default)]
    pub identity_url: String,
    #[serde(default)]
    pub notifications_url: String,
    #[serde(default)]
    pub login_token: Option<String>,
    #[serde(default)]
    pub config_key_hash: Option<String>,
    #[serde(default)]
    pub auth_key: Option<String>,
}

impl Default for ConfigFile {
    fn default() -> Self {
        Self {
            version: "0.1.0".to_string(),
            device_uuid: uuid::Uuid::new_v4().to_string(),
            server_url: "https://vault.bitwarden.com".to_string(),
            identity_url: "https://identity.bitwarden.com".to_string(),
            notifications_url: "https://notifications.bitwarden.com".to_string(),
            login_token: None,
            config_key_hash: None,
            auth_key: None,
        }
    }
}
