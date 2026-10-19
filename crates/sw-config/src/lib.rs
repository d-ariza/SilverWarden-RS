use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Configuration lock/pin error: {0}")]
    Lock(String),
}

/// Representation of the configuration stored in ~/.config/goldwarden/goldwarden.json
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ConfigFile {
    pub identity_url: String,
    pub api_url: String,
    pub notifications_url: String,
    pub vault_url: String,
    #[serde(rename = "EncryptedClientID", alias = "EncryptedClientId")]
    pub encrypted_client_id: String,
    pub encrypted_client_secret: String,
    #[serde(rename = "DeviceUUID", alias = "DeviceUuid")]
    pub device_uuid: String,
    pub config_key_hash: String,
    pub encrypted_token: String,
    pub encrypted_user_symmetric_key: String,
    pub encrypted_master_password_hash: String,
    pub encrypted_master_key: String,
}

impl Default for ConfigFile {
    fn default() -> Self {
        Self {
            identity_url: "https://identity.bitwarden.com".to_string(),
            api_url: "https://api.bitwarden.com".to_string(),
            notifications_url: "https://notifications.bitwarden.com".to_string(),
            vault_url: "https://vault.bitwarden.com".to_string(),
            encrypted_client_id: String::new(),
            encrypted_client_secret: String::new(),
            device_uuid: uuid::Uuid::new_v4().to_string(),
            config_key_hash: String::new(),
            encrypted_token: String::new(),
            encrypted_user_symmetric_key: String::new(),
            encrypted_master_password_hash: String::new(),
            encrypted_master_key: String::new(),
        }
    }
}

/// Representation of the decrypted OAuth login token payload
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct LoginToken {
    pub access_token: String,
    pub expires_in: i64,
    pub token_type: String,
    pub refresh_token: String,
    pub key: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_config_file_from_json() {
        let json_data = r#"{
  "IdentityUrl": "https://test.com",
  "ApiUrl": "https://api.test.com",
  "NotificationsUrl": "https://notif.test.com",
  "VaultUrl": "https://vault.test.com",
  "EncryptedClientID": "client_id",
  "EncryptedClientSecret": "client_secret",
  "DeviceUUID": "123e4567-e89b-12d3-a456-426614174000",
  "ConfigKeyHash": "hash123",
  "EncryptedToken": "token",
  "EncryptedUserSymmetricKey": "sym_key",
  "EncryptedMasterPasswordHash": "pass_hash",
  "EncryptedMasterKey": "master_key"
}"#;

        let config: ConfigFile =
            serde_json::from_str(json_data).expect("Should deserialize valid ConfigFile JSON");

        assert_eq!(config.identity_url, "https://test.com");
        assert_eq!(config.api_url, "https://api.test.com");
        assert_eq!(config.notifications_url, "https://notif.test.com");
        assert_eq!(config.vault_url, "https://vault.test.com");
        assert_eq!(config.encrypted_client_id, "client_id");
        assert_eq!(config.encrypted_client_secret, "client_secret");
        assert_eq!(config.device_uuid, "123e4567-e89b-12d3-a456-426614174000");
        assert_eq!(config.config_key_hash, "hash123");
        assert_eq!(config.encrypted_token, "token");
        assert_eq!(config.encrypted_user_symmetric_key, "sym_key");
        assert_eq!(config.encrypted_master_password_hash, "pass_hash");
        assert_eq!(config.encrypted_master_key, "master_key");
    }

    #[test]
    fn test_roundtrip_config_file_default() {
        let original = ConfigFile::default();

        assert_eq!(original.identity_url, "https://identity.bitwarden.com");
        assert_eq!(original.api_url, "https://api.bitwarden.com");
        assert_eq!(
            original.notifications_url,
            "https://notifications.bitwarden.com"
        );
        assert_eq!(original.vault_url, "https://vault.bitwarden.com");
        assert!(original.encrypted_client_id.is_empty());
        assert!(original.encrypted_client_secret.is_empty());
        assert!(original.config_key_hash.is_empty());
        assert!(original.encrypted_token.is_empty());
        assert!(original.encrypted_user_symmetric_key.is_empty());
        assert!(original.encrypted_master_password_hash.is_empty());
        assert!(original.encrypted_master_key.is_empty());
        assert!(!original.device_uuid.is_empty());
        assert!(uuid::Uuid::parse_str(&original.device_uuid).is_ok());

        let serialized =
            serde_json::to_string(&original).expect("Serialization of ConfigFile should succeed");

        // Verify key casing in serialized output matches Go wire format
        assert!(serialized.contains("\"IdentityUrl\":"));
        assert!(serialized.contains("\"ApiUrl\":"));
        assert!(serialized.contains("\"NotificationsUrl\":"));
        assert!(serialized.contains("\"VaultUrl\":"));
        assert!(serialized.contains("\"EncryptedClientID\":"));
        assert!(serialized.contains("\"EncryptedClientSecret\":"));
        assert!(serialized.contains("\"DeviceUUID\":"));
        assert!(serialized.contains("\"ConfigKeyHash\":"));
        assert!(serialized.contains("\"EncryptedToken\":"));
        assert!(serialized.contains("\"EncryptedUserSymmetricKey\":"));
        assert!(serialized.contains("\"EncryptedMasterPasswordHash\":"));
        assert!(serialized.contains("\"EncryptedMasterKey\":"));

        let deserialized: ConfigFile = serde_json::from_str(&serialized)
            .expect("Deserialization of serialized ConfigFile should succeed");

        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_login_token_roundtrip() {
        let token_json = r#"{
  "access_token": "eySAMPLEtoken123",
  "expires_in": 3600,
  "token_type": "Bearer",
  "refresh_token": "def456refreshtoken",
  "key": "base64encsymmetricmasterkey"
}"#;

        let token: LoginToken =
            serde_json::from_str(token_json).expect("Should deserialize LoginToken JSON");

        assert_eq!(token.access_token, "eySAMPLEtoken123");
        assert_eq!(token.expires_in, 3600);
        assert_eq!(token.token_type, "Bearer");
        assert_eq!(token.refresh_token, "def456refreshtoken");
        assert_eq!(token.key, "base64encsymmetricmasterkey");

        let serialized =
            serde_json::to_string(&token).expect("Serialization of LoginToken should succeed");
        assert!(serialized.contains("\"access_token\":"));
        assert!(serialized.contains("\"expires_in\":3600"));

        let deserialized: LoginToken = serde_json::from_str(&serialized)
            .expect("Deserialization of serialized LoginToken should succeed");

        assert_eq!(token, deserialized);
    }

    #[test]
    fn test_parse_real_goldwarden_json_if_exists() {
        if let Ok(home) = std::env::var("HOME") {
            let config_path = std::path::PathBuf::from(home)
                .join(".config")
                .join("goldwarden")
                .join("goldwarden.json");
            if config_path.exists() {
                let content =
                    std::fs::read_to_string(&config_path).expect("Should read goldwarden.json");
                let parsed: ConfigFile = serde_json::from_str(&content)
                    .expect("Should deserialize real goldwarden.json without error");

                assert!(!parsed.device_uuid.is_empty());
                assert!(!parsed.config_key_hash.is_empty());

                let serialized =
                    serde_json::to_string(&parsed).expect("Should re-serialize ConfigFile");
                let roundtripped: ConfigFile = serde_json::from_str(&serialized)
                    .expect("Should deserialize re-serialized ConfigFile");

                assert_eq!(parsed, roundtripped);
            }
        }
    }
}
