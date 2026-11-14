use base64::Engine;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::path::Path;
use subtle::ConstantTimeEq;
use thiserror::Error;

use crate::defaults::{
    derive_server_urls, RuntimeConfig, KDF_ITERATIONS, KDF_MEMORY_KIB, KDF_PARALLELISM, NONCE_LEN,
    TINK_HEADER,
};
use crate::migration::get_new_config_path;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("KDF error: {0}")]
    Kdf(String),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Invalid PIN: verification failed")]
    InvalidPin,

    #[error("Configuration lock/pin error: {0}")]
    Lock(String),
}

/// Derives the 32-byte configuration key from PIN and Device UUID using Argon2i with custom memory.
pub fn derive_config_key_with_params(
    pin: &str,
    device_uuid: &str,
    memory_kib: u32,
) -> Result<[u8; 32], ConfigError> {
    use argon2::{Algorithm, Argon2, Params, Version};

    let params = Params::new(memory_kib, KDF_ITERATIONS, KDF_PARALLELISM, Some(32))
        .map_err(|e| ConfigError::Kdf(format!("Invalid Argon2i params: {e}")))?;

    let argon2 = Argon2::new(Algorithm::Argon2i, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(pin.as_bytes(), device_uuid.as_bytes(), &mut key)
        .map_err(|e| ConfigError::Kdf(format!("Argon2i derivation failed: {e}")))?;

    Ok(key)
}

/// Derives the 32-byte configuration key from PIN and Device UUID using Argon2i.
///
/// Parity with Goldwarden Go:
/// - Algorithm: Argon2i, Version 0x13
/// - Parameters: t = 2 (iterations), m = 2048 MiB (2 * 1024 * 1024 KiB), p = 8 (parallelism lanes)
/// - Output: 32 bytes
pub fn derive_config_key(pin: &str, device_uuid: &str) -> Result<[u8; 32], ConfigError> {
    derive_config_key_with_params(pin, device_uuid, KDF_MEMORY_KIB)
}

/// Calculates the lowercase hexadecimal SHA3-256 hash of a derived key.
pub fn hash_config_key(key: &[u8; 32]) -> String {
    let hash = Sha3_256::digest(key);
    hex::encode(hash)
}

/// Verifies if a PIN matches the stored config_key_hash for a given device_uuid and memory setting in constant time.
pub fn verify_pin_with_params(
    pin: &str,
    device_uuid: &str,
    expected_hash_hex: &str,
    memory_kib: u32,
) -> Result<bool, ConfigError> {
    if expected_hash_hex.len() != 64 {
        return Ok(false);
    }

    let key = derive_config_key_with_params(pin, device_uuid, memory_kib)?;
    let calculated_hash = hash_config_key(&key);

    let matches = calculated_hash
        .as_bytes()
        .ct_eq(expected_hash_hex.as_bytes());
    Ok(matches.into())
}

/// Verifies if a PIN matches the stored config_key_hash for a given device_uuid in constant time.
pub fn verify_pin(
    pin: &str,
    device_uuid: &str,
    expected_hash_hex: &str,
) -> Result<bool, ConfigError> {
    verify_pin_with_params(pin, device_uuid, expected_hash_hex, KDF_MEMORY_KIB)
}

/// Encrypts a plaintext string using Google Tink ChaCha20-Poly1305 wire format.
///
/// Binary layout:
/// `[0x00, 0x00, 0x00, 0x00, 0x00]` (5-byte Key ID) || `nonce` (12 bytes) || `ciphertext + Poly1305 tag` (16 bytes).
/// The resulting binary blob is returned as a standard Base64 string.
pub fn encrypt_string(plaintext: &str, key: &[u8; 32]) -> Result<String, ConfigError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| ConfigError::Crypto(format!("ChaCha20Poly1305 init failed: {e}")))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext_and_tag = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| ConfigError::Crypto(format!("ChaCha20Poly1305 encryption failed: {e}")))?;

    let mut raw = Vec::with_capacity(TINK_HEADER.len() + NONCE_LEN + ciphertext_and_tag.len());
    raw.extend_from_slice(&TINK_HEADER);
    raw.extend_from_slice(&nonce_bytes);
    raw.extend_from_slice(&ciphertext_and_tag);

    Ok(base64::engine::general_purpose::STANDARD.encode(&raw))
}

/// Decrypts a standard Base64 string wrapping Google Tink ChaCha20-Poly1305 wire format.
///
/// Supports both:
/// - Tink Keyset format: 5 bytes `[0x00, 0x00, 0x00, 0x00, 0x00]` + 12-byte nonce + ciphertext + 16-byte tag.
/// - Tink subtle format (raw Go): 12-byte nonce + ciphertext + 16-byte tag.
pub fn decrypt_string(b64: &str, key: &[u8; 32]) -> Result<String, ConfigError> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|e| ConfigError::Crypto(format!("Invalid base64 encoding: {e}")))?;

    let (nonce_bytes, ciphertext_and_tag) = if raw.starts_with(&TINK_HEADER) && raw.len() >= 33 {
        (&raw[5..17], &raw[17..])
    } else if raw.len() >= NONCE_LEN + 16 {
        (&raw[..NONCE_LEN], &raw[NONCE_LEN..])
    } else {
        return Err(ConfigError::Crypto(
            "Encrypted payload too short for Tink nonce and tag".to_string(),
        ));
    };

    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| ConfigError::Crypto(format!("ChaCha20Poly1305 init failed: {e}")))?;
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext_bytes = cipher
        .decrypt(nonce, ciphertext_and_tag)
        .map_err(|e| ConfigError::Crypto(format!("ChaCha20Poly1305 decryption failed: {e}")))?;

    String::from_utf8(plaintext_bytes)
        .map_err(|e| ConfigError::Crypto(format!("Plaintext is not valid UTF-8: {e}")))
}

/// Helper function to deserialize an optional or null struct as Default
pub fn deserialize_opt_or_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    let opt = Option::<T>::deserialize(deserializer)?;
    Ok(opt.unwrap_or_default())
}

/// Representation of the configuration stored in ~/.config/goldwarden/goldwarden.json
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct ConfigFile {
    #[serde(alias = "identityUrl")]
    pub identity_url: String,
    #[serde(alias = "apiUrl")]
    pub api_url: String,
    #[serde(alias = "notificationsUrl")]
    pub notifications_url: String,
    #[serde(alias = "vaultUrl")]
    pub vault_url: String,
    #[serde(
        rename = "EncryptedClientID",
        alias = "EncryptedClientId",
        alias = "encryptedClientId",
        alias = "encrypted_client_id"
    )]
    pub encrypted_client_id: String,
    #[serde(alias = "encryptedClientSecret", alias = "encrypted_client_secret")]
    pub encrypted_client_secret: String,
    #[serde(
        rename = "DeviceUUID",
        alias = "DeviceUuid",
        alias = "deviceUuid",
        alias = "device_uuid"
    )]
    pub device_uuid: String,
    #[serde(alias = "configKeyHash", alias = "config_key_hash")]
    pub config_key_hash: String,
    #[serde(alias = "encryptedToken", alias = "encrypted_token")]
    pub encrypted_token: String,
    #[serde(
        alias = "encryptedUserSymmetricKey",
        alias = "encrypted_user_symmetric_key"
    )]
    pub encrypted_user_symmetric_key: String,
    #[serde(
        alias = "encryptedMasterPasswordHash",
        alias = "encrypted_master_password_hash"
    )]
    pub encrypted_master_password_hash: String,
    #[serde(alias = "encryptedMasterKey", alias = "encrypted_master_key")]
    pub encrypted_master_key: String,
    #[serde(
        deserialize_with = "deserialize_opt_or_default",
        alias = "runtimeConfig",
        alias = "runtime_config"
    )]
    pub runtime_config: RuntimeConfig,
    #[serde(
        rename = "DangerAcceptInvalidCerts",
        alias = "dangerAcceptInvalidCerts",
        alias = "danger_accept_invalid_certs"
    )]
    pub danger_accept_invalid_certs: bool,
    #[serde(rename = "ServerUrl", alias = "serverUrl", alias = "server_url")]
    pub server_url: String,
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
            runtime_config: RuntimeConfig::default(),
            danger_accept_invalid_certs: false,
            server_url: String::new(),
        }
    }
}

impl ConfigFile {
    /// Verifies if a PIN is valid against this configuration with custom memory parameter.
    pub fn verify_pin_with_params(&self, pin: &str, memory_kib: u32) -> Result<bool, ConfigError> {
        verify_pin_with_params(pin, &self.device_uuid, &self.config_key_hash, memory_kib)
    }

    /// Verifies if a PIN is valid against this configuration in constant time.
    pub fn verify_pin(&self, pin: &str) -> Result<bool, ConfigError> {
        self.verify_pin_with_params(pin, KDF_MEMORY_KIB)
    }

    /// Unlocks and returns the 32-byte derived configuration key if PIN is valid, using custom memory parameter.
    pub fn unlock_with_params(&self, pin: &str, memory_kib: u32) -> Result<[u8; 32], ConfigError> {
        if !self.verify_pin_with_params(pin, memory_kib)? {
            return Err(ConfigError::InvalidPin);
        }
        derive_config_key_with_params(pin, &self.device_uuid, memory_kib)
    }

    /// Unlocks and returns the 32-byte derived configuration key if PIN is valid.
    pub fn unlock(&self, pin: &str) -> Result<[u8; 32], ConfigError> {
        self.unlock_with_params(pin, KDF_MEMORY_KIB)
    }

    /// Re-encrypts all sensitive fields with a new PIN using custom memory parameter and updates `config_key_hash`.
    pub fn update_pin_with_params(
        &mut self,
        old_pin: &str,
        new_pin: &str,
        memory_kib: u32,
    ) -> Result<(), ConfigError> {
        let old_key = self.unlock_with_params(old_pin, memory_kib)?;
        let new_key = derive_config_key_with_params(new_pin, &self.device_uuid, memory_kib)?;

        let reencrypt = |val: &str| -> Result<String, ConfigError> {
            if val.is_empty() {
                Ok(String::new())
            } else {
                let decrypted = decrypt_string(val, &old_key)?;
                encrypt_string(&decrypted, &new_key)
            }
        };

        self.encrypted_client_id = reencrypt(&self.encrypted_client_id)?;
        self.encrypted_client_secret = reencrypt(&self.encrypted_client_secret)?;
        self.encrypted_token = reencrypt(&self.encrypted_token)?;
        self.encrypted_user_symmetric_key = reencrypt(&self.encrypted_user_symmetric_key)?;
        self.encrypted_master_password_hash = reencrypt(&self.encrypted_master_password_hash)?;
        self.encrypted_master_key = reencrypt(&self.encrypted_master_key)?;

        self.config_key_hash = hash_config_key(&new_key);
        Ok(())
    }

    /// Re-encrypts all sensitive fields with a new PIN and updates `config_key_hash`.
    pub fn update_pin(&mut self, old_pin: &str, new_pin: &str) -> Result<(), ConfigError> {
        self.update_pin_with_params(old_pin, new_pin, KDF_MEMORY_KIB)
    }

    /// Decrypts the OAuth login token payload using the derived key.
    pub fn decrypt_token(&self, key: &[u8; 32]) -> Result<LoginToken, ConfigError> {
        if self.encrypted_token.is_empty() {
            return Err(ConfigError::Crypto("EncryptedToken is empty".to_string()));
        }
        let decrypted_json = decrypt_string(&self.encrypted_token, key)?;
        serde_json::from_str(&decrypted_json).map_err(ConfigError::Json)
    }

    /// Checks whether the user is currently logged in (encrypted_token is present).
    pub fn is_logged_in(&self) -> bool {
        !self.encrypted_token.is_empty()
    }

    /// Encrypts and sets the OAuth login token payload using the derived key.
    pub fn set_token(&mut self, token: &LoginToken, key: &[u8; 32]) -> Result<(), ConfigError> {
        let serialized = serde_json::to_string(token).map_err(ConfigError::Json)?;
        self.encrypted_token = encrypt_string(&serialized, key)?;
        Ok(())
    }

    /// Encrypts and sets the raw user symmetric key bytes using the derived key.
    pub fn set_user_symmetric_key(
        &mut self,
        sym_key: &[u8],
        key: &[u8; 32],
    ) -> Result<(), ConfigError> {
        let b64 = base64::engine::general_purpose::STANDARD.encode(sym_key);
        self.encrypted_user_symmetric_key = encrypt_string(&b64, key)?;
        Ok(())
    }

    /// Encrypts and sets the API client ID using the derived key.
    pub fn set_client_id(&mut self, client_id: &str, key: &[u8; 32]) -> Result<(), ConfigError> {
        self.encrypted_client_id = encrypt_string(client_id, key)?;
        Ok(())
    }

    /// Decrypts the API client ID using the derived key.
    pub fn decrypt_client_id(&self, key: &[u8; 32]) -> Result<String, ConfigError> {
        if self.encrypted_client_id.is_empty() {
            return Err(ConfigError::Crypto(
                "EncryptedClientID is empty".to_string(),
            ));
        }
        decrypt_string(&self.encrypted_client_id, key)
    }

    /// Encrypts and sets the API client secret using the derived key.
    pub fn set_client_secret(
        &mut self,
        client_secret: &str,
        key: &[u8; 32],
    ) -> Result<(), ConfigError> {
        self.encrypted_client_secret = encrypt_string(client_secret, key)?;
        Ok(())
    }

    /// Decrypts the API client secret using the derived key.
    pub fn decrypt_client_secret(&self, key: &[u8; 32]) -> Result<String, ConfigError> {
        if self.encrypted_client_secret.is_empty() {
            return Err(ConfigError::Crypto(
                "EncryptedClientSecret is empty".to_string(),
            ));
        }
        decrypt_string(&self.encrypted_client_secret, key)
    }

    /// Decrypts the raw user symmetric key bytes using the derived key.
    pub fn decrypt_user_symmetric_key(&self, key: &[u8; 32]) -> Result<Vec<u8>, ConfigError> {
        if self.encrypted_user_symmetric_key.is_empty() {
            return Err(ConfigError::Crypto(
                "EncryptedUserSymmetricKey is empty".to_string(),
            ));
        }
        let decrypted = decrypt_string(&self.encrypted_user_symmetric_key, key)?;
        if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(decrypted.trim()) {
            Ok(bytes)
        } else {
            Ok(decrypted.into_bytes())
        }
    }

    /// Saves the configuration to a file on disk atomically.
    pub fn save_to_file(&self, path: &Path) -> Result<(), std::io::Error> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let content = serde_json::to_string_pretty(self).map_err(std::io::Error::other)?;
        std::fs::write(path, content)
    }

    /// Loads the configuration from a file on disk.
    pub fn load_from_file(path: &Path) -> Result<Self, std::io::Error> {
        let content = std::fs::read_to_string(path)?;
        serde_json::from_str(&content)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    /// Loads the configuration from the default path or returns default configuration.
    pub fn load_or_default() -> Self {
        if let Ok(home) = std::env::var("HOME") {
            let path = get_new_config_path(Path::new(&home));
            if path.exists() {
                if let Ok(cfg) = Self::load_from_file(&path) {
                    return cfg;
                }
            }
        }
        Self::default()
    }

    /// Sets identity, api, and notifications URLs derived from a base server URL.
    pub fn set_server(&mut self, server: &str) {
        self.server_url = server.to_string();
        let (identity, api, notif) = derive_server_urls(server);
        self.identity_url = identity;
        self.api_url = api;
        self.notifications_url = notif;
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
    #[serde(default, alias = "Key")]
    pub key: String,
    #[serde(default, alias = "Kdf")]
    pub kdf: Option<i32>,
    #[serde(default, alias = "KdfIterations")]
    pub kdf_iterations: Option<u32>,
    #[serde(default, alias = "KdfMemory")]
    pub kdf_memory: Option<u32>,
    #[serde(default, alias = "KdfParallelism")]
    pub kdf_parallelism: Option<u32>,
}
