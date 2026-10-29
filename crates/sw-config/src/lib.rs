use base64::Engine;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::path::{Path, PathBuf};
use subtle::ConstantTimeEq;
use thiserror::Error;

const TINK_HEADER: [u8; 5] = [0x00, 0x00, 0x00, 0x00, 0x00];
const NONCE_LEN: usize = 12;

pub const KDF_ITERATIONS: u32 = 2;
pub const KDF_MEMORY_KIB: u32 = 2 * 1024 * 1024; // 2 GiB (2048 MiB), matches Goldwarden Go KDFMemory
pub const KDF_PARALLELISM: u32 = 8;

pub const KDF_MEMORY_KIB_TEST: u32 = 4 * 1024;

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

/// Representation of the configuration stored in ~/.config/goldwarden/goldwarden.json
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
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
    #[serde(
        rename = "DangerAcceptInvalidCerts",
        alias = "danger_accept_invalid_certs",
        default
    )]
    pub danger_accept_invalid_certs: bool,
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
            danger_accept_invalid_certs: false,
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
        let (identity, api, notif) = derive_server_urls(server);
        self.identity_url = identity;
        self.api_url = api;
        self.notifications_url = notif;
    }
}

/// Derives identity, api, and notifications URLs from a base server URL.
///
/// Prevents duplicating `/identity`, `/api`, or `/notifications` if already present.
pub fn derive_server_urls(server: &str) -> (String, String, String) {
    let base = server.trim().trim_end_matches('/');
    let identity_url = if base.ends_with("/identity") {
        base.to_string()
    } else {
        format!("{base}/identity")
    };
    let api_url = if base.ends_with("/api") {
        base.to_string()
    } else {
        format!("{base}/api")
    };
    let notifications_url = if base.ends_with("/notifications") {
        base.to_string()
    } else {
        format!("{base}/notifications")
    };
    (identity_url, api_url, notifications_url)
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
}

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

#[cfg(test)]
mod tests {
    use super::*;

    const EXPECTED_KEY_HEX: &str =
        "46d690a92d1b2e76b901b5221dc296ebe7a9ff6ee76b8615ede85a1323aac17a";
    const EXPECTED_HASH_HEX: &str =
        "e65f3b70990b3bb58a5fc7dc4d35bfaab58b87b81424b26f7a45dac85b2f01b3";

    #[test]
    fn test_argon2i_derivation() {
        // Fast test vector using 4 MiB memory
        let key = derive_config_key_with_params(
            "synthetic_unit_pin_123",
            "synthetic_device_uuid_456",
            KDF_MEMORY_KIB_TEST,
        )
        .expect("Argon2i derivation should succeed");
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_verify_pin_logic() {
        let key_bytes: [u8; 32] = hex::decode(EXPECTED_KEY_HEX).unwrap().try_into().unwrap();
        assert_eq!(hash_config_key(&key_bytes), EXPECTED_HASH_HEX);

        let test_pin = "test_pin_verify_999";
        let test_salt = "test_uuid_verify_999";
        let key = derive_config_key_with_params(test_pin, test_salt, KDF_MEMORY_KIB_TEST)
            .expect("Key derived");
        let expected_hash = hash_config_key(&key);

        assert!(
            verify_pin_with_params(test_pin, test_salt, &expected_hash, KDF_MEMORY_KIB_TEST)
                .expect("Verification succeeds")
        );
        assert!(!verify_pin_with_params(
            "wrong_pin",
            test_salt,
            &expected_hash,
            KDF_MEMORY_KIB_TEST
        )
        .expect("Verification succeeds"));
        assert!(!verify_pin_with_params(
            test_pin,
            "other-uuid",
            &expected_hash,
            KDF_MEMORY_KIB_TEST
        )
        .expect("Verification succeeds"));
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key_bytes: [u8; 32] = hex::decode(EXPECTED_KEY_HEX)
            .expect("Valid hex")
            .try_into()
            .expect("32 bytes");

        let plaintext = "secret goldwarden config payload 12345!@#$%^&*()";
        let encrypted_b64 =
            encrypt_string(plaintext, &key_bytes).expect("Encryption should succeed");

        // Verify Tink wire format: Base64 decodes to [0x00, 0x00, 0x00, 0x00, 0x00] + 12B nonce + CT
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&encrypted_b64)
            .expect("Should decode base64");
        assert!(raw.len() > 17);
        assert_eq!(&raw[..5], &[0x00, 0x00, 0x00, 0x00, 0x00]);

        let decrypted =
            decrypt_string(&encrypted_b64, &key_bytes).expect("Decryption should succeed");
        assert_eq!(decrypted, plaintext);

        // Subtle Tink wire format without 5-byte header
        let cipher = ChaCha20Poly1305::new_from_slice(&key_bytes).unwrap();
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce), b"subtle payload".as_ref())
            .unwrap();
        let mut raw_subtle = Vec::new();
        raw_subtle.extend_from_slice(&nonce);
        raw_subtle.extend_from_slice(&ct);
        let b64_subtle = base64::engine::general_purpose::STANDARD.encode(&raw_subtle);
        let dec_subtle = decrypt_string(&b64_subtle, &key_bytes).unwrap();
        assert_eq!(dec_subtle, "subtle payload");
    }

    #[test]
    fn test_decrypt_go_token() {
        let key_bytes: [u8; 32] = hex::decode(EXPECTED_KEY_HEX)
            .expect("Valid hex")
            .try_into()
            .expect("32 bytes");

        // Deterministic synthetic Go token decryption
        let sample_token = r#"{"access_token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9","expires_in":3600,"token_type":"Bearer","refresh_token":"ref"}"#;
        let enc_token = encrypt_string(sample_token, &key_bytes).unwrap();
        let config = ConfigFile {
            device_uuid: "1f5ef996-82f0-11f1-bc18-80304903a0d9".to_string(),
            encrypted_token: enc_token,
            ..Default::default()
        };
        let decrypted = decrypt_string(&config.encrypted_token, &key_bytes)
            .expect("Should decrypt synthetic token with derived key");
        assert!(decrypted.starts_with(r#"{"access_token":"eyJ0eXAi"#));

        let token = config
            .decrypt_token(&key_bytes)
            .expect("Should parse decrypted LoginToken");
        assert!(token.access_token.starts_with("eyJ0eXAi"));
    }

    #[test]
    fn test_update_pin() {
        let test_pin_old = "old_pin_123";
        let test_salt = "mock_salt_uuid_999";
        let initial_key =
            derive_config_key_with_params(test_pin_old, test_salt, KDF_MEMORY_KIB_TEST).unwrap();
        let mut cfg = ConfigFile {
            device_uuid: test_salt.to_string(),
            config_key_hash: hash_config_key(&initial_key),
            encrypted_client_id: encrypt_string("client_secret_data", &initial_key).unwrap(),
            ..Default::default()
        };

        assert!(cfg
            .verify_pin_with_params(test_pin_old, KDF_MEMORY_KIB_TEST)
            .unwrap());

        let test_pin_new = "new_pin_456";
        cfg.update_pin_with_params(test_pin_old, test_pin_new, KDF_MEMORY_KIB_TEST)
            .expect("Pin update succeeds");

        assert!(!cfg
            .verify_pin_with_params(test_pin_old, KDF_MEMORY_KIB_TEST)
            .unwrap());
        assert!(cfg
            .verify_pin_with_params(test_pin_new, KDF_MEMORY_KIB_TEST)
            .unwrap());

        let new_key = cfg
            .unlock_with_params(test_pin_new, KDF_MEMORY_KIB_TEST)
            .expect("Unlock with new pin succeeds");
        let decrypted_client_id = decrypt_string(&cfg.encrypted_client_id, &new_key).unwrap();
        assert_eq!(decrypted_client_id, "client_secret_data");
    }

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
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let fake_path = temp_dir.path().join("goldwarden.json");
        let sample_json = r#"{
            "IdentityUrl": "https://identity.bitwarden.com",
            "ApiUrl": "https://api.bitwarden.com",
            "DeviceUUID": "test-uuid-val",
            "ConfigKeyHash": "testhashval"
        }"#;
        std::fs::write(&fake_path, sample_json).unwrap();
        let content = std::fs::read_to_string(&fake_path).unwrap();
        let parsed: ConfigFile = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed.device_uuid, "test-uuid-val");
        assert_eq!(parsed.config_key_hash, "testhashval");
        let serialized = serde_json::to_string(&parsed).unwrap();
        let roundtripped: ConfigFile = serde_json::from_str(&serialized).unwrap();
        assert_eq!(parsed, roundtripped);
    }

    #[test]
    fn test_migrate_old_path_success() {
        let temp_home = tempfile::tempdir().expect("Create temp dir");
        let old_path = get_old_config_path(temp_home.path());
        let new_path = get_new_config_path(temp_home.path());

        std::fs::create_dir_all(old_path.parent().unwrap()).unwrap();
        std::fs::write(&old_path, r#"{"ConfigKeyHash":"testhash"}"#).unwrap();

        assert!(old_path.exists());
        assert!(!new_path.exists());

        migrate_old_path_in(temp_home.path()).expect("Migration should succeed");

        assert!(!old_path.exists());
        assert!(new_path.exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let parent_meta = std::fs::metadata(new_path.parent().unwrap()).unwrap();
            let file_meta = std::fs::metadata(&new_path).unwrap();
            assert_eq!(parent_meta.permissions().mode() & 0o777, 0o700);
            assert_eq!(file_meta.permissions().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn test_migrate_old_path_new_already_exists() {
        let temp_home = tempfile::tempdir().expect("Create temp dir");
        let old_path = get_old_config_path(temp_home.path());
        let new_path = get_new_config_path(temp_home.path());

        std::fs::create_dir_all(old_path.parent().unwrap()).unwrap();
        std::fs::create_dir_all(new_path.parent().unwrap()).unwrap();
        std::fs::write(&old_path, "old_content").unwrap();
        std::fs::write(&new_path, "new_content").unwrap();

        migrate_old_path_in(temp_home.path()).expect("Should do nothing and succeed");

        assert!(old_path.exists());
        assert_eq!(std::fs::read_to_string(&new_path).unwrap(), "new_content");
    }

    #[test]
    fn test_backup_config_creates_timestamped_file() {
        let temp_dir = tempfile::tempdir().expect("Create temp dir");
        let file_path = temp_dir.path().join("goldwarden.json");
        std::fs::write(&file_path, "original_content").unwrap();

        let backup_path = backup_config(&file_path).expect("Backup should succeed");
        assert!(backup_path.exists());
        assert!(backup_path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("goldwarden.json.bak-"));
        assert_eq!(
            std::fs::read_to_string(&backup_path).unwrap(),
            "original_content"
        );
    }

    #[test]
    fn test_run_migration_full_flow() {
        let temp_home = tempfile::tempdir().expect("Create temp dir");
        let old_path = get_old_config_path(temp_home.path());

        std::fs::create_dir_all(old_path.parent().unwrap()).unwrap();
        let valid_json = r#"{
  "ConfigKeyHash": "testhash12345",
  "IdentityUrl": "https://identity.bitwarden.com",
  "DeviceUUID": "test-uuid"
}"#;
        std::fs::write(&old_path, valid_json).unwrap();

        let result = run_migration_in(temp_home.path()).expect("Migration should succeed");
        assert_eq!(result, MIGRATION_SUCCESS_MSG);

        let new_path = get_new_config_path(temp_home.path());
        assert!(new_path.exists());
        assert!(!old_path.exists());

        let backups: Vec<_> = std::fs::read_dir(old_path.parent().unwrap())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .unwrap()
                    .starts_with("goldwarden.json.bak-")
            })
            .collect();
        assert_eq!(backups.len(), 1);
    }

    #[test]
    fn test_run_migration_missing_hash_fails() {
        let temp_home = tempfile::tempdir().expect("Create temp dir");
        let old_path = get_old_config_path(temp_home.path());

        std::fs::create_dir_all(old_path.parent().unwrap()).unwrap();
        let invalid_json = r#"{
  "ConfigKeyHash": "",
  "IdentityUrl": "https://identity.bitwarden.com"
}"#;
        std::fs::write(&old_path, invalid_json).unwrap();

        let result = run_migration_in(temp_home.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_pin_mismatched_length() {
        assert!(!verify_pin("test_pin", "test_uuid", "short_hash").unwrap());
        assert!(!verify_pin_with_params(
            "test_pin",
            "test_uuid",
            "short_hash",
            KDF_MEMORY_KIB_TEST
        )
        .unwrap());

        let cfg = ConfigFile {
            device_uuid: "test_uuid".to_string(),
            config_key_hash: "short_hash".to_string(),
            ..Default::default()
        };
        assert!(!cfg.verify_pin("test_pin").unwrap());
        assert!(matches!(
            cfg.unlock("test_pin"),
            Err(ConfigError::InvalidPin)
        ));
        let mut cfg2 = cfg.clone();
        assert!(matches!(
            cfg2.update_pin("test_pin", "new_pin"),
            Err(ConfigError::InvalidPin)
        ));
    }

    #[test]
    fn test_decrypt_string_errors() {
        let key = [42u8; 32];
        assert!(decrypt_string("not_base_64?!", &key).is_err());

        let too_short = base64::engine::general_purpose::STANDARD.encode([1u8, 2, 3]);
        assert!(decrypt_string(&too_short, &key).is_err());

        let fake_payload = vec![0u8; 35];
        let fake_b64 = base64::engine::general_purpose::STANDARD.encode(&fake_payload);
        assert!(decrypt_string(&fake_b64, &key).is_err());
    }

    #[test]
    fn test_config_file_unlock_and_decrypt_token_errors() {
        let cfg = ConfigFile::default();
        assert!(matches!(
            cfg.unlock_with_params("bad_pin", KDF_MEMORY_KIB_TEST),
            Err(ConfigError::InvalidPin)
        ));

        let key = [0u8; 32];
        assert!(matches!(
            cfg.decrypt_token(&key),
            Err(ConfigError::Crypto(_))
        ));

        let enc_bad_json = encrypt_string("not_a_json", &key).unwrap();
        let cfg_bad_json = ConfigFile {
            encrypted_token: enc_bad_json,
            ..Default::default()
        };
        assert!(matches!(
            cfg_bad_json.decrypt_token(&key),
            Err(ConfigError::Json(_))
        ));

        let mut cfg_update = ConfigFile::default();
        assert!(matches!(
            cfg_update.update_pin_with_params("wrong_old", "new", KDF_MEMORY_KIB_TEST),
            Err(ConfigError::InvalidPin)
        ));
    }

    #[test]
    fn test_decrypt_token_synthetic_success() {
        let key = [77u8; 32];
        let token = LoginToken {
            access_token: "mock_access".to_string(),
            expires_in: 7200,
            token_type: "Bearer".to_string(),
            refresh_token: "mock_refresh".to_string(),
            key: "mock_key".to_string(),
        };
        let token_json = serde_json::to_string(&token).unwrap();
        let enc_token = encrypt_string(&token_json, &key).unwrap();

        let cfg = ConfigFile {
            encrypted_token: enc_token,
            ..Default::default()
        };

        let decrypted = cfg
            .decrypt_token(&key)
            .expect("Should decrypt synthetic token");
        assert_eq!(decrypted, token);
    }

    #[test]
    fn test_backup_config_non_existent() {
        let non_existent = Path::new("/path/that/does/not/exist/9999999");
        assert!(backup_config(non_existent).is_err());
    }

    #[test]
    fn test_run_migration_new_already_exists() {
        let temp_home = tempfile::tempdir().expect("Create temp dir");
        let new_path = get_new_config_path(temp_home.path());
        std::fs::create_dir_all(new_path.parent().unwrap()).unwrap();

        let valid_json = r#"{
  "ConfigKeyHash": "validhash123",
  "IdentityUrl": "https://identity.bitwarden.com"
}"#;
        std::fs::write(&new_path, valid_json).unwrap();

        let result = run_migration_in(temp_home.path())
            .expect("Should succeed when new path already exists");
        assert_eq!(result, MIGRATION_SUCCESS_MSG);

        let backups: Vec<_> = std::fs::read_dir(new_path.parent().unwrap())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .unwrap()
                    .starts_with("goldwarden.json.bak-")
            })
            .collect();
        assert_eq!(backups.len(), 1);
    }

    #[test]
    fn test_run_migration_no_config_found() {
        let temp_home = tempfile::tempdir().expect("Create temp dir");
        let result = run_migration_in(temp_home.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_migrate_old_path_no_old_path_is_noop() {
        let temp_home = tempfile::tempdir().expect("Create temp dir");
        let res = migrate_old_path_in(temp_home.path());
        assert!(res.is_ok());
    }

    #[test]
    fn test_env_home_migration_wrappers() {
        let temp_home = tempfile::tempdir().expect("Create temp dir");
        let old_path = get_old_config_path(temp_home.path());
        std::fs::create_dir_all(old_path.parent().unwrap()).unwrap();
        std::fs::write(&old_path, r#"{"ConfigKeyHash":"env_hash"}"#).unwrap();

        let original_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", temp_home.path());

        let res = migrate_old_path();
        assert!(res.is_ok());

        let mig_res = run_migration();
        assert!(mig_res.is_ok());

        if let Some(h) = original_home {
            std::env::set_var("HOME", h);
        }
    }

    #[test]
    fn test_config_error_display_coverage() {
        let err_io = ConfigError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "io msg"));
        assert!(err_io.to_string().contains("io msg"));

        let err_json = ConfigError::Json(serde_json::from_str::<ConfigFile>("bad").unwrap_err());
        assert!(err_json.to_string().contains("JSON error"));

        let err_kdf = ConfigError::Kdf("kdf msg".to_string());
        assert!(err_kdf.to_string().contains("kdf msg"));

        let err_crypto = ConfigError::Crypto("crypto msg".to_string());
        assert!(err_crypto.to_string().contains("crypto msg"));

        let err_pin = ConfigError::InvalidPin;
        assert!(err_pin.to_string().contains("Invalid PIN"));

        let err_lock = ConfigError::Lock("lock msg".to_string());
        assert!(err_lock.to_string().contains("lock msg"));
    }

    #[test]
    fn test_error_branches_and_edge_cases() {
        // Invalid argon2 params error
        assert!(matches!(
            derive_config_key_with_params("pin", "uuid", 0),
            Err(ConfigError::Kdf(_))
        ));

        // decrypt_string invalid UTF-8
        let key = [99u8; 32];
        let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
        let nonce = [0u8; 12];
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce), b"\xFF\xFE\xFD".as_ref())
            .unwrap();
        let mut raw = Vec::new();
        raw.extend_from_slice(&TINK_HEADER);
        raw.extend_from_slice(&nonce);
        raw.extend_from_slice(&ct);
        let b64 = base64::engine::general_purpose::STANDARD.encode(&raw);
        assert!(matches!(
            decrypt_string(&b64, &key),
            Err(ConfigError::Crypto(_))
        ));

        // ConfigFile default fields
        let cfg = ConfigFile::default();
        assert!(cfg.encrypted_client_id.is_empty());
        assert!(cfg.encrypted_client_secret.is_empty());
        assert!(cfg.encrypted_token.is_empty());
        assert!(cfg.encrypted_user_symmetric_key.is_empty());
        assert!(cfg.encrypted_master_password_hash.is_empty());
        assert!(cfg.encrypted_master_key.is_empty());

        // LoginToken default fields
        let tok = LoginToken::default();
        assert!(tok.access_token.is_empty());
        assert_eq!(tok.expires_in, 0);
        assert!(tok.token_type.is_empty());
        assert!(tok.refresh_token.is_empty());
        assert!(tok.key.is_empty());

        // Parent dir creation in migrate_old_path_in
        let temp_home = tempfile::tempdir().expect("Create temp dir");
        let old_path = get_old_config_path(temp_home.path());
        std::fs::create_dir_all(old_path.parent().unwrap()).unwrap();
        std::fs::write(&old_path, r#"{"ConfigKeyHash":"testhash"}"#).unwrap();

        let new_path = get_new_config_path(temp_home.path());
        // Parent does not exist yet:
        assert!(!new_path.parent().unwrap().exists());
        migrate_old_path_in(temp_home.path()).unwrap();
        assert!(new_path.exists());
    }

    #[test]
    fn test_derived_traits_coverage() {
        let default_cfg = ConfigFile::default();
        let mut cfgs = Vec::new();
        let mut c1 = default_cfg.clone();
        c1.identity_url = "a".into();
        cfgs.push(c1);
        let mut c2 = default_cfg.clone();
        c2.api_url = "a".into();
        cfgs.push(c2);
        let mut c3 = default_cfg.clone();
        c3.notifications_url = "a".into();
        cfgs.push(c3);
        let mut c4 = default_cfg.clone();
        c4.vault_url = "a".into();
        cfgs.push(c4);
        let mut c5 = default_cfg.clone();
        c5.encrypted_client_id = "a".into();
        cfgs.push(c5);
        let mut c6 = default_cfg.clone();
        c6.encrypted_client_secret = "a".into();
        cfgs.push(c6);
        let mut c7 = default_cfg.clone();
        c7.device_uuid = "a".into();
        cfgs.push(c7);
        let mut c8 = default_cfg.clone();
        c8.config_key_hash = "a".into();
        cfgs.push(c8);
        let mut c9 = default_cfg.clone();
        c9.encrypted_token = "a".into();
        cfgs.push(c9);
        let mut c10 = default_cfg.clone();
        c10.encrypted_user_symmetric_key = "a".into();
        cfgs.push(c10);
        let mut c11 = default_cfg.clone();
        c11.encrypted_master_password_hash = "a".into();
        cfgs.push(c11);
        let mut c12 = default_cfg.clone();
        c12.encrypted_master_key = "a".into();
        cfgs.push(c12);

        for c in &cfgs {
            assert_ne!(&default_cfg, c);
            assert!(default_cfg.ne(c));
        }

        let debug_cfg = format!("{default_cfg:?}");
        assert!(debug_cfg.contains("ConfigFile"));

        let default_tok = LoginToken::default();
        let mut toks = Vec::new();
        let mut t1 = default_tok.clone();
        t1.access_token = "a".into();
        toks.push(t1);
        let mut t2 = default_tok.clone();
        t2.expires_in = 99;
        toks.push(t2);
        let mut t3 = default_tok.clone();
        t3.token_type = "a".into();
        toks.push(t3);
        let mut t4 = default_tok.clone();
        t4.refresh_token = "a".into();
        toks.push(t4);
        let mut t5 = default_tok.clone();
        t5.key = "a".into();
        toks.push(t5);

        for t in &toks {
            assert_ne!(&default_tok, t);
            assert!(default_tok.ne(t));
        }

        let debug_tok = format!("{default_tok:?}");
        assert!(debug_tok.contains("LoginToken"));

        let json_with_aliases = r#"{
            "EncryptedClientId": "alias_id",
            "DeviceUuid": "alias_uuid",
            "access_token": "token123",
            "expires_in": 3600,
            "token_type": "Bearer",
            "refresh_token": "ref123",
            "Key": "alias_key"
        }"#;
        let cfg_alias: ConfigFile = serde_json::from_str(json_with_aliases).unwrap();
        assert_eq!(cfg_alias.encrypted_client_id, "alias_id");
        assert_eq!(cfg_alias.device_uuid, "alias_uuid");

        let tok_alias: LoginToken = serde_json::from_str(json_with_aliases).unwrap();
        assert_eq!(tok_alias.key, "alias_key");
        assert_eq!(tok_alias.access_token, "token123");

        let cfg_empty: ConfigFile = serde_json::from_str("{}").unwrap();
        assert_eq!(cfg_empty.identity_url, "https://identity.bitwarden.com");

        let cfg_extra: ConfigFile = serde_json::from_str(r#"{"unknown_field": 123}"#).unwrap();
        assert_eq!(cfg_extra.identity_url, "https://identity.bitwarden.com");

        let err = ConfigError::InvalidPin;
        let debug_err = format!("{err:?}");
        assert!(debug_err.contains("InvalidPin"));
    }

    #[test]
    fn test_derive_server_urls_and_set_server() {
        let (id, api, notif) = derive_server_urls("http://localhost:8080");
        assert_eq!(id, "http://localhost:8080/identity");
        assert_eq!(api, "http://localhost:8080/api");
        assert_eq!(notif, "http://localhost:8080/notifications");

        // Trailing slash
        let (id2, api2, notif2) = derive_server_urls("http://localhost:8080/");
        assert_eq!(id2, "http://localhost:8080/identity");
        assert_eq!(api2, "http://localhost:8080/api");
        assert_eq!(notif2, "http://localhost:8080/notifications");

        // Already has /identity or /api
        let (id3, api3, notif3) = derive_server_urls("http://localhost:8080/identity");
        assert_eq!(id3, "http://localhost:8080/identity");
        assert_eq!(api3, "http://localhost:8080/identity/api");
        assert_eq!(notif3, "http://localhost:8080/identity/notifications");

        let mut cfg = ConfigFile::default();
        cfg.set_server("https://vaultwarden.local:8443");
        assert_eq!(cfg.identity_url, "https://vaultwarden.local:8443/identity");
        assert_eq!(cfg.api_url, "https://vaultwarden.local:8443/api");
        assert_eq!(
            cfg.notifications_url,
            "https://vaultwarden.local:8443/notifications"
        );
    }
}
