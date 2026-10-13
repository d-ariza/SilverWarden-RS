use crate::error::CryptoError;
use crate::mem::{LockedBuffer, MemLockedBuffer};
use argon2::Argon2;
use pbkdf2::pbkdf2_hmac;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// Supported Key Derivation Function types in Bitwarden.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum KdfType {
    Pbkdf2 = 0,
    Argon2id = 1,
}

impl KdfType {
    pub fn from_i32(val: i32) -> Result<Self, CryptoError> {
        match val {
            0 => Ok(Self::Pbkdf2),
            1 => Ok(Self::Argon2id),
            other => Err(CryptoError::UnsupportedCipherType(other)),
        }
    }
}

impl<'de> Deserialize<'de> for KdfType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let val = i32::deserialize(deserializer)?;
        KdfType::from_i32(val).map_err(serde::de::Error::custom)
    }
}

impl Serialize for KdfType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_i32(*self as i32)
    }
}

/// Configuration parameters for key derivation as provided by the server.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct KdfConfig {
    #[serde(alias = "kdf", alias = "Kdf", alias = "kdfType", alias = "Type")]
    pub kdf_type: KdfType,

    #[serde(alias = "kdfIterations", alias = "KdfIterations", alias = "iterations")]
    pub iterations: u32,

    #[serde(default, alias = "kdfMemory", alias = "KdfMemory", alias = "memory")]
    pub memory: Option<u32>,

    #[serde(
        default,
        alias = "kdfParallelism",
        alias = "KdfParallelism",
        alias = "parallelism"
    )]
    pub parallelism: Option<u32>,
}

/// Protected in-memory container for the 32-byte derived master key.
#[derive(Debug)]
pub struct MasterKey {
    inner: MemLockedBuffer,
}

impl MasterKey {
    /// Creates a MasterKey from a 32-byte secret slice, locking it into RAM.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidKdfParams(format!(
                "MasterKey must be exactly 32 bytes, got {}",
                bytes.len()
            )));
        }
        let inner = MemLockedBuffer::new(bytes)?;
        Ok(Self { inner })
    }

    pub fn as_slice(&self) -> &[u8] {
        self.inner.as_slice()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

/// Normalizes email according to Bitwarden/Goldwarden parity: lowercase without trim.
fn normalize_email(email: &str) -> String {
    email.to_lowercase()
}

/// Derives the 32-byte master key from the master password and email using the specified KDF configuration.
pub fn derive_master_key(
    password: &[u8],
    email: &str,
    config: &KdfConfig,
) -> Result<MasterKey, CryptoError> {
    if config.iterations == 0 {
        return Err(CryptoError::InvalidKdfParams(
            "iterations must be greater than 0".into(),
        ));
    }

    let mut key_buf = vec![0u8; 32];

    match config.kdf_type {
        KdfType::Pbkdf2 => {
            let normalized_email = normalize_email(email);
            let salt = normalized_email.as_bytes();
            pbkdf2_hmac::<Sha256>(password, salt, config.iterations, &mut key_buf);
        }
        KdfType::Argon2id => {
            let memory = config.memory.ok_or_else(|| {
                CryptoError::InvalidKdfParams("Argon2id requires memory parameter".into())
            })?;
            let parallelism = config.parallelism.ok_or_else(|| {
                CryptoError::InvalidKdfParams("Argon2id requires parallelism parameter".into())
            })?;

            if memory == 0 {
                return Err(CryptoError::InvalidKdfParams(
                    "memory must be greater than 0".into(),
                ));
            }
            if parallelism == 0 {
                return Err(CryptoError::InvalidKdfParams(
                    "parallelism must be greater than 0".into(),
                ));
            }
            // Defense-in-depth: limit memory to 4 GiB (4 * 1024 * 1024 KiB)
            if memory > 4 * 1024 {
                return Err(CryptoError::InvalidKdfParams(
                    "memory parameter exceeds maximum allowed limit (4 GiB)".into(),
                ));
            }

            // D5 adjustment: Server passes Memory in MB. RustCrypto argon2 expects KiB blocks.
            // 64 MB * 1024 = 65536 KiB (exact parity with Go kdfConfig.Memory * 1024).
            let m_cost = memory.checked_mul(1024).ok_or_else(|| {
                CryptoError::InvalidKdfParams("memory parameter integer overflow".into())
            })?;

            // D6: parallelism truncated to u8 (parity with Go uint8(kdfConfig.Parallelism)).
            let p_cost = {
                let p = parallelism as u8;
                if p == 0 {
                    1u32
                } else {
                    p as u32
                }
            };

            // D4: Salt for Argon2id is SHA256(lowercase(email)) (32 bytes).
            let salt = Sha256::digest(normalize_email(email).as_bytes());

            let params = argon2::Params::new(m_cost, config.iterations, p_cost, Some(32))
                .map_err(|e| CryptoError::InvalidKdfParams(e.to_string()))?;

            let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

            argon2
                .hash_password_into(password, &salt, &mut key_buf)
                .map_err(|e| CryptoError::KdfError(e.to_string()))?;
        }
    }

    let master_key = MasterKey::from_bytes(&key_buf);
    key_buf.zeroize();
    master_key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kdf_type_from_i32() {
        assert_eq!(KdfType::from_i32(0).unwrap(), KdfType::Pbkdf2);
        assert_eq!(KdfType::from_i32(1).unwrap(), KdfType::Argon2id);
        assert!(KdfType::from_i32(2).is_err());
        assert!(KdfType::from_i32(-1).is_err());
    }

    #[test]
    fn test_normalize_email_no_trim() {
        assert_eq!(normalize_email("User@Example.COM"), "user@example.com");
        // Verify whitespace is NOT trimmed (strict Go parity)
        assert_eq!(normalize_email(" user@example.com "), " user@example.com ");
    }

    #[test]
    fn test_pbkdf2_hmac_sha256_vector() {
        // Standard test vector for PBKDF2-HMAC-SHA256 (password="password", salt="salt", c=1)
        let mut out = [0u8; 32];
        pbkdf2_hmac::<Sha256>(b"password", b"salt", 1, &mut out);
        let expected = [
            0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c, 0x43, 0xe7, 0x22, 0x52, 0x56, 0xc4,
            0xf8, 0x37, 0xa8, 0x65, 0x48, 0xc9, 0x2c, 0xcc, 0x35, 0x48, 0x08, 0x05, 0x98, 0x7c,
            0xb7, 0x0b, 0xe1, 0x7b,
        ];
        assert_eq!(out, expected);
    }

    #[test]
    fn test_parity_go_pbkdf2() {
        // Vector extracted directly from Go crypto.DeriveMasterKey
        let config = KdfConfig {
            kdf_type: KdfType::Pbkdf2,
            iterations: 100_000,
            memory: None,
            parallelism: None,
        };
        let key = derive_master_key(b"password123", "user@example.com", &config).unwrap();
        let expected_hex = "f4de0e1196ff2e80ac327345d9e035ddbb6fb8c6129acdf1cbf9991c63f16370";
        assert_eq!(hex_encode(key.as_slice()), expected_hex);
    }

    #[test]
    fn test_parity_go_argon2id() {
        // Vector extracted directly from Go crypto.DeriveMasterKey with 64 MB (65536 KiB)
        let config = KdfConfig {
            kdf_type: KdfType::Argon2id,
            iterations: 3,
            memory: Some(64),
            parallelism: Some(4),
        };
        let key = derive_master_key(b"password123", "user@example.com", &config).unwrap();
        let expected_hex = "8fc048a537cbda3e8b6c8596a13ec3a879b929a1a0304dddffec8df18a06222f";
        assert_eq!(hex_encode(key.as_slice()), expected_hex);
    }

    #[test]
    fn test_param_validation() {
        // Zero iterations
        let config_zero_iter = KdfConfig {
            kdf_type: KdfType::Pbkdf2,
            iterations: 0,
            memory: None,
            parallelism: None,
        };
        assert!(derive_master_key(b"pass", "a@b.c", &config_zero_iter).is_err());

        // Argon2id missing memory
        let config_no_mem = KdfConfig {
            kdf_type: KdfType::Argon2id,
            iterations: 3,
            memory: None,
            parallelism: Some(4),
        };
        assert!(derive_master_key(b"pass", "a@b.c", &config_no_mem).is_err());

        // Argon2id zero memory
        let config_zero_mem = KdfConfig {
            kdf_type: KdfType::Argon2id,
            iterations: 3,
            memory: Some(0),
            parallelism: Some(4),
        };
        assert!(derive_master_key(b"pass", "a@b.c", &config_zero_mem).is_err());

        // Argon2id missing parallelism
        let config_no_par = KdfConfig {
            kdf_type: KdfType::Argon2id,
            iterations: 3,
            memory: Some(64),
            parallelism: None,
        };
        assert!(derive_master_key(b"pass", "a@b.c", &config_no_par).is_err());

        // Argon2id zero parallelism
        let config_zero_par = KdfConfig {
            kdf_type: KdfType::Argon2id,
            iterations: 3,
            memory: Some(64),
            parallelism: Some(0),
        };
        assert!(derive_master_key(b"pass", "a@b.c", &config_zero_par).is_err());

        // Argon2id memory exceeding 4 GiB
        let config_excess_mem = KdfConfig {
            kdf_type: KdfType::Argon2id,
            iterations: 3,
            memory: Some(5000), // > 4096 MB
            parallelism: Some(4),
        };
        assert!(derive_master_key(b"pass", "a@b.c", &config_excess_mem).is_err());
    }

    #[test]
    fn test_master_key_lifecycle() {
        let valid_bytes = [42u8; 32];
        let master_key = MasterKey::from_bytes(&valid_bytes).unwrap();
        assert_eq!(master_key.len(), 32);
        assert!(!master_key.is_empty());
        assert_eq!(master_key.as_slice(), &valid_bytes);

        // Invalid length
        assert!(MasterKey::from_bytes(&[1u8; 16]).is_err());
        assert!(MasterKey::from_bytes(&[1u8; 64]).is_err());
    }

    #[test]
    fn test_kdf_config_serde() {
        let json = r#"{"kdf": 1, "kdfIterations": 3, "kdfMemory": 64, "kdfParallelism": 4}"#;
        let config: KdfConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.kdf_type, KdfType::Argon2id);
        assert_eq!(config.iterations, 3);
        assert_eq!(config.memory, Some(64));
        assert_eq!(config.parallelism, Some(4));
    }

    fn hex_encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
