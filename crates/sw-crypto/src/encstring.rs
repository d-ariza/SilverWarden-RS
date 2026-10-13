use crate::error::CryptoError;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum EncStringType {
    AesCbc256B64 = 0,
    AesCbc128HmacSha256B64 = 1,
    AesCbc256HmacSha256B64 = 2,
    Rsa2048OaepSha256B64 = 3,
    Rsa2048OaepSha1B64 = 4,
    Rsa2048OaepSha256HmacSha256B64 = 5,
    Rsa2048OaepSha1HmacSha256B64 = 6,
}

impl EncStringType {
    pub fn from_i32(val: i32) -> Result<Self, CryptoError> {
        match val {
            0 => Ok(Self::AesCbc256B64),
            1 => Ok(Self::AesCbc128HmacSha256B64),
            2 => Ok(Self::AesCbc256HmacSha256B64),
            3 => Ok(Self::Rsa2048OaepSha256B64),
            4 => Ok(Self::Rsa2048OaepSha1B64),
            5 => Ok(Self::Rsa2048OaepSha256HmacSha256B64),
            6 => Ok(Self::Rsa2048OaepSha1HmacSha256B64),
            other => Err(CryptoError::UnsupportedCipherType(other)),
        }
    }

    pub fn has_mac(&self) -> bool {
        !matches!(self, Self::AesCbc256B64)
    }
}

/// Bitwarden compatible Encrypted String representation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EncString {
    pub cipher_type: Option<EncStringType>,
    pub iv: Vec<u8>,
    pub ct: Vec<u8>,
    pub mac: Vec<u8>,
}

impl EncString {
    pub fn new(cipher_type: EncStringType, iv: Vec<u8>, ct: Vec<u8>, mac: Vec<u8>) -> Self {
        Self {
            cipher_type: Some(cipher_type),
            iv,
            ct,
            mac,
        }
    }

    pub fn is_null(&self) -> bool {
        self.iv.is_empty() && self.ct.is_empty() && self.mac.is_empty()
    }

    /// Serializes to the standard Bitwarden EncString string: `type.iv|ct[|mac]`
    pub fn to_string_repr(&self) -> Result<String, CryptoError> {
        if self.is_null() {
            return Ok(String::new());
        }

        let cipher_type = self
            .cipher_type
            .ok_or_else(|| CryptoError::InvalidEncString("Missing cipher type".into()))?;

        let iv_b64 = B64.encode(&self.iv);
        let ct_b64 = B64.encode(&self.ct);

        if cipher_type.has_mac() {
            let mac_b64 = B64.encode(&self.mac);
            Ok(format!("{}.{}|{}|{}", cipher_type as i32, iv_b64, ct_b64, mac_b64))
        } else {
            Ok(format!("{}.{}|{}", cipher_type as i32, iv_b64, ct_b64))
        }
    }
}

impl fmt::Display for EncString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.to_string_repr() {
            Ok(s) => write!(f, "{}", s),
            Err(_) => write!(f, ""),
        }
    }
}

impl FromStr for EncString {
    type Err = CryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Ok(Self::default());
        }

        let dot_pos = trimmed
            .find('.')
            .ok_or_else(|| CryptoError::InvalidEncString(format!("Missing dot separator in '{}'", trimmed)))?;

        let type_num: i32 = trimmed[..dot_pos]
            .parse()
            .map_err(|_| CryptoError::InvalidEncString(format!("Invalid cipher type integer '{}'", &trimmed[..dot_pos])))?;

        let cipher_type = EncStringType::from_i32(type_num)?;
        let remainder = &trimmed[dot_pos + 1..];
        let parts: Vec<&str> = remainder.split('|').collect();

        match cipher_type {
            EncStringType::AesCbc256HmacSha256B64 | EncStringType::AesCbc128HmacSha256B64 => {
                if parts.len() != 3 {
                    return Err(CryptoError::InvalidEncString(format!(
                        "Expected 3 parts for type {}, got {}",
                        type_num,
                        parts.len()
                    )));
                }
                let iv = B64.decode(parts[0]).map_err(|e| CryptoError::Base64Error(e.to_string()))?;
                let ct = B64.decode(parts[1]).map_err(|e| CryptoError::Base64Error(e.to_string()))?;
                let mac = B64.decode(parts[2]).map_err(|e| CryptoError::Base64Error(e.to_string()))?;
                Ok(Self {
                    cipher_type: Some(cipher_type),
                    iv,
                    ct,
                    mac,
                })
            }
            EncStringType::AesCbc256B64 => {
                if parts.len() != 2 {
                    return Err(CryptoError::InvalidEncString(format!(
                        "Expected 2 parts for type {}, got {}",
                        type_num,
                        parts.len()
                    )));
                }
                let iv = B64.decode(parts[0]).map_err(|e| CryptoError::Base64Error(e.to_string()))?;
                let ct = B64.decode(parts[1]).map_err(|e| CryptoError::Base64Error(e.to_string()))?;
                Ok(Self {
                    cipher_type: Some(cipher_type),
                    iv,
                    ct,
                    mac: Vec::new(),
                })
            }
            EncStringType::Rsa2048OaepSha1B64 | EncStringType::Rsa2048OaepSha256B64 => {
                // Asymmetric keys in Bitwarden are formatted as 4.ct
                if parts.len() == 1 {
                    let ct = B64.decode(parts[0]).map_err(|e| CryptoError::Base64Error(e.to_string()))?;
                    Ok(Self {
                        cipher_type: Some(cipher_type),
                        iv: Vec::new(),
                        ct,
                        mac: Vec::new(),
                    })
                } else if parts.len() == 2 {
                    let ct = B64.decode(parts[0]).map_err(|e| CryptoError::Base64Error(e.to_string()))?;
                    let mac = B64.decode(parts[1]).map_err(|e| CryptoError::Base64Error(e.to_string()))?;
                    Ok(Self {
                        cipher_type: Some(cipher_type),
                        iv: Vec::new(),
                        ct,
                        mac,
                    })
                } else {
                    Err(CryptoError::InvalidEncString(format!(
                        "Invalid asymmetric EncString parts count {}",
                        parts.len()
                    )))
                }
            }
            other => Err(CryptoError::UnsupportedCipherType(other as i32)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_type_2() {
        let iv = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let ct = vec![100, 101, 102, 103, 104];
        let mac = vec![200, 201, 202, 203, 204, 205];

        let enc = EncString::new(EncStringType::AesCbc256HmacSha256B64, iv.clone(), ct.clone(), mac.clone());
        let serialized = enc.to_string_repr().unwrap();
        assert!(serialized.starts_with("2."));

        let parsed: EncString = serialized.parse().unwrap();
        assert_eq!(parsed.cipher_type, Some(EncStringType::AesCbc256HmacSha256B64));
        assert_eq!(parsed.iv, iv);
        assert_eq!(parsed.ct, ct);
        assert_eq!(parsed.mac, mac);
        assert!(!parsed.is_null());
    }

    #[test]
    fn test_roundtrip_type_0() {
        let iv = vec![1, 2, 3, 4];
        let ct = vec![5, 6, 7, 8];

        let enc = EncString::new(EncStringType::AesCbc256B64, iv.clone(), ct.clone(), vec![]);
        let serialized = enc.to_string_repr().unwrap();
        assert!(serialized.starts_with("0."));

        let parsed: EncString = serialized.parse().unwrap();
        assert_eq!(parsed.cipher_type, Some(EncStringType::AesCbc256B64));
        assert_eq!(parsed.iv, iv);
        assert_eq!(parsed.ct, ct);
        assert!(parsed.mac.is_empty());
    }

    #[test]
    fn test_is_null() {
        let enc = EncString::default();
        assert!(enc.is_null());
    }

    #[test]
    fn test_invalid_formats() {
        assert!("invalid".parse::<EncString>().is_err());
        assert!("99.abc|def|ghi".parse::<EncString>().is_err());
        assert!("2.abc|def".parse::<EncString>().is_err()); // type 2 requires 3 parts
    }
}
