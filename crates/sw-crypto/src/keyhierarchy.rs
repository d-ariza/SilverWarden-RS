use crate::error::CryptoError;
use crate::kdf::{KdfConfig, MasterKey};
use crate::mem::{LockedBuffer, MemLockedBuffer};
use hkdf::Hkdf;
use sha2::Sha256;
use std::collections::HashMap;
use std::fmt;
use zeroize::Zeroize;

/// 64-byte symmetric key container holding separated 32-byte encryption and MAC keys in locked RAM.
pub struct SymmetricKey {
    enc_key: MemLockedBuffer,
    mac_key: MemLockedBuffer,
}

impl SymmetricKey {
    /// Creates a SymmetricKey from a 64-byte slice (32 bytes encKey || 32 bytes macKey).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != 64 {
            return Err(CryptoError::InvalidKeyLength(format!(
                "SymmetricKey requires exactly 64 bytes, got {}",
                bytes.len()
            )));
        }
        Self::from_parts(&bytes[0..32], &bytes[32..64])
    }

    /// Creates a SymmetricKey from separate 32-byte encryption and MAC key slices.
    pub fn from_parts(enc_key: &[u8], mac_key: &[u8]) -> Result<Self, CryptoError> {
        if enc_key.len() != 32 {
            return Err(CryptoError::InvalidKeyLength(format!(
                "enc_key must be exactly 32 bytes, got {}",
                enc_key.len()
            )));
        }
        if mac_key.len() != 32 {
            return Err(CryptoError::InvalidKeyLength(format!(
                "mac_key must be exactly 32 bytes, got {}",
                mac_key.len()
            )));
        }

        let enc_buf = MemLockedBuffer::new(enc_key)?;
        let mac_buf = MemLockedBuffer::new(mac_key)?;

        Ok(Self {
            enc_key: enc_buf,
            mac_key: mac_buf,
        })
    }

    /// Concatenates `enc_key || mac_key` into a 64-byte array.
    pub fn bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[0..32].copy_from_slice(self.enc_key.as_slice());
        out[32..64].copy_from_slice(self.mac_key.as_slice());
        out
    }

    /// Returns a slice reference to the 32-byte encryption key.
    pub fn enc_key(&self) -> &[u8] {
        self.enc_key.as_slice()
    }

    /// Returns a slice reference to the 32-byte MAC key.
    pub fn mac_key(&self) -> &[u8] {
        self.mac_key.as_slice()
    }

    /// Total key length in bytes (always 64).
    pub fn len(&self) -> usize {
        64
    }

    /// Always false for a valid symmetric key.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Wipes internal buffers.
    pub fn wipe(&mut self) {
        self.enc_key.wipe();
        self.mac_key.wipe();
    }

    /// Fallible clone. Returns error if memory locking fails for the new buffers.
    pub fn try_clone(&self) -> Result<Self, CryptoError> {
        Self::from_parts(self.enc_key.as_slice(), self.mac_key.as_slice())
    }
}

impl fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SymmetricKey")
            .field("enc_key", &"[REDACTED]")
            .field("mac_key", &"[REDACTED]")
            .finish()
    }
}

/// Derives encryption and MAC keys from a master key using HKDF-Expand (SHA-256).
///
/// Notice: uses `Hkdf::from_prk` because the master key is already pseudorandom.
/// Parity with Go: `hkdf.Expand(sha256.New, masterKey, []byte("enc"))` and `[]byte("mac")`.
pub fn stretch_key(master_key: &MasterKey) -> Result<SymmetricKey, CryptoError> {
    let hk = Hkdf::<Sha256>::from_prk(master_key.as_slice())
        .map_err(|e| CryptoError::KdfError(format!("HKDF from_prk failed: {e}")))?;

    let mut enc_buf = [0u8; 32];
    let mut mac_buf = [0u8; 32];

    hk.expand(b"enc", &mut enc_buf)
        .map_err(|e| CryptoError::KdfError(format!("HKDF expand enc failed: {e}")))?;

    hk.expand(b"mac", &mut mac_buf)
        .map_err(|e| CryptoError::KdfError(format!("HKDF expand mac failed: {e}")))?;

    let key = SymmetricKey::from_parts(&enc_buf, &mac_buf);

    enc_buf.zeroize();
    mac_buf.zeroize();

    key
}

/// In-memory keyring managing unlocked session keys.
#[derive(Debug, Default)]
pub struct Keyring {
    is_locked: bool,
    account_key: Option<SymmetricKey>,
    organization_keys: HashMap<String, String>,
}

impl Keyring {
    /// Creates a new locked Keyring.
    pub fn new() -> Self {
        Self {
            is_locked: true,
            account_key: None,
            organization_keys: HashMap::new(),
        }
    }

    /// Whether the keyring is currently locked.
    pub fn is_locked(&self) -> bool {
        self.is_locked
    }

    /// Locks the keyring and wipes all sensitive keys from memory.
    pub fn lock(&mut self) {
        self.is_locked = true;
        if let Some(mut key) = self.account_key.take() {
            key.wipe();
        }
        self.organization_keys.clear();
    }

    /// Unlocks the keyring with the provided account symmetric key.
    pub fn unlock_with_account_key(&mut self, key: SymmetricKey) {
        self.is_locked = false;
        self.account_key = Some(key);
    }

    /// Returns a reference to the active account symmetric key, if unlocked.
    pub fn account_key(&self) -> Option<&SymmetricKey> {
        self.account_key.as_ref()
    }

    /// Returns a reference to the organization encrypted keys map.
    pub fn organization_keys(&self) -> &HashMap<String, String> {
        &self.organization_keys
    }

    /// Sets the organization keys map.
    pub fn set_organization_keys(&mut self, keys: HashMap<String, String>) {
        self.organization_keys = keys;
    }

    /// Stub for organization key decryption (Opción A, implemented in SW-006).
    pub fn get_symmetric_key_for_organization(
        &self,
        _uuid: &str,
    ) -> Result<SymmetricKey, CryptoError> {
        Err(CryptoError::NotImplemented(
            "get_symmetric_key_for_organization requires SW-006".into(),
        ))
    }
}

pub fn get_symmetric_key_for_organization(
    keyring: &Keyring,
    uuid: &str,
) -> Result<SymmetricKey, CryptoError> {
    keyring.get_symmetric_key_for_organization(uuid)
}

// Stubs for Option A (to be implemented in SW-005 / SW-006)

pub fn init_keyring_from_master_password(
    _keyring: &mut Keyring,
    _account_key: &crate::EncString,
    _account_private_key: &crate::EncString,
    _org_keys: HashMap<String, String>,
    _password: &[u8],
    _email: &str,
    _kdf_config: &KdfConfig,
) -> Result<(), CryptoError> {
    Err(CryptoError::NotImplemented(
        "init_keyring_from_master_password requires SW-005/SW-006".into(),
    ))
}

pub fn init_keyring_from_master_key(
    _keyring: &mut Keyring,
    _account_key: &crate::EncString,
    _account_private_key: &crate::EncString,
    _org_keys: HashMap<String, String>,
    _master_key: &MasterKey,
) -> Result<(), CryptoError> {
    Err(CryptoError::NotImplemented(
        "init_keyring_from_master_key requires SW-005/SW-006".into(),
    ))
}

pub fn init_keyring_from_user_symmetric_key(
    keyring: &mut Keyring,
    account_key: SymmetricKey,
    account_private_key: &crate::EncString,
    org_keys: HashMap<String, String>,
) -> Result<(), CryptoError> {
    if !account_private_key.is_null() && !account_private_key.ct.is_empty() {
        let _ = crate::decrypt_with(account_private_key, &account_key);
    }

    keyring.unlock_with_account_key(account_key);
    keyring.set_organization_keys(org_keys);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::derive_master_key;
    use crate::kdf::KdfType;

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[test]
    fn test_symmetric_key_from_bytes_exact_64() {
        let valid_64 = [7u8; 64];
        let key = SymmetricKey::from_bytes(&valid_64).unwrap();
        assert_eq!(key.len(), 64);
        assert!(!key.is_empty());
        assert_eq!(key.bytes(), valid_64);

        // Invalid lengths
        assert!(SymmetricKey::from_bytes(&[7u8; 63]).is_err());
        assert!(SymmetricKey::from_bytes(&[7u8; 65]).is_err());
        assert!(SymmetricKey::from_bytes(&[]).is_err());
    }

    #[test]
    fn test_symmetric_key_from_parts() {
        let enc = [1u8; 32];
        let mac = [2u8; 32];
        let key = SymmetricKey::from_parts(&enc, &mac).unwrap();
        assert_eq!(key.enc_key(), &enc);
        assert_eq!(key.mac_key(), &mac);

        // Invalid parts
        assert!(SymmetricKey::from_parts(&[1u8; 31], &mac).is_err());
        assert!(SymmetricKey::from_parts(&enc, &[2u8; 33]).is_err());
    }

    #[test]
    fn test_symmetric_key_debug_redacted() {
        let key = SymmetricKey::from_bytes(&[9u8; 64]).unwrap();
        let debug_str = format!("{:?}", key);
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains("09"));
    }

    #[test]
    fn test_symmetric_key_try_clone_and_wipe() {
        let original = SymmetricKey::from_bytes(&[5u8; 64]).unwrap();
        let mut cloned = original.try_clone().unwrap();
        assert_eq!(cloned.bytes(), original.bytes());

        cloned.wipe();
        assert_eq!(cloned.bytes(), [0u8; 64]);
        // Original remains untouched
        assert_eq!(original.bytes(), [5u8; 64]);
    }

    #[test]
    fn test_stretch_key_differentiation() {
        let mk = MasterKey::from_bytes(&[42u8; 32]).unwrap();
        let stretched = stretch_key(&mk).unwrap();
        // HKDF expand "enc" vs "mac" must produce distinct keys
        assert_ne!(stretched.enc_key(), stretched.mac_key());
    }

    #[test]
    fn test_parity_go_stretch_pbkdf2() {
        // MasterKey derived from PBKDF2 ("password123", "user@example.com", 100000)
        let mk_bytes =
            hex_to_bytes("f4de0e1196ff2e80ac327345d9e035ddbb6fb8c6129acdf1cbf9991c63f16370");
        let mk = MasterKey::from_bytes(&mk_bytes).unwrap();

        let stretched = stretch_key(&mk).unwrap();

        let expected_enc = "4259e08507dbfad827ca1c49441249ddff3456f09e7827522e197917d9449928";
        let expected_mac = "b552622d1da25d3fe35e9a9718d76e996e344156195fe903f0eb2018c695f557";
        let expected_all = "4259e08507dbfad827ca1c49441249ddff3456f09e7827522e197917d9449928b552622d1da25d3fe35e9a9718d76e996e344156195fe903f0eb2018c695f557";

        assert_eq!(hex_encode(stretched.enc_key()), expected_enc);
        assert_eq!(hex_encode(stretched.mac_key()), expected_mac);
        assert_eq!(hex_encode(&stretched.bytes()), expected_all);
    }

    #[test]
    fn test_parity_go_stretch_argon2id() {
        // MasterKey derived from Argon2id ("password123", "user@example.com", t=3, m=64MB, p=4)
        let mk_bytes =
            hex_to_bytes("8fc048a537cbda3e8b6c8596a13ec3a879b929a1a0304dddffec8df18a06222f");
        let mk = MasterKey::from_bytes(&mk_bytes).unwrap();

        let stretched = stretch_key(&mk).unwrap();

        let expected_enc = "f7f449446a3e586d480c4aa83a4640c180a8737fcc6efd7a483645e39761b008";
        let expected_mac = "6911da83c0e785d2a32217600ecf67fa4006e59a04760f311dd2c55724ee1ee3";
        let expected_all = "f7f449446a3e586d480c4aa83a4640c180a8737fcc6efd7a483645e39761b0086911da83c0e785d2a32217600ecf67fa4006e59a04760f311dd2c55724ee1ee3";

        assert_eq!(hex_encode(stretched.enc_key()), expected_enc);
        assert_eq!(hex_encode(stretched.mac_key()), expected_mac);
        assert_eq!(hex_encode(&stretched.bytes()), expected_all);
    }

    #[test]
    fn test_full_pipeline_from_password_to_stretch() {
        let config = KdfConfig {
            kdf_type: KdfType::Pbkdf2,
            iterations: 100_000,
            memory: None,
            parallelism: None,
        };
        let mk = derive_master_key(b"password123", "user@example.com", &config).unwrap();
        let stretched = stretch_key(&mk).unwrap();

        assert_eq!(
            hex_encode(stretched.enc_key()),
            "4259e08507dbfad827ca1c49441249ddff3456f09e7827522e197917d9449928"
        );
    }

    #[test]
    fn test_keyring_lifecycle() {
        let mut keyring = Keyring::new();
        assert!(keyring.is_locked());
        assert!(keyring.account_key().is_none());
        assert!(keyring.organization_keys().is_empty());

        let key = SymmetricKey::from_bytes(&[8u8; 64]).unwrap();
        keyring.unlock_with_account_key(key);

        assert!(!keyring.is_locked());
        assert!(keyring.account_key().is_some());
        assert_eq!(keyring.account_key().unwrap().bytes(), [8u8; 64]);

        let mut orgs = HashMap::new();
        orgs.insert("org-1".to_string(), "key-data".to_string());
        keyring.set_organization_keys(orgs);
        assert_eq!(keyring.organization_keys().len(), 1);

        keyring.lock();
        assert!(keyring.is_locked());
        assert!(keyring.account_key().is_none());
        assert!(keyring.organization_keys().is_empty());
    }

    #[test]
    fn test_stubs_return_not_implemented() {
        let mut keyring = Keyring::new();
        let enc_str =
            crate::EncString::new(crate::EncStringType::AesCbc256B64, vec![0], vec![0], vec![]);
        let mk = MasterKey::from_bytes(&[1u8; 32]).unwrap();
        let sym_key = SymmetricKey::from_bytes(&[1u8; 64]).unwrap();
        let config = KdfConfig {
            kdf_type: KdfType::Pbkdf2,
            iterations: 1000,
            memory: None,
            parallelism: None,
        };

        let was_locked = keyring.is_locked();
        let had_account_key = keyring.account_key().is_some();
        let org_count = keyring.organization_keys().len();

        assert!(matches!(
            keyring.get_symmetric_key_for_organization("org-1"),
            Err(CryptoError::NotImplemented(_))
        ));
        assert_eq!(keyring.is_locked(), was_locked);
        assert_eq!(keyring.account_key().is_some(), had_account_key);
        assert_eq!(keyring.organization_keys().len(), org_count);

        assert!(matches!(
            init_keyring_from_master_password(
                &mut keyring,
                &enc_str,
                &enc_str,
                HashMap::new(),
                b"pass",
                "a@b.c",
                &config
            ),
            Err(CryptoError::NotImplemented(_))
        ));
        assert_eq!(keyring.is_locked(), was_locked);
        assert_eq!(keyring.account_key().is_some(), had_account_key);
        assert_eq!(keyring.organization_keys().len(), org_count);

        assert!(matches!(
            init_keyring_from_master_key(&mut keyring, &enc_str, &enc_str, HashMap::new(), &mk),
            Err(CryptoError::NotImplemented(_))
        ));
        assert_eq!(keyring.is_locked(), was_locked);
        assert_eq!(keyring.account_key().is_some(), had_account_key);
        assert_eq!(keyring.organization_keys().len(), org_count);

        let mut orgs = HashMap::new();
        orgs.insert("org-1".to_string(), "key-1".to_string());
        let res = init_keyring_from_user_symmetric_key(&mut keyring, sym_key, &enc_str, orgs);
        assert!(res.is_ok());
        assert!(!keyring.is_locked());
        assert!(keyring.account_key().is_some());
        assert_eq!(keyring.organization_keys().get("org-1").unwrap(), "key-1");
    }
}
