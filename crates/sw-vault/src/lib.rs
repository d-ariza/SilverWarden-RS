use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
pub use sw_crypto::{
    decrypt_with, encrypt_with, encrypt_with_to_string, EncString, EncStringType, SymmetricKey,
};
use thiserror::Error;
pub use uuid::Uuid;

/// Bitwarden cipher types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(try_from = "i32", into = "i32")]
pub enum CipherType {
    #[default]
    Login = 1,
    Note = 2,
    Card = 3,
    Identity = 4,
    SshKey = 5,
}

impl TryFrom<i32> for CipherType {
    type Error = String;

    fn try_from(v: i32) -> Result<Self, Self::Error> {
        match v {
            1 => Ok(Self::Login),
            2 => Ok(Self::Note),
            3 => Ok(Self::Card),
            4 => Ok(Self::Identity),
            5 => Ok(Self::SshKey),
            other => Err(format!("Unknown CipherType: {other}")),
        }
    }
}

impl From<CipherType> for i32 {
    fn from(c: CipherType) -> Self {
        c as i32
    }
}

/// Bitwarden custom field types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(from = "i32", into = "i32")]
pub enum FieldType {
    #[default]
    Text,
    Hidden,
    Boolean,
    Linked,
    Other(i32),
}

impl From<i32> for FieldType {
    fn from(v: i32) -> Self {
        match v {
            0 => Self::Text,
            1 => Self::Hidden,
            2 => Self::Boolean,
            3 => Self::Linked,
            other => Self::Other(other),
        }
    }
}

impl From<FieldType> for i32 {
    fn from(f: FieldType) -> Self {
        match f {
            FieldType::Text => 0,
            FieldType::Hidden => 1,
            FieldType::Boolean => 2,
            FieldType::Linked => 3,
            FieldType::Other(o) => o,
        }
    }
}

/// Bitwarden URI matching algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(from = "i32", into = "i32")]
pub enum URIMatch {
    #[default]
    Domain,
    Host,
    StartsWith,
    Exact,
    RegularExpression,
    Never,
    Other(i32),
}

impl From<i32> for URIMatch {
    fn from(v: i32) -> Self {
        match v {
            0 => Self::Domain,
            1 => Self::Host,
            2 => Self::StartsWith,
            3 => Self::Exact,
            4 => Self::RegularExpression,
            5 => Self::Never,
            other => Self::Other(other),
        }
    }
}

impl From<URIMatch> for i32 {
    fn from(u: URIMatch) -> Self {
        match u {
            URIMatch::Domain => 0,
            URIMatch::Host => 1,
            URIMatch::StartsWith => 2,
            URIMatch::Exact => 3,
            URIMatch::RegularExpression => 4,
            URIMatch::Never => 5,
            URIMatch::Other(o) => o,
        }
    }
}

/// Bitwarden secure note types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(from = "i32", into = "i32")]
pub enum SecureNoteType {
    #[default]
    Generic,
    Other(i32),
}

impl From<i32> for SecureNoteType {
    fn from(v: i32) -> Self {
        match v {
            0 => Self::Generic,
            other => Self::Other(other),
        }
    }
}

impl From<SecureNoteType> for i32 {
    fn from(s: SecureNoteType) -> Self {
        match s {
            SecureNoteType::Generic => 0,
            SecureNoteType::Other(o) => o,
        }
    }
}

/// URI entry associated with a login cipher
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct URI {
    #[serde(default)]
    pub uri: Option<String>,
    #[serde(default, rename = "match")]
    pub r#match: Option<URIMatch>,
}

/// Custom field in a cipher
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Field {
    #[serde(default, rename = "type")]
    pub r#type: Option<FieldType>,
    #[serde(default)]
    pub name: Option<EncString>,
    #[serde(default)]
    pub value: Option<EncString>,
}

/// Helper function for serde to deserialize a null value as an empty Vec
pub fn deserialize_null_as_empty_vec<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    let opt = Option::<Vec<T>>::deserialize(deserializer)?;
    Ok(opt.unwrap_or_default())
}

/// Login specific payload of a cipher
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct LoginCipher {
    #[serde(default)]
    pub password: Option<EncString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<EncString>,
    #[serde(default, deserialize_with = "deserialize_null_as_empty_vec")]
    pub uris: Vec<URI>,
    #[serde(default)]
    pub username: Option<EncString>,
    #[serde(default)]
    pub totp: Option<EncString>,
}

/// SSH key specific payload of a cipher
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SSHKeyCipher {
    #[serde(default)]
    pub private_key: Option<EncString>,
    #[serde(default)]
    pub public_key: Option<EncString>,
    #[serde(default)]
    pub key_fingerprint: Option<EncString>,
}

/// Payment card payload of a cipher
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Card {
    #[serde(default)]
    pub cardholder_name: Option<EncString>,
    #[serde(default)]
    pub brand: Option<EncString>,
    #[serde(default)]
    pub number: Option<EncString>,
    #[serde(default)]
    pub exp_month: Option<EncString>,
    #[serde(default)]
    pub exp_year: Option<EncString>,
    #[serde(default)]
    pub code: Option<EncString>,
}

/// Personal identity payload of a cipher
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Identity {
    #[serde(default)]
    pub title: Option<EncString>,
    #[serde(default)]
    pub first_name: Option<EncString>,
    #[serde(default)]
    pub middle_name: Option<EncString>,
    #[serde(default)]
    pub last_name: Option<EncString>,
    #[serde(default)]
    pub username: Option<EncString>,
    #[serde(default)]
    pub company: Option<EncString>,
    #[serde(default)]
    pub ssn: Option<EncString>,
    #[serde(default)]
    pub passport_number: Option<EncString>,
    #[serde(default)]
    pub license_number: Option<EncString>,
    #[serde(default)]
    pub email: Option<EncString>,
    #[serde(default)]
    pub phone: Option<EncString>,
    #[serde(default)]
    pub address1: Option<EncString>,
    #[serde(default)]
    pub address2: Option<EncString>,
    #[serde(default)]
    pub address3: Option<EncString>,
    #[serde(default)]
    pub city: Option<EncString>,
    #[serde(default)]
    pub state: Option<EncString>,
    #[serde(default)]
    pub postal_code: Option<EncString>,
    #[serde(default)]
    pub country: Option<EncString>,
}

/// Secure note specific payload
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SecureNoteCipher {
    #[serde(default, rename = "type")]
    pub r#type: Option<SecureNoteType>,
}

/// Folder representation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Folder {
    #[serde(default)]
    pub id: Option<Uuid>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub revision_date: Option<String>,
}

/// Organization representation in user profile
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Organization {
    #[serde(default)]
    pub object: Option<String>,
    #[serde(default)]
    pub id: Option<Uuid>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub use_groups: bool,
    #[serde(default)]
    pub use_directory: bool,
    #[serde(default)]
    pub use_events: bool,
    #[serde(default)]
    pub use_totp: bool,
    #[serde(default)]
    pub use2fa: bool,
    #[serde(default)]
    pub use_api: bool,
    #[serde(default)]
    pub users_get_premium: bool,
    #[serde(default)]
    pub self_host: bool,
    #[serde(default)]
    pub seats: Option<i32>,
    #[serde(default)]
    pub max_collections: Option<i32>,
    #[serde(default)]
    pub max_storage_gb: Option<i32>,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub status: Option<i32>,
    #[serde(default, rename = "type")]
    pub r#type: Option<i32>,
    #[serde(default)]
    pub enabled: bool,
}

/// User profile received during sync
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    #[serde(default)]
    pub id: Option<Uuid>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: bool,
    #[serde(default)]
    pub premium: bool,
    #[serde(default)]
    pub master_password_hint: Option<String>,
    #[serde(default)]
    pub culture: Option<String>,
    #[serde(default)]
    pub two_factor_enabled: bool,
    #[serde(default)]
    pub key: Option<EncString>,
    #[serde(default)]
    pub private_key: Option<EncString>,
    #[serde(default)]
    pub security_stamp: Option<String>,
    #[serde(default)]
    pub organizations: Vec<Organization>,
}

/// Complete Bitwarden Cipher representation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Cipher {
    #[serde(default, rename = "type")]
    pub r#type: CipherType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<Uuid>,
    #[serde(default)]
    pub name: EncString,
    #[serde(default)]
    pub notes: Option<EncString>,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default)]
    pub reprompt: i32,
    #[serde(default)]
    pub folder_id: Option<Uuid>,
    #[serde(default)]
    pub organization_id: Option<Uuid>,
    #[serde(
        default,
        rename = "encryptedFor",
        skip_serializing_if = "Option::is_none"
    )]
    pub encrypted_for: Option<Uuid>,
    #[serde(default, deserialize_with = "deserialize_null_as_empty_vec")]
    pub fields: Vec<Field>,

    #[serde(default)]
    pub login: Option<LoginCipher>,
    #[serde(default)]
    pub secure_note: Option<SecureNoteCipher>,
    #[serde(default)]
    pub card: Option<Card>,
    #[serde(default)]
    pub identity: Option<Identity>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_key: Option<SSHKeyCipher>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<EncString>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub edit: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision_date: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted_date: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attachments: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub organization_use_totp: bool,
    #[serde(
        default,
        deserialize_with = "deserialize_null_as_empty_vec",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub collection_ids: Vec<String>,
}

/// Root data structure returned by Bitwarden `/sync`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SyncData {
    #[serde(default)]
    pub profile: Profile,
    #[serde(default)]
    pub folders: Vec<Folder>,
    #[serde(default)]
    pub ciphers: Vec<Cipher>,
}

/// Decrypted representation of a Bitwarden cipher with plaintext secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecryptedCipher {
    pub id: Uuid,
    pub name: String,
    pub cipher_type: CipherType,
    pub username: Option<String>,
    pub password: Option<String>,
    pub uri: Option<String>,
    pub notes: Option<String>,
    pub totp: Option<String>,
    pub favorite: bool,
}

impl Cipher {
    /// Decrypts sensitive fields of this cipher using the provided symmetric key.
    pub fn decrypt(&self, key: &SymmetricKey) -> Result<DecryptedCipher, VaultError> {
        VaultStore::decrypt_cipher(self, key)
    }
}

/// Represents an SSH key extracted and decrypted from the vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultSshKey {
    pub id: Option<Uuid>,
    pub name: String,
    pub private_key: String,
    pub public_key: Option<String>,
}

/// Errors that can occur during vault caching, persistence, and synchronization.
#[derive(Error, Debug)]
pub enum VaultError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Vault file not found at: {0}")]
    NotFound(PathBuf),

    #[error("API error during sync: {0}")]
    Api(String),

    #[error("Crypto error: {0}")]
    Crypto(#[from] sw_crypto::CryptoError),

    #[error("UTF-8 decoding error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),

    #[error("Vault error: {0}")]
    Other(String),
}

/// Configurable paths for local vault caching and persistent storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultPaths {
    base_dir: PathBuf,
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

/// In-memory secure vault store protected by a `RwLock`.
#[derive(Debug, Default)]
pub struct VaultStore {
    ciphers: tokio::sync::RwLock<HashMap<Uuid, Cipher>>,
    folders: tokio::sync::RwLock<Vec<Folder>>,
    profile: tokio::sync::RwLock<Option<Profile>>,
    last_synced: tokio::sync::RwLock<Option<u64>>,
}

impl VaultStore {
    /// Creates a new empty `VaultStore`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Loads a full `SyncData` payload into the store in memory without preliminary mass decryption.
    pub async fn load_sync_data(&self, sync_data: SyncData) {
        let mut c_guard = self.ciphers.write().await;
        let mut f_guard = self.folders.write().await;
        let mut p_guard = self.profile.write().await;

        c_guard.clear();
        for cipher in sync_data.ciphers {
            if let Some(id) = cipher.id {
                c_guard.insert(id, cipher);
            }
        }

        *f_guard = sync_data.folders;
        *p_guard = Some(sync_data.profile);
    }

    /// Exports the current in-memory store state to a `SyncData` snapshot.
    pub async fn to_sync_data(&self) -> SyncData {
        let c_guard = self.ciphers.read().await;
        let f_guard = self.folders.read().await;
        let p_guard = self.profile.read().await;

        SyncData {
            profile: p_guard.clone().unwrap_or_default(),
            folders: f_guard.clone(),
            ciphers: c_guard.values().cloned().collect(),
        }
    }

    /// Inserts or updates a cipher in the store.
    pub async fn insert(&self, cipher: Cipher) {
        if let Some(id) = cipher.id {
            self.ciphers.write().await.insert(id, cipher);
        }
    }

    /// Retrieves a cloned cipher by its UUID.
    pub async fn get(&self, id: &Uuid) -> Option<Cipher> {
        self.ciphers.read().await.get(id).cloned()
    }

    /// Removes a cipher by its UUID.
    pub async fn delete(&self, id: &Uuid) -> Option<Cipher> {
        self.ciphers.write().await.remove(id)
    }

    /// Removes a cipher by its UUID from the in-memory VaultStore (with write lock).
    pub async fn delete_cipher(&self, id: &Uuid) -> Option<Cipher> {
        self.ciphers.write().await.remove(id)
    }

    /// Synchronous variant of `delete_cipher`.
    pub fn blocking_delete_cipher(&self, id: &Uuid) -> Option<Cipher> {
        self.ciphers.blocking_write().remove(id)
    }

    /// Returns a list of all ciphers currently in memory.
    pub async fn all(&self) -> Vec<Cipher> {
        self.ciphers.read().await.values().cloned().collect()
    }

    /// Number of ciphers in the store.
    pub async fn len(&self) -> usize {
        self.ciphers.read().await.len()
    }

    /// Whether the store contains any ciphers.
    pub async fn is_empty(&self) -> bool {
        self.ciphers.read().await.is_empty()
    }

    /// Clears all ciphers, folders, and profile from memory.
    pub async fn clear(&self) {
        self.ciphers.write().await.clear();
        self.folders.write().await.clear();
        *self.profile.write().await = None;
        *self.last_synced.write().await = None;
    }

    /// Gets the timestamp of the last successful sync.
    pub async fn last_synced(&self) -> Option<u64> {
        *self.last_synced.read().await
    }

    /// Sets the timestamp of the last successful sync.
    pub async fn set_last_synced(&self, ts: u64) {
        *self.last_synced.write().await = Some(ts);
    }

    /// Gets the cached user profile.
    pub async fn profile(&self) -> Option<Profile> {
        self.profile.read().await.clone()
    }

    /// Gets the cached list of folders.
    pub async fn folders(&self) -> Vec<Folder> {
        self.folders.read().await.clone()
    }

    // Synchronous / blocking convenience methods for sync contexts
    pub fn blocking_insert(&self, cipher: Cipher) {
        if let Some(id) = cipher.id {
            self.ciphers.blocking_write().insert(id, cipher);
        }
    }

    pub fn blocking_get(&self, id: &Uuid) -> Option<Cipher> {
        self.ciphers.blocking_read().get(id).cloned()
    }

    pub fn blocking_delete(&self, id: &Uuid) -> Option<Cipher> {
        self.ciphers.blocking_write().remove(id)
    }

    pub fn blocking_all(&self) -> Vec<Cipher> {
        self.ciphers.blocking_read().values().cloned().collect()
    }

    pub fn blocking_len(&self) -> usize {
        self.ciphers.blocking_read().len()
    }

    pub fn blocking_is_empty(&self) -> bool {
        self.ciphers.blocking_read().is_empty()
    }

    pub fn blocking_clear(&self) {
        self.ciphers.blocking_write().clear();
        self.folders.blocking_write().clear();
        *self.profile.blocking_write() = None;
        *self.last_synced.blocking_write() = None;
    }

    pub fn blocking_load_sync_data(&self, sync_data: SyncData) {
        let mut c_guard = self.ciphers.blocking_write();
        let mut f_guard = self.folders.blocking_write();
        let mut p_guard = self.profile.blocking_write();

        c_guard.clear();
        for cipher in sync_data.ciphers {
            if let Some(id) = cipher.id {
                c_guard.insert(id, cipher);
            }
        }
        *f_guard = sync_data.folders;
        *p_guard = Some(sync_data.profile);
    }

    /// Returns all un-deleted login ciphers in the vault.
    pub async fn get_logins(&self) -> Vec<Cipher> {
        self.ciphers
            .read()
            .await
            .values()
            .filter(|c| c.r#type == CipherType::Login && c.deleted_date.is_none())
            .cloned()
            .collect()
    }

    /// Blocking variant of `get_logins`.
    pub fn blocking_get_logins(&self) -> Vec<Cipher> {
        self.ciphers
            .blocking_read()
            .values()
            .filter(|c| c.r#type == CipherType::Login && c.deleted_date.is_none())
            .cloned()
            .collect()
    }

    /// Returns all un-deleted note ciphers in the vault.
    pub async fn get_notes(&self) -> Vec<Cipher> {
        self.ciphers
            .read()
            .await
            .values()
            .filter(|c| c.r#type == CipherType::Note && c.deleted_date.is_none())
            .cloned()
            .collect()
    }

    /// Blocking variant of `get_notes`.
    pub fn blocking_get_notes(&self) -> Vec<Cipher> {
        self.ciphers
            .blocking_read()
            .values()
            .filter(|c| c.r#type == CipherType::Note && c.deleted_date.is_none())
            .cloned()
            .collect()
    }

    /// Finds the first login cipher matching the given filters.
    pub async fn get_login_by_filter(
        &self,
        uuid: Option<&Uuid>,
        org_id: Option<&Uuid>,
        name: Option<&str>,
        username: Option<&str>,
        key: &SymmetricKey,
    ) -> Option<Cipher> {
        let logins = self.get_logins().await;
        Self::filter_logins(logins, uuid, org_id, name, username, key)
    }

    /// Blocking variant of `get_login_by_filter`.
    pub fn blocking_get_login_by_filter(
        &self,
        uuid: Option<&Uuid>,
        org_id: Option<&Uuid>,
        name: Option<&str>,
        username: Option<&str>,
        key: &SymmetricKey,
    ) -> Option<Cipher> {
        let logins = self.blocking_get_logins();
        Self::filter_logins(logins, uuid, org_id, name, username, key)
    }

    fn filter_logins(
        logins: Vec<Cipher>,
        uuid: Option<&Uuid>,
        org_id: Option<&Uuid>,
        name: Option<&str>,
        username: Option<&str>,
        key: &SymmetricKey,
    ) -> Option<Cipher> {
        for cipher in logins {
            if let Some(expected_id) = uuid {
                if cipher.id.as_ref() != Some(expected_id) {
                    continue;
                }
            }
            if let Some(expected_org) = org_id {
                if cipher.organization_id.as_ref() != Some(expected_org) {
                    continue;
                }
            }
            if let Some(expected_name) = name {
                if cipher.name.is_null() {
                    continue;
                }
                match sw_crypto::decrypt_with(&cipher.name, key) {
                    Ok(bytes) => {
                        if let Ok(dec_name) = String::from_utf8(bytes) {
                            if dec_name != expected_name {
                                continue;
                            }
                        } else {
                            continue;
                        }
                    }
                    Err(_) => continue,
                }
            }
            if let Some(expected_username) = username {
                let login_match = match &cipher.login {
                    Some(login) => match &login.username {
                        Some(enc_un) if !enc_un.is_null() => {
                            match sw_crypto::decrypt_with(enc_un, key) {
                                Ok(bytes) => match String::from_utf8(bytes) {
                                    Ok(dec_un) => dec_un == expected_username,
                                    Err(_) => false,
                                },
                                Err(_) => false,
                            }
                        }
                        _ => false,
                    },
                    None => false,
                };
                if !login_match {
                    continue;
                }
            }
            return Some(cipher);
        }
        None
    }

    /// Finds the first note cipher matching the given filters.
    pub async fn get_note_by_filter(
        &self,
        uuid: Option<&Uuid>,
        org_id: Option<&Uuid>,
        name: Option<&str>,
        key: &SymmetricKey,
    ) -> Option<Cipher> {
        let notes = self.get_notes().await;
        Self::filter_notes(notes, uuid, org_id, name, key)
    }

    /// Blocking variant of `get_note_by_filter`.
    pub fn blocking_get_note_by_filter(
        &self,
        uuid: Option<&Uuid>,
        org_id: Option<&Uuid>,
        name: Option<&str>,
        key: &SymmetricKey,
    ) -> Option<Cipher> {
        let notes = self.blocking_get_notes();
        Self::filter_notes(notes, uuid, org_id, name, key)
    }

    fn filter_notes(
        notes: Vec<Cipher>,
        uuid: Option<&Uuid>,
        org_id: Option<&Uuid>,
        name: Option<&str>,
        key: &SymmetricKey,
    ) -> Option<Cipher> {
        for cipher in notes {
            if let Some(expected_id) = uuid {
                if cipher.id.as_ref() != Some(expected_id) {
                    continue;
                }
            }
            if let Some(expected_org) = org_id {
                if cipher.organization_id.as_ref() != Some(expected_org) {
                    continue;
                }
            }
            if let Some(expected_name) = name {
                if cipher.name.is_null() {
                    continue;
                }
                match sw_crypto::decrypt_with(&cipher.name, key) {
                    Ok(bytes) => {
                        if let Ok(dec_name) = String::from_utf8(bytes) {
                            if dec_name != expected_name {
                                continue;
                            }
                        } else {
                            continue;
                        }
                    }
                    Err(_) => continue,
                }
            }
            return Some(cipher);
        }
        None
    }

    /// Decrypts sensitive fields of a cipher on demand using the provided symmetric key.
    ///
    /// Synchronous method as decryption is CPU-bound.
    pub fn decrypt_cipher(
        cipher: &Cipher,
        key: &SymmetricKey,
    ) -> Result<DecryptedCipher, VaultError> {
        if cipher.name.is_null() {
            return Err(VaultError::Other(
                "Cipher name is missing or empty".to_string(),
            ));
        }
        let name_bytes = sw_crypto::decrypt_with(&cipher.name, key)?;
        let name = String::from_utf8(name_bytes)?;

        let mut username = None;
        let mut password = None;
        let mut uri = None;
        let mut totp = None;

        if let Some(ref login) = cipher.login {
            if let Some(ref enc_un) = login.username {
                if !enc_un.is_null() {
                    let bytes = sw_crypto::decrypt_with(enc_un, key)?;
                    username = Some(String::from_utf8(bytes)?);
                }
            }
            if let Some(ref enc_pw) = login.password {
                if !enc_pw.is_null() {
                    let bytes = sw_crypto::decrypt_with(enc_pw, key)?;
                    password = Some(String::from_utf8(bytes)?);
                }
            }
            if let Some(ref enc_uri) = login.uri {
                if !enc_uri.is_null() {
                    let bytes = sw_crypto::decrypt_with(enc_uri, key)?;
                    uri = Some(String::from_utf8(bytes)?);
                } else {
                    uri = login.uris.first().and_then(|u| u.uri.clone());
                }
            } else {
                uri = login.uris.first().and_then(|u| u.uri.clone());
            }
            if let Some(ref enc_totp) = login.totp {
                if !enc_totp.is_null() {
                    let bytes = sw_crypto::decrypt_with(enc_totp, key)?;
                    totp = Some(String::from_utf8(bytes)?);
                }
            }
        }

        let mut notes = None;
        if let Some(ref enc_notes) = cipher.notes {
            if !enc_notes.is_null() {
                let bytes = sw_crypto::decrypt_with(enc_notes, key)?;
                notes = Some(String::from_utf8(bytes)?);
            }
        }

        Ok(DecryptedCipher {
            id: cipher.id.unwrap_or_default(),
            name,
            cipher_type: cipher.r#type,
            username,
            password,
            uri,
            notes,
            totp,
            favorite: cipher.favorite,
        })
    }

    /// Searches active logins and notes whose decrypted name or username matches `filter`.
    pub async fn search(&self, filter: &str, key: &SymmetricKey) -> Vec<DecryptedCipher> {
        let ciphers = self.ciphers.read().await;
        let active_ciphers: Vec<Cipher> = ciphers
            .values()
            .filter(|c| {
                c.deleted_date.is_none()
                    && (c.r#type == CipherType::Login || c.r#type == CipherType::Note)
            })
            .cloned()
            .collect();
        drop(ciphers);

        Self::filter_search(active_ciphers, filter, key)
    }

    /// Blocking variant of `search`.
    pub fn blocking_search(&self, filter: &str, key: &SymmetricKey) -> Vec<DecryptedCipher> {
        let ciphers = self.ciphers.blocking_read();
        let active_ciphers: Vec<Cipher> = ciphers
            .values()
            .filter(|c| {
                c.deleted_date.is_none()
                    && (c.r#type == CipherType::Login || c.r#type == CipherType::Note)
            })
            .cloned()
            .collect();
        drop(ciphers);

        Self::filter_search(active_ciphers, filter, key)
    }

    fn filter_search(
        ciphers: Vec<Cipher>,
        filter: &str,
        key: &SymmetricKey,
    ) -> Vec<DecryptedCipher> {
        let filter_lower = filter.to_lowercase();
        let mut results = Vec::new();

        for cipher in ciphers {
            if let Ok(dec) = Self::decrypt_cipher(&cipher, key) {
                let name_matches =
                    dec.name.contains(filter) || dec.name.to_lowercase().contains(&filter_lower);
                let username_matches = dec.username.as_deref().is_some_and(|u| {
                    u.contains(filter) || u.to_lowercase().contains(&filter_lower)
                });

                if name_matches || username_matches {
                    results.push(dec);
                }
            }
        }

        results
    }

    /// Extracts and decrypts SSH keys from stored ciphers asynchronously.
    pub async fn get_ssh_keys(
        &self,
        user_key: &SymmetricKey,
    ) -> Result<Vec<VaultSshKey>, VaultError> {
        let ciphers = self.all().await;
        Self::extract_ssh_keys(&ciphers, user_key)
    }

    /// Synchronous variant of `get_ssh_keys`.
    pub fn blocking_get_ssh_keys(
        &self,
        user_key: &SymmetricKey,
    ) -> Result<Vec<VaultSshKey>, VaultError> {
        let ciphers = self.blocking_all();
        Self::extract_ssh_keys(&ciphers, user_key)
    }

    /// Extracts SSH keys from a slice of ciphers (supports both SshKey ciphers and Secure Notes).
    pub fn extract_ssh_keys(
        ciphers: &[Cipher],
        user_key: &SymmetricKey,
    ) -> Result<Vec<VaultSshKey>, VaultError> {
        let mut keys = Vec::new();
        for cipher in ciphers {
            if cipher.deleted_date.is_some() {
                continue;
            }

            let cipher_key_owned = if let Some(ref enc_k) = cipher.key {
                if !enc_k.is_null() {
                    match sw_crypto::decrypt_with(enc_k, user_key) {
                        Ok(kb) => SymmetricKey::from_bytes(&kb).ok(),
                        Err(_) => None,
                    }
                } else {
                    None
                }
            } else {
                None
            };
            let cipher_key = cipher_key_owned.as_ref().unwrap_or(user_key);

            let name = if !cipher.name.is_null() {
                match sw_crypto::decrypt_with(&cipher.name, cipher_key) {
                    Ok(b) => String::from_utf8(b).unwrap_or_else(|_| "unnamed".to_string()),
                    Err(_) => "unnamed".to_string(),
                }
            } else {
                "unnamed".to_string()
            };

            if cipher.r#type == CipherType::SshKey {
                if let Some(ref ssh) = cipher.ssh_key {
                    let private_key = if let Some(ref pk) = ssh.private_key {
                        if !pk.is_null() {
                            sw_crypto::decrypt_with(pk, cipher_key)
                                .ok()
                                .and_then(|b| String::from_utf8(b).ok())
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    let public_key = if let Some(ref pubk) = ssh.public_key {
                        if !pubk.is_null() {
                            sw_crypto::decrypt_with(pubk, cipher_key)
                                .ok()
                                .and_then(|b| String::from_utf8(b).ok())
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    if let Some(pk_str) = private_key {
                        keys.push(VaultSshKey {
                            id: cipher.id,
                            name,
                            private_key: Self::normalize_pem(&pk_str),
                            public_key,
                        });
                    }
                }
            } else if cipher.r#type == CipherType::Note {
                let mut is_ssh = false;
                let mut pk_opt = None;
                let mut pubk_opt = None;

                for field in &cipher.fields {
                    let fname = if let Some(ref fn_enc) = field.name {
                        if !fn_enc.is_null() {
                            sw_crypto::decrypt_with(fn_enc, cipher_key)
                                .ok()
                                .and_then(|b| String::from_utf8(b).ok())
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    let fval = if let Some(ref fv_enc) = field.value {
                        if !fv_enc.is_null() {
                            sw_crypto::decrypt_with(fv_enc, cipher_key)
                                .ok()
                                .and_then(|b| String::from_utf8(b).ok())
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    if let (Some(fn_str), Some(fv_str)) = (fname.as_deref(), fval.as_deref()) {
                        if fn_str == "custom-type" && fv_str == "ssh-key" || fn_str == "ssh-key" {
                            is_ssh = true;
                        }
                        if fn_str == "private-key" {
                            pk_opt = Some(fv_str.to_string());
                        }
                        if fn_str == "public-key" {
                            pubk_opt = Some(fv_str.to_string());
                        }
                    }
                }

                if let Some(pk_str) = pk_opt {
                    if is_ssh || !pk_str.is_empty() {
                        keys.push(VaultSshKey {
                            id: cipher.id,
                            name,
                            private_key: Self::normalize_pem(&pk_str),
                            public_key: pubk_opt,
                        });
                    }
                }
            }
        }
        Ok(keys)
    }

    fn normalize_pem(pem: &str) -> String {
        let trimmed = pem.trim();
        if trimmed.starts_with("-----")
            && !trimmed.contains('\n')
            && trimmed.contains("-----BEGIN ")
        {
            if let Some(begin_end) = trimmed.find("----- ") {
                let header = &trimmed[..begin_end + 5];
                let remainder = &trimmed[begin_end + 5..].trim_start();
                if let Some(last_dash) = remainder.rfind(" -----END ") {
                    let body = &remainder[..last_dash];
                    let footer = &remainder[last_dash + 1..];
                    let body_lines = body.split_whitespace().collect::<Vec<_>>().join("\n");
                    return format!("{header}\n{body_lines}\n{footer}\n");
                }
            }
        }
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_data_full_deserialization() {
        let json_str = r#"{
            "profile": {
                "id": "11111111-1111-1111-1111-111111111111",
                "name": "Alice Tester",
                "email": "alice@example.com",
                "emailVerified": true,
                "premium": false,
                "masterPasswordHint": "favorite color",
                "culture": "en-US",
                "twoFactorEnabled": false,
                "key": "2.aXZfMTZfYnl0ZXNfbG9uZw==|Y2lwaGVydGV4dF9ieXRlcw==|bWFjXzMyX2J5dGVzX2xvbmdfaGFzaF9zdHJpbmchIQ==",
                "privateKey": "4.Y2lwaGVydGV4dF9ieXRlcw==",
                "securityStamp": "stamp123",
                "organizations": [
                    {
                        "object": "organization",
                        "id": "22222222-2222-2222-2222-222222222222",
                        "name": "Acme Corp",
                        "useGroups": true,
                        "useDirectory": false,
                        "useEvents": false,
                        "useTotp": true,
                        "use2fa": true,
                        "useApi": false,
                        "usersGetPremium": true,
                        "selfHost": false,
                        "seats": 10,
                        "maxCollections": 5,
                        "maxStorageGb": 100,
                        "key": "org_key_base64",
                        "status": 1,
                        "type": 1,
                        "enabled": true
                    }
                ]
            },
            "folders": [
                {
                    "id": "33333333-3333-3333-3333-333333333333",
                    "name": "Work Logins",
                    "revisionDate": "2026-10-24T12:00:00Z"
                }
            ],
            "ciphers": [
                {
                    "type": 1,
                    "id": "44444444-4444-4444-4444-444444444444",
                    "name": "2.aXZfMTZfYnl0ZXNfbG9uZw==|Y2lwaGVydGV4dF9ieXRlcw==|bWFjXzMyX2J5dGVzX2xvbmdfaGFzaF9zdHJpbmchIQ==",
                    "notes": "2.aXZfMTZfYnl0ZXNfbG9uZw==|Y2lwaGVydGV4dF9ieXRlcw==|bWFjXzMyX2J5dGVzX2xvbmdfaGFzaF9zdHJpbmchIQ==",
                    "folderId": "33333333-3333-3333-3333-333333333333",
                    "favorite": true,
                    "organizationUseTotp": false,
                    "collectionIds": ["col1", "col2"],
                    "fields": [
                        {
                            "type": 0,
                            "name": "2.aXZfMTZfYnl0ZXNfbG9uZw==|Y2lwaGVydGV4dF9ieXRlcw==|bWFjXzMyX2J5dGVzX2xvbmdfaGFzaF9zdHJpbmchIQ==",
                            "value": "2.aXZfMTZfYnl0ZXNfbG9uZw==|Y2lwaGVydGV4dF9ieXRlcw==|bWFjXzMyX2J5dGVzX2xvbmdfaGFzaF9zdHJpbmchIQ=="
                        }
                    ],
                    "login": {
                        "username": "2.aXZfMTZfYnl0ZXNfbG9uZw==|Y2lwaGVydGV4dF9ieXRlcw==|bWFjXzMyX2J5dGVzX2xvbmdfaGFzaF9zdHJpbmchIQ==",
                        "password": "2.aXZfMTZfYnl0ZXNfbG9uZw==|Y2lwaGVydGV4dF9ieXRlcw==|bWFjXzMyX2J5dGVzX2xvbmdfaGFzaF9zdHJpbmchIQ==",
                        "totp": "2.aXZfMTZfYnl0ZXNfbG9uZw==|Y2lwaGVydGV4dF9ieXRlcw==|bWFjXzMyX2J5dGVzX2xvbmdfaGFzaF9zdHJpbmchIQ==",
                        "uri": "2.aXZfMTZfYnl0ZXNfbG9uZw==|Y2lwaGVydGV4dF9ieXRlcw==|bWFjXzMyX2J5dGVzX2xvbmdfaGFzaF9zdHJpbmchIQ==",
                        "uris": [
                            {
                                "uri": "https://example.com/login",
                                "match": 0
                            }
                        ]
                    },
                    "key": "2.aXZfMTZfYnl0ZXNfbG9uZw==|Y2lwaGVydGV4dF9ieXRlcw==|bWFjXzMyX2J5dGVzX2xvbmdfaGFzaF9zdHJpbmchIQ=="
                },
                {
                    "type": 5,
                    "id": "55555555-5555-5555-5555-555555555555",
                    "name": "2.aXZfMTZfYnl0ZXNfbG9uZw==|Y2lwaGVydGV4dF9ieXRlcw==|bWFjXzMyX2J5dGVzX2xvbmdfaGFzaF9zdHJpbmchIQ==",
                    "sshKey": {
                        "privateKey": "2.aXZfMTZfYnl0ZXNfbG9uZw==|Y2lwaGVydGV4dF9ieXRlcw==|bWFjXzMyX2J5dGVzX2xvbmdfaGFzaF9zdHJpbmchIQ==",
                        "publicKey": "2.aXZfMTZfYnl0ZXNfbG9uZw==|Y2lwaGVydGV4dF9ieXRlcw==|bWFjXzMyX2J5dGVzX2xvbmdfaGFzaF9zdHJpbmchIQ==",
                        "keyFingerprint": "2.aXZfMTZfYnl0ZXNfbG9uZw==|Y2lwaGVydGV4dF9ieXRlcw==|bWFjXzMyX2J5dGVzX2xvbmdfaGFzaF9zdHJpbmchIQ=="
                    }
                }
            ]
        }"#;

        let sync_data: SyncData =
            serde_json::from_str(json_str).expect("SyncData must deserialize");

        // Profile checks
        assert_eq!(sync_data.profile.name, Some("Alice Tester".to_string()));
        assert_eq!(
            sync_data.profile.email,
            Some("alice@example.com".to_string())
        );
        assert_eq!(sync_data.profile.organizations.len(), 1);
        assert_eq!(
            sync_data.profile.organizations[0].name,
            Some("Acme Corp".to_string())
        );

        // Folders checks
        assert_eq!(sync_data.folders.len(), 1);
        assert_eq!(sync_data.folders[0].name, Some("Work Logins".to_string()));

        // Ciphers checks
        assert_eq!(sync_data.ciphers.len(), 2);

        // Cipher 1: Login
        let login_cipher = &sync_data.ciphers[0];
        assert_eq!(login_cipher.r#type, CipherType::Login);
        assert!(login_cipher.favorite);
        assert_eq!(login_cipher.collection_ids, vec!["col1", "col2"]);
        assert!(login_cipher.login.is_some());

        let login_data = login_cipher.login.as_ref().unwrap();
        assert!(login_data.username.is_some());
        assert!(login_data.password.is_some());
        assert_eq!(login_data.uris.len(), 1);
        assert_eq!(
            login_data.uris[0].uri,
            Some("https://example.com/login".to_string())
        );
        assert_eq!(login_data.uris[0].r#match, Some(URIMatch::Domain));

        // Cipher 2: SSH Key
        let ssh_cipher = &sync_data.ciphers[1];
        assert_eq!(ssh_cipher.r#type, CipherType::SshKey);
        assert!(ssh_cipher.ssh_key.is_some());
        let ssh_data = ssh_cipher.ssh_key.as_ref().unwrap();
        assert!(ssh_data.private_key.is_some());
        assert!(ssh_data.public_key.is_some());
        assert!(ssh_data.key_fingerprint.is_some());
    }

    #[test]
    fn test_roundtrip_serialization() {
        let original = SyncData {
            profile: Profile {
                id: Some(Uuid::new_v4()),
                email: Some("roundtrip@test.com".into()),
                organizations: vec![],
                ..Default::default()
            },
            folders: vec![Folder {
                id: Some(Uuid::new_v4()),
                name: Some("Personal".into()),
                revision_date: None,
            }],
            ciphers: vec![
                Cipher {
                    r#type: CipherType::Card,
                    id: Some(Uuid::new_v4()),
                    name: EncString::default(),
                    card: Some(Card {
                        brand: None,
                        cardholder_name: None,
                        number: None,
                        exp_month: None,
                        exp_year: None,
                        code: None,
                    }),
                    ..Default::default()
                },
                Cipher {
                    r#type: CipherType::Identity,
                    id: Some(Uuid::new_v4()),
                    identity: Some(Identity {
                        first_name: None,
                        last_name: None,
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                Cipher {
                    r#type: CipherType::Note,
                    id: Some(Uuid::new_v4()),
                    secure_note: Some(SecureNoteCipher {
                        r#type: Some(SecureNoteType::Generic),
                    }),
                    ..Default::default()
                },
            ],
        };

        let serialized = serde_json::to_string(&original).expect("Must serialize SyncData");
        let deserialized: SyncData =
            serde_json::from_str(&serialized).expect("Must deserialize serialized SyncData");

        assert_eq!(original, deserialized);
    }

    #[tokio::test]
    async fn test_vault_store_operations() {
        let store = VaultStore::new();
        assert!(store.is_empty().await);

        let id1 = Uuid::new_v4();
        let c1 = Cipher {
            id: Some(id1),
            r#type: CipherType::Login,
            ..Default::default()
        };

        let id2 = Uuid::new_v4();
        let c2 = Cipher {
            id: Some(id2),
            r#type: CipherType::SshKey,
            ..Default::default()
        };

        store.insert(c1).await;
        store.insert(c2).await;

        assert_eq!(store.len().await, 2);
        assert!(!store.is_empty().await);

        assert_eq!(store.get(&id1).await.unwrap().r#type, CipherType::Login);
        assert_eq!(store.get(&id2).await.unwrap().r#type, CipherType::SshKey);
        assert_eq!(store.all().await.len(), 2);

        // Delete test
        let deleted = store.delete(&id1).await;
        assert!(deleted.is_some());
        assert_eq!(store.len().await, 1);
        assert!(store.get(&id1).await.is_none());

        // SyncData load & export
        let sync_data = SyncData {
            profile: Profile {
                name: Some("Bob".to_string()),
                ..Default::default()
            },
            folders: vec![Folder {
                name: Some("Folder1".to_string()),
                ..Default::default()
            }],
            ciphers: vec![Cipher {
                id: Some(id1),
                r#type: CipherType::Card,
                ..Default::default()
            }],
        };

        store.load_sync_data(sync_data).await;
        assert_eq!(store.len().await, 1);
        assert_eq!(store.folders().await.len(), 1);
        assert_eq!(store.profile().await.unwrap().name.as_deref(), Some("Bob"));

        let exported = store.to_sync_data().await;
        assert_eq!(exported.ciphers.len(), 1);
        assert_eq!(exported.folders.len(), 1);

        // Timestamps
        store.set_last_synced(1234567890).await;
        assert_eq!(store.last_synced().await, Some(1234567890));

        store.clear().await;
        assert!(store.is_empty().await);
        assert_eq!(store.len().await, 0);
    }

    #[tokio::test]
    async fn test_vault_store_delete_cipher() {
        let store = VaultStore::new();
        let id = Uuid::new_v4();
        let cipher = Cipher {
            id: Some(id),
            r#type: CipherType::SshKey,
            ..Default::default()
        };
        store.insert(cipher).await;
        assert_eq!(store.len().await, 1);
        let removed = store.delete_cipher(&id).await;
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().id, Some(id));
        assert!(store.get(&id).await.is_none());
        assert!(store.is_empty().await);
        assert!(store.delete_cipher(&id).await.is_none());
    }

    #[test]
    fn test_vault_store_blocking_operations() {
        let store = VaultStore::new();
        let id1 = Uuid::new_v4();

        assert!(store.blocking_is_empty());
        assert_eq!(store.blocking_len(), 0);

        store.blocking_insert(Cipher {
            id: Some(id1),
            r#type: CipherType::Note,
            ..Default::default()
        });

        assert_eq!(store.blocking_len(), 1);
        assert_eq!(store.blocking_get(&id1).unwrap().r#type, CipherType::Note);
        assert_eq!(store.blocking_all().len(), 1);
        assert!(store.blocking_delete_cipher(&id1).is_some());
        assert_eq!(store.blocking_len(), 0);

        store.blocking_load_sync_data(SyncData {
            ciphers: vec![Cipher {
                id: Some(id1),
                ..Default::default()
            }],
            ..Default::default()
        });
        assert_eq!(store.blocking_len(), 1);
        store.blocking_clear();
        assert_eq!(store.blocking_len(), 0);
    }

    #[test]
    fn test_vault_save_and_load_roundtrip() {
        let temp_dir = tempfile::tempdir().unwrap();
        let vault_path = temp_dir.path().join("sub").join("vault.json");

        let id = Uuid::new_v4();
        let original_data = SyncData {
            profile: Profile {
                id: Some(Uuid::new_v4()),
                email: Some("test@example.com".to_string()),
                name: Some("Tester".to_string()),
                ..Default::default()
            },
            folders: vec![Folder {
                id: Some(Uuid::new_v4()),
                name: Some("Personal".to_string()),
                revision_date: Some("2026-10-24T12:00:00Z".to_string()),
            }],
            ciphers: vec![Cipher {
                id: Some(id),
                r#type: CipherType::Login,
                favorite: true,
                ..Default::default()
            }],
        };

        // Atomic write
        save_vault(&vault_path, &original_data).expect("save_vault should succeed");
        assert!(vault_path.exists());

        // Load back
        let loaded_data = load_vault(&vault_path).expect("load_vault should succeed");
        assert_eq!(original_data, loaded_data);
    }

    #[test]
    #[cfg(unix)]
    fn test_vault_file_permissions_0600() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = tempfile::tempdir().unwrap();
        let vault_paths = VaultPaths::new(temp_dir.path().join("secure_vault"));
        vault_paths.ensure_dirs().unwrap();

        // Check directory perms 0700
        let dir_meta = std::fs::metadata(vault_paths.base_dir()).unwrap();
        let dir_mode = dir_meta.permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "Directory permissions must be 0700");

        let data = SyncData::default();
        let vault_file = vault_paths.vault_file();
        save_vault(&vault_file, &data).unwrap();

        let file_meta = std::fs::metadata(&vault_file).unwrap();
        let file_mode = file_meta.permissions().mode() & 0o777;
        assert_eq!(
            file_mode, 0o600,
            "Vault file permissions must be exactly 0600"
        );
    }

    #[tokio::test]
    async fn test_vault_store_rwlock_concurrency() {
        use std::sync::Arc;

        let store = Arc::new(VaultStore::new());
        let mut handles = Vec::new();

        // Spawn 5 concurrent writers
        for i in 0..5 {
            let s = Arc::clone(&store);
            handles.push(tokio::spawn(async move {
                let id = Uuid::new_v4();
                let cipher = Cipher {
                    id: Some(id),
                    r#type: CipherType::Login,
                    notes: Some(EncString::default()),
                    ..Default::default()
                };
                s.insert(cipher).await;
                s.set_last_synced(1000 + i).await;
            }));
        }

        // Spawn 10 concurrent readers
        for _ in 0..10 {
            let s = Arc::clone(&store);
            handles.push(tokio::spawn(async move {
                let _len = s.len().await;
                let _all = s.all().await;
                let _sync = s.last_synced().await;
                let _snap = s.to_sync_data().await;
            }));
        }

        for h in handles {
            h.await.expect("Task should join cleanly without deadlocks");
        }

        assert_eq!(store.len().await, 5);
        assert!(store.last_synced().await.is_some());
    }

    #[test]
    fn test_vault_load_nonexistent_and_corrupt_errors() {
        let temp_dir = tempfile::tempdir().unwrap();

        // Nonexistent
        let missing_path = temp_dir.path().join("does_not_exist.json");
        let res = load_vault(&missing_path);
        assert!(matches!(res, Err(VaultError::NotFound(_))));

        // Corrupted JSON
        let corrupt_path = temp_dir.path().join("corrupt.json");
        std::fs::write(&corrupt_path, b"{ this is invalid json ]").unwrap();
        let res_corrupt = load_vault(&corrupt_path);
        assert!(matches!(res_corrupt, Err(VaultError::Json(_))));
    }

    #[tokio::test]
    async fn test_vault_paths_custom_and_default() {
        let temp_dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(temp_dir.path());
        assert_eq!(paths.base_dir(), temp_dir.path());
        assert_eq!(paths.vault_file(), temp_dir.path().join("vault.json"));

        let def_paths = VaultPaths::default();
        assert!(def_paths.vault_file().ends_with("vault.json"));
    }

    #[tokio::test]
    async fn test_vault_async_save_and_load() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("async_vault.json");

        let sync_data = SyncData {
            profile: Profile {
                name: Some("Async User".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };

        save_vault_async(path.clone(), sync_data.clone())
            .await
            .unwrap();
        let loaded = load_vault_async(path).await.unwrap();
        assert_eq!(loaded.profile.name.as_deref(), Some("Async User"));
    }

    #[test]
    fn test_cipher_type_conversion_and_fallback() {
        assert_eq!(CipherType::try_from(1).unwrap(), CipherType::Login);
        assert_eq!(CipherType::try_from(2).unwrap(), CipherType::Note);
        assert_eq!(CipherType::try_from(3).unwrap(), CipherType::Card);
        assert_eq!(CipherType::try_from(4).unwrap(), CipherType::Identity);
        assert_eq!(CipherType::try_from(5).unwrap(), CipherType::SshKey);
        assert!(CipherType::try_from(99).is_err());

        assert_eq!(i32::from(CipherType::Login), 1);
        assert_eq!(i32::from(CipherType::SshKey), 5);

        // FieldType conversion
        assert_eq!(FieldType::from(0), FieldType::Text);
        assert_eq!(FieldType::from(1), FieldType::Hidden);
        assert_eq!(FieldType::from(2), FieldType::Boolean);
        assert_eq!(FieldType::from(3), FieldType::Linked);
        assert_eq!(FieldType::from(42), FieldType::Other(42));
        assert_eq!(i32::from(FieldType::Text), 0);
        assert_eq!(i32::from(FieldType::Other(42)), 42);

        // URIMatch conversion
        assert_eq!(URIMatch::from(0), URIMatch::Domain);
        assert_eq!(URIMatch::from(1), URIMatch::Host);
        assert_eq!(URIMatch::from(2), URIMatch::StartsWith);
        assert_eq!(URIMatch::from(3), URIMatch::Exact);
        assert_eq!(URIMatch::from(4), URIMatch::RegularExpression);
        assert_eq!(URIMatch::from(5), URIMatch::Never);
        assert_eq!(URIMatch::from(77), URIMatch::Other(77));
        assert_eq!(i32::from(URIMatch::Domain), 0);
        assert_eq!(i32::from(URIMatch::Other(77)), 77);

        // SecureNoteType conversion
        assert_eq!(SecureNoteType::from(0), SecureNoteType::Generic);
        assert_eq!(SecureNoteType::from(10), SecureNoteType::Other(10));
        assert_eq!(i32::from(SecureNoteType::Generic), 0);
        assert_eq!(i32::from(SecureNoteType::Other(10)), 10);
    }

    // --- SW-036 Test Helpers and Tests ---

    pub(crate) fn make_test_key() -> SymmetricKey {
        SymmetricKey::from_bytes(&[0x42u8; 64]).expect("Failed to create 64-byte symmetric key")
    }

    pub(crate) fn make_encrypted_cipher(
        key: &SymmetricKey,
        name: &str,
        username: &str,
        password: &str,
    ) -> Cipher {
        let enc_name = encrypt_with(name.as_bytes(), EncStringType::AesCbc256HmacSha256B64, key)
            .expect("encrypt name");
        let enc_user = encrypt_with(
            username.as_bytes(),
            EncStringType::AesCbc256HmacSha256B64,
            key,
        )
        .expect("encrypt username");
        let enc_pass = encrypt_with(
            password.as_bytes(),
            EncStringType::AesCbc256HmacSha256B64,
            key,
        )
        .expect("encrypt password");

        Cipher {
            id: Some(Uuid::new_v4()),
            r#type: CipherType::Login,
            name: enc_name,
            login: Some(LoginCipher {
                username: Some(enc_user),
                password: Some(enc_pass),
                ..Default::default()
            }),
            deleted_date: None,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_vault_store_get_logins() {
        let store = VaultStore::new();
        let key = make_test_key();

        // 3 logins
        let l1 = make_encrypted_cipher(&key, "Site 1", "user1", "pass1");
        let l2 = make_encrypted_cipher(&key, "Site 2", "user2", "pass2");
        let l3 = make_encrypted_cipher(&key, "Site 3", "user3", "pass3");

        // 1 note
        let mut note = make_encrypted_cipher(&key, "My Note", "user", "pass");
        note.r#type = CipherType::Note;
        note.login = None;

        // 1 deleted cipher
        let mut deleted = make_encrypted_cipher(&key, "Deleted Site", "user", "pass");
        deleted.deleted_date = Some("2026-10-24T00:00:00Z".to_string());

        store.insert(l1).await;
        store.insert(l2).await;
        store.insert(l3).await;
        store.insert(note).await;
        store.insert(deleted).await;

        let logins = store.get_logins().await;
        assert_eq!(logins.len(), 3);
        for login in &logins {
            assert_eq!(login.r#type, CipherType::Login);
            assert!(login.deleted_date.is_none());
        }
    }

    #[tokio::test]
    async fn test_vault_store_get_notes() {
        let store = VaultStore::new();
        let key = make_test_key();

        // 3 notes
        let mut n1 = make_encrypted_cipher(&key, "Note 1", "u", "p");
        n1.r#type = CipherType::Note;
        n1.login = None;

        let mut n2 = make_encrypted_cipher(&key, "Note 2", "u", "p");
        n2.r#type = CipherType::Note;
        n2.login = None;

        let mut n3 = make_encrypted_cipher(&key, "Note 3", "u", "p");
        n3.r#type = CipherType::Note;
        n3.login = None;

        // 1 login
        let l1 = make_encrypted_cipher(&key, "Site 1", "user1", "pass1");

        // 1 deleted note
        let mut deleted_note = make_encrypted_cipher(&key, "Deleted Note", "u", "p");
        deleted_note.r#type = CipherType::Note;
        deleted_note.deleted_date = Some("2026-10-24T00:00:00Z".to_string());

        store.insert(n1).await;
        store.insert(n2).await;
        store.insert(n3).await;
        store.insert(l1).await;
        store.insert(deleted_note).await;

        let notes = store.get_notes().await;
        assert_eq!(notes.len(), 3);
        for note in &notes {
            assert_eq!(note.r#type, CipherType::Note);
            assert!(note.deleted_date.is_none());
        }
    }

    #[tokio::test]
    async fn test_get_login_by_filter_name() {
        let store = VaultStore::new();
        let key = make_test_key();

        let l1 = make_encrypted_cipher(&key, "GitHub", "octocat", "pass1");
        let l2 = make_encrypted_cipher(&key, "GitLab", "gitlab_user", "pass2");
        let l1_id = l1.id;

        store.insert(l1).await;
        store.insert(l2).await;

        // Matching name
        let found = store
            .get_login_by_filter(None, None, Some("GitHub"), None, &key)
            .await;
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, l1_id);

        // Non-matching name
        let not_found = store
            .get_login_by_filter(None, None, Some("Bitbucket"), None, &key)
            .await;
        assert!(not_found.is_none());
    }

    #[tokio::test]
    async fn test_get_login_by_filter_username() {
        let store = VaultStore::new();
        let key = make_test_key();

        let l1 = make_encrypted_cipher(&key, "Service A", "alice@example.com", "pass1");
        let l2 = make_encrypted_cipher(&key, "Service B", "bob@example.com", "pass2");
        let l2_id = l2.id;

        store.insert(l1).await;
        store.insert(l2).await;

        // Matching username
        let found = store
            .get_login_by_filter(None, None, None, Some("bob@example.com"), &key)
            .await;
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, l2_id);

        // Filter by uuid and username matching
        let found_with_id = store
            .get_login_by_filter(l2_id.as_ref(), None, None, Some("bob@example.com"), &key)
            .await;
        assert!(found_with_id.is_some());

        // Non-matching username
        let not_found = store
            .get_login_by_filter(None, None, None, Some("charlie@example.com"), &key)
            .await;
        assert!(not_found.is_none());
    }

    #[tokio::test]
    async fn test_get_note_by_filter() {
        let store = VaultStore::new();
        let key = make_test_key();

        let mut n1 = make_encrypted_cipher(&key, "Meeting Notes", "u", "p");
        n1.r#type = CipherType::Note;
        n1.login = None;
        let org_uuid = Uuid::new_v4();
        n1.organization_id = Some(org_uuid);
        let n1_id = n1.id;

        store.insert(n1).await;

        // Filter by name and org
        let found = store
            .get_note_by_filter(None, Some(&org_uuid), Some("Meeting Notes"), &key)
            .await;
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, n1_id);

        // Non-matching
        let not_found = store
            .get_note_by_filter(None, None, Some("Other Note"), &key)
            .await;
        assert!(not_found.is_none());
    }

    #[test]
    fn test_decrypt_cipher_full() {
        let key = make_test_key();
        let cipher_id = Uuid::new_v4();

        let enc_name =
            encrypt_with(b"Bank Login", EncStringType::AesCbc256HmacSha256B64, &key).unwrap();
        let enc_user =
            encrypt_with(b"bankuser", EncStringType::AesCbc256HmacSha256B64, &key).unwrap();
        let enc_pass =
            encrypt_with(b"P@ssword123!", EncStringType::AesCbc256HmacSha256B64, &key).unwrap();
        let enc_uri = encrypt_with(
            b"https://bank.example.com",
            EncStringType::AesCbc256HmacSha256B64,
            &key,
        )
        .unwrap();
        let enc_notes =
            encrypt_with(b"PIN: 9876", EncStringType::AesCbc256HmacSha256B64, &key).unwrap();
        let enc_totp = encrypt_with(
            b"JBSWY3DPEHPK3PXP",
            EncStringType::AesCbc256HmacSha256B64,
            &key,
        )
        .unwrap();

        let cipher = Cipher {
            id: Some(cipher_id),
            r#type: CipherType::Login,
            name: enc_name,
            favorite: true,
            notes: Some(enc_notes),
            login: Some(LoginCipher {
                username: Some(enc_user),
                password: Some(enc_pass),
                uri: Some(enc_uri),
                totp: Some(enc_totp),
                ..Default::default()
            }),
            ..Default::default()
        };

        // Decrypt using VaultStore::decrypt_cipher
        let dec = VaultStore::decrypt_cipher(&cipher, &key).expect("Decryption must succeed");

        assert_eq!(dec.id, cipher_id);
        assert_eq!(dec.name, "Bank Login");
        assert_eq!(dec.cipher_type, CipherType::Login);
        assert_eq!(dec.username.as_deref(), Some("bankuser"));
        assert_eq!(dec.password.as_deref(), Some("P@ssword123!"));
        assert_eq!(dec.uri.as_deref(), Some("https://bank.example.com"));
        assert_eq!(dec.notes.as_deref(), Some("PIN: 9876"));
        assert_eq!(dec.totp.as_deref(), Some("JBSWY3DPEHPK3PXP"));
        assert!(dec.favorite);

        // Also test cipher.decrypt(&key) convenience method
        let dec2 = cipher
            .decrypt(&key)
            .expect("Convenience decrypt must succeed");
        assert_eq!(dec, dec2);
    }

    #[test]
    fn test_decrypt_cipher_with_null_fields() {
        let key = make_test_key();
        let cipher_id = Uuid::new_v4();

        let enc_name =
            encrypt_with(b"Empty Note", EncStringType::AesCbc256HmacSha256B64, &key).unwrap();

        let cipher = Cipher {
            id: Some(cipher_id),
            r#type: CipherType::Note,
            name: enc_name,
            favorite: false,
            notes: None,
            login: None,
            ..Default::default()
        };

        let dec = VaultStore::decrypt_cipher(&cipher, &key).expect("Decryption must succeed");

        assert_eq!(dec.id, cipher_id);
        assert_eq!(dec.name, "Empty Note");
        assert_eq!(dec.cipher_type, CipherType::Note);
        assert_eq!(dec.username, None);
        assert_eq!(dec.password, None);
        assert_eq!(dec.uri, None);
        assert_eq!(dec.notes, None);
        assert_eq!(dec.totp, None);
        assert!(!dec.favorite);
    }

    #[test]
    fn test_decrypt_cipher_error_on_null_name() {
        let key = make_test_key();
        let cipher = Cipher {
            id: Some(Uuid::new_v4()),
            r#type: CipherType::Note,
            name: EncString::default(),
            ..Default::default()
        };

        let res = VaultStore::decrypt_cipher(&cipher, &key);
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_search_matches_name_and_username() {
        let store = VaultStore::new();
        let key = make_test_key();

        let l1 = make_encrypted_cipher(&key, "GitHub Production", "devops_lead", "pass1");
        let l2 = make_encrypted_cipher(&key, "AWS Console", "github-sync-bot", "pass2");
        let mut note = make_encrypted_cipher(&key, "Secret Database Notes", "none", "none");
        note.r#type = CipherType::Note;
        note.login = None;

        let mut deleted = make_encrypted_cipher(&key, "GitHub Staging", "staging_user", "pass");
        deleted.deleted_date = Some("2026-10-24T00:00:00Z".to_string());

        store.insert(l1).await;
        store.insert(l2).await;
        store.insert(note).await;
        store.insert(deleted).await;

        // Search matching name ("GitHub") -> should match l1 by name and l2 by username ("github-sync-bot"), ignoring deleted
        let results = store.search("GitHub", &key).await;
        assert_eq!(results.len(), 2);
        let names: Vec<&str> = results.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"GitHub Production"));
        assert!(names.contains(&"AWS Console"));

        // Search matching username ("devops") -> should match l1
        let devops_results = store.search("devops", &key).await;
        assert_eq!(devops_results.len(), 1);
        assert_eq!(devops_results[0].name, "GitHub Production");

        // Search matching note by name ("Database")
        let db_results = store.search("Database", &key).await;
        assert_eq!(db_results.len(), 1);
        assert_eq!(db_results[0].name, "Secret Database Notes");

        // Search non-existent
        let empty_results = store.search("NoSuchEntry12345", &key).await;
        assert!(empty_results.is_empty());
    }

    #[test]
    fn test_vault_store_blocking_filtering_and_search() {
        let store = VaultStore::new();
        let key = make_test_key();

        let l1 = make_encrypted_cipher(&key, "GitHub", "octocat", "pass1");
        let mut n1 = make_encrypted_cipher(&key, "Meeting Notes", "u", "p");
        n1.r#type = CipherType::Note;
        n1.login = None;
        let n1_id = n1.id;
        let l1_id = l1.id;

        store.blocking_insert(l1);
        store.blocking_insert(n1);

        assert_eq!(store.blocking_get_logins().len(), 1);
        assert_eq!(store.blocking_get_notes().len(), 1);

        let found_login =
            store.blocking_get_login_by_filter(None, None, Some("GitHub"), None, &key);
        assert_eq!(found_login.unwrap().id, l1_id);

        let found_note = store.blocking_get_note_by_filter(n1_id.as_ref(), None, None, &key);
        assert_eq!(found_note.unwrap().id, n1_id);

        let search_res = store.blocking_search("Git", &key);
        assert_eq!(search_res.len(), 1);
        assert_eq!(search_res[0].name, "GitHub");
    }

    #[test]
    fn test_vault_errors_display() {
        let err_api = VaultError::Api("sync timeout".into());
        assert!(format!("{err_api}").contains("sync timeout"));

        let err_other = VaultError::Other("custom error".into());
        assert!(format!("{err_other}").contains("custom error"));

        let err_crypto = VaultError::Crypto(sw_crypto::CryptoError::InvalidKeyLength(
            "32 bytes expected".into(),
        ));
        assert!(format!("{err_crypto}").contains("32 bytes expected"));

        let utf8_err = String::from_utf8(vec![0xFF]).unwrap_err();
        let err_utf8 = VaultError::Utf8(utf8_err);
        assert!(format!("{err_utf8}").contains("UTF-8"));
    }

    #[test]
    fn test_vault_paths_default_paths() {
        let paths = VaultPaths::default_paths();
        if let Ok(p) = paths {
            assert!(p.vault_file().ends_with("vault.json"));
        }
    }

    #[test]
    fn test_decrypt_cipher_uri_fallback_and_login_cases() {
        let key = make_test_key();
        let id = Uuid::new_v4();

        // Case 1: login.uri is null EncString, but login.uris has a URI
        let enc_name = encrypt_with(
            b"Test URI Fallback",
            EncStringType::AesCbc256HmacSha256B64,
            &key,
        )
        .unwrap();
        let cipher1 = Cipher {
            id: Some(id),
            r#type: CipherType::Login,
            name: enc_name.clone(),
            login: Some(LoginCipher {
                uri: Some(EncString::default()),
                uris: vec![URI {
                    uri: Some("https://uris-fallback.example.com".into()),
                    r#match: Some(URIMatch::Domain),
                }],
                ..Default::default()
            }),
            ..Default::default()
        };
        let dec1 = VaultStore::decrypt_cipher(&cipher1, &key).unwrap();
        assert_eq!(
            dec1.uri.as_deref(),
            Some("https://uris-fallback.example.com")
        );

        // Case 2: login.uri is None, and login.uris has a URI
        let cipher2 = Cipher {
            id: Some(id),
            r#type: CipherType::Login,
            name: enc_name.clone(),
            login: Some(LoginCipher {
                uri: None,
                uris: vec![URI {
                    uri: Some("https://uris-none.example.com".into()),
                    r#match: None,
                }],
                ..Default::default()
            }),
            ..Default::default()
        };
        let dec2 = VaultStore::decrypt_cipher(&cipher2, &key).unwrap();
        assert_eq!(dec2.uri.as_deref(), Some("https://uris-none.example.com"));

        // Case 3: login.uri is None, login.uris is empty
        let cipher3 = Cipher {
            id: Some(id),
            r#type: CipherType::Login,
            name: enc_name,
            login: Some(LoginCipher {
                uri: None,
                uris: vec![],
                ..Default::default()
            }),
            ..Default::default()
        };
        let dec3 = VaultStore::decrypt_cipher(&cipher3, &key).unwrap();
        assert_eq!(dec3.uri, None);
    }

    #[tokio::test]
    async fn test_filter_edge_cases() {
        let store = VaultStore::new();
        let key = make_test_key();
        let org_a = Uuid::new_v4();
        let org_b = Uuid::new_v4();

        let mut l1 = make_encrypted_cipher(&key, "Alpha", "user_alpha", "pass");
        l1.organization_id = Some(org_a);

        let mut l2 = make_encrypted_cipher(&key, "Beta", "user_beta", "pass");
        l2.organization_id = Some(org_b);

        // Cipher with no login
        let mut l_no_login = make_encrypted_cipher(&key, "NoLogin", "none", "pass");
        l_no_login.login = None;

        // Cipher with null username
        let mut l_null_un = make_encrypted_cipher(&key, "NullUser", "none", "pass");
        l_null_un.login = Some(LoginCipher {
            username: Some(EncString::default()),
            ..Default::default()
        });

        // Cipher with null name
        let l_null_name = Cipher {
            id: Some(Uuid::new_v4()),
            r#type: CipherType::Login,
            name: EncString::default(),
            ..Default::default()
        };

        store.insert(l1.clone()).await;
        store.insert(l2.clone()).await;
        store.insert(l_no_login).await;
        store.insert(l_null_un).await;
        store.insert(l_null_name).await;

        // Match with org_id
        let found_org = store
            .get_login_by_filter(None, Some(&org_a), None, None, &key)
            .await;
        assert_eq!(found_org.unwrap().id, l1.id);

        // Org mismatch
        let nonexistent_org = Uuid::new_v4();
        let not_found_org = store
            .get_login_by_filter(None, Some(&nonexistent_org), None, None, &key)
            .await;
        assert!(not_found_org.is_none());

        // Username filter on cipher without login
        let not_found_user = store
            .get_login_by_filter(None, None, Some("NoLogin"), Some("any"), &key)
            .await;
        assert!(not_found_user.is_none());

        // Username filter on cipher with null username
        let not_found_null_user = store
            .get_login_by_filter(None, None, Some("NullUser"), Some("any"), &key)
            .await;
        assert!(not_found_null_user.is_none());

        // Note filter edge cases
        let mut note = make_encrypted_cipher(&key, "Special Note", "u", "p");
        note.r#type = CipherType::Note;
        note.login = None;
        note.organization_id = Some(org_a);
        let note_id = note.id.unwrap();
        store.insert(note).await;

        // Note filter with uuid
        let found_note_id = store
            .get_note_by_filter(Some(&note_id), None, None, &key)
            .await;
        assert!(found_note_id.is_some());

        // Note filter with mismatched uuid
        let wrong_id = Uuid::new_v4();
        let not_found_note_id = store
            .get_note_by_filter(Some(&wrong_id), None, None, &key)
            .await;
        assert!(not_found_note_id.is_none());

        // Note filter with mismatched org
        let not_found_note_org = store
            .get_note_by_filter(None, Some(&org_b), None, &key)
            .await;
        assert!(not_found_note_org.is_none());
    }

    #[test]
    fn test_all_enum_conversions() {
        // CipherType
        for (i, ct) in [
            (1, CipherType::Login),
            (2, CipherType::Note),
            (3, CipherType::Card),
            (4, CipherType::Identity),
            (5, CipherType::SshKey),
        ] {
            assert_eq!(CipherType::try_from(i).unwrap(), ct);
            assert_eq!(i32::from(ct), i);
        }
        assert!(CipherType::try_from(0).is_err());
        assert!(CipherType::try_from(6).is_err());

        // FieldType
        for (i, ft) in [
            (0, FieldType::Text),
            (1, FieldType::Hidden),
            (2, FieldType::Boolean),
            (3, FieldType::Linked),
            (99, FieldType::Other(99)),
        ] {
            assert_eq!(FieldType::from(i), ft);
            assert_eq!(i32::from(ft), i);
        }

        // URIMatch
        for (i, um) in [
            (0, URIMatch::Domain),
            (1, URIMatch::Host),
            (2, URIMatch::StartsWith),
            (3, URIMatch::Exact),
            (4, URIMatch::RegularExpression),
            (5, URIMatch::Never),
            (99, URIMatch::Other(99)),
        ] {
            assert_eq!(URIMatch::from(i), um);
            assert_eq!(i32::from(um), i);
        }

        // SecureNoteType
        assert_eq!(SecureNoteType::from(0), SecureNoteType::Generic);
        assert_eq!(i32::from(SecureNoteType::Generic), 0);
        assert_eq!(SecureNoteType::from(99), SecureNoteType::Other(99));
        assert_eq!(i32::from(SecureNoteType::Other(99)), 99);
    }

    #[tokio::test]
    async fn test_get_ssh_keys_extraction() {
        let key = make_test_key();
        let store = VaultStore::new();

        let priv_key_1 =
            "-----BEGIN OPENSSH PRIVATE KEY-----\ntestkey1\n-----END OPENSSH PRIVATE KEY-----\n";
        let pub_key_1 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... user@test1";
        let enc_name_1 = encrypt_with(
            b"id_ed25519_test",
            EncStringType::AesCbc256HmacSha256B64,
            &key,
        )
        .unwrap();
        let enc_priv_1 = encrypt_with(
            priv_key_1.as_bytes(),
            EncStringType::AesCbc256HmacSha256B64,
            &key,
        )
        .unwrap();
        let enc_pub_1 = encrypt_with(
            pub_key_1.as_bytes(),
            EncStringType::AesCbc256HmacSha256B64,
            &key,
        )
        .unwrap();

        let cipher_ssh = Cipher {
            id: Some(Uuid::new_v4()),
            r#type: CipherType::SshKey,
            name: enc_name_1,
            ssh_key: Some(SSHKeyCipher {
                private_key: Some(enc_priv_1),
                public_key: Some(enc_pub_1),
                key_fingerprint: None,
            }),
            ..Default::default()
        };

        // Note-based SSH key
        let priv_key_2 = "-----BEGIN RSA PRIVATE KEY----- AAAA BBBB -----END RSA PRIVATE KEY-----";
        let pub_key_2 = "ssh-rsa AAAAB3NzaC1yc2E... user@test2";
        let enc_name_2 =
            encrypt_with(b"id_rsa_note", EncStringType::AesCbc256HmacSha256B64, &key).unwrap();
        let enc_fn_custom =
            encrypt_with(b"custom-type", EncStringType::AesCbc256HmacSha256B64, &key).unwrap();
        let enc_fv_custom =
            encrypt_with(b"ssh-key", EncStringType::AesCbc256HmacSha256B64, &key).unwrap();
        let enc_fn_priv =
            encrypt_with(b"private-key", EncStringType::AesCbc256HmacSha256B64, &key).unwrap();
        let enc_fv_priv = encrypt_with(
            priv_key_2.as_bytes(),
            EncStringType::AesCbc256HmacSha256B64,
            &key,
        )
        .unwrap();
        let enc_fn_pub =
            encrypt_with(b"public-key", EncStringType::AesCbc256HmacSha256B64, &key).unwrap();
        let enc_fv_pub = encrypt_with(
            pub_key_2.as_bytes(),
            EncStringType::AesCbc256HmacSha256B64,
            &key,
        )
        .unwrap();

        let cipher_note = Cipher {
            id: Some(Uuid::new_v4()),
            r#type: CipherType::Note,
            name: enc_name_2,
            fields: vec![
                Field {
                    r#type: Some(FieldType::Text),
                    name: Some(enc_fn_custom),
                    value: Some(enc_fv_custom),
                },
                Field {
                    r#type: Some(FieldType::Hidden),
                    name: Some(enc_fn_priv),
                    value: Some(enc_fv_priv),
                },
                Field {
                    r#type: Some(FieldType::Text),
                    name: Some(enc_fn_pub),
                    value: Some(enc_fv_pub),
                },
            ],
            ..Default::default()
        };

        // Deleted cipher should be ignored
        let mut cipher_deleted = cipher_ssh.clone();
        cipher_deleted.id = Some(Uuid::new_v4());
        cipher_deleted.deleted_date = Some("2026-10-26T00:00:00Z".to_string());

        store.insert(cipher_ssh).await;
        store.insert(cipher_note).await;
        store.insert(cipher_deleted).await;

        let ssh_keys = store.get_ssh_keys(&key).await.unwrap();
        assert_eq!(ssh_keys.len(), 2);

        let key1 = ssh_keys
            .iter()
            .find(|k| k.name == "id_ed25519_test")
            .unwrap();
        assert_eq!(key1.private_key, priv_key_1.trim());
        assert_eq!(key1.public_key.as_deref(), Some(pub_key_1));

        let key2 = ssh_keys.iter().find(|k| k.name == "id_rsa_note").unwrap();
        assert!(key2.private_key.contains("-----BEGIN RSA PRIVATE KEY-----"));
        assert!(key2.private_key.contains("-----END RSA PRIVATE KEY-----"));
        assert_eq!(key2.public_key.as_deref(), Some(pub_key_2));

        // Blocking variant
        let store_arc = std::sync::Arc::new(store);
        let key_bytes = key.bytes();
        let blocking_keys = tokio::task::spawn_blocking(move || {
            let k = SymmetricKey::from_bytes(&key_bytes).unwrap();
            store_arc.blocking_get_ssh_keys(&k).unwrap()
        })
        .await
        .unwrap();
        assert_eq!(blocking_keys.len(), 2);
    }
}
