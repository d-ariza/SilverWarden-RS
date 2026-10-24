use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use sw_crypto::EncString;
use thiserror::Error;
use uuid::Uuid;

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

/// Login specific payload of a cipher
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct LoginCipher {
    #[serde(default)]
    pub password: Option<EncString>,
    #[serde(default)]
    pub uri: Option<EncString>,
    #[serde(default)]
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
    #[serde(default)]
    pub id: Option<Uuid>,
    #[serde(default)]
    pub name: EncString,
    #[serde(default)]
    pub edit: bool,
    #[serde(default)]
    pub revision_date: Option<String>,
    #[serde(default)]
    pub deleted_date: Option<String>,

    #[serde(default)]
    pub folder_id: Option<Uuid>,
    #[serde(default)]
    pub organization_id: Option<Uuid>,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default)]
    pub attachments: Option<serde_json::Value>,
    #[serde(default)]
    pub organization_use_totp: bool,
    #[serde(default)]
    pub collection_ids: Vec<String>,
    #[serde(default)]
    pub fields: Vec<Field>,

    #[serde(default)]
    pub card: Option<Card>,
    #[serde(default)]
    pub identity: Option<Identity>,
    #[serde(default)]
    pub login: Option<LoginCipher>,
    #[serde(default)]
    pub notes: Option<EncString>,
    #[serde(default)]
    pub secure_note: Option<SecureNoteCipher>,
    #[serde(default)]
    pub ssh_key: Option<SSHKeyCipher>,

    #[serde(default)]
    pub key: Option<EncString>,
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
        assert!(store.blocking_delete(&id1).is_some());
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
}
