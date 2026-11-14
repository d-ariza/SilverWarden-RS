use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use sw_crypto::{EncString, SymmetricKey};
use thiserror::Error;
use uuid::Uuid;

use crate::VaultStore;

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
