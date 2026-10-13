use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SyncData {
    pub ciphers: Vec<Cipher>,
    pub last_sync: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Cipher {
    pub id: String,
    pub organization_id: Option<String>,
    pub folder_id: Option<String>,
    #[serde(rename = "type")]
    pub cipher_type: i32,
    pub name: Option<String>,
    pub notes: Option<String>,
    pub favorite: Option<bool>,
    pub login: Option<LoginData>,
    pub secure_note: Option<SecureNoteData>,
    pub ssh_key: Option<SSHKeyData>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LoginData {
    pub username: Option<String>,
    pub password: Option<String>,
    pub totp: Option<String>,
    pub uris: Option<Vec<LoginUri>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LoginUri {
    pub uri: Option<String>,
    pub match_type: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SecureNoteData {
    #[serde(rename = "type")]
    pub note_type: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SSHKeyData {
    pub private_key: Option<String>,
    pub public_key: Option<String>,
}

/// In-memory secure vault store
#[derive(Debug, Default)]
pub struct VaultStore {
    ciphers: HashMap<String, Cipher>,
}

impl VaultStore {
    pub fn new() -> Self {
        Self {
            ciphers: HashMap::new(),
        }
    }

    pub fn insert(&mut self, cipher: Cipher) {
        self.ciphers.insert(cipher.id.clone(), cipher);
    }

    pub fn get(&self, id: &str) -> Option<&Cipher> {
        self.ciphers.get(id)
    }

    pub fn all(&self) -> Vec<&Cipher> {
        self.ciphers.values().collect()
    }

    pub fn clear(&mut self) {
        self.ciphers.clear();
    }
}
