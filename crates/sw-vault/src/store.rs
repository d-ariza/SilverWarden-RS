use std::collections::HashMap;
use sw_crypto::SymmetricKey;
use uuid::Uuid;

use crate::models::{
    Cipher, CipherType, DecryptedCipher, Folder, Profile, SyncData, VaultError, VaultSshKey,
};

/// In-memory secure vault store protected by a `RwLock`.
#[derive(Debug, Default)]
pub struct VaultStore {
    pub(crate) ciphers: tokio::sync::RwLock<HashMap<Uuid, Cipher>>,
    pub(crate) folders: tokio::sync::RwLock<Vec<Folder>>,
    pub(crate) profile: tokio::sync::RwLock<Option<Profile>>,
    pub(crate) last_synced: tokio::sync::RwLock<Option<u64>>,
}

impl VaultStore {
    /// Creates a new empty `VaultStore`.
    pub fn new() -> Self {
        Self::default()
    }

    fn apply_sync_data(
        c_guard: &mut HashMap<Uuid, Cipher>,
        f_guard: &mut Vec<Folder>,
        p_guard: &mut Option<Profile>,
        sync_data: SyncData,
    ) {
        c_guard.clear();
        for cipher in sync_data.ciphers {
            if let Some(id) = cipher.id {
                c_guard.insert(id, cipher);
            }
        }

        *f_guard = sync_data.folders;
        *p_guard = Some(sync_data.profile);
    }

    /// Loads a full `SyncData` payload into the store in memory without preliminary mass decryption.
    pub async fn load_sync_data(&self, sync_data: SyncData) {
        let mut c_guard = self.ciphers.write().await;
        let mut f_guard = self.folders.write().await;
        let mut p_guard = self.profile.write().await;
        Self::apply_sync_data(&mut c_guard, &mut f_guard, &mut p_guard, sync_data);
    }

    /// Synchronously loads a `SyncData` payload when all store locks are immediately available.
    ///
    /// Intended for synchronous initialization paths that run before or outside a Tokio runtime.
    pub fn try_load_sync_data(&self, sync_data: SyncData) -> bool {
        let (Ok(mut c_guard), Ok(mut f_guard), Ok(mut p_guard)) = (
            self.ciphers.try_write(),
            self.folders.try_write(),
            self.profile.try_write(),
        ) else {
            return false;
        };
        Self::apply_sync_data(&mut c_guard, &mut f_guard, &mut p_guard, sync_data);
        true
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
        Self::apply_sync_data(&mut c_guard, &mut f_guard, &mut p_guard, sync_data);
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

    /// Extracts and decrypts SSH keys from stored Type 5 (SshKey) ciphers asynchronously.
    pub async fn get_ssh_keys(
        &self,
        user_key: &SymmetricKey,
    ) -> Result<Vec<VaultSshKey>, VaultError> {
        let ciphers = self.all().await;
        Self::extract_ssh_key_ciphers(&ciphers, user_key)
    }

    /// Synchronous variant of `get_ssh_keys`.
    pub fn blocking_get_ssh_keys(
        &self,
        user_key: &SymmetricKey,
    ) -> Result<Vec<VaultSshKey>, VaultError> {
        let ciphers = self.blocking_all();
        Self::extract_ssh_key_ciphers(&ciphers, user_key)
    }

    /// Extracts and decrypts legacy SSH keys from stored Secure Notes (custom-type: ssh-key) asynchronously.
    pub async fn extract_ssh_keys(
        &self,
        user_key: &SymmetricKey,
    ) -> Result<Vec<VaultSshKey>, VaultError> {
        let ciphers = self.all().await;
        Self::extract_legacy_ssh_notes(&ciphers, user_key)
    }

    /// Synchronous variant of `extract_ssh_keys`.
    pub fn blocking_extract_ssh_keys(
        &self,
        user_key: &SymmetricKey,
    ) -> Result<Vec<VaultSshKey>, VaultError> {
        let ciphers = self.blocking_all();
        Self::extract_legacy_ssh_notes(&ciphers, user_key)
    }
}
