use crate::client::{ApiError, AuthenticatedClient, RequestBody};

impl AuthenticatedClient {
    /// Fetches the full synchronization data (`SyncData`) from the Bitwarden `/sync` endpoint.
    ///
    /// Automatically handles fallback between `/sync` and `/api/sync` for compatibility
    /// with official Bitwarden servers and self-hosted instances.
    pub async fn sync(&self) -> Result<sw_vault::SyncData, ApiError> {
        let mut resp = self
            .fetch_with_auth(reqwest::Method::GET, "sync", RequestBody::Empty)
            .await?;

        // Fallback for self-hosted instances if api_url is root and sync is at /api/sync
        if resp.status() == reqwest::StatusCode::NOT_FOUND && !self.api_url.ends_with("/api") {
            let alt_resp = self
                .fetch_with_auth(reqwest::Method::GET, "api/sync", RequestBody::Empty)
                .await?;
            if alt_resp.status().is_success() {
                resp = alt_resp;
            }
        }

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();

            if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
                return Err(ApiError::RateLimitExceeded);
            }
            if status == reqwest::StatusCode::UNAUTHORIZED {
                return Err(ApiError::InvalidCredentials);
            }

            return Err(ApiError::Status {
                status,
                message: body,
            });
        }

        let sync_data: sw_vault::SyncData = resp.json().await?;
        Ok(sync_data)
    }

    /// Performs a full synchronization:
    /// 1. Queries the remote `/sync` endpoint via `self.sync()`.
    /// 2. If `user_symmetric_key` is provided, initializes the cryptographic `Keyring`.
    /// 3. Persists the raw `SyncData` atomically to disk in `vault_paths.vault_file()`
    ///    with Unix permissions 0600.
    /// 4. Populates the in-memory `VaultStore` with ciphers, folders, profile and updates `last_synced`.
    ///
    /// Returns the synchronized `SyncData`.
    pub async fn do_full_sync(
        &self,
        vault_paths: &sw_vault::VaultPaths,
        vault_store: &sw_vault::VaultStore,
        user_symmetric_key: Option<&sw_crypto::SymmetricKey>,
    ) -> Result<sw_vault::SyncData, ApiError> {
        let sync_data = self.sync().await?;

        // Initialize Keyring if user_symmetric_key is provided
        if let Some(user_sym_key) = user_symmetric_key {
            let mut keyring = sw_crypto::Keyring::new();
            let mut org_keys = std::collections::HashMap::new();
            for org in &sync_data.profile.organizations {
                if let (Some(org_id), Some(org_key)) = (org.id, &org.key) {
                    org_keys.insert(org_id.to_string(), org_key.clone());
                }
            }
            let empty_enc = sw_crypto::EncString::default();
            let priv_key_ref = sync_data.profile.private_key.as_ref().unwrap_or(&empty_enc);
            let _ = sw_crypto::init_keyring_from_user_symmetric_key(
                &mut keyring,
                user_sym_key.try_clone().map_err(ApiError::Crypto)?,
                priv_key_ref,
                org_keys,
            );
        }

        // Atomically save to disk with 0600 permissions
        sw_vault::save_vault(&vault_paths.vault_file(), &sync_data)?;

        // Populate in-memory store
        vault_store.load_sync_data(sync_data.clone()).await;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        vault_store.set_last_synced(now).await;

        Ok(sync_data)
    }
}

/// Standalone convenience wrapper for `AuthenticatedClient::sync`.
pub async fn sync(client: &AuthenticatedClient) -> Result<sw_vault::SyncData, ApiError> {
    client.sync().await
}

/// Standalone convenience wrapper for `AuthenticatedClient::do_full_sync`.
pub async fn do_full_sync(
    client: &AuthenticatedClient,
    vault_paths: &sw_vault::VaultPaths,
    vault_store: &sw_vault::VaultStore,
    user_symmetric_key: Option<&sw_crypto::SymmetricKey>,
) -> Result<sw_vault::SyncData, ApiError> {
    client
        .do_full_sync(vault_paths, vault_store, user_symmetric_key)
        .await
}
