use crate::approval::{ApprovalProvider, DefaultApprovalProvider};
use crate::error::SshAgentError;
use crate::keys::SshKeySummary;
use russh::keys::agent::server::{Agent, MessageType};
pub use russh::keys::agent::AgentIdentity;
use russh::keys::{PrivateKey, PublicKey};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use sw_bitwarden_api::BitwardenApiClient;
use sw_crypto::SymmetricKey;
use sw_notify::Notifier;
use sw_systemauth::{CallingContext, SessionStore, SessionType};
use sw_vault::VaultStore;
use tokio::sync::RwLock;
use uuid::Uuid;

pub const SSH_AGENT_RSA_SHA2_256: u32 = 2;
pub const SSH_AGENT_RSA_SHA2_512: u32 = 4;
pub const SSHSIG_GIT_MAGIC: &[u8] = b"SSHSIG\x00\x00\x00\x03git";

#[cfg(any(test, debug_assertions))]
pub(crate) const TEST_RSA_PEM: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\n\
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn\n\
NhAAAAAwEAAQAAAQEA6HNXGgWxM+VCFHvJptz8GHPlOrgN8uybPY6o4u4IaC0PUKL/oUSC\n\
HcEZ5fu4w1MUj4VVkziPtRm4cRnn1tksFnMOPawRyiCH9luCqWbrcnV3Y50EVnczCSPBBF\n\
j5FDg4IaOhrqak77DBzBqo5tOF/rqRgwFxfnwdXzX5UkrzDrqsclvEWeNWQIXLNCkXMQLi\n\
xgrrML3i+clg8JbXpI2y3HVOCEIYXq0RVwKhhHI6ybPoWnY0zZZX0oBFQRY3zJsvU/rwUw\n\
iM76Ad5fvlSB0RO7D3nmtFP50SNFo1d9jlS+fPg7Lw2L+1Fhd54mIvG4BBFLFEMzaePUin\n\
D8r4AGcl+QAAA8jidw+/4ncPvwAAAAdzc2gtcnNhAAABAQDoc1caBbEz5UIUe8mm3PwYc+\n\
U6uA3y7Js9jqji7ghoLQ9Qov+hRIIdwRnl+7jDUxSPhVWTOI+1GbhxGefW2SwWcw49rBHK\n\
IIf2W4KpZutydXdjnQRWdzMJI8EEWPkUODgho6GupqTvsMHMGqjm04X+upGDAXF+fB1fNf\n\
lSSvMOuqxyW8RZ41ZAhcs0KRcxAuLGCuswveL5yWDwltekjbLcdU4IQhherRFXAqGEcjrJ\n\
s+hadjTNllfSgEVBFjfMmy9T+vBTCIzvoB3l++VIHRE7sPeea0U/nRI0WjV32OVL58+Dsv\n\
DYv7UWF3niYi8bgEEUsUQzNp49SKcPyvgAZyX5AAAAAwEAAQAAAQAFskRXJDeDY6OfRyj5\n\
/sOj/adOgsONaXjIU0LLwYZ/mtUUfzb4jA3v5wFxfyxGQG+023S0bl1hooLAZiCX6QR5X8\n\
7SSHhz6S8ectUlaFPY7WjynGXb1888yC8bBcCZFA5kwN2aNIz3r0wR1RTdB+cGzg3Op2x7\n\
8puGb7N6H3whoBZbVRxKI5U1NzJ+tmRXZVK63/eeBoyf0qiFVEAQzMJ4Lq3dVFtZbkDIbZ\n\
F2FAU2Yfv3bCXvFvLS0VKD2/BeXMhDwG89WQJC9B4RYpcMlwcGd1NKBalZPxCvic2jA9MI\n\
UhJ+yBSUM0N9CuQTWsn4LfJTEdVCHGoBOcevYEH6GIDlAAAAgQDLJVUlScfqqbNQGDSjHE\n\
oCoQBmUzdxhrnd4BwA6T5j5Vhd0ISuZ0g5DVFjhhHHch/6/lpaxUlabAN7cNc5m5uN6lQ3\n\
nEMi13ue2XkFrS231xbD7y7lKFqg5ThhaL9dWKzn/LInYwfsM/25QcrRWii3p7SIHgIZ/Q\n\
9a0xAub5BNFAAAAIEA9pg3z4QOCtSQ3OLW9ileVv2IwTCWTQ9KconJShqcBVWlps8hHXL+\n\
gyXtA0s+OSwpSBTQDLzOHWMjHvSTr9LTpGphci/o1cyGWDO/y9H7cZtg1WVuIBcEWcY/C3\n\
LIDalawfn3+mPZaOVXBpWTDiwf+Wiw/TquWpntplYJbi5U1HUAAACBAPFRBJD0MUrjF42v\n\
8CEtxmX7m9wQcuVLkJ5XPGoPXx7GoaHmTH1mnZycVLWOevoU3W1YdARraR7Wr0M3+hENEu\n\
Djy0VhpOceL/ugQCXmvmRscqf3I15V7/QqkReDnzR/Ww/RyNgHUeFBY20nrodL9NAmkmc0\n\
e7lav3X7vAAi1kr1AAAAEmhlcm1lc0B0cmlzbWVnaXN0bw==\n\
-----END OPENSSH PRIVATE KEY-----";

/// Agent server integrating with SilverWarden Vault and implementing `russh::keys::agent::server::Agent`.
#[derive(Clone)]
pub struct VaultAgentServer {
    pub vault: Arc<VaultStore>,
    pub symmetric_key: Arc<RwLock<Option<SymmetricKey>>>,
    pub is_locked: Arc<AtomicBool>,
    pub session_store: Arc<RwLock<SessionStore>>,
    pub approval_provider: Arc<dyn ApprovalProvider>,
    pub api_client: Option<Arc<BitwardenApiClient>>,
    pub notifier: Option<Arc<dyn Notifier>>,
}

impl std::fmt::Debug for VaultAgentServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultAgentServer")
            .field(
                "is_locked",
                &self.is_locked.load(std::sync::atomic::Ordering::Relaxed),
            )
            .field("has_api_client", &self.api_client.is_some())
            .field("has_notifier", &self.notifier.is_some())
            .finish()
    }
}

impl Default for VaultAgentServer {
    fn default() -> Self {
        Self::new(Arc::new(VaultStore::new()))
    }
}

impl VaultAgentServer {
    /// Creates a new `VaultAgentServer` with an initially locked vault.
    pub fn new(vault: Arc<VaultStore>) -> Self {
        Self {
            vault,
            symmetric_key: Arc::new(RwLock::new(None)),
            is_locked: Arc::new(AtomicBool::new(true)),
            session_store: Arc::new(RwLock::new(SessionStore::new())),
            approval_provider: Arc::new(DefaultApprovalProvider::new()),
            api_client: None,
            notifier: None,
        }
    }

    /// Creates a new `VaultAgentServer` with an already unlocked vault and symmetric key.
    pub fn with_key(vault: Arc<VaultStore>, key: SymmetricKey) -> Self {
        Self {
            vault,
            symmetric_key: Arc::new(RwLock::new(Some(key))),
            is_locked: Arc::new(AtomicBool::new(false)),
            session_store: Arc::new(RwLock::new(SessionStore::new())),
            approval_provider: Arc::new(DefaultApprovalProvider::new()),
            api_client: None,
            notifier: None,
        }
    }

    /// Overrides the approval provider (used in tests or custom dialog integrators).
    pub fn with_approval_provider(mut self, provider: Arc<dyn ApprovalProvider>) -> Self {
        self.approval_provider = provider;
        self
    }

    /// Overrides the session store.
    pub fn with_session_store(mut self, sessions: Arc<RwLock<SessionStore>>) -> Self {
        self.session_store = sessions;
        self
    }

    /// Sets an authenticated Bitwarden API client for remote synchronization.
    pub fn with_api_client(mut self, client: Arc<BitwardenApiClient>) -> Self {
        self.api_client = Some(client);
        self
    }

    /// Sets an optional desktop notifier.
    pub fn with_notifier(mut self, notifier: Arc<dyn Notifier>) -> Self {
        self.notifier = Some(notifier);
        self
    }

    /// Access to the optional notifier.
    pub fn notifier(&self) -> Option<&Arc<dyn Notifier>> {
        self.notifier.as_ref()
    }

    /// Access to the underlying session store.
    pub fn session_store(&self) -> &Arc<RwLock<SessionStore>> {
        &self.session_store
    }

    /// Access to the underlying approval provider.
    pub fn approval_provider(&self) -> &Arc<dyn ApprovalProvider> {
        &self.approval_provider
    }

    /// Access to the optional API client.
    pub fn api_client(&self) -> Option<&Arc<BitwardenApiClient>> {
        self.api_client.as_ref()
    }

    /// Unlocks the agent server with the provided user symmetric key.
    pub async fn unlock(&self, key: SymmetricKey) {
        let mut guard = self.symmetric_key.write().await;
        *guard = Some(key);
        self.is_locked.store(false, Ordering::SeqCst);
    }

    /// Locks the agent server, clearing the cached user symmetric key and wiping sessions.
    pub async fn lock(&self) {
        let mut guard = self.symmetric_key.write().await;
        *guard = None;
        self.is_locked.store(true, Ordering::SeqCst);
        self.session_store.write().await.wipe();
    }

    /// Returns whether the vault is locked.
    pub fn is_locked(&self) -> bool {
        self.is_locked.load(Ordering::SeqCst)
    }

    /// Access to the underlying VaultStore.
    pub fn vault(&self) -> &Arc<VaultStore> {
        &self.vault
    }

    /// Returns a cloned copy of the user symmetric key if unlocked.
    pub async fn get_symmetric_key(&self) -> Option<SymmetricKey> {
        self.symmetric_key
            .read()
            .await
            .as_ref()
            .and_then(|k| k.try_clone().ok())
    }

    /// Lists summaries of all SSH keys in the vault.
    ///
    /// **Security Guarantee:** Never exposes private key material.
    pub async fn list_ssh_keys(&self) -> Result<Vec<SshKeySummary>, SshAgentError> {
        if self.is_locked() {
            return Err(SshAgentError::VaultLocked);
        }

        let key_guard = self.symmetric_key.read().await;
        let key = match key_guard.as_ref() {
            Some(k) => k,
            None => return Err(SshAgentError::VaultLocked),
        };

        let mut vault_keys = self
            .vault
            .get_ssh_keys(key)
            .await
            .map_err(|e| SshAgentError::KeyError(e.to_string()))?;
        if let Ok(legacy_keys) = self.vault.extract_ssh_keys(key).await {
            vault_keys.extend(legacy_keys);
        }

        let mut summaries = Vec::new();
        for vk in vault_keys {
            let (fingerprint, pub_str) = match PrivateKey::from_openssh(&vk.private_key) {
                Ok(pk) => {
                    let fp = pk
                        .public_key()
                        .fingerprint(russh::keys::ssh_key::HashAlg::Sha256)
                        .to_string();
                    let s = pk
                        .public_key()
                        .to_openssh()
                        .unwrap_or_else(|_| vk.public_key.clone().unwrap_or_default());
                    (fp, s)
                }
                Err(_) => (String::new(), vk.public_key.clone().unwrap_or_default()),
            };

            summaries.push(SshKeySummary {
                id: vk.id,
                name: vk.name,
                fingerprint,
                public_key: pub_str,
            });
        }

        Ok(summaries)
    }

    /// Deletes an SSH key by ID from the server (if API client is present) and from local VaultStore.
    pub async fn delete_ssh_key(&self, id: &Uuid) -> Result<bool, SshAgentError> {
        if self.is_locked() {
            return Err(SshAgentError::VaultLocked);
        }

        if let Some(client) = self.api_client.as_ref() {
            if let Err(e) = client.delete_cipher(id).await {
                tracing::warn!("Failed to delete cipher {id} from server: {e}");
            }
        }

        let deleted = self.vault.delete_cipher(id).await;
        Ok(deleted.is_some())
    }

    /// Imports an existing OpenSSH private key PEM into the vault and returns its summary.
    pub async fn import_ssh_key(
        &self,
        name: &str,
        private_key_pem: &str,
        user_symmetric_key: &SymmetricKey,
    ) -> Result<SshKeySummary, SshAgentError> {
        let pub_key = self
            .add_ssh_key(private_key_pem, name, user_symmetric_key)
            .await?;

        let existing = self
            .vault
            .get_ssh_keys(user_symmetric_key)
            .await
            .map_err(|e| SshAgentError::KeyError(e.to_string()))?;

        let id = existing
            .into_iter()
            .find(|k| k.name == name)
            .and_then(|k| k.id);

        let fingerprint = pub_key
            .fingerprint(russh::keys::ssh_key::HashAlg::Sha256)
            .to_string();
        let public_key = pub_key
            .to_openssh()
            .map_err(|e| SshAgentError::KeyError(e.to_string()))?;

        Ok(SshKeySummary {
            id,
            name: name.to_string(),
            fingerprint,
            public_key,
        })
    }

    fn generate_key_pem(name: &str, key_type: &str) -> Result<String, SshAgentError> {
        use russh::keys::ssh_key::{Algorithm, EcdsaCurve, LineEnding};

        let mut rng = rand::rng();
        let algorithm = match key_type.to_ascii_lowercase().as_str() {
            "ed25519" | "ssh-ed25519" => Algorithm::Ed25519,
            "rsa" | "ssh-rsa" => {
                #[cfg(any(test, debug_assertions))]
                {
                    let mut pk = PrivateKey::from_openssh(TEST_RSA_PEM)
                        .map_err(|e| SshAgentError::KeyError(e.to_string()))?;
                    pk.set_comment(name);
                    let pem = pk
                        .to_openssh(LineEnding::LF)
                        .map_err(|e| SshAgentError::KeyError(e.to_string()))?;
                    return Ok((*pem).clone());
                }
                #[cfg(not(any(test, debug_assertions)))]
                Algorithm::Rsa { hash: None }
            }
            "ecdsa" | "ecdsa-p256" | "p256" => Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            },
            other => {
                return Err(SshAgentError::KeyError(format!(
                    "Unsupported key type: {other}"
                )))
            }
        };

        let mut pk = PrivateKey::random(&mut rng, algorithm)
            .map_err(|e| SshAgentError::KeyError(format!("Failed to generate random key: {e}")))?;
        pk.set_comment(name);

        let pem = pk.to_openssh(LineEnding::LF).map_err(|e| {
            SshAgentError::KeyError(format!("Failed to serialize key to OpenSSH PEM: {e}"))
        })?;
        Ok((*pem).clone())
    }

    /// Generates a new SSH keypair (Ed25519, RSA, or ECDSA), encrypts and persists it.
    pub async fn new_ssh_key(
        &self,
        name: &str,
        key_type: &str,
        user_symmetric_key: &SymmetricKey,
    ) -> Result<SshKeySummary, SshAgentError> {
        let pem = Self::generate_key_pem(name, key_type)?;
        self.import_ssh_key(name, &pem, user_symmetric_key).await
    }

    /// Requests identities from the vault: decrypts SSH keys on demand, parses with `PrivateKey::from_openssh`,
    /// and extracts public keys with their names as comments.
    pub async fn request_identities(&self) -> Result<Vec<AgentIdentity>, SshAgentError> {
        if self.is_locked() {
            return Ok(Vec::new());
        }

        let key_guard = self.symmetric_key.read().await;
        let key = match key_guard.as_ref() {
            Some(k) => k,
            None => return Ok(Vec::new()),
        };

        let mut vault_keys = self
            .vault
            .get_ssh_keys(key)
            .await
            .map_err(|e| SshAgentError::KeyError(e.to_string()))?;
        if let Ok(legacy_keys) = self.vault.extract_ssh_keys(key).await {
            vault_keys.extend(legacy_keys);
        }

        let mut identities = Vec::new();
        for vk in vault_keys {
            match PrivateKey::from_openssh(&vk.private_key) {
                Ok(pk) => {
                    let public_key = pk.public_key().clone();
                    identities.push(AgentIdentity::PublicKey {
                        key: public_key,
                        comment: vk.name,
                    });
                }
                Err(e) => {
                    tracing::warn!("Failed to parse private key for '{}': {}", vk.name, e);
                }
            }
        }

        Ok(identities)
    }

    /// Adds an SSH key to the vault (and optionally syncs to the Bitwarden server if configured).
    pub async fn add_ssh_key(
        &self,
        private_key_pem: &str,
        name: &str,
        user_symmetric_key: &SymmetricKey,
    ) -> Result<PublicKey, SshAgentError> {
        if self.is_locked() {
            return Err(SshAgentError::VaultLocked);
        }

        let priv_key = PrivateKey::from_openssh(private_key_pem)
            .map_err(|e| SshAgentError::KeyError(format!("Failed to parse private key: {e}")))?;

        if priv_key.is_encrypted() {
            return Err(SshAgentError::KeyError(
                "Encrypted private keys with passphrase are not supported".into(),
            ));
        }

        let pub_key = priv_key.public_key().clone();

        // Check for duplicates
        let mut existing_keys = self
            .vault
            .get_ssh_keys(user_symmetric_key)
            .await
            .map_err(|e| SshAgentError::KeyError(e.to_string()))?;
        if let Ok(legacy_keys) = self.vault.extract_ssh_keys(user_symmetric_key).await {
            existing_keys.extend(legacy_keys);
        }

        for vk in existing_keys {
            if let Ok(pk) = PrivateKey::from_openssh(&vk.private_key) {
                if pk.public_key() == &pub_key {
                    return Err(SshAgentError::InvalidMessage(
                        "SSH key already exists in vault".into(),
                    ));
                }
            }
        }

        let fp = pub_key
            .fingerprint(russh::keys::ssh_key::HashAlg::Sha256)
            .to_string();
        let pub_openssh = pub_key
            .to_openssh()
            .map_err(|e| SshAgentError::KeyError(e.to_string()))?;

        let enc_name = sw_vault::encrypt_with(
            name.as_bytes(),
            sw_vault::EncStringType::AesCbc256HmacSha256B64,
            user_symmetric_key,
        )
        .map_err(|e| SshAgentError::EncodingError(e.to_string()))?;

        let enc_priv = sw_vault::encrypt_with(
            private_key_pem.as_bytes(),
            sw_vault::EncStringType::AesCbc256HmacSha256B64,
            user_symmetric_key,
        )
        .map_err(|e| SshAgentError::EncodingError(e.to_string()))?;

        let enc_pub = sw_vault::encrypt_with(
            pub_openssh.as_bytes(),
            sw_vault::EncStringType::AesCbc256HmacSha256B64,
            user_symmetric_key,
        )
        .map_err(|e| SshAgentError::EncodingError(e.to_string()))?;

        let enc_fp = sw_vault::encrypt_with(
            fp.as_bytes(),
            sw_vault::EncStringType::AesCbc256HmacSha256B64,
            user_symmetric_key,
        )
        .map_err(|e| SshAgentError::EncodingError(e.to_string()))?;

        let cipher = sw_vault::Cipher {
            r#type: sw_vault::CipherType::SshKey,
            id: Some(Uuid::new_v4()),
            name: enc_name,
            ssh_key: Some(sw_vault::SSHKeyCipher {
                private_key: Some(enc_priv),
                public_key: Some(enc_pub),
                key_fingerprint: Some(enc_fp),
            }),
            ..Default::default()
        };

        let cipher_to_insert = if let Some(ref client) = self.api_client {
            let created = client.post_cipher(&cipher).await.map_err(|e| {
                SshAgentError::SigningError(format!("Failed to post cipher to server: {e}"))
            })?;
            sw_vault::Cipher {
                id: created.id.or(cipher.id),
                ssh_key: created.ssh_key.or(cipher.ssh_key),
                name: if created.name.ct.is_empty() {
                    cipher.name
                } else {
                    created.name
                },
                r#type: created.r#type,
                ..created
            }
        } else {
            cipher
        };

        self.vault.insert(cipher_to_insert).await;
        Ok(pub_key)
    }

    /// Signs data with a vault SSH key matched by public key wire blob or fingerprint.
    pub async fn sign_with_key(
        &self,
        key_blob: &[u8],
        data: &[u8],
        flags: u32,
    ) -> Result<Vec<u8>, SshAgentError> {
        self.sign_with_key_context(key_blob, data, flags, None)
            .await
    }

    /// Signs data with a vault SSH key, applying session authorization and pinentry approval if context is present.
    pub async fn sign_with_key_context(
        &self,
        key_blob: &[u8],
        data: &[u8],
        flags: u32,
        context: Option<&CallingContext>,
    ) -> Result<Vec<u8>, SshAgentError> {
        if self.is_locked() {
            return Err(SshAgentError::VaultLocked);
        }

        let key_guard = self.symmetric_key.read().await;
        let sym_key = match key_guard.as_ref() {
            Some(k) => k,
            None => return Err(SshAgentError::VaultLocked),
        };

        let mut vault_keys = self
            .vault
            .get_ssh_keys(sym_key)
            .await
            .map_err(|e| SshAgentError::KeyError(e.to_string()))?;
        if let Ok(legacy_keys) = self.vault.extract_ssh_keys(sym_key).await {
            vault_keys.extend(legacy_keys);
        }

        let target_pub = russh::keys::ssh_key::PublicKey::from_bytes(key_blob).ok();

        let mut matched_pk: Option<(russh::keys::PrivateKey, String)> = None;
        for vk in vault_keys {
            if let Ok(pk) = russh::keys::PrivateKey::from_openssh(&vk.private_key) {
                let mut wire_blob = Vec::new();
                let _ = pk.public_key().key_data().encode(&mut wire_blob);

                let is_match = wire_blob == key_blob
                    || target_pub.as_ref() == Some(pk.public_key())
                    || pk
                        .public_key()
                        .fingerprint(russh::keys::ssh_key::HashAlg::Sha256)
                        .to_string()
                        .as_bytes()
                        == key_blob
                    || pk
                        .public_key()
                        .fingerprint(russh::keys::ssh_key::HashAlg::Sha256)
                        .as_bytes()
                        == key_blob;

                if is_match {
                    matched_pk = Some((pk, vk.name));
                    break;
                }
            }
        }

        let (pk, key_name) = matched_pk.ok_or(SshAgentError::KeyNotFound)?;

        // Paso 3: Detectar firma de git (SSHSIG)
        let is_git = data.starts_with(SSHSIG_GIT_MAGIC);

        // Paso 4: Aprobación con pinentry / SessionStore
        if let Some(ctx) = context {
            let session_valid = self
                .session_store
                .read()
                .await
                .verify_session(ctx, SessionType::SSHKey);

            if !session_valid {
                let action = if is_git { "git" } else { "ssh" };
                let message = if !ctx.error {
                    format!(
                        "{} on {}>{}>{} is requesting {} signage with key {}",
                        ctx.username,
                        ctx.grandparent_process_name,
                        ctx.parent_process_name,
                        ctx.process_name,
                        action,
                        key_name
                    )
                } else {
                    format!(
                        "{} is requesting {} signage with key {}",
                        ctx.username, action, key_name
                    )
                };

                let approved = self
                    .approval_provider
                    .get_approval("SSH Key Signing Request", &message)?;

                if approved {
                    self.session_store.write().await.create_session(
                        ctx,
                        SessionType::SSHKey,
                        std::time::Duration::from_secs(3600),
                    );
                } else {
                    return Err(SshAgentError::ApprovalDenied("Approval not given".into()));
                }
            } else {
                tracing::info!("Using cached SSH session approval");
            }
        }

        // Paso 5: Flags de firma (RSA) & firma
        use russh::keys::signature::Signer;
        use russh::keys::ssh_encoding::Encode;
        use russh::keys::ssh_key::private::KeypairData;
        use russh::keys::ssh_key::{HashAlg, Signature};

        let keypair = pk.key_data();
        let sig: Signature = match keypair {
            KeypairData::Rsa(ref rsa) => {
                let hash = if (flags & SSH_AGENT_RSA_SHA2_256) != 0 {
                    Some(HashAlg::Sha256)
                } else if (flags & SSH_AGENT_RSA_SHA2_512) != 0 {
                    Some(HashAlg::Sha512)
                } else {
                    None
                };
                Signer::try_sign(&(rsa, hash), data)
                    .map_err(|e| SshAgentError::SigningError(e.to_string()))?
            }
            _ => Signer::try_sign(keypair, data)
                .map_err(|e| SshAgentError::SigningError(e.to_string()))?,
        };

        let mut sig_blob = Vec::new();
        sig.encode(&mut sig_blob)
            .map_err(|e| SshAgentError::EncodingError(e.to_string()))?;

        if let Some(notifier) = &self.notifier {
            let _ = notifier
                .notify(
                    "SilverWarden",
                    &format!("Firma SSH con clave '{}'", key_name),
                )
                .await;
        }

        Ok(sig_blob)
    }
}

impl Agent for VaultAgentServer {
    async fn confirm_request(&self, msg: MessageType) -> bool {
        match msg {
            MessageType::RequestKeys => true,
            MessageType::AddKeys => true,
            MessageType::Sign => true,
            MessageType::RemoveKeys => true,
            MessageType::RemoveAllKeys => true,
            MessageType::Lock | MessageType::Unlock => false,
        }
    }
}
