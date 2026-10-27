use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::RwLock;

use russh::keys::agent::server::{Agent, MessageType};
pub use russh::keys::agent::AgentIdentity;
pub use russh::keys::ssh_encoding::{Decode, Encode};
pub use russh::keys::{PrivateKey, PublicKey};
use sw_bitwarden_api::BitwardenApiClient;
use sw_crypto::SymmetricKey;
use sw_systemauth::{CallingContext, SessionStore, SessionType};
use sw_vault::{VaultSshKey, VaultStore};
use uuid::Uuid;

pub const SSH_AGENT_FAILURE: u8 = 5;
pub const SSH_AGENT_SUCCESS: u8 = 6;
pub const SSH2_AGENTC_REQUEST_IDENTITIES: u8 = 11;
pub const SSH2_AGENT_IDENTITIES_ANSWER: u8 = 12;
pub const SSH2_AGENTC_SIGN_REQUEST: u8 = 13;
pub const SSH2_AGENT_SIGN_RESPONSE: u8 = 14;
pub const SSH2_AGENTC_ADD_IDENTITY: u8 = 17;
pub const SSH2_AGENTC_REMOVE_IDENTITY: u8 = 18;
pub const SSH2_AGENTC_REMOVE_ALL_IDENTITIES: u8 = 19;
pub const SSH2_AGENTC_ADD_ID_CONSTRAINED: u8 = 25;
pub const MAX_AGENT_FRAME_LEN: usize = 256 * 1024;

pub const SSH_AGENT_RSA_SHA2_256: u32 = 2;
pub const SSH_AGENT_RSA_SHA2_512: u32 = 4;
pub const SSHSIG_GIT_MAGIC: &[u8] = b"SSHSIG\x00\x00\x00\x03git";

#[derive(Error, Debug)]
pub enum SshAgentError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid agent message: {0}")]
    InvalidMessage(String),

    #[error("Key parsing error: {0}")]
    KeyError(String),

    #[error("Key not found")]
    KeyNotFound,

    #[error("Vault is locked")]
    VaultLocked,

    #[error("Approval denied: {0}")]
    ApprovalDenied(String),

    #[error("Signing error: {0}")]
    SigningError(String),

    #[error("Encoding error: {0}")]
    EncodingError(String),

    #[error("Agent failure")]
    AgentFailure,
}

/// Public summary of an SSH key stored in the vault.
///
/// **Security Notice:** This struct intentionally never contains private key material.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct SshKeySummary {
    pub id: Option<Uuid>,
    pub name: String,
    pub fingerprint: String,
    pub public_key: String,
}

/// Trait abstracting approval requests (e.g., via pinentry, desktop prompt, or test mocks).
pub trait ApprovalProvider: Send + Sync {
    fn get_approval(&self, title: &str, description: &str) -> Result<bool, SshAgentError>;
}

/// Default approval provider using pinentry.
#[derive(Debug, Default, Clone)]
pub struct DefaultApprovalProvider {
    bypass: bool,
    #[cfg(test)]
    custom_bin: Option<PathBuf>,
}

impl DefaultApprovalProvider {
    pub fn new() -> Self {
        Self {
            bypass: false,
            #[cfg(test)]
            custom_bin: None,
        }
    }

    #[cfg(test)]
    pub fn with_bypass() -> Self {
        Self {
            bypass: true,
            custom_bin: None,
        }
    }

    #[cfg(test)]
    pub fn with_custom_bin(bin: PathBuf) -> Self {
        Self {
            bypass: false,
            custom_bin: Some(bin),
        }
    }
}

impl ApprovalProvider for DefaultApprovalProvider {
    fn get_approval(&self, title: &str, description: &str) -> Result<bool, SshAgentError> {
        if self.bypass {
            tracing::info!("Approval bypassed via test configuration; approving signature");
            return Ok(true);
        }

        #[cfg(test)]
        let pinentry_bin = self.custom_bin.clone().or_else(|| {
            [
                "pinentry",
                "pinentry-curses",
                "pinentry-gnome3",
                "pinentry-qt",
                "pinentry-mac",
            ]
            .iter()
            .find_map(|bin| which_bin(bin))
        });

        #[cfg(not(test))]
        let pinentry_bin = [
            "pinentry",
            "pinentry-curses",
            "pinentry-gnome3",
            "pinentry-qt",
            "pinentry-mac",
        ]
        .iter()
        .find_map(|bin| which_bin(bin));

        let bin = match pinentry_bin {
            Some(b) => b,
            None => {
                tracing::warn!("No pinentry binary found for approval dialog");
                return Err(SshAgentError::ApprovalDenied(
                    "No pinentry binary available".into(),
                ));
            }
        };

        run_pinentry_confirm(&bin, title, description)
    }
}

fn which_bin(name: &str) -> Option<PathBuf> {
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let full = dir.join(name);
            if full.is_file() {
                return Some(full);
            }
        }
    }
    None
}

fn run_pinentry_confirm(bin: &Path, title: &str, description: &str) -> Result<bool, SshAgentError> {
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Command, Stdio};

    let mut child = Command::new(bin)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| SshAgentError::ApprovalDenied(format!("Failed to spawn pinentry: {e}")))?;

    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| SshAgentError::ApprovalDenied("Failed to open pinentry stdin".into()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| SshAgentError::ApprovalDenied("Failed to open pinentry stdout".into()))?;
    let mut reader = BufReader::new(stdout);

    // Initial OK greeting from pinentry
    let mut greeting = String::new();
    let _ = reader.read_line(&mut greeting);

    let mut send_cmd = |cmd: &str| -> Result<String, SshAgentError> {
        stdin
            .write_all(cmd.as_bytes())
            .map_err(|e| SshAgentError::ApprovalDenied(e.to_string()))?;
        stdin
            .write_all(b"\n")
            .map_err(|e| SshAgentError::ApprovalDenied(e.to_string()))?;
        stdin
            .flush()
            .map_err(|e| SshAgentError::ApprovalDenied(e.to_string()))?;

        loop {
            let mut resp = String::new();
            let bytes_read = reader
                .read_line(&mut resp)
                .map_err(|e| SshAgentError::ApprovalDenied(e.to_string()))?;
            if bytes_read == 0 {
                return Err(SshAgentError::ApprovalDenied(
                    "Pinentry closed unexpectedly".into(),
                ));
            }
            if resp.starts_with("OK") || resp.starts_with("ERR") {
                return Ok(resp);
            }
        }
    };

    let _ = send_cmd(&format!("SETTITLE {}", title.replace(['\n', '\r'], " ")));
    let _ = send_cmd(&format!(
        "SETDESC {}",
        description.replace(['\n', '\r'], " ")
    ));
    let _ = send_cmd(&format!("SETPROMPT {}", title.replace(['\n', '\r'], " ")));
    let confirm_res = send_cmd("CONFIRM")?;
    let _ = send_cmd("BYE");
    let _ = child.wait();

    if confirm_res.starts_with("OK") {
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Mock approval provider for deterministic unit and integration tests.
#[derive(Debug, Default)]
pub struct MockApprovalProvider {
    approved: AtomicBool,
    call_count: std::sync::atomic::AtomicUsize,
    last_title: std::sync::RwLock<Option<String>>,
    last_description: std::sync::RwLock<Option<String>>,
}

impl MockApprovalProvider {
    pub fn new(approved: bool) -> Self {
        Self {
            approved: AtomicBool::new(approved),
            call_count: std::sync::atomic::AtomicUsize::new(0),
            last_title: std::sync::RwLock::new(None),
            last_description: std::sync::RwLock::new(None),
        }
    }

    pub fn set_approved(&self, approved: bool) {
        self.approved.store(approved, Ordering::SeqCst);
    }

    pub fn call_count(&self) -> usize {
        self.call_count.load(Ordering::SeqCst)
    }

    pub fn last_title(&self) -> Option<String> {
        self.last_title.read().unwrap().clone()
    }

    pub fn last_description(&self) -> Option<String> {
        self.last_description.read().unwrap().clone()
    }
}

impl ApprovalProvider for MockApprovalProvider {
    fn get_approval(&self, title: &str, description: &str) -> Result<bool, SshAgentError> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        *self.last_title.write().unwrap() = Some(title.to_string());
        *self.last_description.write().unwrap() = Some(description.to_string());
        Ok(self.approved.load(Ordering::SeqCst))
    }
}

/// Agent server integrating with SilverWarden Vault and implementing `russh::keys::agent::server::Agent`.
#[derive(Clone)]
pub struct VaultAgentServer {
    vault: Arc<VaultStore>,
    symmetric_key: Arc<RwLock<Option<SymmetricKey>>>,
    is_locked: Arc<AtomicBool>,
    session_store: Arc<RwLock<SessionStore>>,
    approval_provider: Arc<dyn ApprovalProvider>,
    api_client: Option<Arc<BitwardenApiClient>>,
}

impl std::fmt::Debug for VaultAgentServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultAgentServer")
            .field(
                "is_locked",
                &self.is_locked.load(std::sync::atomic::Ordering::Relaxed),
            )
            .field("has_api_client", &self.api_client.is_some())
            .finish()
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

        let vault_keys = self
            .vault
            .get_ssh_keys(key)
            .await
            .map_err(|e| SshAgentError::KeyError(e.to_string()))?;

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
            "rsa" | "ssh-rsa" => Algorithm::Rsa { hash: None },
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

        let vault_keys = self
            .vault
            .get_ssh_keys(key)
            .await
            .map_err(|e| SshAgentError::KeyError(e.to_string()))?;

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
        let priv_key = PrivateKey::from_openssh(private_key_pem)
            .map_err(|e| SshAgentError::KeyError(format!("Failed to parse private key: {e}")))?;

        let pub_key = priv_key.public_key().clone();

        // Check for duplicates
        let existing_keys = self
            .vault
            .get_ssh_keys(user_symmetric_key)
            .await
            .map_err(|e| SshAgentError::KeyError(e.to_string()))?;

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

        let vault_keys = self
            .vault
            .get_ssh_keys(sym_key)
            .await
            .map_err(|e| SshAgentError::KeyError(e.to_string()))?;

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

/// High-level SSH agent server manager binding a socket path to a `VaultAgentServer`.
pub struct SshAgentServer {
    socket_path: PathBuf,
    agent: VaultAgentServer,
}

impl SshAgentServer {
    pub fn new(socket_path: impl Into<PathBuf>, agent: VaultAgentServer) -> Self {
        Self {
            socket_path: socket_path.into(),
            agent,
        }
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub fn agent(&self) -> &VaultAgentServer {
        &self.agent
    }

    pub async fn serve(&self) -> Result<(), SshAgentError> {
        serve(&self.socket_path, self.agent.clone()).await
    }

    pub async fn serve_with_shutdown(
        &self,
        shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    ) -> Result<(), SshAgentError> {
        serve_with_shutdown(&self.socket_path, self.agent.clone(), shutdown_rx).await
    }
}

/// Cleans orphan socket if exists, binds `UnixListener` with permissions 0600,
/// and serves SSH agent connections.
pub async fn serve<P: AsRef<Path>>(path: P, agent: VaultAgentServer) -> Result<(), SshAgentError> {
    let (_tx, rx) = tokio::sync::broadcast::channel(1);
    serve_with_shutdown(path, agent, rx).await
}

/// Serves SSH agent connections on the specified socket path with a shutdown broadcast receiver.
pub async fn serve_with_shutdown<P: AsRef<Path>>(
    path: P,
    agent: VaultAgentServer,
    mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
) -> Result<(), SshAgentError> {
    let path = path.as_ref();
    if path.exists() {
        let _ = std::fs::remove_file(path);
    }

    let listener = UnixListener::bind(path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        let _ = std::fs::set_permissions(path, perms);
    }

    loop {
        tokio::select! {
            accept_res = listener.accept() => {
                match accept_res {
                    Ok((stream, _)) => {
                        let agent_clone = agent.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(stream, agent_clone).await {
                                tracing::debug!("SSH agent client connection finished: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        tracing::error!("Error accepting SSH agent connection: {}", e);
                    }
                }
            }
            _ = shutdown_rx.recv() => {
                tracing::info!("SSH agent server received shutdown signal");
                break;
            }
        }
    }

    if path.exists() {
        let _ = std::fs::remove_file(path);
    }

    Ok(())
}

/// Handles a single SSH agent client connection according to the SSH Agent protocol.
pub async fn handle_connection(
    mut stream: UnixStream,
    agent: VaultAgentServer,
) -> Result<(), SshAgentError> {
    let ctx = sw_systemauth::get_calling_context(&stream);
    let mut len_buf = [0u8; 4];

    loop {
        match stream.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                break;
            }
            Err(e) => return Err(SshAgentError::Io(e)),
        }

        let len = u32::from_be_bytes(len_buf) as usize;
        if len > MAX_AGENT_FRAME_LEN || len == 0 {
            return Err(SshAgentError::InvalidMessage(format!(
                "Invalid frame length: {}",
                len
            )));
        }

        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await?;

        let msg_type = buf[0];
        match msg_type {
            SSH2_AGENTC_REQUEST_IDENTITIES => {
                let allowed =
                    agent.confirm_request(MessageType::RequestKeys).await && !agent.is_locked();
                let identities = if allowed {
                    agent.request_identities().await?
                } else {
                    Vec::new()
                };

                let mut resp_body = Vec::new();
                resp_body.push(SSH2_AGENT_IDENTITIES_ANSWER);
                (identities.len() as u32)
                    .encode(&mut resp_body)
                    .map_err(|e| SshAgentError::EncodingError(e.to_string()))?;

                for identity in &identities {
                    match identity {
                        AgentIdentity::PublicKey { key, comment } => {
                            let mut key_blob = Vec::new();
                            key.key_data()
                                .encode(&mut key_blob)
                                .map_err(|e| SshAgentError::EncodingError(e.to_string()))?;
                            key_blob
                                .encode(&mut resp_body)
                                .map_err(|e| SshAgentError::EncodingError(e.to_string()))?;
                            comment
                                .encode(&mut resp_body)
                                .map_err(|e| SshAgentError::EncodingError(e.to_string()))?;
                        }
                        AgentIdentity::Certificate {
                            certificate,
                            comment,
                        } => {
                            let mut cert_blob = Vec::new();
                            certificate
                                .encode(&mut cert_blob)
                                .map_err(|e| SshAgentError::EncodingError(e.to_string()))?;
                            cert_blob
                                .encode(&mut resp_body)
                                .map_err(|e| SshAgentError::EncodingError(e.to_string()))?;
                            comment
                                .encode(&mut resp_body)
                                .map_err(|e| SshAgentError::EncodingError(e.to_string()))?;
                        }
                    }
                }

                send_frame(&mut stream, &resp_body).await?;
            }
            SSH2_AGENTC_SIGN_REQUEST => {
                let allowed = agent.confirm_request(MessageType::Sign).await && !agent.is_locked();
                if !allowed {
                    send_failure(&mut stream).await?;
                    continue;
                }

                // Parse: [u32 key_blob_len][key_blob][u32 data_len][data][u32 flags]
                let mut offset = 1;
                if offset + 4 > buf.len() {
                    send_failure(&mut stream).await?;
                    continue;
                }
                let key_len =
                    u32::from_be_bytes(buf[offset..offset + 4].try_into().unwrap()) as usize;
                offset += 4;
                if offset + key_len > buf.len() {
                    send_failure(&mut stream).await?;
                    continue;
                }
                let key_blob = &buf[offset..offset + key_len];
                offset += key_len;

                if offset + 4 > buf.len() {
                    send_failure(&mut stream).await?;
                    continue;
                }
                let data_len =
                    u32::from_be_bytes(buf[offset..offset + 4].try_into().unwrap()) as usize;
                offset += 4;
                if offset + data_len > buf.len() {
                    send_failure(&mut stream).await?;
                    continue;
                }
                let data = &buf[offset..offset + data_len];
                offset += data_len;

                if offset + 4 > buf.len() {
                    send_failure(&mut stream).await?;
                    continue;
                }
                let flags = u32::from_be_bytes(buf[offset..offset + 4].try_into().unwrap());

                match agent
                    .sign_with_key_context(key_blob, data, flags, Some(&ctx))
                    .await
                {
                    Ok(sig_blob) => {
                        let mut resp_body = Vec::new();
                        resp_body.push(SSH2_AGENT_SIGN_RESPONSE);
                        (sig_blob.len() as u32)
                            .encode(&mut resp_body)
                            .map_err(|e| SshAgentError::EncodingError(e.to_string()))?;
                        resp_body.extend_from_slice(&sig_blob);
                        send_frame(&mut stream, &resp_body).await?;
                    }
                    Err(e) => {
                        tracing::warn!("Sign request rejected or failed: {}", e);
                        send_failure(&mut stream).await?;
                    }
                }
            }
            SSH2_AGENTC_ADD_IDENTITY | SSH2_AGENTC_ADD_ID_CONSTRAINED => {
                if agent.is_locked() {
                    send_failure(&mut stream).await?;
                    continue;
                }

                let sym_key_guard = agent.symmetric_key.read().await;
                let sym_key = match sym_key_guard.as_ref() {
                    Some(k) => k,
                    None => {
                        send_failure(&mut stream).await?;
                        continue;
                    }
                };

                if buf.len() < 2 {
                    send_failure(&mut stream).await?;
                    continue;
                }

                let mut slice = &buf[1..];
                let pk = match russh::keys::ssh_key::private::KeypairData::decode(&mut slice) {
                    Ok(keypair_data) => {
                        let comment = String::decode(&mut slice).unwrap_or_default();
                        match PrivateKey::new(keypair_data, comment) {
                            Ok(pk) => pk,
                            Err(e) => {
                                tracing::warn!("Failed to construct PrivateKey: {e}");
                                send_failure(&mut stream).await?;
                                continue;
                            }
                        }
                    }
                    Err(_) => {
                        let mut fallback_slice = &buf[1..];
                        match PrivateKey::decode(&mut fallback_slice) {
                            Ok(k) => {
                                slice = fallback_slice;
                                k
                            }
                            Err(e) => {
                                tracing::warn!("Failed to decode key from ADD_IDENTITY: {e}");
                                send_failure(&mut stream).await?;
                                continue;
                            }
                        }
                    }
                };

                if msg_type == SSH2_AGENTC_ADD_ID_CONSTRAINED {
                    while !slice.is_empty() {
                        let constraint_type = slice[0];
                        slice = &slice[1..];
                        match constraint_type {
                            1 => {
                                if slice.len() >= 4 {
                                    let _secs = u32::from_be_bytes([
                                        slice[0], slice[1], slice[2], slice[3],
                                    ]);
                                    slice = &slice[4..];
                                }
                            }
                            2 => {}
                            _ => break,
                        }
                    }
                }

                let comment_str = pk.comment().as_str().unwrap_or("unnamed");
                let key_comment = if comment_str.trim().is_empty() {
                    "unnamed".to_string()
                } else {
                    comment_str.to_string()
                };

                let message = if !ctx.error {
                    format!(
                        "{} on {}>{}>{} is adding key {}",
                        ctx.username,
                        ctx.grandparent_process_name,
                        ctx.parent_process_name,
                        ctx.process_name,
                        key_comment
                    )
                } else {
                    format!("{} is adding key {}", ctx.username, key_comment)
                };

                let approved = match agent
                    .approval_provider()
                    .get_approval("SSH Key Addition Request", &message)
                {
                    Ok(app) => app,
                    Err(e) => {
                        tracing::warn!("Approval request error: {e}");
                        false
                    }
                };

                if !approved {
                    tracing::warn!(
                        "Addition of key '{}' denied by approval provider",
                        key_comment
                    );
                    send_failure(&mut stream).await?;
                    continue;
                }

                let pem = match pk.to_openssh(russh::keys::ssh_key::LineEnding::LF) {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::warn!("Failed to convert added key to OpenSSH PEM: {e}");
                        send_failure(&mut stream).await?;
                        continue;
                    }
                };

                match agent.add_ssh_key(&pem, &key_comment, sym_key).await {
                    Ok(_) => {
                        send_success(&mut stream).await?;
                    }
                    Err(e) => {
                        tracing::warn!("Failed to add SSH key to vault: {e}");
                        send_failure(&mut stream).await?;
                    }
                }
            }
            SSH2_AGENTC_REMOVE_IDENTITY => {
                if agent.is_locked() {
                    send_failure(&mut stream).await?;
                    continue;
                }

                let sym_key_guard = agent.symmetric_key.read().await;
                let sym_key = match sym_key_guard.as_ref() {
                    Some(k) => k,
                    None => {
                        send_failure(&mut stream).await?;
                        continue;
                    }
                };

                if buf.len() < 5 {
                    send_failure(&mut stream).await?;
                    continue;
                }

                let key_blob_len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
                if buf.len() < 5 + key_blob_len {
                    send_failure(&mut stream).await?;
                    continue;
                }
                let key_blob = &buf[5..5 + key_blob_len];

                let vault_keys = match agent.vault.get_ssh_keys(sym_key).await {
                    Ok(k) => k,
                    Err(e) => {
                        tracing::warn!("Failed to retrieve vault keys for removal: {e}");
                        send_failure(&mut stream).await?;
                        continue;
                    }
                };

                let target_pub = russh::keys::ssh_key::PublicKey::from_bytes(key_blob).ok();
                let mut matched_key: Option<VaultSshKey> = None;

                for vk in vault_keys {
                    if let Ok(pk) = PrivateKey::from_openssh(&vk.private_key) {
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
                            matched_key = Some(vk);
                            break;
                        }
                    }
                }

                let vk = match matched_key {
                    Some(k) => k,
                    None => {
                        tracing::warn!("Key to remove not found in vault");
                        send_failure(&mut stream).await?;
                        continue;
                    }
                };

                let message = if !ctx.error {
                    format!(
                        "{} on {}>{}>{} is removing key {}",
                        ctx.username,
                        ctx.grandparent_process_name,
                        ctx.parent_process_name,
                        ctx.process_name,
                        vk.name
                    )
                } else {
                    format!("{} is removing key {}", ctx.username, vk.name)
                };

                let approved = match agent
                    .approval_provider()
                    .get_approval("SSH Key Removal Request", &message)
                {
                    Ok(app) => app,
                    Err(e) => {
                        tracing::warn!("Approval error on remove key: {e}");
                        false
                    }
                };

                if !approved {
                    tracing::warn!("Removal of key '{}' denied by approval provider", vk.name);
                    send_failure(&mut stream).await?;
                    continue;
                }

                if let Some(id) = vk.id {
                    if let Some(client) = agent.api_client.as_ref() {
                        if let Err(e) = client.delete_cipher(&id).await {
                            tracing::warn!("Failed to delete cipher {id} from server: {e}");
                        }
                    }
                    agent.vault.delete_cipher(&id).await;
                }

                send_success(&mut stream).await?;
            }
            SSH2_AGENTC_REMOVE_ALL_IDENTITIES => {
                if agent.is_locked() {
                    send_failure(&mut stream).await?;
                    continue;
                }

                let sym_key_guard = agent.symmetric_key.read().await;
                let sym_key = match sym_key_guard.as_ref() {
                    Some(k) => k,
                    None => {
                        send_failure(&mut stream).await?;
                        continue;
                    }
                };

                let vault_keys = match agent.vault.get_ssh_keys(sym_key).await {
                    Ok(k) => k,
                    Err(e) => {
                        tracing::warn!("Failed to retrieve vault keys for remove all: {e}");
                        send_failure(&mut stream).await?;
                        continue;
                    }
                };

                let message = if !ctx.error {
                    format!(
                        "{} on {}>{}>{} is removing all SSH keys",
                        ctx.username,
                        ctx.grandparent_process_name,
                        ctx.parent_process_name,
                        ctx.process_name,
                    )
                } else {
                    format!("{} is removing all SSH keys", ctx.username)
                };

                let approved = match agent
                    .approval_provider()
                    .get_approval("SSH Key Removal Request", &message)
                {
                    Ok(app) => app,
                    Err(e) => {
                        tracing::warn!("Approval error on remove all keys: {e}");
                        false
                    }
                };

                if !approved {
                    tracing::warn!("Removal of all keys denied by approval provider");
                    send_failure(&mut stream).await?;
                    continue;
                }

                for vk in vault_keys {
                    if let Some(id) = vk.id {
                        if let Some(client) = agent.api_client.as_ref() {
                            if let Err(e) = client.delete_cipher(&id).await {
                                tracing::warn!("Failed to delete cipher {id} from server: {e}");
                            }
                        }
                        agent.vault.delete_cipher(&id).await;
                    }
                }

                send_success(&mut stream).await?;
            }
            _ => {
                send_failure(&mut stream).await?;
            }
        }
    }

    Ok(())
}

async fn send_frame(stream: &mut UnixStream, payload: &[u8]) -> Result<(), SshAgentError> {
    let len_bytes = (payload.len() as u32).to_be_bytes();
    stream.write_all(&len_bytes).await?;
    stream.write_all(payload).await?;
    stream.flush().await?;
    Ok(())
}

async fn send_failure(stream: &mut UnixStream) -> Result<(), SshAgentError> {
    send_frame(stream, &[SSH_AGENT_FAILURE]).await
}

async fn send_success(stream: &mut UnixStream) -> Result<(), SshAgentError> {
    send_frame(stream, &[SSH_AGENT_SUCCESS]).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh::keys::agent::client::AgentClient;
    use std::time::Duration;
    use sw_crypto::{encrypt_with, EncStringType};
    use sw_vault::{Cipher, CipherType, Field, FieldType, SSHKeyCipher};
    use tempfile::TempDir;
    use uuid::Uuid;

    fn make_test_key() -> SymmetricKey {
        SymmetricKey::from_bytes(&[0x42u8; 64]).unwrap()
    }

    fn generate_test_ed25519(seed_byte: u8, comment: &str) -> (String, String) {
        let keypair = russh::keys::ssh_key::private::KeypairData::Ed25519(
            russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&[seed_byte; 32]),
        );
        let pk = russh::keys::PrivateKey::new(keypair, comment).unwrap();
        let pem = pk
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .unwrap()
            .to_string();
        let pub_openssh = pk.public_key().to_openssh().unwrap();
        (pem, pub_openssh)
    }

    async fn setup_test_vault_with_keys(
        key: &SymmetricKey,
    ) -> (Arc<VaultStore>, (String, String), (String, String)) {
        let store = Arc::new(VaultStore::new());

        // Key 1: SshKey cipher
        let (priv_1, pub_1) = generate_test_ed25519(1, "work-laptop");
        let enc_name_1 =
            encrypt_with(b"work-laptop", EncStringType::AesCbc256HmacSha256B64, key).unwrap();
        let enc_priv_1 = encrypt_with(
            priv_1.as_bytes(),
            EncStringType::AesCbc256HmacSha256B64,
            key,
        )
        .unwrap();
        let enc_pub_1 =
            encrypt_with(pub_1.as_bytes(), EncStringType::AesCbc256HmacSha256B64, key).unwrap();

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

        // Key 2: Note-based SSH key
        let (priv_2, pub_2) = generate_test_ed25519(2, "personal-server");
        let enc_name_2 = encrypt_with(
            b"personal-server",
            EncStringType::AesCbc256HmacSha256B64,
            key,
        )
        .unwrap();
        let enc_fn_custom =
            encrypt_with(b"custom-type", EncStringType::AesCbc256HmacSha256B64, key).unwrap();
        let enc_fv_custom =
            encrypt_with(b"ssh-key", EncStringType::AesCbc256HmacSha256B64, key).unwrap();
        let enc_fn_priv =
            encrypt_with(b"private-key", EncStringType::AesCbc256HmacSha256B64, key).unwrap();
        let enc_fv_priv = encrypt_with(
            priv_2.as_bytes(),
            EncStringType::AesCbc256HmacSha256B64,
            key,
        )
        .unwrap();
        let enc_fn_pub =
            encrypt_with(b"public-key", EncStringType::AesCbc256HmacSha256B64, key).unwrap();
        let enc_fv_pub =
            encrypt_with(pub_2.as_bytes(), EncStringType::AesCbc256HmacSha256B64, key).unwrap();

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

        store.insert(cipher_ssh).await;
        store.insert(cipher_note).await;

        (store, (priv_1, pub_1), (priv_2, pub_2))
    }

    async fn wait_for_socket(path: &Path) {
        for _ in 0..50 {
            if path.exists() && tokio::net::UnixStream::connect(path).await.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("Socket was not created in time: {:?}", path);
    }

    #[tokio::test]
    async fn test_serve_and_connect() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("agent_serve_connect.sock");

        let vault = Arc::new(VaultStore::new());
        let agent = VaultAgentServer::new(vault);

        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
        let s_path = socket_path.clone();
        let a = agent.clone();
        let server_handle =
            tokio::spawn(async move { serve_with_shutdown(s_path, a, shutdown_rx).await });

        wait_for_socket(&socket_path).await;

        let mut client = AgentClient::connect_uds(&socket_path).await.unwrap();
        let identities = client.request_identities().await.unwrap();
        assert!(identities.is_empty());

        let _ = shutdown_tx.send(());
        let res = server_handle.await.unwrap();
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_list_empty_vault() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("agent_empty.sock");

        let key = make_test_key();
        let vault = Arc::new(VaultStore::new());
        let agent = VaultAgentServer::with_key(vault, key);

        let identities = agent.request_identities().await.unwrap();
        assert!(identities.is_empty());

        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
        let s_path = socket_path.clone();
        let a = agent.clone();
        let server_handle =
            tokio::spawn(async move { serve_with_shutdown(s_path, a, shutdown_rx).await });

        wait_for_socket(&socket_path).await;

        let mut client = AgentClient::connect_uds(&socket_path).await.unwrap();
        let client_identities = client.request_identities().await.unwrap();
        assert!(client_identities.is_empty());

        let _ = shutdown_tx.send(());
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn test_list_with_keys() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("agent_with_keys.sock");

        let key = make_test_key();
        let (vault, (_, pub_1), (_, pub_2)) = setup_test_vault_with_keys(&key).await;
        let agent = VaultAgentServer::with_key(vault, key);

        // Direct call
        let direct_identities = agent.request_identities().await.unwrap();
        assert_eq!(direct_identities.len(), 2);

        // Over socket with AgentClient
        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
        let s_path = socket_path.clone();
        let a = agent.clone();
        let server_handle =
            tokio::spawn(async move { serve_with_shutdown(s_path, a, shutdown_rx).await });

        wait_for_socket(&socket_path).await;

        let mut client = AgentClient::connect_uds(&socket_path).await.unwrap();
        let identities = client.request_identities().await.unwrap();
        assert_eq!(identities.len(), 2);

        let mut comments: Vec<String> = identities
            .iter()
            .map(|id| match id {
                AgentIdentity::PublicKey { comment, .. } => comment.clone(),
                AgentIdentity::Certificate { comment, .. } => comment.clone(),
            })
            .collect();
        comments.sort();
        assert_eq!(comments, vec!["personal-server", "work-laptop"]);

        // Verify public key string matches
        let full_keys: Vec<String> = identities
            .iter()
            .map(|id| match id {
                AgentIdentity::PublicKey { key, comment } => {
                    format!("{} {}", key.to_openssh().unwrap(), comment)
                }
                AgentIdentity::Certificate { .. } => String::new(),
            })
            .collect();

        assert!(full_keys.iter().any(|s| s == &pub_1));
        assert!(full_keys.iter().any(|s| s == &pub_2));

        let _ = shutdown_tx.send(());
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn test_ssh_add_l() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("ssh_add_l.sock");

        let key = make_test_key();
        let (vault, (_, pub_1), (_, pub_2)) = setup_test_vault_with_keys(&key).await;
        let agent = VaultAgentServer::with_key(vault, key);

        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
        let s_path = socket_path.clone();
        let a = agent.clone();
        let server_handle =
            tokio::spawn(async move { serve_with_shutdown(s_path, a, shutdown_rx).await });

        wait_for_socket(&socket_path).await;

        // Run ssh-add -L
        let output = tokio::process::Command::new("ssh-add")
            .arg("-L")
            .env("SSH_AUTH_SOCK", &socket_path)
            .output()
            .await
            .expect("Failed to execute ssh-add");

        assert!(
            output.status.success(),
            "ssh-add -L failed: stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.contains("work-laptop"));
        assert!(stdout.contains("personal-server"));
        assert!(stdout.contains(&pub_1));
        assert!(stdout.contains(&pub_2));

        let _ = shutdown_tx.send(());
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn test_ssh_add_l_empty_vault() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("ssh_add_empty.sock");

        let key = make_test_key();
        let vault = Arc::new(VaultStore::new());
        let agent = VaultAgentServer::with_key(vault, key);

        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
        let s_path = socket_path.clone();
        let a = agent.clone();
        let server_handle =
            tokio::spawn(async move { serve_with_shutdown(s_path, a, shutdown_rx).await });

        wait_for_socket(&socket_path).await;

        // When empty, ssh-add -L outputs "The agent has no identities." and exits with code 1
        let output = tokio::process::Command::new("ssh-add")
            .arg("-L")
            .env("SSH_AUTH_SOCK", &socket_path)
            .output()
            .await
            .expect("Failed to execute ssh-add");

        assert_eq!(output.status.code(), Some(1));
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stderr.contains("The agent has no identities.")
                || stdout.contains("The agent has no identities.")
        );

        let _ = shutdown_tx.send(());
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn test_vault_agent_server_lifecycle() {
        let vault = Arc::new(VaultStore::new());
        let agent = VaultAgentServer::new(vault.clone());

        assert!(agent.is_locked());
        assert_eq!(agent.vault().len().await, 0);

        let key = make_test_key();
        agent.unlock(key).await;
        assert!(!agent.is_locked());

        agent.lock().await;
        assert!(agent.is_locked());
        let ids = agent.request_identities().await.unwrap();
        assert!(ids.is_empty());
    }

    #[tokio::test]
    async fn test_confirm_request() {
        let vault = Arc::new(VaultStore::new());
        let agent = VaultAgentServer::new(vault);

        assert!(agent.confirm_request(MessageType::RequestKeys).await);
        assert!(agent.confirm_request(MessageType::AddKeys).await);
        assert!(agent.confirm_request(MessageType::Sign).await);
        assert!(agent.confirm_request(MessageType::RemoveKeys).await);
        assert!(agent.confirm_request(MessageType::RemoveAllKeys).await);
        assert!(!agent.confirm_request(MessageType::Lock).await);
        assert!(!agent.confirm_request(MessageType::Unlock).await);
    }

    #[tokio::test]
    async fn test_ssh_agent_server_struct() {
        let temp_dir = TempDir::new().unwrap();
        let sock_path = temp_dir.path().join("server_struct.sock");

        let vault = Arc::new(VaultStore::new());
        let agent = VaultAgentServer::new(vault);
        let server = SshAgentServer::new(&sock_path, agent.clone());

        assert_eq!(server.socket_path(), sock_path.as_path());
        assert!(server.agent().is_locked());

        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
        let s_handle = tokio::spawn(async move { server.serve_with_shutdown(shutdown_rx).await });

        wait_for_socket(&sock_path).await;
        let _ = shutdown_tx.send(());
        let res = s_handle.await.unwrap();
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_add_requires_approval() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("agent_add_keys.sock");

        let key = make_test_key();
        let vault = Arc::new(VaultStore::new());
        let mock_approval = Arc::new(MockApprovalProvider::new(false));
        let agent =
            VaultAgentServer::with_key(vault, key).with_approval_provider(mock_approval.clone());

        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
        let s_path = socket_path.clone();
        let a = agent.clone();
        let server_handle =
            tokio::spawn(async move { serve_with_shutdown(s_path, a, shutdown_rx).await });

        wait_for_socket(&socket_path).await;

        let mut client = AgentClient::connect_uds(&socket_path).await.unwrap();

        let keypair = russh::keys::ssh_key::private::KeypairData::Ed25519(
            russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&[5u8; 32]),
        );
        let pk = russh::keys::PrivateKey::new(keypair, "test_add").unwrap();

        // Adding key fails when approval is denied
        let add_res = client.add_identity(&pk, &[]).await;
        assert!(add_res.is_err());
        assert_eq!(mock_approval.call_count(), 1);
        let desc = mock_approval.last_description().unwrap();
        assert!(desc.contains("is adding key"));

        let _ = shutdown_tx.send(());
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn test_handle_connection_raw_stream_edge_cases() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("agent_raw_edge.sock");

        let vault = Arc::new(VaultStore::new());
        let agent = VaultAgentServer::new(vault);

        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
        let s_path = socket_path.clone();
        let a = agent.clone();
        let server_handle =
            tokio::spawn(async move { serve_with_shutdown(s_path, a, shutdown_rx).await });

        wait_for_socket(&socket_path).await;

        // 1. Send unknown message type (e.g., 99)
        let mut stream = UnixStream::connect(&socket_path).await.unwrap();
        let mut req = Vec::new();
        1u32.encode(&mut req).unwrap();
        req.push(99);
        stream.write_all(&req).await.unwrap();
        stream.flush().await.unwrap();

        let mut resp_len = [0u8; 4];
        stream.read_exact(&mut resp_len).await.unwrap();
        assert_eq!(u32::from_be_bytes(resp_len), 1);
        let mut resp_code = [0u8; 1];
        stream.read_exact(&mut resp_code).await.unwrap();
        assert_eq!(resp_code[0], SSH_AGENT_FAILURE);

        // 2. Send oversized frame length (> 256KB)
        let oversized_len = ((MAX_AGENT_FRAME_LEN + 1) as u32).to_be_bytes();
        stream.write_all(&oversized_len).await.unwrap();
        stream.flush().await.unwrap();

        // Connection should be closed by server
        let mut buf = [0u8; 1];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(n, 0);

        let _ = shutdown_tx.send(());
        let _ = server_handle.await;
    }

    const TEST_RSA_PEM: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\n\
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

    const TEST_RSA_PUB: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDoc1caBbEz5UIUe8mm3PwYc+U6uA3y7Js9jqji7ghoLQ9Qov+hRIIdwRnl+7jDUxSPhVWTOI+1GbhxGefW2SwWcw49rBHKIIf2W4KpZutydXdjnQRWdzMJI8EEWPkUODgho6GupqTvsMHMGqjm04X+upGDAXF+fB1fNflSSvMOuqxyW8RZ41ZAhcs0KRcxAuLGCuswveL5yWDwltekjbLcdU4IQhherRFXAqGEcjrJs+hadjTNllfSgEVBFjfMmy9T+vBTCIzvoB3l++VIHRE7sPeea0U/nRI0WjV32OVL58+DsvDYv7UWF3niYi8bgEEUsUQzNp49SKcPyvgAZyX5 rsa-server";

    #[tokio::test]
    async fn test_sign_with_key_ed25519() {
        let key = make_test_key();
        let (vault, (priv_1, _), _) = setup_test_vault_with_keys(&key).await;
        let agent = VaultAgentServer::with_key(vault, key);

        let pk = PrivateKey::from_openssh(&priv_1).unwrap();
        let mut key_blob = Vec::new();
        pk.public_key().key_data().encode(&mut key_blob).unwrap();

        let test_data = b"Testing Ed25519 signature in SilverWarden";
        let sig_bytes = agent.sign_with_key(&key_blob, test_data, 0).await.unwrap();

        use russh::keys::ssh_encoding::Decode;
        use russh::keys::ssh_key::Signature;
        let mut slice = sig_bytes.as_slice();
        let sig = Signature::decode(&mut slice).expect("Valid signature blob");
        assert_eq!(sig.algorithm().as_str(), "ssh-ed25519");

        use russh::keys::signature::Verifier;
        pk.public_key()
            .key_data()
            .verify(test_data, &sig)
            .expect("Signature verification should succeed");
    }

    #[tokio::test]
    async fn test_sign_with_key_context_approval_caching() {
        let key = make_test_key();
        let (vault, (priv_1, _), _) = setup_test_vault_with_keys(&key).await;
        let mock_approval = Arc::new(MockApprovalProvider::new(true));
        let agent =
            VaultAgentServer::with_key(vault, key).with_approval_provider(mock_approval.clone());

        let pk = PrivateKey::from_openssh(&priv_1).unwrap();
        let mut key_blob = Vec::new();
        pk.public_key().key_data().encode(&mut key_blob).unwrap();

        let ctx = CallingContext {
            username: "hermes".into(),
            process_name: "git".into(),
            parent_process_name: "bash".into(),
            grandparent_process_name: "alacritty".into(),
            process_pid: 1000,
            parent_process_pid: 900,
            grandparent_process_pid: 800,
            error: false,
            authenticated: true,
        };

        // 1st signing request: prompts approval
        let sig1 = agent
            .sign_with_key_context(&key_blob, b"data1", 0, Some(&ctx))
            .await
            .unwrap();
        assert!(!sig1.is_empty());
        assert_eq!(mock_approval.call_count(), 1);
        assert_eq!(
            mock_approval.last_title().as_deref(),
            Some("SSH Key Signing Request")
        );
        let desc1 = mock_approval.last_description().unwrap();
        assert!(desc1.contains(
            "hermes on alacritty>bash>git is requesting ssh signage with key work-laptop"
        ));

        // 2nd signing request: session is cached, no prompt!
        let sig2 = agent
            .sign_with_key_context(&key_blob, b"data2", 0, Some(&ctx))
            .await
            .unwrap();
        assert!(!sig2.is_empty());
        assert_eq!(mock_approval.call_count(), 1); // Still 1!
    }

    #[tokio::test]
    async fn test_sign_with_key_approval_denied() {
        let key = make_test_key();
        let (vault, (priv_1, _), _) = setup_test_vault_with_keys(&key).await;
        let mock_approval = Arc::new(MockApprovalProvider::new(false));
        let agent = VaultAgentServer::with_key(vault, key).with_approval_provider(mock_approval);

        let pk = PrivateKey::from_openssh(&priv_1).unwrap();
        let mut key_blob = Vec::new();
        pk.public_key().key_data().encode(&mut key_blob).unwrap();

        let ctx = CallingContext {
            username: "hermes".into(),
            process_name: "ssh".into(),
            parent_process_name: "bash".into(),
            grandparent_process_name: "tmux".into(),
            process_pid: 2000,
            parent_process_pid: 1900,
            grandparent_process_pid: 1800,
            error: false,
            authenticated: true,
        };

        let res = agent
            .sign_with_key_context(&key_blob, b"data", 0, Some(&ctx))
            .await;
        assert!(matches!(res, Err(SshAgentError::ApprovalDenied(_))));
    }

    #[tokio::test]
    async fn test_detect_git_sshsig_payload() {
        let key = make_test_key();
        let (vault, (priv_1, _), _) = setup_test_vault_with_keys(&key).await;
        let mock_approval = Arc::new(MockApprovalProvider::new(true));
        let agent =
            VaultAgentServer::with_key(vault, key).with_approval_provider(mock_approval.clone());

        let pk = PrivateKey::from_openssh(&priv_1).unwrap();
        let mut key_blob = Vec::new();
        pk.public_key().key_data().encode(&mut key_blob).unwrap();

        let ctx = CallingContext {
            username: "hermes".into(),
            process_name: "git".into(),
            parent_process_name: "bash".into(),
            grandparent_process_name: "terminal".into(),
            process_pid: 3000,
            parent_process_pid: 2900,
            grandparent_process_pid: 2800,
            error: false,
            authenticated: true,
        };

        // Git SSHSIG payload
        let git_data = [SSHSIG_GIT_MAGIC, b"tree 12345\nparent abcde\n"].concat();
        let _ = agent
            .sign_with_key_context(&key_blob, &git_data, 0, Some(&ctx))
            .await
            .unwrap();

        let desc = mock_approval.last_description().unwrap();
        assert!(desc.contains("is requesting git signage with key work-laptop"));

        // Clear session
        agent.session_store().write().await.wipe();

        // Non-git payload with error context
        let err_ctx = CallingContext {
            username: "unknown_user".into(),
            error: true,
            authenticated: false,
            ..Default::default()
        };
        let ssh_data = b"ssh connection challenge data";
        let _ = agent
            .sign_with_key_context(&key_blob, ssh_data, 0, Some(&err_ctx))
            .await
            .unwrap();

        let desc_err = mock_approval.last_description().unwrap();
        assert_eq!(
            desc_err,
            "unknown_user is requesting ssh signage with key work-laptop"
        );
    }

    #[tokio::test]
    async fn test_rsa_signing_flags() {
        let key = make_test_key();
        let store = Arc::new(VaultStore::new());

        let enc_name =
            encrypt_with(b"rsa-server", EncStringType::AesCbc256HmacSha256B64, &key).unwrap();
        let enc_priv = encrypt_with(
            TEST_RSA_PEM.as_bytes(),
            EncStringType::AesCbc256HmacSha256B64,
            &key,
        )
        .unwrap();
        let enc_pub = encrypt_with(
            TEST_RSA_PUB.as_bytes(),
            EncStringType::AesCbc256HmacSha256B64,
            &key,
        )
        .unwrap();

        let cipher_rsa = Cipher {
            id: Some(Uuid::new_v4()),
            r#type: CipherType::SshKey,
            name: enc_name,
            ssh_key: Some(SSHKeyCipher {
                private_key: Some(enc_priv),
                public_key: Some(enc_pub),
                key_fingerprint: None,
            }),
            ..Default::default()
        };
        store.insert(cipher_rsa).await;

        let agent = VaultAgentServer::with_key(store, key);
        let pk = PrivateKey::from_openssh(TEST_RSA_PEM).unwrap();
        let mut key_blob = Vec::new();
        pk.public_key().key_data().encode(&mut key_blob).unwrap();

        let data = b"data to sign with RSA";

        use russh::keys::signature::Verifier;
        use russh::keys::ssh_encoding::Decode;
        use russh::keys::ssh_key::Signature;

        // 1. flags = 0 -> default ssh-rsa
        let sig_blob_default = agent.sign_with_key(&key_blob, data, 0).await.unwrap();
        let mut slice_default = sig_blob_default.as_slice();
        let sig_default = Signature::decode(&mut slice_default).unwrap();
        assert_eq!(sig_default.algorithm().as_str(), "ssh-rsa");
        pk.public_key()
            .key_data()
            .verify(data, &sig_default)
            .expect("ssh-rsa valid");

        // 2. flags = 2 (SSH_AGENT_RSA_SHA2_256) -> rsa-sha2-256
        let sig_blob_sha256 = agent
            .sign_with_key(&key_blob, data, SSH_AGENT_RSA_SHA2_256)
            .await
            .unwrap();
        let mut slice_sha256 = sig_blob_sha256.as_slice();
        let sig_sha256 = Signature::decode(&mut slice_sha256).unwrap();
        assert_eq!(sig_sha256.algorithm().as_str(), "rsa-sha2-256");
        pk.public_key()
            .key_data()
            .verify(data, &sig_sha256)
            .expect("rsa-sha2-256 valid");

        // 3. flags = 4 (SSH_AGENT_RSA_SHA2_512) -> rsa-sha2-512
        let sig_blob_sha512 = agent
            .sign_with_key(&key_blob, data, SSH_AGENT_RSA_SHA2_512)
            .await
            .unwrap();
        let mut slice_sha512 = sig_blob_sha512.as_slice();
        let sig_sha512 = Signature::decode(&mut slice_sha512).unwrap();
        assert_eq!(sig_sha512.algorithm().as_str(), "rsa-sha2-512");
        pk.public_key()
            .key_data()
            .verify(data, &sig_sha512)
            .expect("rsa-sha2-512 valid");
    }

    #[tokio::test]
    async fn test_handle_connection_sign_request_raw() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("agent_raw_sign.sock");

        let key = make_test_key();
        let (vault, (priv_1, _), _) = setup_test_vault_with_keys(&key).await;
        let mock_approval = Arc::new(MockApprovalProvider::new(true));
        let agent = VaultAgentServer::with_key(vault, key).with_approval_provider(mock_approval);

        let pk = PrivateKey::from_openssh(&priv_1).unwrap();
        let mut key_blob = Vec::new();
        pk.public_key().key_data().encode(&mut key_blob).unwrap();

        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
        let s_path = socket_path.clone();
        let a = agent.clone();
        let server_handle =
            tokio::spawn(async move { serve_with_shutdown(s_path, a, shutdown_rx).await });

        wait_for_socket(&socket_path).await;

        let mut stream = UnixStream::connect(&socket_path).await.unwrap();

        // 1. Successful sign request
        let data = b"payload to be signed via socket";
        let mut req_body = Vec::new();
        req_body.push(SSH2_AGENTC_SIGN_REQUEST);
        (key_blob.len() as u32).encode(&mut req_body).unwrap();
        req_body.extend_from_slice(&key_blob);
        (data.len() as u32).encode(&mut req_body).unwrap();
        req_body.extend_from_slice(data);
        0u32.encode(&mut req_body).unwrap(); // flags = 0

        send_frame(&mut stream, &req_body).await.unwrap();

        let mut resp_len = [0u8; 4];
        stream.read_exact(&mut resp_len).await.unwrap();
        let len = u32::from_be_bytes(resp_len) as usize;
        let mut resp_buf = vec![0u8; len];
        stream.read_exact(&mut resp_buf).await.unwrap();

        assert_eq!(resp_buf[0], SSH2_AGENT_SIGN_RESPONSE);
        let sig_len = u32::from_be_bytes(resp_buf[1..5].try_into().unwrap()) as usize;
        let sig_blob = &resp_buf[5..5 + sig_len];

        use russh::keys::signature::Verifier;
        use russh::keys::ssh_encoding::Decode;
        use russh::keys::ssh_key::Signature;
        let mut slice = sig_blob;
        let sig = Signature::decode(&mut slice).unwrap();
        pk.public_key().key_data().verify(data, &sig).unwrap();

        // 2. Unknown key blob -> SSH_AGENT_FAILURE
        let mut fail_req = Vec::new();
        fail_req.push(SSH2_AGENTC_SIGN_REQUEST);
        let bad_key = vec![0x99; 32];
        (bad_key.len() as u32).encode(&mut fail_req).unwrap();
        fail_req.extend_from_slice(&bad_key);
        (data.len() as u32).encode(&mut fail_req).unwrap();
        fail_req.extend_from_slice(data);
        0u32.encode(&mut fail_req).unwrap();

        send_frame(&mut stream, &fail_req).await.unwrap();
        let mut fail_len = [0u8; 4];
        stream.read_exact(&mut fail_len).await.unwrap();
        assert_eq!(u32::from_be_bytes(fail_len), 1);
        let mut fail_code = [0u8; 1];
        stream.read_exact(&mut fail_code).await.unwrap();
        assert_eq!(fail_code[0], SSH_AGENT_FAILURE);

        // 3. Locked agent -> SSH_AGENT_FAILURE
        agent.lock().await;
        send_frame(&mut stream, &req_body).await.unwrap();
        let mut lock_len = [0u8; 4];
        stream.read_exact(&mut lock_len).await.unwrap();
        assert_eq!(u32::from_be_bytes(lock_len), 1);
        let mut lock_code = [0u8; 1];
        stream.read_exact(&mut lock_code).await.unwrap();
        assert_eq!(lock_code[0], SSH_AGENT_FAILURE);

        let _ = shutdown_tx.send(());
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn test_ssh_keygen_y_sign_and_verify() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("keygen_sign.sock");

        let key = make_test_key();
        let (vault, (_, pub_1), _) = setup_test_vault_with_keys(&key).await;
        let mock_approval = Arc::new(DefaultApprovalProvider::with_bypass());
        let agent = VaultAgentServer::with_key(vault, key).with_approval_provider(mock_approval);

        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
        let s_path = socket_path.clone();
        let a = agent.clone();
        let server_handle =
            tokio::spawn(async move { serve_with_shutdown(s_path, a, shutdown_rx).await });

        wait_for_socket(&socket_path).await;

        let pub_path = temp_dir.path().join("id_ed25519.pub");
        std::fs::write(&pub_path, &pub_1).unwrap();

        let data_path = temp_dir.path().join("document.txt");
        std::fs::write(&data_path, b"Authentic document for signing").unwrap();

        let sign_res = tokio::process::Command::new("ssh-keygen")
            .args([
                "-Y",
                "sign",
                "-f",
                pub_path.to_str().unwrap(),
                "-n",
                "file",
                data_path.to_str().unwrap(),
            ])
            .env("SSH_AUTH_SOCK", &socket_path)
            .output()
            .await
            .expect("Failed to execute ssh-keygen -Y sign");

        assert!(
            sign_res.status.success(),
            "ssh-keygen -Y sign failed: stderr={}",
            String::from_utf8_lossy(&sign_res.stderr)
        );

        let sig_path = temp_dir.path().join("document.txt.sig");
        assert!(sig_path.exists(), "Signature file must exist");

        // Allowed signers file
        let allowed_signers = temp_dir.path().join("allowed_signers");
        std::fs::write(
            &allowed_signers,
            format!("test@silverwarden.local {}\n", pub_1),
        )
        .unwrap();

        let data_bytes = std::fs::read(&data_path).unwrap();
        let mut verify_cmd = tokio::process::Command::new("ssh-keygen");
        verify_cmd
            .args([
                "-Y",
                "verify",
                "-f",
                allowed_signers.to_str().unwrap(),
                "-I",
                "test@silverwarden.local",
                "-n",
                "file",
                "-s",
                sig_path.to_str().unwrap(),
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        let mut child = verify_cmd
            .spawn()
            .expect("Failed to spawn ssh-keygen -Y verify");
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(&data_bytes).await.unwrap();
        }
        let verify_res = child
            .wait_with_output()
            .await
            .expect("Failed to wait on verify");

        assert!(
            verify_res.status.success(),
            "ssh-keygen -Y verify failed: stderr={}",
            String::from_utf8_lossy(&verify_res.stderr)
        );

        let _ = shutdown_tx.send(());
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn test_git_commit_signed_with_agent() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("git_sign.sock");

        let key = make_test_key();
        let (vault, (_, pub_1), _) = setup_test_vault_with_keys(&key).await;
        let mock_approval = Arc::new(DefaultApprovalProvider::with_bypass());
        let agent = VaultAgentServer::with_key(vault, key).with_approval_provider(mock_approval);

        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
        let s_path = socket_path.clone();
        let a = agent.clone();
        let server_handle =
            tokio::spawn(async move { serve_with_shutdown(s_path, a, shutdown_rx).await });

        wait_for_socket(&socket_path).await;

        let git_dir = temp_dir.path().join("repo");
        std::fs::create_dir_all(&git_dir).unwrap();

        async fn run_git(
            args: &[&str],
            git_dir: &Path,
            socket_path: &Path,
        ) -> std::process::Output {
            let res = tokio::process::Command::new("git")
                .args(args)
                .current_dir(git_dir)
                .env("SSH_AUTH_SOCK", socket_path)
                .output()
                .await
                .expect("Failed to execute git");
            assert!(
                res.status.success(),
                "git {:?} failed: stderr={}",
                args,
                String::from_utf8_lossy(&res.stderr)
            );
            res
        }

        run_git(&["init", "-b", "main"], &git_dir, &socket_path).await;
        run_git(
            &["config", "user.name", "SilverWarden Test"],
            &git_dir,
            &socket_path,
        )
        .await;
        run_git(
            &["config", "user.email", "test@silverwarden.local"],
            &git_dir,
            &socket_path,
        )
        .await;
        run_git(&["config", "gpg.format", "ssh"], &git_dir, &socket_path).await;
        let key_pub_path = git_dir.join("id_ed25519.pub");
        std::fs::write(&key_pub_path, &pub_1).unwrap();
        run_git(
            &["config", "user.signingkey", key_pub_path.to_str().unwrap()],
            &git_dir,
            &socket_path,
        )
        .await;
        let allowed_signers_path = git_dir.join("allowed_signers");
        std::fs::write(
            &allowed_signers_path,
            format!("test@silverwarden.local {}\n", pub_1),
        )
        .unwrap();
        run_git(
            &[
                "config",
                "gpg.ssh.allowedSignersFile",
                allowed_signers_path.to_str().unwrap(),
            ],
            &git_dir,
            &socket_path,
        )
        .await;
        run_git(
            &["config", "commit.gpgsign", "true"],
            &git_dir,
            &socket_path,
        )
        .await;

        std::fs::write(git_dir.join("README.md"), "test commit").unwrap();
        run_git(&["add", "README.md"], &git_dir, &socket_path).await;
        run_git(
            &["commit", "-m", "Signed commit from silverwarden agent"],
            &git_dir,
            &socket_path,
        )
        .await;

        let log_res = run_git(&["log", "--show-signature", "-1"], &git_dir, &socket_path).await;
        let stdout = String::from_utf8_lossy(&log_res.stdout);
        assert!(stdout.contains("Good \"git\" signature"));

        let _ = shutdown_tx.send(());
        let _ = server_handle.await;
    }

    #[test]
    fn test_default_approval_provider_no_bypass() {
        use std::os::unix::fs::PermissionsExt;

        let default_prov = DefaultApprovalProvider::new();
        assert!(!default_prov.bypass);

        let bypass_prov = DefaultApprovalProvider::with_bypass();
        assert!(bypass_prov.bypass);
        assert!(bypass_prov.get_approval("title", "desc").unwrap());

        let temp_dir = TempDir::new().unwrap();
        let witness_file = temp_dir.path().join("witness.txt");
        let mock_script = temp_dir.path().join("mock_pinentry.sh");

        let script_content = format!(
            r#"#!/bin/sh
echo "called" >> "{}"
echo "OK Pleased to meet you"
while read -r line; do
  case "$line" in
    CONFIRM*)
      echo "OK"
      ;;
    BYE*)
      echo "OK"
      exit 0
      ;;
    *)
      echo "OK"
      ;;
  esac
done
"#,
            witness_file.display()
        );

        std::fs::write(&mock_script, script_content).unwrap();
        let mut perms = std::fs::metadata(&mock_script).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&mock_script, perms).unwrap();

        let provider = DefaultApprovalProvider::with_custom_bin(mock_script);
        let res = provider.get_approval("Signing Test", "Approve signature");
        assert!(res.unwrap());
        assert!(witness_file.exists());
        let witness_content = std::fs::read_to_string(&witness_file).unwrap();
        assert!(witness_content.contains("called"));
    }

    #[test]
    fn test_error_display() {
        let io_err = SshAgentError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "not found",
        ));
        assert!(format!("{}", io_err).contains("not found"));

        let msg_err = SshAgentError::InvalidMessage("bad frame".into());
        assert!(format!("{}", msg_err).contains("bad frame"));

        let key_err = SshAgentError::KeyError("corrupt key".into());
        assert!(format!("{}", key_err).contains("corrupt key"));

        let enc_err = SshAgentError::EncodingError("encode failed".into());
        assert!(format!("{}", enc_err).contains("encode failed"));

        let fail_err = SshAgentError::AgentFailure;
        assert_eq!(format!("{}", fail_err), "Agent failure");

        let not_found_err = SshAgentError::KeyNotFound;
        assert_eq!(format!("{}", not_found_err), "Key not found");

        let locked_err = SshAgentError::VaultLocked;
        assert_eq!(format!("{}", locked_err), "Vault is locked");

        let denied_err = SshAgentError::ApprovalDenied("cancelled".into());
        assert!(format!("{}", denied_err).contains("cancelled"));

        let sign_err = SshAgentError::SigningError("signature failed".into());
        assert!(format!("{}", sign_err).contains("signature failed"));
    }

    #[tokio::test]
    async fn test_add_ssh_key_ed25519() {
        let key = make_test_key();
        let vault = Arc::new(VaultStore::new());
        let agent = VaultAgentServer::with_key(vault.clone(), key.try_clone().unwrap());

        let (priv_pem, pub_openssh) = generate_test_ed25519(7, "vault-key-7");
        let pub_key = agent
            .add_ssh_key(&priv_pem, "vault-key-7", &key)
            .await
            .unwrap();

        assert_eq!(pub_key.to_openssh().unwrap(), pub_openssh);

        let vault_keys = vault.get_ssh_keys(&key).await.unwrap();
        assert_eq!(vault_keys.len(), 1);
        assert_eq!(vault_keys[0].name, "vault-key-7");
        assert_eq!(vault_keys[0].private_key.trim(), priv_pem.trim());
    }

    #[tokio::test]
    async fn test_ssh_add_duplicate() {
        let key = make_test_key();
        let vault = Arc::new(VaultStore::new());
        let agent = VaultAgentServer::with_key(vault.clone(), key.try_clone().unwrap());

        let (priv_pem, _) = generate_test_ed25519(8, "duplicate-key");
        let res1 = agent.add_ssh_key(&priv_pem, "dup-1", &key).await;
        assert!(res1.is_ok());

        let res2 = agent.add_ssh_key(&priv_pem, "dup-2", &key).await;
        assert!(res2.is_err());
        assert!(format!("{:?}", res2.unwrap_err()).contains("already exists"));
    }

    #[tokio::test]
    async fn test_ssh_add_command() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("ssh_add_cmd.sock");

        let key = make_test_key();
        let vault = Arc::new(VaultStore::new());
        let mock_approval = Arc::new(DefaultApprovalProvider::with_bypass());
        let agent =
            VaultAgentServer::with_key(vault.clone(), key).with_approval_provider(mock_approval);

        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
        let s_path = socket_path.clone();
        let a = agent.clone();
        let server_handle =
            tokio::spawn(async move { serve_with_shutdown(s_path, a, shutdown_rx).await });

        wait_for_socket(&socket_path).await;

        let (priv_pem, pub_key) = generate_test_ed25519(15, "cli-added-key");
        let key_file = temp_dir.path().join("id_ed25519");
        std::fs::write(&key_file, &priv_pem).unwrap();
        let mut perms = std::fs::metadata(&key_file).unwrap().permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&key_file, perms).unwrap();

        let output = tokio::process::Command::new("ssh-add")
            .arg(&key_file)
            .env("SSH_AUTH_SOCK", &socket_path)
            .output()
            .await
            .expect("Failed to execute ssh-add");

        assert!(
            output.status.success(),
            "ssh-add failed: stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let list_out = tokio::process::Command::new("ssh-add")
            .arg("-L")
            .env("SSH_AUTH_SOCK", &socket_path)
            .output()
            .await
            .expect("Failed to execute ssh-add -L");
        assert!(list_out.status.success());
        let stdout = String::from_utf8_lossy(&list_out.stdout);
        assert!(stdout.contains(&pub_key));

        let _ = shutdown_tx.send(());
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn test_add_constrained_lifetime() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("ssh_add_constrained.sock");

        let key = make_test_key();
        let vault = Arc::new(VaultStore::new());
        let mock_approval = Arc::new(DefaultApprovalProvider::with_bypass());
        let agent = VaultAgentServer::with_key(vault.clone(), key.try_clone().unwrap())
            .with_approval_provider(mock_approval);

        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
        let s_path = socket_path.clone();
        let a = agent.clone();
        let server_handle =
            tokio::spawn(async move { serve_with_shutdown(s_path, a, shutdown_rx).await });

        wait_for_socket(&socket_path).await;

        let (priv_pem, _) = generate_test_ed25519(16, "constrained-key");
        let key_file = temp_dir.path().join("id_ed25519");
        std::fs::write(&key_file, &priv_pem).unwrap();
        let mut perms = std::fs::metadata(&key_file).unwrap().permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&key_file, perms).unwrap();

        let output = tokio::process::Command::new("ssh-add")
            .arg("-t")
            .arg("60")
            .arg(&key_file)
            .env("SSH_AUTH_SOCK", &socket_path)
            .output()
            .await
            .expect("Failed to execute ssh-add -t 60");

        assert!(
            output.status.success(),
            "ssh-add -t 60 failed: stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let keys = vault.get_ssh_keys(&key).await.unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].name, "constrained-key");

        let _ = shutdown_tx.send(());
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn test_ssh_add_d_command() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("ssh_add_d.sock");

        let key = make_test_key();
        let (vault, (_, pub_1), _) = setup_test_vault_with_keys(&key).await;
        let mock_approval = Arc::new(DefaultApprovalProvider::with_bypass());
        let agent =
            VaultAgentServer::with_key(vault.clone(), key).with_approval_provider(mock_approval);

        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
        let s_path = socket_path.clone();
        let a = agent.clone();
        let server_handle =
            tokio::spawn(async move { serve_with_shutdown(s_path, a, shutdown_rx).await });

        wait_for_socket(&socket_path).await;

        let pub_path = temp_dir.path().join("id_ed25519.pub");
        std::fs::write(&pub_path, &pub_1).unwrap();

        let del_res = tokio::process::Command::new("ssh-add")
            .arg("-d")
            .arg(&pub_path)
            .env("SSH_AUTH_SOCK", &socket_path)
            .output()
            .await
            .expect("Failed to execute ssh-add -d");

        assert!(
            del_res.status.success(),
            "ssh-add -d failed: stderr: {}",
            String::from_utf8_lossy(&del_res.stderr)
        );

        let list_out = tokio::process::Command::new("ssh-add")
            .arg("-L")
            .env("SSH_AUTH_SOCK", &socket_path)
            .output()
            .await
            .expect("Failed to execute ssh-add -L");
        let stdout = String::from_utf8_lossy(&list_out.stdout);
        assert!(!stdout.contains("work-laptop"));
        assert!(stdout.contains("personal-server"));

        let _ = shutdown_tx.send(());
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn test_ssh_add_remove_all() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("ssh_add_remove_all.sock");

        let key = make_test_key();
        let (vault, _, _) = setup_test_vault_with_keys(&key).await;
        let mock_approval = Arc::new(DefaultApprovalProvider::with_bypass());
        let agent =
            VaultAgentServer::with_key(vault.clone(), key).with_approval_provider(mock_approval);

        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
        let s_path = socket_path.clone();
        let a = agent.clone();
        let server_handle =
            tokio::spawn(async move { serve_with_shutdown(s_path, a, shutdown_rx).await });

        wait_for_socket(&socket_path).await;

        let del_res = tokio::process::Command::new("ssh-add")
            .arg("-D")
            .env("SSH_AUTH_SOCK", &socket_path)
            .output()
            .await
            .expect("Failed to execute ssh-add -D");

        assert!(
            del_res.status.success(),
            "ssh-add -D failed: stderr: {}",
            String::from_utf8_lossy(&del_res.stderr)
        );

        let list_out = tokio::process::Command::new("ssh-add")
            .arg("-L")
            .env("SSH_AUTH_SOCK", &socket_path)
            .output()
            .await
            .expect("Failed to execute ssh-add -L");
        assert_eq!(list_out.status.code(), Some(1));
        let stderr = String::from_utf8_lossy(&list_out.stderr);
        let stdout = String::from_utf8_lossy(&list_out.stdout);
        assert!(
            stderr.contains("The agent has no identities.")
                || stdout.contains("The agent has no identities.")
        );

        let _ = shutdown_tx.send(());
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn test_ssh_add_full_cycle() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("full_cycle.sock");

        let key = make_test_key();
        let vault = Arc::new(VaultStore::new());
        let mock_approval = Arc::new(DefaultApprovalProvider::with_bypass());
        let agent =
            VaultAgentServer::with_key(vault.clone(), key).with_approval_provider(mock_approval);

        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
        let s_path = socket_path.clone();
        let a = agent.clone();
        let server_handle =
            tokio::spawn(async move { serve_with_shutdown(s_path, a, shutdown_rx).await });

        wait_for_socket(&socket_path).await;

        let (priv_pem, pub_key) = generate_test_ed25519(25, "full-cycle-key");
        let key_file = temp_dir.path().join("id_ed25519");
        let pub_file = temp_dir.path().join("id_ed25519.pub");
        std::fs::write(&key_file, &priv_pem).unwrap();
        std::fs::write(&pub_file, &pub_key).unwrap();
        let mut perms = std::fs::metadata(&key_file).unwrap().permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&key_file, perms).unwrap();

        // 1. ssh-add
        let add_out = tokio::process::Command::new("ssh-add")
            .arg(&key_file)
            .env("SSH_AUTH_SOCK", &socket_path)
            .output()
            .await
            .expect("Failed to execute ssh-add");
        assert!(add_out.status.success());

        // 2. ssh-add -L -> key is present
        let list1 = tokio::process::Command::new("ssh-add")
            .arg("-L")
            .env("SSH_AUTH_SOCK", &socket_path)
            .output()
            .await
            .expect("Failed to execute ssh-add -L");
        assert!(list1.status.success());
        let stdout1 = String::from_utf8_lossy(&list1.stdout);
        assert!(stdout1.contains(&pub_key));

        // 3. ssh-add -d -> delete key
        let del_out = tokio::process::Command::new("ssh-add")
            .arg("-d")
            .arg(&pub_file)
            .env("SSH_AUTH_SOCK", &socket_path)
            .output()
            .await
            .expect("Failed to execute ssh-add -d");
        assert!(del_out.status.success());

        // 4. ssh-add -L -> key is absent
        let list2 = tokio::process::Command::new("ssh-add")
            .arg("-L")
            .env("SSH_AUTH_SOCK", &socket_path)
            .output()
            .await
            .expect("Failed to execute ssh-add -L");
        assert_eq!(list2.status.code(), Some(1));
        let stdout2 = String::from_utf8_lossy(&list2.stdout);
        assert!(!stdout2.contains(&pub_key));

        let _ = shutdown_tx.send(());
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn test_ssh_add_syncs_to_server() {
        use std::os::unix::fs::PermissionsExt;
        use sw_bitwarden_api::AuthenticatedClient;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let server_uuid = Uuid::new_v4();

        Mock::given(method("POST"))
            .and(path("/ciphers"))
            .respond_with(move |req: &wiremock::Request| {
                let mut body: serde_json::Value = req.body_json().unwrap();
                body["id"] = serde_json::json!(server_uuid.to_string());
                ResponseTemplate::new(200).set_body_json(body)
            })
            .expect(1)
            .mount(&server)
            .await;

        let delete_path = format!("/ciphers/{server_uuid}");
        Mock::given(method("DELETE"))
            .and(path(delete_path))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let api_client = Arc::new(AuthenticatedClient::from_token(
            server.uri(),
            server.uri(),
            sw_bitwarden_api::LoginToken::default(),
        ));

        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("sync_server.sock");

        let key = make_test_key();
        let vault = Arc::new(VaultStore::new());
        let mock_approval = Arc::new(DefaultApprovalProvider::with_bypass());
        let agent = VaultAgentServer::with_key(vault.clone(), key)
            .with_approval_provider(mock_approval)
            .with_api_client(api_client);

        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
        let s_path = socket_path.clone();
        let a = agent.clone();
        let server_handle =
            tokio::spawn(async move { serve_with_shutdown(s_path, a, shutdown_rx).await });

        wait_for_socket(&socket_path).await;

        let (priv_pem, pub_key) = generate_test_ed25519(33, "sync-server-key");
        let key_file = temp_dir.path().join("id_ed25519");
        let pub_file = temp_dir.path().join("id_ed25519.pub");
        std::fs::write(&key_file, &priv_pem).unwrap();
        std::fs::write(&pub_file, &pub_key).unwrap();
        let mut perms = std::fs::metadata(&key_file).unwrap().permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&key_file, perms).unwrap();

        // 1. Add key via ssh-add -> triggers post_cipher
        let add_out = tokio::process::Command::new("ssh-add")
            .arg(&key_file)
            .env("SSH_AUTH_SOCK", &socket_path)
            .output()
            .await
            .expect("Failed to execute ssh-add");
        assert!(add_out.status.success());

        // Check vault stored cipher with server_uuid
        let ciphers = vault.all().await;
        assert_eq!(ciphers.len(), 1);
        assert_eq!(ciphers[0].id, Some(server_uuid));

        // 2. Remove key via ssh-add -d -> triggers delete_cipher
        let del_out = tokio::process::Command::new("ssh-add")
            .arg("-d")
            .arg(&pub_file)
            .env("SSH_AUTH_SOCK", &socket_path)
            .output()
            .await
            .expect("Failed to execute ssh-add -d");
        assert!(del_out.status.success());

        assert_eq!(vault.len().await, 0);

        let _ = shutdown_tx.send(());
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn test_vault_agent_server_ssh_helpers() {
        let key = make_test_key();
        let vault = Arc::new(VaultStore::new());
        let agent = VaultAgentServer::new(vault.clone());

        // When locked, listing or deleting fails
        assert!(matches!(
            agent.list_ssh_keys().await,
            Err(SshAgentError::VaultLocked)
        ));
        let dummy_id = Uuid::new_v4();
        assert!(matches!(
            agent.delete_ssh_key(&dummy_id).await,
            Err(SshAgentError::VaultLocked)
        ));

        // Unlock
        agent.unlock(key.try_clone().unwrap()).await;
        assert!(agent.get_symmetric_key().await.is_some());

        // Empty list
        let initial_list = agent.list_ssh_keys().await.unwrap();
        assert!(initial_list.is_empty());

        // Generate Ed25519
        let ed_summary = agent
            .new_ssh_key("my-ed-key", "ed25519", &key)
            .await
            .expect("Failed to create ed25519 key");
        assert_eq!(ed_summary.name, "my-ed-key");
        assert!(ed_summary.public_key.starts_with("ssh-ed25519"));
        assert!(ed_summary.fingerprint.starts_with("SHA256:"));
        assert!(ed_summary.id.is_some());
        let ed_id = ed_summary.id.unwrap();

        // Generate RSA
        let rsa_summary = agent
            .new_ssh_key("my-rsa-key", "rsa", &key)
            .await
            .expect("Failed to create rsa key");
        assert_eq!(rsa_summary.name, "my-rsa-key");
        assert!(rsa_summary.public_key.starts_with("ssh-rsa"));

        // Generate ECDSA
        let ecdsa_summary = agent
            .new_ssh_key("my-ecdsa-key", "ecdsa", &key)
            .await
            .expect("Failed to create ecdsa key");
        assert_eq!(ecdsa_summary.name, "my-ecdsa-key");
        assert!(ecdsa_summary.public_key.starts_with("ecdsa-sha2-nistp256"));

        // List SSH keys: should return 3 keys
        let keys = agent.list_ssh_keys().await.unwrap();
        assert_eq!(keys.len(), 3);
        for k in &keys {
            assert!(!k.public_key.contains("PRIVATE"));
        }

        // Delete Ed25519 key
        let deleted = agent.delete_ssh_key(&ed_id).await.unwrap();
        assert!(deleted);
        let remaining = agent.list_ssh_keys().await.unwrap();
        assert_eq!(remaining.len(), 2);
        assert!(!remaining.iter().any(|k| k.id == Some(ed_id)));

        // Import key
        let (priv_pem, pub_str) = generate_test_ed25519(42, "imported-ed");
        let imported = agent
            .import_ssh_key("imported-ed", &priv_pem, &key)
            .await
            .expect("Failed to import key");
        assert_eq!(imported.name, "imported-ed");
        assert_eq!(imported.public_key.trim(), pub_str.trim());

        let after_import = agent.list_ssh_keys().await.unwrap();
        assert_eq!(after_import.len(), 3);

        // Lock agent
        agent.lock().await;
        assert!(agent.is_locked());
        assert!(agent.get_symmetric_key().await.is_none());
    }
}
