use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::RwLock;

use russh::keys::agent::server::{Agent, MessageType};
pub use russh::keys::agent::AgentIdentity;
use russh::keys::ssh_encoding::Encode;
use russh::keys::PrivateKey;
use sw_crypto::SymmetricKey;
use sw_vault::VaultStore;

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

#[derive(Error, Debug)]
pub enum SshAgentError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid agent message: {0}")]
    InvalidMessage(String),

    #[error("Key parsing error: {0}")]
    KeyError(String),

    #[error("Encoding error: {0}")]
    EncodingError(String),

    #[error("Agent failure")]
    AgentFailure,
}

/// Agent server integrating with SilverWarden Vault and implementing `russh::keys::agent::server::Agent`.
#[derive(Clone)]
pub struct VaultAgentServer {
    vault: Arc<VaultStore>,
    symmetric_key: Arc<RwLock<Option<SymmetricKey>>>,
    is_locked: Arc<AtomicBool>,
}

impl VaultAgentServer {
    /// Creates a new `VaultAgentServer` with an initially locked vault.
    pub fn new(vault: Arc<VaultStore>) -> Self {
        Self {
            vault,
            symmetric_key: Arc::new(RwLock::new(None)),
            is_locked: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Creates a new `VaultAgentServer` with an already unlocked vault and symmetric key.
    pub fn with_key(vault: Arc<VaultStore>, key: SymmetricKey) -> Self {
        Self {
            vault,
            symmetric_key: Arc::new(RwLock::new(Some(key))),
            is_locked: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Unlocks the agent server with the provided user symmetric key.
    pub async fn unlock(&self, key: SymmetricKey) {
        let mut guard = self.symmetric_key.write().await;
        *guard = Some(key);
        self.is_locked.store(false, Ordering::SeqCst);
    }

    /// Locks the agent server, clearing the cached user symmetric key.
    pub async fn lock(&self) {
        let mut guard = self.symmetric_key.write().await;
        *guard = None;
        self.is_locked.store(true, Ordering::SeqCst);
    }

    /// Returns whether the vault is locked.
    pub fn is_locked(&self) -> bool {
        self.is_locked.load(Ordering::SeqCst)
    }

    /// Access to the underlying VaultStore.
    pub fn vault(&self) -> &Arc<VaultStore> {
        &self.vault
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
}

impl Agent for VaultAgentServer {
    async fn confirm_request(&self, msg: MessageType) -> bool {
        match msg {
            MessageType::RequestKeys => true,
            MessageType::AddKeys => false,
            MessageType::Sign => true,
            _ => false,
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
                if allowed {
                    // Sign will be implemented in SW-042/SW-043
                    send_failure(&mut stream).await?;
                } else {
                    send_failure(&mut stream).await?;
                }
            }
            SSH2_AGENTC_ADD_IDENTITY | SSH2_AGENTC_ADD_ID_CONSTRAINED => {
                let allowed = agent.confirm_request(MessageType::AddKeys).await;
                if allowed {
                    send_success(&mut stream).await?;
                } else {
                    send_failure(&mut stream).await?;
                }
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
        assert!(!agent.confirm_request(MessageType::AddKeys).await);
        assert!(agent.confirm_request(MessageType::Sign).await);
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
    async fn test_handle_connection_add_keys_rejected() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("agent_add_keys.sock");

        let key = make_test_key();
        let vault = Arc::new(VaultStore::new());
        let agent = VaultAgentServer::with_key(vault, key);

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

        // Adding key should fail because confirm_request(AddKeys) returns false
        let add_res = client.add_identity(&pk, &[]).await;
        assert!(add_res.is_err());

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
    }
}
