use std::path::{Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

use russh::keys::agent::server::{Agent, MessageType};
pub use russh::keys::ssh_encoding::{Decode, Encode};
pub use russh::keys::{PrivateKey, PublicKey};
use sw_vault_agent::sw_vault::VaultSshKey;

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

/// Helper function to generate an Ed25519 keypair for tests or fixtures.
pub fn generate_test_ed25519(seed_byte: u8, comment: &str) -> (String, String) {
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

#[cfg(test)]
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

pub use sw_vault_agent::SshAgentError;
use sw_vault_agent::{sw_systemauth, AgentIdentity, VaultAgentServer};

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

/// Returns the default SSH agent socket path `~/.silverwarden-ssh-agent.sock` for a specific home or falling back to `$HOME`.
pub fn default_ssh_agent_socket_path_from_home(
    home: Option<&str>,
) -> Result<PathBuf, SshAgentError> {
    let home = home
        .map(String::from)
        .or_else(|| std::env::var("HOME").ok())
        .ok_or_else(|| SshAgentError::Other("HOME no definido".into()))?;
    Ok(PathBuf::from(home).join(".silverwarden-ssh-agent.sock"))
}

/// Returns the default SSH agent socket path `~/.silverwarden-ssh-agent.sock` for the current user.
pub fn default_ssh_agent_socket_path() -> Result<PathBuf, SshAgentError> {
    default_ssh_agent_socket_path_from_home(None)
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
                        #[rustfmt::skip]
                        AgentIdentity::Certificate { certificate, comment } => {
                            let mut cert_blob = Vec::new();
                            let _ = certificate.encode(&mut cert_blob);
                            let _ = cert_blob.encode(&mut resp_body);
                            let _ = comment.encode(&mut resp_body);
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

                let mut vault_keys = match agent.vault.get_ssh_keys(sym_key).await {
                    Ok(k) => k,
                    Err(e) => {
                        tracing::warn!("Failed to retrieve vault keys for removal: {e}");
                        send_failure(&mut stream).await?;
                        continue;
                    }
                };
                if let Ok(legacy_keys) = agent.vault.extract_ssh_keys(sym_key).await {
                    vault_keys.extend(legacy_keys);
                }

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

                let mut vault_keys = match agent.vault.get_ssh_keys(sym_key).await {
                    Ok(k) => k,
                    Err(e) => {
                        tracing::warn!("Failed to retrieve vault keys for remove all: {e}");
                        send_failure(&mut stream).await?;
                        continue;
                    }
                };
                if let Ok(legacy_keys) = agent.vault.extract_ssh_keys(sym_key).await {
                    vault_keys.extend(legacy_keys);
                }

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
    use std::sync::Arc;
    use std::time::Duration;
    use sw_vault_agent::sw_bitwarden_api::{self, AuthenticatedClient, BitwardenApiClient};
    use sw_vault_agent::sw_crypto::{encrypt_with, EncStringType, SymmetricKey};
    use sw_vault_agent::sw_systemauth::SessionStore;
    use sw_vault_agent::sw_vault::{
        Cipher, CipherType, Field, FieldType, SSHKeyCipher, VaultStore,
    };
    use sw_vault_agent::{which_bin, DefaultApprovalProvider, MockApprovalProvider};
    use tempfile::TempDir;
    use tokio::sync::RwLock;
    use uuid::Uuid;

    fn make_test_key() -> SymmetricKey {
        SymmetricKey::from_bytes(&[0x42u8; 64]).unwrap()
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
        let keys_openssh: Vec<String> = identities
            .iter()
            .map(|id| match id {
                AgentIdentity::PublicKey { key, .. } => key.to_openssh().unwrap(),
                AgentIdentity::Certificate { .. } => String::new(),
            })
            .collect();

        assert!(keys_openssh
            .iter()
            .any(|s| s.contains(&pub_1) || pub_1.contains(s)));
        assert!(keys_openssh
            .iter()
            .any(|s| s.contains(&pub_2) || pub_2.contains(s)));

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
    async fn test_ssh_agent_server_struct() {
        let temp_dir = TempDir::new().unwrap();
        let sock_path = temp_dir.path().join("server_struct.sock");

        let vault = Arc::new(VaultStore::new());
        let agent = VaultAgentServer::new(vault);
        let server = SshAgentServer::new(&sock_path, agent.clone());

        assert_eq!(server.socket_path(), sock_path.as_path());
        assert!(server.agent().is_locked());
        let dbg_str = format!("{:?}", server.agent());
        assert!(dbg_str.contains("VaultAgentServer"));

        let sessions = Arc::new(RwLock::new(SessionStore::new()));
        let with_sess = agent.clone().with_session_store(sessions.clone());
        assert!(Arc::ptr_eq(with_sess.session_store(), &sessions));

        let api_client = Arc::new(BitwardenApiClient::new(
            "http://localhost:8080",
            "http://localhost:8080",
            Arc::new(tokio::sync::Mutex::new(
                sw_bitwarden_api::LoginToken::default(),
            )),
        ));
        let with_client = agent.clone().with_api_client(api_client.clone());
        assert!(with_client.api_client().is_some());

        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
        let s_handle = tokio::spawn(async move { server.serve_with_shutdown(shutdown_rx).await });

        wait_for_socket(&sock_path).await;
        let _ = shutdown_tx.send(());
        let res = s_handle.await.unwrap();
        assert!(res.is_ok());

        // Test serve helper
        let s_path_2 = temp_dir.path().join("serve_fn.sock");
        let a_2 = agent.clone();
        let h_serve = tokio::spawn(async move {
            let _ = serve(&s_path_2, a_2).await;
        });
        tokio::time::sleep(Duration::from_millis(15)).await;
        h_serve.abort();

        // Test SshAgentServer::serve method
        let s_path_3 = temp_dir.path().join("server_serve.sock");
        let server_3 = SshAgentServer::new(&s_path_3, agent.clone());
        let h_serve_3 = tokio::spawn(async move {
            let _ = server_3.serve().await;
        });
        tokio::time::sleep(Duration::from_millis(15)).await;
        h_serve_3.abort();
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

    const TEST_RSA_PUB: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDoc1caBbEz5UIUe8mm3PwYc+U6uA3y7Js9jqji7ghoLQ9Qov+hRIIdwRnl+7jDUxSPhVWTOI+1GbhxGefW2SwWcw49rBHKIIf2W4KpZutydXdjnQRWdzMJI8EEWPkUODgho6GupqTvsMHMGqjm04X+upGDAXF+fB1fNflSSvMOuqxyW8RZ41ZAhcs0KRcxAuLGCuswveL5yWDwltekjbLcdU4IQhherRFXAqGEcjrJs+hadjTNllfSgEVBFjfMmy9T+vBTCIzvoB3l++VIHRE7sPeea0U/nRI0WjV32OVL58+DsvDYv7UWF3niYi8bgEEUsUQzNp49SKcPyvgAZyX5 rsa-server";

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
    async fn test_remove_all_with_multiple_keys() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("remove_multiple.sock");

        let key = make_test_key();
        let (vault, _, _) = setup_test_vault_with_keys(&key).await;

        // Add a 3rd key (RSA)
        let (priv_3, pub_3) = (TEST_RSA_PEM.to_string(), TEST_RSA_PUB.to_string());
        let enc_name_3 =
            encrypt_with(b"rsa-backup", EncStringType::AesCbc256HmacSha256B64, &key).unwrap();
        let enc_priv_3 = encrypt_with(
            priv_3.as_bytes(),
            EncStringType::AesCbc256HmacSha256B64,
            &key,
        )
        .unwrap();
        let enc_pub_3 = encrypt_with(
            pub_3.as_bytes(),
            EncStringType::AesCbc256HmacSha256B64,
            &key,
        )
        .unwrap();

        vault
            .insert(Cipher {
                id: Some(Uuid::new_v4()),
                r#type: CipherType::SshKey,
                name: enc_name_3,
                ssh_key: Some(SSHKeyCipher {
                    private_key: Some(enc_priv_3),
                    public_key: Some(enc_pub_3),
                    key_fingerprint: None,
                }),
                ..Default::default()
            })
            .await;

        let mock_approval = Arc::new(DefaultApprovalProvider::with_bypass());
        let agent =
            VaultAgentServer::with_key(vault.clone(), key).with_approval_provider(mock_approval);

        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
        let s_path = socket_path.clone();
        let a = agent.clone();
        let server_handle =
            tokio::spawn(async move { serve_with_shutdown(s_path, a, shutdown_rx).await });

        wait_for_socket(&socket_path).await;

        // Verify initial list has 3 keys
        let list_before = tokio::process::Command::new("ssh-add")
            .arg("-L")
            .env("SSH_AUTH_SOCK", &socket_path)
            .output()
            .await
            .expect("Failed to execute ssh-add -L");
        assert!(list_before.status.success());
        let stdout_before = String::from_utf8_lossy(&list_before.stdout);
        let key_count = stdout_before
            .lines()
            .filter(|l| !l.trim().is_empty())
            .count();
        assert_eq!(key_count, 3, "Expected 3 keys in initial list");

        // Remove all
        let del_res = tokio::process::Command::new("ssh-add")
            .arg("-D")
            .env("SSH_AUTH_SOCK", &socket_path)
            .output()
            .await
            .expect("Failed to execute ssh-add -D");
        assert!(del_res.status.success());

        // Verify list is now empty
        let list_after = tokio::process::Command::new("ssh-add")
            .arg("-L")
            .env("SSH_AUTH_SOCK", &socket_path)
            .output()
            .await
            .expect("Failed to execute ssh-add -L");
        assert_eq!(list_after.status.code(), Some(1));
        let stderr_after = String::from_utf8_lossy(&list_after.stderr);
        let stdout_after = String::from_utf8_lossy(&list_after.stdout);
        assert!(
            stderr_after.contains("The agent has no identities.")
                || stdout_after.contains("The agent has no identities.")
        );

        let _ = shutdown_tx.send(());
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn test_handle_connection_protocol_edge_cases() {
        use russh::keys::ssh_encoding::Encode;

        let key = make_test_key();
        let (vault, (priv_1, _), _) = setup_test_vault_with_keys(&key).await;
        let mock_denied = Arc::new(MockApprovalProvider::new(false));
        let agent_denied = VaultAgentServer::with_key(vault.clone(), key.try_clone().unwrap())
            .with_approval_provider(mock_denied);

        let pk = PrivateKey::from_openssh(&priv_1).unwrap();
        let mut key_blob = Vec::new();
        pk.public_key().key_data().encode(&mut key_blob).unwrap();

        // 1. Locked agent: Request identities returns failure
        let (mut client, server) = UnixStream::pair().unwrap();
        let handle = tokio::spawn(handle_connection(server, agent_denied.clone()));
        agent_denied.lock().await;

        send_frame(&mut client, &[SSH2_AGENTC_REQUEST_IDENTITIES])
            .await
            .unwrap();
        let mut resp_len = [0u8; 4];
        client.read_exact(&mut resp_len).await.unwrap();
        assert_eq!(u32::from_be_bytes(resp_len), 5);
        let mut resp_buf = [0u8; 5];
        client.read_exact(&mut resp_buf).await.unwrap();
        assert_eq!(resp_buf[0], SSH2_AGENT_IDENTITIES_ANSWER);
        assert_eq!(u32::from_be_bytes(resp_buf[1..5].try_into().unwrap()), 0);

        let mut resp_code = [0u8; 1];

        // 2. Locked agent: Add identity returns failure
        send_frame(&mut client, &[SSH2_AGENTC_ADD_IDENTITY, 0, 0])
            .await
            .unwrap();
        client.read_exact(&mut resp_len).await.unwrap();
        assert_eq!(u32::from_be_bytes(resp_len), 1);
        client.read_exact(&mut resp_code).await.unwrap();
        assert_eq!(resp_code[0], SSH_AGENT_FAILURE);

        // 3. Locked agent: Remove identity returns failure
        send_frame(&mut client, &[SSH2_AGENTC_REMOVE_IDENTITY, 0, 0])
            .await
            .unwrap();
        client.read_exact(&mut resp_len).await.unwrap();
        assert_eq!(u32::from_be_bytes(resp_len), 1);
        client.read_exact(&mut resp_code).await.unwrap();
        assert_eq!(resp_code[0], SSH_AGENT_FAILURE);

        // 4. Locked agent: Remove all identities returns failure
        send_frame(&mut client, &[SSH2_AGENTC_REMOVE_ALL_IDENTITIES])
            .await
            .unwrap();
        client.read_exact(&mut resp_len).await.unwrap();
        assert_eq!(u32::from_be_bytes(resp_len), 1);
        client.read_exact(&mut resp_code).await.unwrap();
        assert_eq!(resp_code[0], SSH_AGENT_FAILURE);

        // Unlock agent with denied approvals
        agent_denied.unlock(key.try_clone().unwrap()).await;

        // 5. Sign request with denied approval returns failure
        let data = b"some data";
        let mut sign_req = Vec::new();
        sign_req.push(SSH2_AGENTC_SIGN_REQUEST);
        (key_blob.len() as u32).encode(&mut sign_req).unwrap();
        sign_req.extend_from_slice(&key_blob);
        (data.len() as u32).encode(&mut sign_req).unwrap();
        sign_req.extend_from_slice(data);
        0u32.encode(&mut sign_req).unwrap();
        send_frame(&mut client, &sign_req).await.unwrap();
        client.read_exact(&mut resp_len).await.unwrap();
        assert_eq!(u32::from_be_bytes(resp_len), 1);
        client.read_exact(&mut resp_code).await.unwrap();
        assert_eq!(resp_code[0], SSH_AGENT_FAILURE);

        // 6. Sign request with truncated payload (only message byte)
        send_frame(&mut client, &[SSH2_AGENTC_SIGN_REQUEST])
            .await
            .unwrap();
        client.read_exact(&mut resp_len).await.unwrap();
        assert_eq!(u32::from_be_bytes(resp_len), 1);
        client.read_exact(&mut resp_code).await.unwrap();
        assert_eq!(resp_code[0], SSH_AGENT_FAILURE);

        // 7. Sign request with truncated key blob
        send_frame(&mut client, &[SSH2_AGENTC_SIGN_REQUEST, 0, 0, 0, 10, 1, 2])
            .await
            .unwrap();
        client.read_exact(&mut resp_len).await.unwrap();
        assert_eq!(u32::from_be_bytes(resp_len), 1);
        client.read_exact(&mut resp_code).await.unwrap();
        assert_eq!(resp_code[0], SSH_AGENT_FAILURE);

        // 8. Sign request with truncated data len
        let mut trunc_sign = Vec::new();
        trunc_sign.push(SSH2_AGENTC_SIGN_REQUEST);
        (key_blob.len() as u32).encode(&mut trunc_sign).unwrap();
        trunc_sign.extend_from_slice(&key_blob);
        send_frame(&mut client, &trunc_sign).await.unwrap();
        client.read_exact(&mut resp_len).await.unwrap();
        assert_eq!(u32::from_be_bytes(resp_len), 1);
        client.read_exact(&mut resp_code).await.unwrap();
        assert_eq!(resp_code[0], SSH_AGENT_FAILURE);

        // 9. Sign request with truncated data payload
        let mut trunc_data = Vec::new();
        trunc_data.push(SSH2_AGENTC_SIGN_REQUEST);
        (key_blob.len() as u32).encode(&mut trunc_data).unwrap();
        trunc_data.extend_from_slice(&key_blob);
        100u32.encode(&mut trunc_data).unwrap();
        send_frame(&mut client, &trunc_data).await.unwrap();
        client.read_exact(&mut resp_len).await.unwrap();
        assert_eq!(u32::from_be_bytes(resp_len), 1);
        client.read_exact(&mut resp_code).await.unwrap();
        assert_eq!(resp_code[0], SSH_AGENT_FAILURE);

        // 10. Add identity with invalid key bytes returns failure
        send_frame(
            &mut client,
            &[SSH2_AGENTC_ADD_IDENTITY, 0, 0, 0, 5, b'b', b'a', b'd'],
        )
        .await
        .unwrap();
        client.read_exact(&mut resp_len).await.unwrap();
        assert_eq!(u32::from_be_bytes(resp_len), 1);
        client.read_exact(&mut resp_code).await.unwrap();
        assert_eq!(resp_code[0], SSH_AGENT_FAILURE);

        // 11. Remove identity with truncated key len
        send_frame(&mut client, &[SSH2_AGENTC_REMOVE_IDENTITY, 0])
            .await
            .unwrap();
        client.read_exact(&mut resp_len).await.unwrap();
        assert_eq!(u32::from_be_bytes(resp_len), 1);
        client.read_exact(&mut resp_code).await.unwrap();
        assert_eq!(resp_code[0], SSH_AGENT_FAILURE);

        // 12. Remove identity with truncated key blob
        send_frame(
            &mut client,
            &[SSH2_AGENTC_REMOVE_IDENTITY, 0, 0, 0, 20, 1, 2, 3],
        )
        .await
        .unwrap();
        client.read_exact(&mut resp_len).await.unwrap();
        assert_eq!(u32::from_be_bytes(resp_len), 1);
        client.read_exact(&mut resp_code).await.unwrap();
        assert_eq!(resp_code[0], SSH_AGENT_FAILURE);

        // 13. Remove identity: key not found in vault
        let mut not_found_rem = Vec::new();
        not_found_rem.push(SSH2_AGENTC_REMOVE_IDENTITY);
        let non_existent_key = vec![0x77; 32];
        (non_existent_key.len() as u32)
            .encode(&mut not_found_rem)
            .unwrap();
        not_found_rem.extend_from_slice(&non_existent_key);
        send_frame(&mut client, &not_found_rem).await.unwrap();
        client.read_exact(&mut resp_len).await.unwrap();
        assert_eq!(u32::from_be_bytes(resp_len), 1);
        client.read_exact(&mut resp_code).await.unwrap();
        assert_eq!(resp_code[0], SSH_AGENT_FAILURE);

        // 14. Remove identity: approval denied
        let mut rem_denied = Vec::new();
        rem_denied.push(SSH2_AGENTC_REMOVE_IDENTITY);
        (key_blob.len() as u32).encode(&mut rem_denied).unwrap();
        rem_denied.extend_from_slice(&key_blob);
        send_frame(&mut client, &rem_denied).await.unwrap();
        client.read_exact(&mut resp_len).await.unwrap();
        assert_eq!(u32::from_be_bytes(resp_len), 1);
        client.read_exact(&mut resp_code).await.unwrap();
        assert_eq!(resp_code[0], SSH_AGENT_FAILURE);

        // 15. Remove all identities: approval denied
        send_frame(&mut client, &[SSH2_AGENTC_REMOVE_ALL_IDENTITIES])
            .await
            .unwrap();
        client.read_exact(&mut resp_len).await.unwrap();
        assert_eq!(u32::from_be_bytes(resp_len), 1);
        client.read_exact(&mut resp_code).await.unwrap();
        assert_eq!(resp_code[0], SSH_AGENT_FAILURE);

        drop(client);
        let _ = handle.await;

        // 16. Add constrained identity with lifetime and confirm
        let (ed_pem, _) = generate_test_ed25519(99, "add-stream-test");
        let pk_add = PrivateKey::from_openssh(&ed_pem).unwrap();
        let mut keypair_bytes = Vec::new();
        pk_add.key_data().encode(&mut keypair_bytes).unwrap();
        let comment = "add-stream-test";

        let mock_bypass = Arc::new(DefaultApprovalProvider::with_bypass());
        let agent_bypass = VaultAgentServer::with_key(vault.clone(), key.try_clone().unwrap())
            .with_approval_provider(mock_bypass);
        let (mut client2, server2) = UnixStream::pair().unwrap();
        let handle2 = tokio::spawn(handle_connection(server2, agent_bypass.clone()));

        let mut add_req = Vec::new();
        add_req.push(SSH2_AGENTC_ADD_ID_CONSTRAINED);
        add_req.extend_from_slice(&keypair_bytes);
        comment.encode(&mut add_req).unwrap();
        add_req.push(1);
        3600u32.encode(&mut add_req).unwrap();
        add_req.push(2);
        send_frame(&mut client2, &add_req).await.unwrap();
        client2.read_exact(&mut resp_len).await.unwrap();
        assert_eq!(u32::from_be_bytes(resp_len), 1);
        client2.read_exact(&mut resp_code).await.unwrap();
        assert_eq!(resp_code[0], SSH_AGENT_SUCCESS);

        // 17. Duplicate key -> SSH_AGENT_FAILURE
        send_frame(&mut client2, &add_req).await.unwrap();
        client2.read_exact(&mut resp_len).await.unwrap();
        assert_eq!(u32::from_be_bytes(resp_len), 1);
        client2.read_exact(&mut resp_code).await.unwrap();
        assert_eq!(resp_code[0], SSH_AGENT_FAILURE);

        drop(client2);
        let _ = handle2.await;

        // Also test which_bin helper directly
        assert!(which_bin("nonexistent_binary_for_test_123").is_none());
    }

    #[tokio::test]
    async fn test_handle_connection_more_edge_cases() {
        let store = Arc::new(VaultStore::new());
        let key = make_test_key();
        let agent = VaultAgentServer::with_key(store.clone(), key.try_clone().unwrap());

        // Add 1 key
        let (ed1_pem, _) = generate_test_ed25519(88, "ed1");
        let _ = agent.add_ssh_key(&ed1_pem, "ed1", &key).await.unwrap();
        let pk = PrivateKey::from_openssh(&ed1_pem).unwrap();
        let mut key_wire = Vec::new();
        pk.public_key().key_data().encode(&mut key_wire).unwrap();

        let (mut client, server) = UnixStream::pair().unwrap();
        let mock_provider = Arc::new(MockApprovalProvider::new(true));
        let agent_with_provider = agent.clone().with_approval_provider(mock_provider.clone());
        let handle = tokio::spawn(handle_connection(server, agent_with_provider));

        let mut resp_len = [0u8; 4];
        let mut resp_code = [0u8; 1];

        // 1. Unknown message type (250)
        send_frame(&mut client, &[250u8, 0, 0, 0]).await.unwrap();
        client.read_exact(&mut resp_len).await.unwrap();
        assert_eq!(u32::from_be_bytes(resp_len), 1);
        client.read_exact(&mut resp_code).await.unwrap();
        assert_eq!(resp_code[0], SSH_AGENT_FAILURE);

        // 2. SSH2_AGENTC_SIGN_REQUEST with truncated buffer (< 5 bytes)
        send_frame(&mut client, &[SSH2_AGENTC_SIGN_REQUEST, 0, 0])
            .await
            .unwrap();
        client.read_exact(&mut resp_len).await.unwrap();
        assert_eq!(u32::from_be_bytes(resp_len), 1);
        client.read_exact(&mut resp_code).await.unwrap();
        assert_eq!(resp_code[0], SSH_AGENT_FAILURE);

        // 3. SSH2_AGENTC_SIGN_REQUEST with key length exceeding frame
        send_frame(
            &mut client,
            &[SSH2_AGENTC_SIGN_REQUEST, 0, 0, 1, 0, 1, 2, 3],
        )
        .await
        .unwrap();
        client.read_exact(&mut resp_len).await.unwrap();
        assert_eq!(u32::from_be_bytes(resp_len), 1);
        client.read_exact(&mut resp_code).await.unwrap();
        assert_eq!(resp_code[0], SSH_AGENT_FAILURE);

        // 4. SSH2_AGENTC_REMOVE_IDENTITY with truncated frame (< 5 bytes)
        send_frame(&mut client, &[SSH2_AGENTC_REMOVE_IDENTITY, 0, 0])
            .await
            .unwrap();
        client.read_exact(&mut resp_len).await.unwrap();
        assert_eq!(u32::from_be_bytes(resp_len), 1);
        client.read_exact(&mut resp_code).await.unwrap();
        assert_eq!(resp_code[0], SSH_AGENT_FAILURE);

        // 5. SSH2_AGENTC_REMOVE_IDENTITY with key not found
        let mut fake_rem = Vec::new();
        fake_rem.push(SSH2_AGENTC_REMOVE_IDENTITY);
        let fake_blob = b"not-a-real-ssh-key-blob-at-all";
        (fake_blob.len() as u32).encode(&mut fake_rem).unwrap();
        fake_rem.extend_from_slice(fake_blob);
        send_frame(&mut client, &fake_rem).await.unwrap();
        client.read_exact(&mut resp_len).await.unwrap();
        assert_eq!(u32::from_be_bytes(resp_len), 1);
        client.read_exact(&mut resp_code).await.unwrap();
        assert_eq!(resp_code[0], SSH_AGENT_FAILURE);

        // 6. SSH2_AGENTC_REMOVE_IDENTITY with approval denied
        mock_provider.set_approved(false);
        let mut rem_req = Vec::new();
        rem_req.push(SSH2_AGENTC_REMOVE_IDENTITY);
        (key_wire.len() as u32).encode(&mut rem_req).unwrap();
        rem_req.extend_from_slice(&key_wire);
        send_frame(&mut client, &rem_req).await.unwrap();
        client.read_exact(&mut resp_len).await.unwrap();
        assert_eq!(u32::from_be_bytes(resp_len), 1);
        client.read_exact(&mut resp_code).await.unwrap();
        assert_eq!(resp_code[0], SSH_AGENT_FAILURE);

        // 7. SSH2_AGENTC_REMOVE_ALL_IDENTITIES with approval denied
        send_frame(&mut client, &[SSH2_AGENTC_REMOVE_ALL_IDENTITIES])
            .await
            .unwrap();
        client.read_exact(&mut resp_len).await.unwrap();
        assert_eq!(u32::from_be_bytes(resp_len), 1);
        client.read_exact(&mut resp_code).await.unwrap();
        assert_eq!(resp_code[0], SSH_AGENT_FAILURE);

        // 8. SSH2_AGENTC_ADD_IDENTITY with approval denied
        let mut add_req = Vec::new();
        add_req.push(SSH2_AGENTC_ADD_IDENTITY);
        let mut keypair_bytes = Vec::new();
        pk.encode(&mut keypair_bytes).unwrap();
        add_req.extend_from_slice(&keypair_bytes);
        "test_comment".encode(&mut add_req).unwrap();
        send_frame(&mut client, &add_req).await.unwrap();
        client.read_exact(&mut resp_len).await.unwrap();
        assert_eq!(u32::from_be_bytes(resp_len), 1);
        client.read_exact(&mut resp_code).await.unwrap();
        assert_eq!(resp_code[0], SSH_AGENT_FAILURE);

        drop(client);
        let _ = handle.await;
    }
}
