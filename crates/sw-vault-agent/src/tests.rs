use super::*;
use russh::keys::ssh_encoding::{Decode, Encode};
use russh::keys::PrivateKey;
use std::path::Path;
use std::sync::Arc;
use sw_crypto::{encrypt_with, EncStringType, SymmetricKey};
use sw_systemauth::CallingContext;
use sw_vault::{Cipher, CipherType, Field, FieldType, SSHKeyCipher, VaultStore};
use tempfile::TempDir;
use uuid::Uuid;

fn make_test_key() -> SymmetricKey {
    SymmetricKey::from_bytes(&[0x42u8; 64]).unwrap()
}

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

const TEST_RSA_PUB: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDoc1caBbEz5UIUe8mm3PwYc+U6uA3y7Js9jqji7ghoLQ9Qov+hRIIdwRnl+7jDUxSPhVWTOI+1GbhxGefW2SwWcw49rBHKIIf2W4KpZutydXdjnQRWdzMJI8EEWPkUODgho6GupqTvsMHMGqjm04X+upGDAXF+fB1fNflSSvMOuqxyW8RZ41ZAhcs0KRcxAuLGCuswveL5yWDwltekjbLcdU4IQhherRFXAqGEcjrJs+hadjTNllfSgEVBFjfMmy9T+vBTCIzvoB3l++VIHRE7sPeea0U/nRI0WjV32OVL58+DsvDYv7UWF3niYi8bgEEUsUQzNp49SKcPyvgAZyX5 rsa-server";

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
    assert!(desc1
        .contains("hermes on alacritty>bash>git is requesting ssh signage with key work-laptop"));

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

#[tokio::test]
async fn test_sign_with_ecdsa_key() {
    use russh::keys::ssh_encoding::Encode;
    use russh::keys::ssh_key::{Algorithm, EcdsaCurve, LineEnding, Signature};

    let key = make_test_key();
    let vault = Arc::new(VaultStore::new());
    let agent = VaultAgentServer::new(vault);
    agent.unlock(key.try_clone().unwrap()).await;

    let mut rng = rand::rng();
    let pk = PrivateKey::random(
        &mut rng,
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        },
    )
    .unwrap();
    let pem = pk.to_openssh(LineEnding::LF).unwrap().to_string();

    agent
        .add_ssh_key(&pem, "test-ecdsa", &key)
        .await
        .expect("Failed to add ECDSA key");

    let mut wire_blob = Vec::new();
    pk.public_key().key_data().encode(&mut wire_blob).unwrap();

    let data = b"SilverWarden ECDSA test payload";
    let sig_blob = agent
        .sign_with_key(&wire_blob, data, 0)
        .await
        .expect("ECDSA signing failed");
    assert!(!sig_blob.is_empty());

    let sig = Signature::decode(&mut sig_blob.as_slice()).expect("Decode signature failed");
    assert_eq!(sig.algorithm().as_str(), "ecdsa-sha2-nistp256");

    use russh::keys::signature::Verifier;
    pk.public_key()
        .key_data()
        .verify(data, &sig)
        .expect("ECDSA signature verification failed");
}

#[tokio::test]
async fn test_list_with_rsa_key() {
    let key = make_test_key();
    let vault = Arc::new(VaultStore::new());
    let agent = VaultAgentServer::new(vault);
    agent.unlock(key.try_clone().unwrap()).await;

    agent
        .add_ssh_key(TEST_RSA_PEM, "rsa-listed-key", &key)
        .await
        .expect("Failed to add RSA key");

    let list = agent.list_ssh_keys().await.expect("List keys failed");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].name, "rsa-listed-key");
    assert!(list[0].public_key.starts_with("ssh-rsa"));
    assert!(list[0].fingerprint.starts_with("SHA256:"));
}

#[tokio::test]
async fn test_import_rsa_key() {
    let key = make_test_key();
    let vault = Arc::new(VaultStore::new());
    let agent = VaultAgentServer::new(vault);
    agent.unlock(key.try_clone().unwrap()).await;

    let summary = agent
        .import_ssh_key("imported-rsa", TEST_RSA_PEM, &key)
        .await
        .expect("Import RSA key failed");

    assert_eq!(summary.name, "imported-rsa");
    assert!(summary.public_key.starts_with("ssh-rsa"));
    assert!(summary.id.is_some());

    let list = agent.list_ssh_keys().await.expect("List keys failed");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].name, "imported-rsa");
}

#[tokio::test]
async fn test_import_ecdsa_key() {
    use russh::keys::ssh_key::{Algorithm, EcdsaCurve, LineEnding};

    let key = make_test_key();
    let vault = Arc::new(VaultStore::new());
    let agent = VaultAgentServer::new(vault);
    agent.unlock(key.try_clone().unwrap()).await;

    let mut rng = rand::rng();
    let pk = PrivateKey::random(
        &mut rng,
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        },
    )
    .unwrap();
    let pem = pk.to_openssh(LineEnding::LF).unwrap().to_string();

    let summary = agent
        .import_ssh_key("imported-ecdsa", &pem, &key)
        .await
        .expect("Import ECDSA key failed");

    assert_eq!(summary.name, "imported-ecdsa");
    assert!(summary.public_key.starts_with("ecdsa-sha2-nistp256"));
    assert!(summary.id.is_some());

    let list = agent.list_ssh_keys().await.expect("List keys failed");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].name, "imported-ecdsa");
}

#[tokio::test]
async fn test_import_unsupported_key_type() {
    let key = make_test_key();
    let vault = Arc::new(VaultStore::new());
    let agent = VaultAgentServer::new(vault);
    agent.unlock(key.try_clone().unwrap()).await;

    let res_invalid = agent
        .import_ssh_key("invalid-key", "NOT_A_VALID_KEY_PEM", &key)
        .await;
    assert!(matches!(res_invalid, Err(SshAgentError::KeyError(_))));

    let res_dsa_new = agent.new_ssh_key("dsa-key", "dsa", &key).await;
    assert!(matches!(res_dsa_new, Err(SshAgentError::KeyError(_))));
}

#[tokio::test]
async fn test_add_key_with_passphrase() {
    const ENCRYPTED_OPENSSH_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\n\
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABB2rz6jGv\n\
xsDha4R8WJMFswAAAAIAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIKv16mdUNbzCXhmp\n\
59Yk2E+yAWxRCHAxzPa/Da6Ic/ffAAAAkH67YsXg7XWyI++7vzYYV8N0GyLhljwwe17U79\n\
F/ArF9GZc1s0c3v+O0XWCYNA77nx9yZtGoZncHXmVZXu5VIECIL9Mr61pbX31Jwi3B/Hui\n\
iDyhCsdzcCa6WF4d3xRh9HyDsj2hWCN+OHNfhBxubuY/hyjtBj+lrp3GsBTU3teastrjl9\n\
OaGPv7jRnKvmNDiw==\n\
-----END OPENSSH PRIVATE KEY-----";

    let key = make_test_key();
    let vault = Arc::new(VaultStore::new());
    let agent = VaultAgentServer::new(vault);
    agent.unlock(key.try_clone().unwrap()).await;

    let res_add = agent
        .add_ssh_key(ENCRYPTED_OPENSSH_KEY, "enc-key", &key)
        .await;
    assert!(matches!(res_add, Err(SshAgentError::KeyError(_))));

    let res_import = agent
        .import_ssh_key("enc-key", ENCRYPTED_OPENSSH_KEY, &key)
        .await;
    assert!(matches!(res_import, Err(SshAgentError::KeyError(_))));
}

#[tokio::test]
async fn test_pinentry_runner_and_mock_provider() {
    let temp_dir = TempDir::new().unwrap();
    let script_path = temp_dir.path().join("mock_pinentry.sh");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(
            &script_path,
            "#!/bin/sh\n\
            echo 'OK Pleased to meet you'\n\
            while read line; do\n\
              case \"$line\" in\n\
                CONFIRM*)\n\
                  if [ \"$PINENTRY_FAIL\" = \"1\" ]; then\n\
                    echo 'ERR 123 User cancelled'\n\
                  else\n\
                    echo 'OK'\n\
                  fi\n\
                  ;;\n\
                BYE*)\n\
                  echo 'OK'\n\
                  exit 0\n\
                  ;;\n\
                *)\n\
                  echo 'OK'\n\
                  ;;\n\
              esac\n\
            done\n",
        )
        .unwrap();
        std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    // Test run_pinentry_confirm OK
    assert!(run_pinentry_confirm(&script_path, "Title\n", "Desc\r\n").unwrap());

    // Test DefaultApprovalProvider with custom bin
    let provider = DefaultApprovalProvider::with_custom_bin(script_path.clone());
    assert!(provider.get_approval("Title", "Description").unwrap());

    // Test run_pinentry_confirm ERR
    unsafe {
        std::env::set_var("PINENTRY_FAIL", "1");
    }
    assert!(!run_pinentry_confirm(&script_path, "Title", "Desc").unwrap());
    unsafe {
        std::env::remove_var("PINENTRY_FAIL");
    }

    // Test run_pinentry_confirm exit immediately (broken pinentry)
    let broken_path = temp_dir.path().join("broken_pinentry.sh");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(&broken_path, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&broken_path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    assert!(run_pinentry_confirm(&broken_path, "Title", "Desc").is_err());

    // Test run_pinentry_confirm spawn error
    assert!(run_pinentry_confirm(Path::new("/nonexistent/bin/path"), "Title", "Desc").is_err());

    // Test MockApprovalProvider set_approved
    let mock = Arc::new(MockApprovalProvider::new(true));
    assert!(mock.get_approval("T", "D").unwrap());
    mock.set_approved(false);
    assert!(!mock.get_approval("T", "D").unwrap());
    mock.set_approved(true);
    assert!(mock.get_approval("T", "D").unwrap());
}

#[tokio::test]
async fn test_vault_agent_locked_and_edge_branches() {
    let store = Arc::new(VaultStore::new());
    let agent = VaultAgentServer::new(store.clone());

    // Check is_locked on empty agent
    assert!(agent.is_locked());

    // request_identities when locked
    let ids = agent.request_identities().await.unwrap();
    assert!(ids.is_empty());

    // sign_with_key when locked
    let sign_res = agent.sign_with_key(b"keyblob", b"data", 0).await;
    assert!(matches!(sign_res, Err(SshAgentError::VaultLocked)));

    // delete_ssh_key when locked
    let del_res = agent.delete_ssh_key(&Uuid::new_v4()).await;
    assert!(matches!(del_res, Err(SshAgentError::VaultLocked)));

    // Unlock agent
    let key = make_test_key();
    agent.unlock(key).await;
    assert!(!agent.is_locked());

    // delete_ssh_key when unlocked but not found
    let del_res2 = agent.delete_ssh_key(&Uuid::new_v4()).await;
    assert!(del_res2.is_ok());
}

#[tokio::test]
async fn test_request_identities_combines_type5_and_legacy_notes() {
    let key = make_test_key();
    let (vault, (_, pub_1), (_, pub_2)) = setup_test_vault_with_keys(&key).await;
    let agent = VaultAgentServer::new(vault);
    agent.unlock(key.try_clone().unwrap()).await;

    let identities = agent.request_identities().await.unwrap();
    assert_eq!(
        identities.len(),
        2,
        "request_identities must combine both Type 5 and legacy notes"
    );

    let mut comments: Vec<String> = identities
        .iter()
        .map(|id| match id {
            AgentIdentity::PublicKey { comment, .. } => comment.clone(),
            AgentIdentity::Certificate { comment, .. } => comment.clone(),
        })
        .collect();
    comments.sort();
    assert_eq!(comments, vec!["personal-server", "work-laptop"]);

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
}

#[tokio::test]
async fn test_sign_notifies_on_success() {
    let key = make_test_key();
    let (vault, (priv_1, _), _) = setup_test_vault_with_keys(&key).await;
    let mock_notifier = Arc::new(sw_notify::MockNotifier::new());
    let agent = VaultAgentServer::with_key(vault, key)
        .with_approval_provider(Arc::new(MockApprovalProvider::new(true)))
        .with_notifier(mock_notifier.clone());

    let pk = PrivateKey::from_openssh(&priv_1).unwrap();
    let mut key_blob = Vec::new();
    pk.public_key().key_data().encode(&mut key_blob).unwrap();

    let sig = agent
        .sign_with_key_context(&key_blob, b"data_to_sign", 0, None)
        .await
        .unwrap();
    assert!(!sig.is_empty());

    let notifs = mock_notifier.notifications();
    assert_eq!(notifs.len(), 1);
    assert_eq!(notifs[0].0, "SilverWarden");
    assert!(notifs[0].1.contains("Firma SSH con clave 'work-laptop'"));
}

#[tokio::test]
async fn test_sign_succeeds_even_if_notifier_fails() {
    let key = make_test_key();
    let (vault, (priv_1, _), _) = setup_test_vault_with_keys(&key).await;
    let mock_notifier = Arc::new(sw_notify::MockNotifier::failing());
    let agent = VaultAgentServer::with_key(vault, key)
        .with_approval_provider(Arc::new(MockApprovalProvider::new(true)))
        .with_notifier(mock_notifier.clone());

    let pk = PrivateKey::from_openssh(&priv_1).unwrap();
    let mut key_blob = Vec::new();
    pk.public_key().key_data().encode(&mut key_blob).unwrap();

    let sig = agent
        .sign_with_key_context(&key_blob, b"data_to_sign", 0, None)
        .await
        .expect("Signing should succeed even if notifier fails (silent fallback)");
    assert!(!sig.is_empty());
    assert!(mock_notifier.notifications().is_empty());
}
