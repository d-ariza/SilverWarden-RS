use super::*;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;

#[tokio::test]
async fn test_agent_socket_actions_flow() {
    let temp_dir = tempfile::tempdir().expect("Create temp dir");
    let socket_path = temp_dir.path().join(".silverwarden.sock");

    let test_pin = "agent_test_pin_987";
    let test_salt = "agent_uuid_test";
    let derived_key =
        sw_config::derive_config_key_with_params(test_pin, test_salt, AGENT_KDF_MEMORY_KIB)
            .unwrap();
    let config = ConfigFile {
        device_uuid: test_salt.to_string(),
        config_key_hash: sw_config::hash_config_key(&derived_key),
        ..Default::default()
    };

    let daemon = AgentDaemon::with_state(
        AgentState::new(config, Arc::new(VaultAgentServer::default()))
            .with_config_directory(temp_dir.path()),
    );
    let daemon_clone = daemon.clone();
    let agent_socket = socket_path.clone();

    let listener = bind_socket(&socket_path).await.unwrap();
    let agent_task = tokio::spawn(async move {
        accept_loop(listener, daemon_clone, &agent_socket, std::future::pending()).await
    });

    let mut stream = UnixStream::connect(&socket_path)
        .await
        .expect("Client should successfully connect to agent socket");

    // 1. Send Status request
    let status_req = Request::Status;
    write_message(&mut stream, &status_req).await.unwrap();
    let status_resp: Response = read_message(&mut stream).await.unwrap();
    assert!(status_resp.is_ok());
    let status_payload = status_resp.unwrap_ok().unwrap();
    assert_eq!(status_payload["locked"], true);
    assert_eq!(status_payload["has_pin"], true);

    // 2. Unlock with wrong PIN -> should fail
    let wrong_unlock_req = Request::Unlock {
        pin: Some("wrong_pin".into()),
    };
    write_message(&mut stream, &wrong_unlock_req).await.unwrap();
    let wrong_resp: Response = read_message(&mut stream).await.unwrap();
    assert!(wrong_resp.is_err());

    // 3. Unlock with correct PIN -> should succeed
    let unlock_req = Request::Unlock {
        pin: Some(test_pin.into()),
    };
    write_message(&mut stream, &unlock_req).await.unwrap();
    let unlock_resp: Response = read_message(&mut stream).await.unwrap();
    assert!(unlock_resp.is_ok());
    let unlock_payload = unlock_resp.unwrap_ok().unwrap();
    assert_eq!(unlock_payload["status"], "unlocked");

    // Status after unlock -> locked must be false
    write_message(&mut stream, &status_req).await.unwrap();
    let status_after_unlock: Response = read_message(&mut stream).await.unwrap();
    let status_after_payload = status_after_unlock.unwrap_ok().unwrap();
    assert_eq!(status_after_payload["locked"], false);

    // 4. Send Lock request
    let lock_req = Request::Lock;
    write_message(&mut stream, &lock_req).await.unwrap();
    let lock_resp: Response = read_message(&mut stream).await.unwrap();
    assert!(lock_resp.is_ok());
    let lock_payload = lock_resp.unwrap_ok().unwrap();
    assert_eq!(lock_payload["status"], "locked");

    // 5. Send AgentShutdown request to stop the daemon
    let shutdown_req = Request::AgentShutdown;
    write_message(&mut stream, &shutdown_req).await.unwrap();
    let shutdown_resp: Response = read_message(&mut stream).await.unwrap();
    assert!(shutdown_resp.is_ok());
    let shutdown_payload = shutdown_resp.unwrap_ok().unwrap();
    assert_eq!(shutdown_payload["status"], "shutting_down");

    let agent_res = agent_task.await.expect("Agent task completed");
    assert!(agent_res.is_ok());
    assert!(!socket_path.exists());
}

#[tokio::test]
async fn test_actions_registry_direct() {
    let temp_dir = tempfile::tempdir().unwrap();
    let mut state = AgentState::default().with_config_directory(temp_dir.path());
    assert!(!state.session.has_pin);

    let registry = default_registry();
    let ctx = CallingContext {
        username: "tester".into(),
        process_name: "test".into(),
        parent_process_name: "test_runner".into(),
        grandparent_process_name: "cargo".into(),
        process_pid: 10,
        parent_process_pid: 5,
        grandparent_process_pid: 1,
        error: false,
        authenticated: true,
    };

    // Status on unconfigured agent
    let status_res = registry
        .execute("Status", &mut state, &ctx, &serde_json::json!({}))
        .await
        .unwrap();
    assert_eq!(status_res["has_pin"], false);
    assert_eq!(status_res["locked"], true);

    // PinSet
    let pin_set_res = registry
        .execute(
            "PinSet",
            &mut state,
            &ctx,
            &serde_json::json!({ "pin": "initial_pin_123" }),
        )
        .await
        .unwrap();
    assert_eq!(pin_set_res["status"], "pin_set");
    assert!(state.session.has_pin);

    // Second PinSet should fail
    assert!(registry
        .execute(
            "PinSet",
            &mut state,
            &ctx,
            &serde_json::json!({ "pin": "other_pin" })
        )
        .await
        .is_err());

    // Unlock with wrong PIN
    assert!(registry
        .execute(
            "Unlock",
            &mut state,
            &ctx,
            &serde_json::json!({ "pin": "bad_pin" })
        )
        .await
        .is_err());

    // Unlock with correct PIN
    let unlock_res = registry
        .execute(
            "Unlock",
            &mut state,
            &ctx,
            &serde_json::json!({ "pin": "initial_pin_123" }),
        )
        .await
        .unwrap();
    assert_eq!(unlock_res["status"], "unlocked");
    assert!(!state.session.is_locked);
    assert!(state
        .session
        .sessions
        .verify_session(&ctx, SessionType::AccessVault));

    // PinUpdate
    let update_res = registry
        .execute(
            "PinUpdate",
            &mut state,
            &ctx,
            &serde_json::json!({
                "old_pin": "initial_pin_123",
                "new_pin": "new_pin_456"
            }),
        )
        .await
        .unwrap();
    assert_eq!(update_res["status"], "pin_updated");

    // Verify old PIN no longer unlocks
    assert!(registry
        .execute(
            "Unlock",
            &mut state,
            &ctx,
            &serde_json::json!({ "pin": "initial_pin_123" })
        )
        .await
        .is_err());

    // New PIN unlocks
    assert!(registry
        .execute(
            "Unlock",
            &mut state,
            &ctx,
            &serde_json::json!({ "pin": "new_pin_456" })
        )
        .await
        .is_ok());

    // Lock wipes sessions
    let lock_res = registry
        .execute("Lock", &mut state, &ctx, &serde_json::json!({}))
        .await
        .unwrap();
    assert_eq!(lock_res["status"], "locked");
    assert!(state.session.is_locked);
    assert!(!state
        .session
        .sessions
        .verify_session(&ctx, SessionType::AccessVault));

    // Unknown action
    let unknown_res = registry
        .execute("NonExistent", &mut state, &ctx, &serde_json::json!({}))
        .await;
    assert!(unknown_res.is_err());
}

#[tokio::test]
async fn test_agent_orphan_socket_removal() {
    let temp_dir = tempfile::tempdir().expect("Create temp dir");
    let socket_path = temp_dir.path().join("orphan.sock");

    std::fs::write(&socket_path, b"orphaned socket content").unwrap();
    assert!(socket_path.exists());

    let res = check_and_prepare_socket(&socket_path).await;
    assert!(res.is_ok());
    assert!(!socket_path.exists());

    // Socket does not exist -> Ok
    let non_existent = temp_dir.path().join("does_not_exist.sock");
    assert!(check_and_prepare_socket(&non_existent).await.is_ok());

    // Socket already in use -> SocketAlreadyInUse
    let active_path = temp_dir.path().join("active.sock");
    let listener = tokio::net::UnixListener::bind(&active_path).unwrap();
    let in_use = check_and_prepare_socket(&active_path).await;
    assert!(matches!(in_use, Err(AgentError::SocketAlreadyInUse(_))));
    drop(listener);
}

#[test]
fn test_default_socket_path() {
    let path = default_socket_path().expect("Default socket path succeeds");
    assert!(path.to_string_lossy().contains(".silverwarden.sock"));

    let custom = socket_path_from_home(Some("/custom/home")).unwrap();
    assert_eq!(custom, PathBuf::from("/custom/home/.silverwarden.sock"));
}

#[test]
fn test_agent_error_display() {
    let io_err = AgentError::Io(std::io::Error::new(
        std::io::ErrorKind::AddrInUse,
        "address in use",
    ));
    assert!(io_err.to_string().contains("address in use"));

    let collision = AgentError::SocketAlreadyInUse(PathBuf::from("/test.sock"));
    assert!(collision.to_string().contains("ya está en uso"));

    let other = AgentError::Other("custom msg".to_string());
    assert!(other.to_string().contains("custom msg"));

    let ipc = AgentError::from(sw_ipc::IpcError::Protocol("bad payload".into()));
    assert!(ipc.to_string().contains("bad payload"));
}

#[tokio::test]
async fn test_agent_daemon_handle_message() {
    let daemon = AgentDaemon::default();
    let ctx = CallingContext {
        username: "tester".into(),
        process_name: "test".into(),
        parent_process_name: "parent".into(),
        grandparent_process_name: "grandparent".into(),
        process_pid: 1,
        parent_process_pid: 2,
        grandparent_process_pid: 3,
        error: false,
        authenticated: true,
    };
    let ok_msg = daemon.handle_message(&ctx, Request::Status).await;
    assert!(ok_msg.is_ok());
    let err_msg = daemon.handle_message(&ctx, Request::ListLogins).await;
    assert!(err_msg.is_err());
}

#[tokio::test]
async fn test_run_agent_entrypoint_error() {
    let res = run_agent(
        Path::new("/proc/impossible/agent.sock"),
        Arc::new(VaultAgentServer::default()),
    )
    .await;
    assert!(res.is_err());
}

#[tokio::test]
async fn test_agent_corrupted_message_handled() {
    let temp_dir = tempfile::tempdir().expect("Create temp dir");
    let socket_path = temp_dir.path().join("corrupted.sock");
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let agent_socket = socket_path.clone();

    let listener = bind_socket(&socket_path).await.unwrap();
    let handle = tokio::spawn(async move {
        let daemon = AgentDaemon::default();
        let _ = accept_loop(listener, daemon, &agent_socket, async {
            let _ = shutdown_rx.await;
        })
        .await;
    });

    let mut stream = UnixStream::connect(&socket_path).await.unwrap();
    let _ = stream.write_all(&[0, 0, 0, 10, 1, 2]).await;

    let _ = shutdown_tx.send(());
    let _ = handle.await;
}

#[tokio::test]
async fn test_ssh_actions_full_lifecycle() {
    use sw_crypto::SymmetricKey;
    use sw_vault::VaultStore;

    let key = SymmetricKey::from_bytes(&[42u8; 64]).unwrap();
    let vault = Arc::new(VaultStore::new());
    let vault_agent = Arc::new(VaultAgentServer::new(vault.clone()));

    let mut state = AgentState::default().with_vault_agent(vault_agent.clone());
    let registry = default_registry_with_ssh(vault_agent.clone());
    let ctx = CallingContext {
        username: "tester".into(),
        process_name: "test".into(),
        parent_process_name: "test_runner".into(),
        grandparent_process_name: "cargo".into(),
        process_pid: 10,
        parent_process_pid: 5,
        grandparent_process_pid: 1,
        error: false,
        authenticated: true,
    };

    // 1. Locked: all SSH actions fail with Locked
    let res = registry
        .execute("ListSSHKeys", &mut state, &ctx, &serde_json::json!({}))
        .await;
    assert!(res.is_err());
    assert_eq!(res.unwrap_err(), AgentError::Locked);

    let res = registry
        .execute(
            "ImportSSHKey",
            &mut state,
            &ctx,
            &serde_json::json!({ "name": "foo", "private_key_pem": "bar" }),
        )
        .await;
    assert_eq!(res.unwrap_err(), AgentError::Locked);

    let res = registry
        .execute(
            "NewSSHKey",
            &mut state,
            &ctx,
            &serde_json::json!({ "name": "foo" }),
        )
        .await;
    assert_eq!(res.unwrap_err(), AgentError::Locked);

    let res = registry
        .execute(
            "DeleteSSHKey",
            &mut state,
            &ctx,
            &serde_json::json!({ "id": uuid::Uuid::new_v4().to_string() }),
        )
        .await;
    assert_eq!(res.unwrap_err(), AgentError::Locked);

    // 2. Unlock vault agent
    vault_agent.unlock(key.try_clone().unwrap()).await;

    // 3. test_list_ssh_keys empty initially
    let list_val = registry
        .execute("ListSSHKeys", &mut state, &ctx, &serde_json::json!({}))
        .await
        .unwrap();
    let list: Vec<serde_json::Value> = serde_json::from_value(list_val).unwrap();
    assert!(list.is_empty());

    // 4. test_new_ssh_key_ed25519
    let ed_val = registry
        .execute(
            "NewSSHKey",
            &mut state,
            &ctx,
            &serde_json::json!({ "name": "ed-key-1", "key_type": "Ed25519" }),
        )
        .await
        .unwrap();
    assert_eq!(ed_val["name"], "ed-key-1");
    assert!(ed_val["fingerprint"]
        .as_str()
        .unwrap()
        .starts_with("SHA256:"));
    assert!(ed_val["public_key"]
        .as_str()
        .unwrap()
        .starts_with("ssh-ed25519"));
    assert!(ed_val.get("private_key").is_none());
    let ed_id = ed_val["id"].as_str().unwrap().to_string();

    // 5. test_new_ssh_key_rsa
    let rsa_val = registry
        .execute(
            "NewSSHKey",
            &mut state,
            &ctx,
            &serde_json::json!({ "name": "rsa-key-1", "key_type": "RSA" }),
        )
        .await
        .unwrap();
    assert_eq!(rsa_val["name"], "rsa-key-1");
    assert!(rsa_val["public_key"]
        .as_str()
        .unwrap()
        .starts_with("ssh-rsa"));

    // 6. test_list_ssh_keys: vault with 2 keys, ListSSHKeys returns 2
    let list_val = registry
        .execute("ListSSHKeys", &mut state, &ctx, &serde_json::json!({}))
        .await
        .unwrap();
    let list: Vec<serde_json::Value> = serde_json::from_value(list_val).unwrap();
    assert_eq!(list.len(), 2);

    // 7. test_list_ssh_keys_never_returns_private
    for item in &list {
        assert!(item.get("private_key").is_none());
        assert!(item.get("private_key_pem").is_none());
        let pub_str = item["public_key"].as_str().unwrap();
        assert!(!pub_str.contains("PRIVATE KEY"));
    }

    // 8. test_import_ssh_key
    let keypair = russh::keys::ssh_key::private::KeypairData::Ed25519(
        russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&[77u8; 32]),
    );
    let pk = russh::keys::PrivateKey::new(keypair, "imported-key").unwrap();
    let ed25519_pem = pk
        .to_openssh(russh::keys::ssh_key::LineEnding::LF)
        .unwrap()
        .to_string();
    let import_val = registry
        .execute(
            "ImportSSHKey",
            &mut state,
            &ctx,
            &serde_json::json!({
                "name": "imported-key",
                "private_key_pem": ed25519_pem
            }),
        )
        .await
        .unwrap();
    assert_eq!(import_val["name"], "imported-key");
    assert!(import_val["public_key"]
        .as_str()
        .unwrap()
        .starts_with("ssh-ed25519"));

    // Now 3 keys in vault
    let list_val = registry
        .execute("ListSSHKeys", &mut state, &ctx, &serde_json::json!({}))
        .await
        .unwrap();
    let list: Vec<serde_json::Value> = serde_json::from_value(list_val).unwrap();
    assert_eq!(list.len(), 3);

    // 9. test_delete_ssh_key
    let del_val = registry
        .execute(
            "DeleteSSHKey",
            &mut state,
            &ctx,
            &serde_json::json!({ "id": ed_id }),
        )
        .await
        .unwrap();
    assert_eq!(del_val["status"], "deleted");
    assert_eq!(del_val["id"], ed_id);

    let list_val = registry
        .execute("ListSSHKeys", &mut state, &ctx, &serde_json::json!({}))
        .await
        .unwrap();
    let list: Vec<serde_json::Value> = serde_json::from_value(list_val).unwrap();
    assert_eq!(list.len(), 2);
    assert!(!list.iter().any(|k| k["id"] == ed_id));

    // 10. Lock via registry also locks vault agent
    let lock_val = registry
        .execute("Lock", &mut state, &ctx, &serde_json::json!({}))
        .await
        .unwrap();
    assert_eq!(lock_val["status"], "locked");
    assert!(vault_agent.is_locked());
}

#[tokio::test]
async fn test_ssh_actions_daemon_ipc_messages() {
    use sw_crypto::SymmetricKey;
    use sw_vault::VaultStore;

    let key = SymmetricKey::from_bytes(&[77u8; 64]).unwrap();
    let vault = Arc::new(VaultStore::new());
    let vault_agent = Arc::new(VaultAgentServer::new(vault.clone()));
    vault_agent.unlock(key).await;

    let state = AgentState::default().with_vault_agent(vault_agent.clone());
    let daemon = AgentDaemon::with_vault_agent(state, vault_agent);
    let ctx = CallingContext {
        username: "tester".into(),
        process_name: "test".into(),
        parent_process_name: "test_runner".into(),
        grandparent_process_name: "cargo".into(),
        process_pid: 10,
        parent_process_pid: 5,
        grandparent_process_pid: 1,
        error: false,
        authenticated: true,
    };

    // Create key via handle_message
    let req = Request::NewSshKey {
        name: "daemon-key".into(),
        key_type: "Ed25519".into(),
    };
    let resp = daemon.handle_message(&ctx, req).await;
    assert!(resp.is_ok());
    let val = resp.unwrap_ok().unwrap();
    assert_eq!(val["name"], "daemon-key");

    // List keys via handle_message
    let list_resp = daemon.handle_message(&ctx, Request::ListSshKeys).await;
    assert!(list_resp.is_ok());
    let list_val = list_resp.unwrap_ok().unwrap();
    assert_eq!(list_val.as_array().unwrap().len(), 1);

    // Import key via handle_message
    let keypair = russh::keys::ssh_key::private::KeypairData::Ed25519(
        russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&[33u8; 32]),
    );
    let pk = russh::keys::PrivateKey::new(keypair, "daemon-imported").unwrap();
    let pem = pk
        .to_openssh(russh::keys::ssh_key::LineEnding::LF)
        .unwrap()
        .to_string();
    let imp_req = Request::ImportSshKey {
        name: "daemon-imported".into(),
        pem,
    };
    let imp_resp = daemon.handle_message(&ctx, imp_req).await;
    assert!(imp_resp.is_ok());
    let imp_val = imp_resp.unwrap_ok().unwrap();
    let imp_id = imp_val["id"].as_str().unwrap();

    // Delete key via handle_message
    let del_req = Request::DeleteSshKey {
        id: imp_id.to_string(),
    };
    let del_resp = daemon.handle_message(&ctx, del_req).await;
    assert!(del_resp.is_ok());
}

#[tokio::test]
async fn test_ssh_actions_invalid_payloads() {
    use sw_crypto::SymmetricKey;
    use sw_vault::VaultStore;

    let key = SymmetricKey::from_bytes(&[88u8; 64]).unwrap();
    let vault = Arc::new(VaultStore::new());
    let vault_agent = Arc::new(VaultAgentServer::new(vault.clone()));
    vault_agent.unlock(key).await;

    let mut state = AgentState::default().with_vault_agent(vault_agent.clone());
    let registry = default_registry_with_ssh(vault_agent);
    let ctx = CallingContext {
        username: "tester".into(),
        process_name: "test".into(),
        parent_process_name: "test_runner".into(),
        grandparent_process_name: "cargo".into(),
        process_pid: 10,
        parent_process_pid: 5,
        grandparent_process_pid: 1,
        error: false,
        authenticated: true,
    };

    // ImportSSHKey missing name
    let res = registry
        .execute(
            "ImportSSHKey",
            &mut state,
            &ctx,
            &serde_json::json!({ "private_key_pem": "abc" }),
        )
        .await;
    assert!(res.is_err());

    // ImportSSHKey missing private_key_pem
    let res = registry
        .execute(
            "ImportSSHKey",
            &mut state,
            &ctx,
            &serde_json::json!({ "name": "my-key" }),
        )
        .await;
    assert!(res.is_err());

    // ImportSSHKey non-object payload
    let res = registry
        .execute(
            "ImportSSHKey",
            &mut state,
            &ctx,
            &serde_json::json!("string"),
        )
        .await;
    assert!(res.is_err());

    // NewSSHKey missing name
    let res = registry
        .execute(
            "NewSSHKey",
            &mut state,
            &ctx,
            &serde_json::json!({ "key_type": "RSA" }),
        )
        .await;
    assert!(res.is_err());

    // NewSSHKey non-object
    let res = registry
        .execute("NewSSHKey", &mut state, &ctx, &serde_json::json!(42))
        .await;
    assert!(res.is_err());

    // DeleteSSHKey missing id
    let res = registry
        .execute(
            "DeleteSSHKey",
            &mut state,
            &ctx,
            &serde_json::json!({ "not_id": "foo" }),
        )
        .await;
    assert!(res.is_err());

    // DeleteSSHKey invalid UUID
    let res = registry
        .execute(
            "DeleteSSHKey",
            &mut state,
            &ctx,
            &serde_json::json!({ "id": "not-a-uuid" }),
        )
        .await;
    assert!(res.is_err());

    // DeleteSSHKey non-object non-string
    let res = registry
        .execute("DeleteSSHKey", &mut state, &ctx, &serde_json::json!(false))
        .await;
    assert!(res.is_err());

    // Unconfigured vault agent error
    let mut unconf_state = AgentState::default();
    let unconf_reg = default_registry();
    let res = unconf_reg
        .execute(
            "ListSSHKeys",
            &mut unconf_state,
            &ctx,
            &serde_json::json!({}),
        )
        .await;
    assert!(res.is_err());
    assert_eq!(res.unwrap_err(), AgentError::Locked);
}

#[tokio::test]
async fn test_agent_state_load_or_default_and_save_config() {
    let temp_dir = tempfile::tempdir().unwrap();
    let config_file = temp_dir.path().join("goldwarden.json");

    let config = ConfigFile {
        device_uuid: "test-device-uuid-123".into(),
        ..Default::default()
    };
    save_config_file(&config, &config_file).expect("Failed to save config");
    assert!(config_file.exists());

    let loaded_state = AgentState::load_or_default_from(Some(temp_dir.path().to_path_buf()));
    assert_eq!(loaded_state.services.config.device_uuid, "test-device-uuid-123");

    // Test with invalid json in config file
    std::fs::write(&config_file, b"not json").unwrap();
    let fallback_state = AgentState::load_or_default_from(Some(temp_dir.path().to_path_buf()));
    assert_ne!(fallback_state.services.config.device_uuid, "test-device-uuid-123");

    // Test when config path is a directory (read_to_string fails)
    let _ = std::fs::remove_file(&config_file);
    std::fs::create_dir(&config_file).unwrap();
    let dir_fallback = AgentState::load_or_default_from(Some(temp_dir.path().to_path_buf()));
    assert_ne!(dir_fallback.services.config.device_uuid, "test-device-uuid-123");
    let _ = std::fs::remove_dir(&config_file);

    // Test with empty dir where config doesn't exist
    let empty_dir = tempfile::tempdir().unwrap();
    let empty_fallback = AgentState::load_or_default_from(Some(empty_dir.path().to_path_buf()));
    assert!(!empty_fallback.services.config.device_uuid.is_empty());
    assert_ne!(empty_fallback.services.config.device_uuid, "test-device-uuid-123");

    // Test when config_dir is None (load_or_default)
    let no_home_fallback = AgentState::load_or_default();
    assert!(!no_home_fallback.services.config.device_uuid.is_empty());

    // Test save_config_file with relative path without parent
    let rel_path = Path::new("temp_test_local_cfg.json");
    assert!(save_config_file(&ConfigFile::default(), rel_path).is_ok());
    let _ = std::fs::remove_file(rel_path);
}

#[tokio::test]
async fn test_run_agent_with_shutdown_signal_clean() {
    let temp_dir = tempfile::tempdir().expect("Create temp dir");
    let socket_path = temp_dir.path().join("clean_shutdown.sock");
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();

    let listener = bind_socket(&socket_path).await.unwrap();
    assert!(socket_path.exists());
    let sock = socket_path.clone();
    let handle = tokio::spawn(async move {
        let daemon = AgentDaemon::default();
        accept_loop(listener, daemon, &sock, async {
            let _ = rx.await;
        })
        .await
    });

    let _ = tx.send(());
    let res = handle.await.unwrap();
    assert!(res.is_ok());
    assert!(!socket_path.exists());
}

#[tokio::test]
async fn test_default_registry_with_vault_agent_in_state() {
    use sw_crypto::SymmetricKey;
    use sw_vault::VaultStore;

    let key = SymmetricKey::from_bytes(&[99u8; 64]).unwrap();
    let vault = Arc::new(VaultStore::new());
    let vault_agent = Arc::new(VaultAgentServer::new(vault.clone()));
    vault_agent.unlock(key).await;

    let mut state = AgentState::default().with_vault_agent(vault_agent.clone());
    let registry = default_registry();
    let ctx = CallingContext {
        username: "tester".into(),
        process_name: "test".into(),
        parent_process_name: "test_runner".into(),
        grandparent_process_name: "cargo".into(),
        process_pid: 10,
        parent_process_pid: 5,
        grandparent_process_pid: 1,
        error: false,
        authenticated: true,
    };

    // List keys
    let list = registry
        .execute("ListSSHKeys", &mut state, &ctx, &serde_json::json!({}))
        .await
        .unwrap();
    assert_eq!(list.as_array().unwrap().len(), 0);

    // New key
    let new_key = registry
        .execute(
            "NewSSHKey",
            &mut state,
            &ctx,
            &serde_json::json!({ "name": "state-key", "key_type": "Ed25519" }),
        )
        .await
        .unwrap();
    assert_eq!(new_key["name"], "state-key");
    let key_id = new_key["id"].as_str().unwrap().to_string();

    // Import key
    let keypair = russh::keys::ssh_key::private::KeypairData::Ed25519(
        russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&[55u8; 32]),
    );
    let pk = russh::keys::PrivateKey::new(keypair, "state-imported").unwrap();
    let pem = pk
        .to_openssh(russh::keys::ssh_key::LineEnding::LF)
        .unwrap()
        .to_string();
    let imported = registry
        .execute(
            "ImportSSHKey",
            &mut state,
            &ctx,
            &serde_json::json!({ "name": "state-imported", "private_key_pem": pem }),
        )
        .await
        .unwrap();
    assert_eq!(imported["name"], "state-imported");

    // Delete key
    let del = registry
        .execute(
            "DeleteSSHKey",
            &mut state,
            &ctx,
            &serde_json::json!({ "id": key_id }),
        )
        .await
        .unwrap();
    assert_eq!(del["status"], "deleted");
}

#[tokio::test]
async fn test_agent_edge_cases_and_validations() {
    let temp_dir = tempfile::tempdir().unwrap();
    let mut state = AgentState::default().with_config_directory(temp_dir.path());
    let registry = default_registry();
    let ctx = CallingContext {
        username: "tester".into(),
        process_name: "test".into(),
        parent_process_name: "test_runner".into(),
        grandparent_process_name: "cargo".into(),
        process_pid: 10,
        parent_process_pid: 5,
        grandparent_process_pid: 1,
        error: false,
        authenticated: true,
    };

    // Status with logged_in
    state.session.is_locked = false;
    state.services.config.encrypted_token = "some_encrypted_token".into();
    let st = registry
        .execute("Status", &mut state, &ctx, &serde_json::json!({}))
        .await
        .unwrap();
    assert_eq!(st["logged_in"], true);
    state.session.is_locked = true;

    // Unlock without PIN configured
    assert!(registry
        .execute(
            "Unlock",
            &mut state,
            &ctx,
            &serde_json::json!({ "pin": "123" })
        )
        .await
        .is_err());

    // Unlock with invalid payload type
    assert!(registry
        .execute("Unlock", &mut state, &ctx, &serde_json::json!(42))
        .await
        .is_err());

    // Unlock with object missing pin
    assert!(registry
        .execute(
            "Unlock",
            &mut state,
            &ctx,
            &serde_json::json!({ "other": 123 })
        )
        .await
        .is_err());

    // PinSet with invalid payload type
    assert!(registry
        .execute("PinSet", &mut state, &ctx, &serde_json::json!(true))
        .await
        .is_err());

    // PinSet with object missing pin
    assert!(registry
        .execute(
            "PinSet",
            &mut state,
            &ctx,
            &serde_json::json!({ "other": 123 })
        )
        .await
        .is_err());

    // PinSet with string payload
    assert!(registry
        .execute(
            "PinSet",
            &mut state,
            &ctx,
            &serde_json::json!("str_pin_123")
        )
        .await
        .is_ok());

    // Unlock with string payload
    assert!(registry
        .execute(
            "Unlock",
            &mut state,
            &ctx,
            &serde_json::json!("str_pin_123")
        )
        .await
        .is_ok());

    // PinUpdate with missing fields or invalid type
    assert!(registry
        .execute(
            "PinUpdate",
            &mut state,
            &ctx,
            &serde_json::json!("not_an_obj")
        )
        .await
        .is_err());
    assert!(registry
        .execute(
            "PinUpdate",
            &mut state,
            &ctx,
            &serde_json::json!({ "old_pin": "123" })
        )
        .await
        .is_err());
    assert!(registry
        .execute(
            "PinUpdate",
            &mut state,
            &ctx,
            &serde_json::json!({ "new_pin": "456" })
        )
        .await
        .is_err());

    // PinUpdate without pin set
    let mut unconf = AgentState::default();
    assert!(registry
        .execute(
            "PinUpdate",
            &mut unconf,
            &ctx,
            &serde_json::json!({ "old_pin": "a", "new_pin": "b" }),
        )
        .await
        .is_err());

    // Check socket in use
    let temp_dir = tempfile::tempdir().unwrap();
    let sock_path = temp_dir.path().join("in_use.sock");
    let listener = tokio::net::UnixListener::bind(&sock_path).unwrap();
    let prep_err = check_and_prepare_socket(&sock_path).await;
    assert!(matches!(prep_err, Err(AgentError::SocketAlreadyInUse(_))));
    drop(listener);

    // Case-insensitive execute
    let st_lower = registry
        .execute("status", &mut state, &ctx, &serde_json::json!({}))
        .await
        .unwrap();
    assert_eq!(st_lower["locked"], false);

    // Custom registered sync closure
    let mut custom_reg = ActionsRegistry::new();
    custom_reg.register("CustomSync", |_state, _ctx, _payload| {
        Ok(serde_json::json!({ "custom": true }))
    });
    let c_res = custom_reg
        .execute("CustomSync", &mut state, &ctx, &serde_json::json!({}))
        .await
        .unwrap();
    assert_eq!(c_res["custom"], true);

    // SSH helper edge cases: "type" alias and string ID delete
    use sw_crypto::SymmetricKey;
    use sw_vault::VaultStore;

    let key = SymmetricKey::from_bytes(&[123u8; 64]).unwrap();
    let vault = Arc::new(VaultStore::new());
    let va = Arc::new(VaultAgentServer::new(vault.clone()));
    va.unlock(key.try_clone().unwrap()).await;

    let new_k = handle_new_ssh_key(&va, &serde_json::json!({ "name": "k1", "type": "Ed25519" }))
        .await
        .unwrap();
    let k1_id = new_k["id"].as_str().unwrap();

    // New SSH key with default type (no key_type / type field)
    let def_k = handle_new_ssh_key(&va, &serde_json::json!({ "name": "default-type-key" }))
        .await
        .unwrap();
    assert_eq!(def_k["name"], "default-type-key");
    assert!(def_k["public_key"]
        .as_str()
        .unwrap()
        .starts_with("ssh-ed25519"));

    // Delete using raw string id
    let del_str = handle_delete_ssh_key(&va, &serde_json::json!(k1_id))
        .await
        .unwrap();
    assert_eq!(del_str["status"], "deleted");

    // Import using "private_key" instead of "private_key_pem"
    let keypair = russh::keys::ssh_key::private::KeypairData::Ed25519(
        russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&[11u8; 32]),
    );
    let pk = russh::keys::PrivateKey::new(keypair, "k-priv").unwrap();
    let pem = pk
        .to_openssh(russh::keys::ssh_key::LineEnding::LF)
        .unwrap()
        .to_string();
    let imp = handle_import_ssh_key(
        &va,
        &serde_json::json!({ "name": "k-priv", "private_key": pem }),
    )
    .await
    .unwrap();
    assert_eq!(imp["name"], "k-priv");

    // Import using "pem" alias
    let keypair2 = russh::keys::ssh_key::private::KeypairData::Ed25519(
        russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&[22u8; 32]),
    );
    let pk2 = russh::keys::PrivateKey::new(keypair2, "k-pem").unwrap();
    let pem2 = pk2
        .to_openssh(russh::keys::ssh_key::LineEnding::LF)
        .unwrap()
        .to_string();
    let imp_pem = handle_import_ssh_key(&va, &serde_json::json!({ "name": "k-pem", "pem": pem2 }))
        .await
        .unwrap();
    assert_eq!(imp_pem["name"], "k-pem");

    // Generate RSA and ECDSA
    let rsa_gen = handle_new_ssh_key(
        &va,
        &serde_json::json!({ "name": "k-rsa", "key_type": "RSA" }),
    )
    .await
    .unwrap();
    assert_eq!(rsa_gen["name"], "k-rsa");

    let ecdsa_gen = handle_new_ssh_key(
        &va,
        &serde_json::json!({ "name": "k-ecdsa", "key_type": "ECDSA" }),
    )
    .await
    .unwrap();
    assert_eq!(ecdsa_gen["name"], "k-ecdsa");

    // AgentShutdown without shutdown_sender
    let mut no_shutdown_state = AgentState::default();
    let shutdown_res = registry
        .execute(
            "AgentShutdown",
            &mut no_shutdown_state,
            &ctx,
            &serde_json::json!({}),
        )
        .await
        .unwrap();
    assert_eq!(shutdown_res["status"], "shutting_down");

    // AgentShutdown with shutdown_sender present
    let (shut_tx, mut shut_rx) = tokio::sync::mpsc::channel(1);
    let mut with_shut_state = AgentState::default();
    with_shut_state.services.shutdown_sender = Some(shut_tx);
    let shut_with_sender = registry
        .execute(
            "AgentShutdown",
            &mut with_shut_state,
            &ctx,
            &serde_json::json!({}),
        )
        .await
        .unwrap();
    assert_eq!(shut_with_sender["status"], "shutting_down");
    assert!(shut_rx.try_recv().is_ok());

    // Lock with no vault agent in state
    let mut lock_no_va_state = AgentState::default();
    let lock_no_va = registry
        .execute("Lock", &mut lock_no_va_state, &ctx, &serde_json::json!({}))
        .await
        .unwrap();
    assert_eq!(lock_no_va["status"], "locked");

    // Constructors coverage
    let d = AgentDaemon::default();
    assert!(d.state.read().await.session.is_locked);
    let d_state = AgentDaemon::with_state(AgentState::default());
    assert!(d_state.state.read().await.session.is_locked);
    let reg = ActionsRegistry::new();
    assert!(reg.actions.is_empty());
    let reg_default = ActionsRegistry::default();
    assert!(reg_default.actions.is_empty());
    let default_daemon = AgentDaemon::default();
    assert!(default_daemon.state.read().await.session.is_locked);
    let d_default = AgentDaemon::default();
    assert!(d_default.state.read().await.session.is_locked);
    let d_with_state = AgentDaemon::with_state(AgentState::new(
        ConfigFile::default(),
        Arc::new(VaultAgentServer::default()),
    ));
    assert!(d_with_state.state.read().await.session.is_locked);
    let d_with_both =
        AgentDaemon::with_state_and_registry(AgentState::default(), default_registry());
    assert!(d_with_both.state.read().await.session.is_locked);
    let d_va = AgentDaemon::with_vault_agent(AgentState::default(), va.clone());
    assert!(d_va.state.read().await.session.is_locked);
    let d_va_cloned = d_va.clone();
    assert!(d_va_cloned.state.read().await.session.is_locked);
    assert!(set_permissions_unix(temp_dir.path(), 0o700).is_ok());

    // AgentState Debug, Clone, with_vault_agent with full fields
    let (tx, _rx) = tokio::sync::mpsc::channel(1);
    let mut full_state = AgentState::new(ConfigFile::default(), va.clone());
    full_state.services.shutdown_sender = Some(tx);
    let cloned_st = full_state.clone();
    let dbg_st = format!("{cloned_st:?}");
    assert!(dbg_st.contains("AgentState"));

    let default_st = AgentState::default();
    let cloned_default = default_st.clone();
    let dbg_default = format!("{cloned_default:?}");
    assert!(dbg_default.contains("AgentState"));

    // Default registry locked vault_agent error for all 4 SSH actions
    let mut unconf_state = AgentState::default();
    let default_reg = default_registry();
    assert_eq!(
        default_reg
            .execute(
                "ListSSHKeys",
                &mut unconf_state,
                &ctx,
                &serde_json::json!({})
            )
            .await
            .unwrap_err(),
        AgentError::Locked
    );
    assert_eq!(
        default_reg
            .execute(
                "ImportSSHKey",
                &mut unconf_state,
                &ctx,
                &serde_json::json!({})
            )
            .await
            .unwrap_err(),
        AgentError::Locked
    );
    assert_eq!(
        default_reg
            .execute("NewSSHKey", &mut unconf_state, &ctx, &serde_json::json!({}))
            .await
            .unwrap_err(),
        AgentError::Locked
    );
    assert_eq!(
        default_reg
            .execute(
                "DeleteSSHKey",
                &mut unconf_state,
                &ctx,
                &serde_json::json!({})
            )
            .await
            .unwrap_err(),
        AgentError::Locked
    );

    // Lock on default_registry with vault_agent present
    let mut state_with_va = AgentState::default().with_vault_agent(va.clone());
    assert!(!va.is_locked());
    let lock_res = default_reg
        .execute("Lock", &mut state_with_va, &ctx, &serde_json::json!({}))
        .await
        .unwrap();
    assert_eq!(lock_res["status"], "locked");
    assert!(va.is_locked());

    // SSH handlers when locked
    assert_eq!(
        handle_list_ssh_keys(&va).await.unwrap_err(),
        AgentError::Locked
    );
    assert_eq!(
        handle_import_ssh_key(&va, &serde_json::json!({ "name": "k", "pem": "abc" }))
            .await
            .unwrap_err(),
        AgentError::Locked
    );
    assert_eq!(
        handle_new_ssh_key(&va, &serde_json::json!({ "name": "k" }))
            .await
            .unwrap_err(),
        AgentError::Locked
    );
    assert_eq!(
        handle_delete_ssh_key(
            &va,
            &serde_json::json!({ "id": uuid::Uuid::new_v4().to_string() })
        )
        .await
        .unwrap_err(),
        AgentError::Locked
    );

    // Unlock va again for payload edge cases
    va.unlock(SymmetricKey::from_bytes(&[123u8; 64]).unwrap())
        .await;
    assert!(!va.is_locked());

    // Invalid payloads for SSH handlers
    assert!(handle_import_ssh_key(&va, &serde_json::json!("not_an_obj"))
        .await
        .is_err());
    assert!(
        handle_import_ssh_key(&va, &serde_json::json!({ "pem": "abc" }))
            .await
            .is_err()
    );
    assert!(
        handle_import_ssh_key(&va, &serde_json::json!({ "name": "k" }))
            .await
            .is_err()
    );
    assert!(handle_import_ssh_key(
        &va,
        &serde_json::json!({ "name": "k", "private_key_pem": "not-a-valid-pem" })
    )
    .await
    .is_err());

    assert!(handle_new_ssh_key(&va, &serde_json::json!("not_an_obj"))
        .await
        .is_err());
    assert!(handle_new_ssh_key(&va, &serde_json::json!({}))
        .await
        .is_err());
    assert!(handle_new_ssh_key(
        &va,
        &serde_json::json!({ "name": "k", "key_type": "UNKNOWN_TYPE" })
    )
    .await
    .is_err());

    assert!(handle_delete_ssh_key(&va, &serde_json::json!(42))
        .await
        .is_err());
    assert!(handle_delete_ssh_key(&va, &serde_json::json!({}))
        .await
        .is_err());
    assert!(
        handle_delete_ssh_key(&va, &serde_json::json!({ "id": "not-a-uuid" }))
            .await
            .is_err()
    );
    assert!(handle_delete_ssh_key(&va, &serde_json::json!("not-a-uuid"))
        .await
        .is_err());
    assert!(handle_delete_ssh_key(
        &va,
        &serde_json::json!({ "id": uuid::Uuid::new_v4().to_string() })
    )
    .await
    .is_ok());

    // Unlock with corrupted config_key_hash where verify_pin returns Err
    let mut corrupted_pin_state = AgentState::default();
    corrupted_pin_state.session.has_pin = true;
    corrupted_pin_state.services.config = ConfigFile {
        device_uuid: "".into(),
        config_key_hash: "0".repeat(64),
        ..Default::default()
    };
    let err = default_reg
        .execute(
            "Unlock",
            &mut corrupted_pin_state,
            &ctx,
            &serde_json::json!({ "pin": "123" }),
        )
        .await
        .unwrap_err();
    assert!(err.contains("Error al verificar PIN"));

    // PinSet with config_directory saving config
    let home_dir = tempfile::tempdir().unwrap();
    let mut home_state = AgentState::default().with_config_directory(home_dir.path());
    let pin_set_home = default_reg
        .execute(
            "PinSet",
            &mut home_state,
            &ctx,
            &serde_json::json!({ "pin": "test_pin_home_1" }),
        )
        .await
        .unwrap();
    assert_eq!(pin_set_home["status"], "pin_set");
    assert!(home_dir.path().join("goldwarden.json").exists());

    // PinSet when already set
    assert!(default_reg
        .execute(
            "PinSet",
            &mut home_state,
            &ctx,
            &serde_json::json!({ "pin": "already_set" }),
        )
        .await
        .is_err());

    // PinUpdate with config_directory saving config
    let pin_update_home = default_reg
        .execute(
            "PinUpdate",
            &mut home_state,
            &ctx,
            &serde_json::json!({ "old_pin": "test_pin_home_1", "new_pin": "new_pin_home_2" }),
        )
        .await
        .unwrap();
    assert_eq!(pin_update_home["status"], "pin_updated");

    // PinUpdate with wrong old_pin
    assert!(default_reg
        .execute(
            "PinUpdate",
            &mut home_state,
            &ctx,
            &serde_json::json!({ "old_pin": "wrong", "new_pin": "new" }),
        )
        .await
        .is_err());

    // save_config_file error with non-writable path
    let bad_path = Path::new("/proc/invalid_dir/goldwarden.json");
    assert!(save_config_file(&ConfigFile::default(), bad_path).is_err());
}

#[tokio::test]
async fn test_agent_write_message_failure_on_closed_client() {
    let temp_dir = tempfile::tempdir().expect("Create temp dir");
    let socket_path = temp_dir.path().join("write_fail.sock");
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let agent_socket = socket_path.clone();

    let listener = bind_socket(&socket_path).await.unwrap();
    let handle = tokio::spawn(async move {
        let daemon = AgentDaemon::default();
        let _ = accept_loop(listener, daemon, &agent_socket, async {
            let _ = shutdown_rx.await;
        })
        .await;
    });

    let mut stream = UnixStream::connect(&socket_path).await.unwrap();
    let req = Request::Status;
    let _ = write_message(&mut stream, &req).await;
    let _ = stream.shutdown().await;
    drop(stream);

    let _ = shutdown_tx.send(());
    let _ = handle.await;
}

#[tokio::test]
async fn test_run_agent_ipc_shutdown() {
    let temp_dir = tempfile::tempdir().unwrap();
    let sock = temp_dir.path().join("run_agent_ipc.sock");
    let s = sock.clone();
    let listener = bind_socket(&sock).await.unwrap();
    let handle = tokio::spawn(async move {
        let daemon = AgentDaemon::default();
        accept_loop(listener, daemon, &s, std::future::pending()).await
    });

    let mut stream = UnixStream::connect(&sock).await.unwrap();
    let req = Request::AgentShutdown;
    let _ = write_message(&mut stream, &req).await;
    let res = handle.await.unwrap();
    assert!(res.is_ok());
}

#[tokio::test]
async fn test_ssh_handlers_and_registry_edge_cases() {
    use sw_crypto::SymmetricKey;
    use sw_vault::VaultStore;

    let key = SymmetricKey::from_bytes(&[88u8; 64]).unwrap();
    let vault = Arc::new(VaultStore::new());
    let va = Arc::new(VaultAgentServer::new(vault));
    va.unlock(key).await;

    let reg = default_registry();
    let mut state = AgentState::default().with_vault_agent(va.clone());
    let ctx = CallingContext {
        username: "tester".into(),
        process_name: "test".into(),
        parent_process_name: "p".into(),
        grandparent_process_name: "gp".into(),
        process_pid: 1,
        parent_process_pid: 2,
        grandparent_process_pid: 3,
        error: false,
        authenticated: true,
    };

    // Unknown action error in registry
    assert!(reg
        .execute(
            "NonExistentAction",
            &mut state,
            &ctx,
            &serde_json::json!({})
        )
        .await
        .is_err());

    // ImportSSHKey edge cases through registry
    assert!(reg
        .execute(
            "ImportSSHKey",
            &mut state,
            &ctx,
            &serde_json::json!("not_obj")
        )
        .await
        .is_err());
    assert!(reg
        .execute(
            "ImportSSHKey",
            &mut state,
            &ctx,
            &serde_json::json!({ "name": "k" })
        )
        .await
        .is_err());
    assert!(reg
        .execute(
            "ImportSSHKey",
            &mut state,
            &ctx,
            &serde_json::json!({ "private_key_pem": "invalid" })
        )
        .await
        .is_err());
    assert!(reg
        .execute(
            "ImportSSHKey",
            &mut state,
            &ctx,
            &serde_json::json!({ "name": "k", "private_key_pem": "not_valid_pem" })
        )
        .await
        .is_err());

    // NewSSHKey edge cases through registry
    assert!(reg
        .execute("NewSSHKey", &mut state, &ctx, &serde_json::json!("not_obj"))
        .await
        .is_err());
    assert!(reg
        .execute("NewSSHKey", &mut state, &ctx, &serde_json::json!({}))
        .await
        .is_err());
    assert!(reg
        .execute(
            "NewSSHKey",
            &mut state,
            &ctx,
            &serde_json::json!({ "name": "k", "key_type": "UNKNOWN" })
        )
        .await
        .is_err());

    // DeleteSSHKey edge cases through registry
    assert!(reg
        .execute("DeleteSSHKey", &mut state, &ctx, &serde_json::json!(123))
        .await
        .is_err());
    assert!(reg
        .execute("DeleteSSHKey", &mut state, &ctx, &serde_json::json!({}))
        .await
        .is_err());
    assert!(reg
        .execute(
            "DeleteSSHKey",
            &mut state,
            &ctx,
            &serde_json::json!({ "id": "not_uuid" })
        )
        .await
        .is_err());
    assert!(reg
        .execute(
            "DeleteSSHKey",
            &mut state,
            &ctx,
            &serde_json::json!("not_uuid")
        )
        .await
        .is_err());

    // Direct helper validations
    assert!(
        handle_import_ssh_key(&va, &serde_json::json!({ "name": "k" }))
            .await
            .is_err()
    );
    assert!(
        handle_import_ssh_key(&va, &serde_json::json!({ "private_key_pem": "pem" }))
            .await
            .is_err()
    );
    assert!(handle_new_ssh_key(&va, &serde_json::json!({}))
        .await
        .is_err());
    assert!(handle_delete_ssh_key(&va, &serde_json::json!({}))
        .await
        .is_err());
    assert!(handle_delete_ssh_key(&va, &serde_json::json!(123))
        .await
        .is_err());
    assert!(handle_delete_ssh_key(&va, &serde_json::json!("bad-uuid"))
        .await
        .is_err());

    // Daemon handle_message with invalid action payload
    let daemon = AgentDaemon::with_vault_agent(AgentState::default(), va.clone());
    let err_resp = daemon
        .handle_message(
            &ctx,
            Request::DeleteSshKey {
                id: "invalid-uuid".into(),
            },
        )
        .await;
    assert!(err_resp.is_err());
}

#[tokio::test]
async fn test_regression_home_config_untouched() {
    let real_config_path = std::env::var("HOME")
        .ok()
        .map(|h| sw_config::get_new_config_path(Path::new(&h)));

    let before_content = real_config_path
        .as_ref()
        .and_then(|p| std::fs::read(p).ok());

    // Run full PinSet and PinUpdate flow without config_directory set
    let registry = default_registry();
    let mut state = AgentState::default();
    let ctx = CallingContext {
        username: "tester".into(),
        process_name: "test".into(),
        parent_process_name: "test_runner".into(),
        grandparent_process_name: "cargo".into(),
        process_pid: 10,
        parent_process_pid: 5,
        grandparent_process_pid: 1,
        error: false,
        authenticated: true,
    };

    // PinSet must succeed without writing to real $HOME
    let pin_set = registry
        .execute(
            "PinSet",
            &mut state,
            &ctx,
            &serde_json::json!({ "pin": "regression_pin_123" }),
        )
        .await
        .unwrap();
    assert_eq!(pin_set["status"], "pin_set");

    // PinUpdate must succeed without writing to real $HOME
    let pin_upd = registry
        .execute(
            "PinUpdate",
            &mut state,
            &ctx,
            &serde_json::json!({
                "old_pin": "regression_pin_123",
                "new_pin": "regression_pin_456"
            }),
        )
        .await
        .unwrap();
    assert_eq!(pin_upd["status"], "pin_updated");

    // Verify that real ~/.config/goldwarden/goldwarden.json was NOT modified
    let after_content = real_config_path
        .as_ref()
        .and_then(|p| std::fs::read(p).ok());

    assert_eq!(
        before_content, after_content,
        "Regression: PinSet or PinUpdate wrote to real ~/.config/goldwarden/goldwarden.json!"
    );
}

// ====================================================================
// FASE 0 — Helpers de test
// ====================================================================

fn test_ctx() -> CallingContext {
    CallingContext {
        username: "tester".into(),
        process_name: "test".into(),
        parent_process_name: "test_runner".into(),
        grandparent_process_name: "cargo".into(),
        process_pid: 10,
        parent_process_pid: 5,
        grandparent_process_pid: 1,
        error: false,
        authenticated: true,
    }
}

fn test_agent(seed: u8) -> (Arc<VaultAgentServer>, sw_crypto::SymmetricKey) {
    let key = sw_crypto::SymmetricKey::from_bytes(&[seed; 64]).unwrap();
    let vault = Arc::new(sw_vault::VaultStore::new());
    let agent = Arc::new(VaultAgentServer::new(vault));
    (agent, key)
}

fn encrypted_login(
    name: &str,
    username: &str,
    password: &str,
    key: &sw_crypto::SymmetricKey,
) -> sw_vault::Cipher {
    let enc_name = sw_vault::encrypt_with(
        name.as_bytes(),
        sw_vault::EncStringType::AesCbc256HmacSha256B64,
        key,
    )
    .unwrap();
    let enc_user = sw_vault::encrypt_with(
        username.as_bytes(),
        sw_vault::EncStringType::AesCbc256HmacSha256B64,
        key,
    )
    .unwrap();
    let enc_pass = sw_vault::encrypt_with(
        password.as_bytes(),
        sw_vault::EncStringType::AesCbc256HmacSha256B64,
        key,
    )
    .unwrap();

    sw_vault::Cipher {
        id: Some(uuid::Uuid::new_v4()),
        r#type: sw_vault::CipherType::Login,
        name: enc_name,
        favorite: false,
        reprompt: 0,
        fields: vec![],
        login: Some(sw_vault::LoginCipher {
            username: Some(enc_user),
            password: Some(enc_pass),
            uri: None,
            uris: vec![],
            totp: None,
        }),
        ..Default::default()
    }
}

fn temp_state() -> (AgentState, tempfile::TempDir) {
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let (agent, _) = test_agent(42);
    let state =
        AgentState::new(ConfigFile::default(), agent).with_config_directory(temp_dir.path());
    (state, temp_dir)
}

fn mock_api_client(base_url: &str) -> Arc<sw_bitwarden_api::AuthenticatedClient> {
    let token = sw_config::LoginToken {
        access_token: "mock_access_token".to_string(),
        expires_in: 3600,
        token_type: "Bearer".to_string(),
        refresh_token: "mock_refresh_token".to_string(),
        key: "mock_key".to_string(),
        kdf: None,
        kdf_iterations: None,
        kdf_memory: None,
        kdf_parallelism: None,
    };
    Arc::new(
        sw_bitwarden_api::AuthenticatedClient::from_token_with_options(
            format!("{base_url}/identity"),
            format!("{base_url}/api"),
            token,
            true,
        ),
    )
}

// ====================================================================
// FASE 1 — Tests de handle_sync
// ====================================================================

#[tokio::test]
async fn test_handle_sync_locked_returns_error() {
    let (mut state, _tmp) = temp_state();
    state.session.is_locked = true;
    let res = handle_sync(&mut state, &serde_json::json!({})).await;
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("Bóveda bloqueada"));
}

#[tokio::test]
async fn test_handle_sync_without_session_returns_error() {
    let (mut state, _tmp) = temp_state();
    state.session.is_locked = false;
    state.services.config.encrypted_token = String::new();
    state.services.api_client = None;
    let res = handle_sync(&mut state, &serde_json::json!({})).await;
    assert!(res.is_err());
    assert_eq!(
        res.unwrap_err(),
        "No hay sesión iniciada. Ejecuta 'silverwarden login' primero."
    );
}

#[tokio::test]
async fn test_handle_sync_payload_updates_config_and_summary() {
    let (mut state, _tmp) = temp_state();
    state.session.is_locked = false;
    let (_, key) = test_agent(42);

    let vault = state.services.vault_agent.vault();
    // Insert 2 logins, 1 ssh key, 1 note
    vault
        .insert(encrypted_login("Login1", "u1", "p1", &key))
        .await;
    vault
        .insert(encrypted_login("Login2", "u2", "p2", &key))
        .await;
    let enc_ssh_name = sw_vault::encrypt_with(
        b"enc_ssh",
        sw_vault::EncStringType::AesCbc256HmacSha256B64,
        &key,
    )
    .unwrap();
    let enc_note_name = sw_vault::encrypt_with(
        b"enc_note",
        sw_vault::EncStringType::AesCbc256HmacSha256B64,
        &key,
    )
    .unwrap();
    vault
        .insert(sw_vault::Cipher {
            id: Some(uuid::Uuid::new_v4()),
            r#type: sw_vault::CipherType::SshKey,
            name: enc_ssh_name,
            ..Default::default()
        })
        .await;
    vault
        .insert(sw_vault::Cipher {
            id: Some(uuid::Uuid::new_v4()),
            r#type: sw_vault::CipherType::Note,
            name: enc_note_name,
            ..Default::default()
        })
        .await;

    let payload = serde_json::json!({
        "encrypted_token": "enc_tok_payload",
        "encrypted_user_symmetric_key": "enc_sym_payload",
        "identity_url": "https://identity.test",
        "api_url": "https://api.test",
        "danger_accept_invalid_certs": true,
    });

    let res = handle_sync(&mut state, &payload)
        .await
        .expect("sync should succeed");
    assert_eq!(state.services.config.encrypted_token, "enc_tok_payload");
    assert_eq!(state.services.config.encrypted_user_symmetric_key, "enc_sym_payload");
    assert_eq!(state.services.config.identity_url, "https://identity.test");
    assert_eq!(state.services.config.api_url, "https://api.test");
    assert!(state.services.config.danger_accept_invalid_certs);

    assert_eq!(res["status"], "synced");
    assert_eq!(res["total"], 4);
    assert_eq!(res["logins"], 2);
    assert_eq!(res["ssh_keys"], 1);
}

#[tokio::test]
async fn test_handle_sync_disk_config_fallback() {
    let (mut state, tmp) = temp_state();
    state.session.is_locked = false;
    state.services.config.encrypted_token = String::new();
    state.services.api_client = None;

    let disk_cfg = ConfigFile {
        encrypted_token: "disk_enc_token".to_string(),
        encrypted_user_symmetric_key: "disk_enc_sym".to_string(),
        identity_url: "https://disk-ident.test".to_string(),
        api_url: "https://disk-api.test".to_string(),
        danger_accept_invalid_certs: true,
        ..Default::default()
    };
    save_config_file(&disk_cfg, &tmp.path().join("goldwarden.json")).unwrap();

    let res = handle_sync(&mut state, &serde_json::json!({}))
        .await
        .expect("sync fallback should succeed");
    assert_eq!(state.services.config.encrypted_token, "disk_enc_token");
    assert_eq!(state.services.config.encrypted_user_symmetric_key, "disk_enc_sym");
    assert_eq!(state.services.config.identity_url, "https://disk-ident.test");
    assert_eq!(state.services.config.api_url, "https://disk-api.test");
    assert_eq!(res["status"], "synced");
}

#[tokio::test]
async fn test_handle_sync_api_success_persists_vault() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let profile_id = uuid::Uuid::new_v4();
    let valid_enc = "2.aXZfMTZfYnl0ZXNfbG9uZw==|Y2lwaGVydGV4dF9ieXRlcw==|bWFjXzMyX2J5dGVzX2xvbmdfaGFzaF9zdHJpbmchIQ==";
    let sync_response = serde_json::json!({
        "profile": {
            "id": profile_id.to_string(),
            "name": "Test User",
            "email": "test@example.com"
        },
        "folders": [],
        "ciphers": [
            {
                "id": uuid::Uuid::new_v4().to_string(),
                "type": 1,
                "name": valid_enc,
                "login": {
                    "username": valid_enc,
                    "password": valid_enc
                }
            },
            {
                "id": uuid::Uuid::new_v4().to_string(),
                "type": 5,
                "name": valid_enc
            }
        ]
    });

    Mock::given(method("GET"))
        .and(path("/api/sync"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&sync_response))
        .mount(&server)
        .await;

    let (mut state, tmp) = temp_state();
    state.session.is_locked = false;
    state.services.api_client = Some(mock_api_client(&server.uri()));

    let res = handle_sync(&mut state, &serde_json::json!({}))
        .await
        .expect("sync should succeed");
    assert_eq!(res["status"], "synced");
    assert_eq!(res["total"], 2);
    assert_eq!(res["logins"], 1);
    assert_eq!(res["ssh_keys"], 1);

    // Verify vault.json was persisted on disk in tmp
    let vault_file = tmp.path().join("vault.json");
    assert!(vault_file.exists());
    let loaded = sw_vault::load_vault(&vault_file).expect("load vault from disk");
    assert_eq!(loaded.ciphers.len(), 2);
    assert_eq!(loaded.profile.id, Some(profile_id));
}

#[tokio::test]
async fn test_handle_sync_api_rate_limit() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/sync"))
        .respond_with(ResponseTemplate::new(429))
        .mount(&server)
        .await;

    let (mut state, _tmp) = temp_state();
    state.session.is_locked = false;
    state.services.api_client = Some(mock_api_client(&server.uri()));

    let err = handle_sync(&mut state, &serde_json::json!({}))
        .await
        .unwrap_err();
    assert!(err.contains("El servidor ha bloqueado temporalmente tu IP"));
}

#[tokio::test]
async fn test_handle_sync_api_server_error() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/sync"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let (mut state, _tmp) = temp_state();
    state.session.is_locked = false;
    state.services.api_client = Some(mock_api_client(&server.uri()));

    let err = handle_sync(&mut state, &serde_json::json!({}))
        .await
        .unwrap_err();
    assert!(err.contains("Error al sincronizar con el servidor"));
}

#[tokio::test]
async fn test_handle_sync_token_payload_builds_api_client() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let sync_response = serde_json::json!({
        "profile": {
            "id": uuid::Uuid::new_v4().to_string(),
            "name": "User",
            "email": "u@test.com",
        },
        "folders": [],
        "collections": [],
        "ciphers": [],
    });

    Mock::given(method("GET"))
        .and(path("/api/sync"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&sync_response))
        .mount(&server)
        .await;

    let (mut state, _tmp) = temp_state();
    state.session.is_locked = false;
    assert!(state.services.api_client.is_none());

    let payload = serde_json::json!({
        "identity_url": format!("{}/identity", server.uri()),
        "api_url": format!("{}/api", server.uri()),
        "danger_accept_invalid_certs": true,
        "token": {
            "access_token": "valid_token_xyz",
            "expires_in": 3600,
            "token_type": "Bearer",
            "refresh_token": "valid_refresh_xyz",
            "key": "valid_key_xyz"
        }
    });

    let res = handle_sync(&mut state, &payload)
        .await
        .expect("sync with token payload should succeed");
    assert_eq!(res["status"], "synced");
    assert!(state.services.api_client.is_some());
}

// ====================================================================
// FASE 2 — Tests de logins
// ====================================================================

#[tokio::test]
async fn test_handle_list_logins_filters_and_locked() {
    let (mut state, _tmp) = temp_state();
    let (agent, key) = test_agent(50);
    state.services.vault_agent = agent.clone();

    // 1. Locked -> returns error
    state.session.is_locked = true;
    let err = handle_list_logins(&state).await.unwrap_err();
    assert!(err.contains("Bóveda bloqueada"));

    // 2. Unlocked
    agent.unlock(key.try_clone().unwrap()).await;
    state.session.is_locked = false;

    let vault = agent.vault();
    // 1 active login
    let mut active_login = encrypted_login("ActiveLogin", "alice", "pass123", &key);
    active_login.deleted_date = None;
    vault.insert(active_login).await;

    // 1 note
    let note_enc_name = sw_vault::encrypt_with(
        b"NoteName",
        sw_vault::EncStringType::AesCbc256HmacSha256B64,
        &key,
    )
    .unwrap();
    vault
        .insert(sw_vault::Cipher {
            id: Some(uuid::Uuid::new_v4()),
            r#type: sw_vault::CipherType::Note,
            name: note_enc_name,
            ..Default::default()
        })
        .await;

    // 1 deleted login
    let mut deleted_login = encrypted_login("DeletedLogin", "bob", "pass456", &key);
    deleted_login.deleted_date = Some("2026-01-01T00:00:00Z".to_string());
    vault.insert(deleted_login).await;

    let res = handle_list_logins(&state)
        .await
        .expect("list logins succeeds");
    let list = res.as_array().expect("array result");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["name"], "ActiveLogin");
    assert_eq!(list[0]["username"], "alice");
}

#[tokio::test]
async fn test_handle_get_login_found_not_found_locked() {
    let (mut state, _tmp) = temp_state();
    let (agent, key) = test_agent(51);
    state.services.vault_agent = agent.clone();

    // Locked error
    state.session.is_locked = true;
    assert!(
        handle_get_login(&state, &serde_json::json!({ "name": "GitHub" }))
            .await
            .is_err()
    );

    // Unlock
    agent.unlock(key.try_clone().unwrap()).await;
    state.session.is_locked = false;

    let login = encrypted_login("GitHub", "octocat", "super_secret", &key);
    agent.vault().insert(login).await;

    // Found exact
    let res_exact = handle_get_login(&state, &serde_json::json!({ "name": "GitHub" }))
        .await
        .unwrap();
    assert_eq!(res_exact["name"], "GitHub");
    assert_eq!(res_exact["username"], "octocat");
    assert_eq!(res_exact["password"], "super_secret");

    // Found case-insensitive
    let res_case = handle_get_login(&state, &serde_json::json!({ "name": "github" }))
        .await
        .unwrap();
    assert_eq!(res_case["name"], "GitHub");

    // Found from primitive string payload
    let res_str = handle_get_login(&state, &serde_json::json!("GITHUB"))
        .await
        .unwrap();
    assert_eq!(res_str["name"], "GitHub");

    // Not found
    let err_not_found = handle_get_login(&state, &serde_json::json!({ "name": "GitLab" }))
        .await
        .unwrap_err();
    assert!(err_not_found.contains("No se encontró ningún acceso con el nombre 'GitLab'"));

    // Missing name in payload
    let err_missing = handle_get_login(&state, &serde_json::json!({}))
        .await
        .unwrap_err();
    assert!(err_missing.contains("Campo 'name' requerido"));
}

#[tokio::test]
async fn test_handle_delete_login_local_and_not_found() {
    let (mut state, _tmp) = temp_state();
    let (agent, key) = test_agent(52);
    state.services.vault_agent = agent.clone();
    state.session.is_locked = false;
    agent.unlock(key.try_clone().unwrap()).await;

    let login = encrypted_login("Twitter", "bird_user", "tweet123", &key);
    agent.vault().insert(login).await;

    assert_eq!(agent.vault().all().await.len(), 1);

    // Delete existing
    let res = handle_delete_login(&mut state, &serde_json::json!({ "name": "Twitter" }))
        .await
        .unwrap();
    assert_eq!(res["status"], "deleted");
    assert_eq!(res["name"], "Twitter");
    assert_eq!(agent.vault().all().await.len(), 0);

    // Delete not found
    let err = handle_delete_login(&mut state, &serde_json::json!({ "name": "Twitter" }))
        .await
        .unwrap_err();
    assert!(err.contains("No se encontró ningún acceso con el nombre 'Twitter'"));
}

#[tokio::test]
async fn test_handle_delete_login_server_error_is_tolerated() {
    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path_regex(r"^/api/ciphers/.*"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let (mut state, _tmp) = temp_state();
    let (agent, key) = test_agent(53);
    state.services.vault_agent = agent.clone();
    state.session.is_locked = false;
    agent.unlock(key.try_clone().unwrap()).await;
    state.services.api_client = Some(mock_api_client(&server.uri()));

    let login = encrypted_login("Reddit", "redditor", "upvote_all", &key);
    agent.vault().insert(login).await;

    let res = handle_delete_login(&mut state, &serde_json::json!({ "name": "Reddit" }))
        .await
        .unwrap();
    assert_eq!(res["status"], "deleted");
    assert_eq!(res["name"], "Reddit");
    assert_eq!(agent.vault().all().await.len(), 0);
}

#[tokio::test]
async fn test_handle_create_login_validations() {
    let (mut state, _tmp) = temp_state();
    let (agent, key) = test_agent(54);
    state.services.vault_agent = agent.clone();

    // 1. Locked
    state.session.is_locked = true;
    let err_locked = handle_create_login(&mut state, &serde_json::json!({}))
        .await
        .unwrap_err();
    assert!(err_locked.contains("Bóveda bloqueada"));

    state.session.is_locked = false;
    agent.unlock(key).await;

    // 2. Non-object payload
    let err_non_obj = handle_create_login(&mut state, &serde_json::json!("not-an-object"))
        .await
        .unwrap_err();
    assert!(err_non_obj.contains("El payload debe ser un objeto JSON"));

    // 3. Missing fields
    assert!(handle_create_login(
        &mut state,
        &serde_json::json!({ "username": "u", "password": "p" })
    )
    .await
    .unwrap_err()
    .contains("Campo 'name' requerido"));
    assert!(handle_create_login(
        &mut state,
        &serde_json::json!({ "name": "n", "password": "p" })
    )
    .await
    .unwrap_err()
    .contains("Campo 'username' requerido"));
    assert!(handle_create_login(
        &mut state,
        &serde_json::json!({ "name": "n", "username": "u" })
    )
    .await
    .unwrap_err()
    .contains("Campo 'password' requerido"));

    // 4. Empty strings
    assert!(handle_create_login(
        &mut state,
        &serde_json::json!({ "name": "  ", "username": "u", "password": "p" })
    )
    .await
    .unwrap_err()
    .contains("El campo 'name' no puede estar vacío"));
    assert!(handle_create_login(
        &mut state,
        &serde_json::json!({ "name": "n", "username": "  ", "password": "p" })
    )
    .await
    .unwrap_err()
    .contains("El campo 'username' no puede estar vacío"));
    assert!(handle_create_login(
        &mut state,
        &serde_json::json!({ "name": "n", "username": "u", "password": "  " })
    )
    .await
    .unwrap_err()
    .contains("El campo 'password' no puede estar vacío"));

    // 5. No profile synced
    let err_no_profile = handle_create_login(
        &mut state,
        &serde_json::json!({ "name": "n", "username": "u", "password": "p" }),
    )
    .await
    .unwrap_err();
    assert!(err_no_profile
        .contains("No se ha sincronizado el perfil. Ejecuta 'silverwarden sync' primero."));

    // 6. Profile present, but no api_client
    agent
        .vault()
        .load_sync_data(sw_vault::SyncData {
            profile: sw_vault::Profile {
                id: Some(uuid::Uuid::new_v4()),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
    state.services.api_client = None;
    let err_no_session = handle_create_login(
        &mut state,
        &serde_json::json!({ "name": "n", "username": "u", "password": "p" }),
    )
    .await
    .unwrap_err();
    assert!(err_no_session.contains("No hay sesión iniciada en el servidor"));
}

#[tokio::test]
async fn test_handle_create_login_success() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let server_cipher_id = uuid::Uuid::new_v4();
    let profile_id = uuid::Uuid::new_v4();

    let valid_enc = "2.aXZfMTZfYnl0ZXNfbG9uZw==|Y2lwaGVydGV4dF9ieXRlcw==|bWFjXzMyX2J5dGVzX2xvbmdfaGFzaF9zdHJpbmchIQ==";
    let response_cipher = serde_json::json!({
        "id": server_cipher_id.to_string(),
        "type": 1,
        "name": valid_enc,
        "encryptedFor": profile_id.to_string(),
        "login": {
            "username": valid_enc,
            "password": valid_enc
        }
    });

    Mock::given(method("POST"))
        .and(path("/api/ciphers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_cipher))
        .mount(&server)
        .await;

    let (mut state, _tmp) = temp_state();
    let (agent, key) = test_agent(55);
    state.services.vault_agent = agent.clone();
    state.session.is_locked = false;
    agent.unlock(key).await;

    // Set profile in vault
    agent
        .vault()
        .load_sync_data(sw_vault::SyncData {
            profile: sw_vault::Profile {
                id: Some(profile_id),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;

    state.services.api_client = Some(mock_api_client(&server.uri()));

    let payload = serde_json::json!({
        "name": "Google",
        "username": "user@gmail.com",
        "password": "secretpassword"
    });

    let res = handle_create_login(&mut state, &payload)
        .await
        .expect("create login should succeed");
    assert_eq!(res["status"], "created");
    assert_eq!(res["id"], server_cipher_id.to_string());
    assert_eq!(res["name"], "Google");

    // Verify inserted into vault
    let all = agent.vault().all().await;
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].id, Some(server_cipher_id));
}

// ====================================================================
// FASE 3 — Tests de sesión y registry
// ====================================================================

#[tokio::test]
async fn test_handle_set_session_persists_and_unlocks() {
    use base64::Engine;

    let (mut state, tmp) = temp_state();
    let key_bytes = [77u8; 64];
    let key_b64 = base64::engine::general_purpose::STANDARD.encode(key_bytes);

    let payload = serde_json::json!({
        "identity_url": "https://ident.custom.test",
        "api_url": "https://api.custom.test",
        "notifications_url": "https://notif.custom.test",
        "danger_accept_invalid_certs": true,
        "encrypted_token": "enc_tok_sample",
        "encrypted_user_symmetric_key": "enc_sym_sample",
        "token": {
            "access_token": "bearer_abc",
            "expires_in": 3600,
            "token_type": "Bearer",
            "refresh_token": "refr_123",
            "key": "key_123"
        },
        "user_symmetric_key": key_b64,
    });

    let res = handle_set_session(&mut state, &payload)
        .await
        .expect("set session should succeed");
    assert_eq!(res["status"], "session_saved");

    // Config updated in memory
    assert_eq!(state.services.config.identity_url, "https://ident.custom.test");
    assert_eq!(state.services.config.api_url, "https://api.custom.test");
    assert_eq!(state.services.config.notifications_url, "https://notif.custom.test");
    assert!(state.services.config.danger_accept_invalid_certs);
    assert_eq!(state.services.config.encrypted_token, "enc_tok_sample");
    assert_eq!(state.services.config.encrypted_user_symmetric_key, "enc_sym_sample");

    // api_client created
    assert!(state.services.api_client.is_some());

    // vault unlocked
    assert!(!state.services.vault_agent.is_locked());

    // config file persisted
    let config_file = tmp.path().join("goldwarden.json");
    assert!(config_file.exists());
    let saved_content = std::fs::read_to_string(config_file).unwrap();
    assert!(saved_content.contains("https://ident.custom.test"));
}

#[tokio::test]
async fn test_handle_set_session_invalid_key_does_not_panic() {
    let (mut state, _tmp) = temp_state();

    // 1. Invalid base64
    let payload1 = serde_json::json!({
        "user_symmetric_key": "not-valid-base64-%%%$$$",
    });
    let res1 = handle_set_session(&mut state, &payload1).await;
    assert!(res1.is_ok());

    // 2. Valid base64 but wrong length (3 bytes instead of 64)
    let payload2 = serde_json::json!({
        "user_symmetric_key": "AQID",
    });
    let res2 = handle_set_session(&mut state, &payload2).await;
    assert!(res2.is_ok());
}

#[tokio::test]
async fn test_handle_sync_data_invalid_payload() {
    let (mut state, _tmp) = temp_state();
    let err = handle_sync_data(&mut state, &serde_json::json!("not-a-syncdata-object"))
        .await
        .unwrap_err();
    assert!(err.contains("Error deserializando SyncData"));
}

#[tokio::test]
async fn test_handle_sync_data_success() {
    let (mut state, tmp) = temp_state();
    let (_, key) = test_agent(60);
    let valid_sync = sw_vault::SyncData {
        profile: sw_vault::Profile {
            id: Some(uuid::Uuid::new_v4()),
            ..Default::default()
        },
        ciphers: vec![
            encrypted_login("LoginSync", "usr", "pwd", &key),
            sw_vault::Cipher {
                id: Some(uuid::Uuid::new_v4()),
                r#type: sw_vault::CipherType::SshKey,
                name: sw_vault::encrypt_with(
                    b"ssh_sync",
                    sw_vault::EncStringType::AesCbc256HmacSha256B64,
                    &key,
                )
                .unwrap(),
                ..Default::default()
            },
        ],
        ..Default::default()
    };

    let payload = serde_json::to_value(&valid_sync).unwrap();
    let res = handle_sync_data(&mut state, &payload)
        .await
        .expect("sync data should succeed");
    assert_eq!(res["status"], "synced");
    assert_eq!(res["total"], 2);
    assert_eq!(res["logins"], 1);
    assert_eq!(res["ssh_keys"], 1);

    // Vault file on disk
    let vault_file = tmp.path().join("vault.json");
    assert!(vault_file.exists());
}

#[tokio::test]
async fn test_agent_state_helpers_and_config_path_variants() {
    let temp_dir = tempfile::tempdir().unwrap();
    let direct_file = temp_dir.path().join("goldwarden.json");
    let state = AgentState::new(ConfigFile::default(), Arc::new(VaultAgentServer::default()))
        .with_config_directory(&direct_file);
    assert_eq!(state.config_path(), Some(direct_file));

    let mock_client = mock_api_client("http://localhost:1234");
    let state_with_client = state.with_api_client(mock_client);
    assert!(state_with_client.services.api_client.is_some());
}

#[tokio::test]
async fn test_registry_login_actions_wire_handlers() {
    let registry = default_registry();
    let (mut state, _tmp) = temp_state();
    let ctx = test_ctx();

    // Locked state: these actions must return their specific locked/validation error, not "Acción no reconocida"
    let res_sync = registry
        .execute("Sync", &mut state, &ctx, &serde_json::json!({}))
        .await;
    assert_eq!(res_sync.unwrap_err(), AgentError::Locked);

    let res_list = registry
        .execute("ListLogins", &mut state, &ctx, &serde_json::json!({}))
        .await;
    assert_eq!(res_list.unwrap_err(), AgentError::Locked);

    let res_get = registry
        .execute(
            "GetLogin",
            &mut state,
            &ctx,
            &serde_json::json!({ "name": "test" }),
        )
        .await;
    assert_eq!(res_get.unwrap_err(), AgentError::Locked);

    let res_create = registry
        .execute("CreateLogin", &mut state, &ctx, &serde_json::json!({}))
        .await;
    assert_eq!(res_create.unwrap_err(), AgentError::Locked);

    let res_del = registry
        .execute("DeleteLogin", &mut state, &ctx, &serde_json::json!({}))
        .await;
    assert_eq!(res_del.unwrap_err(), AgentError::Locked);

    let res_set = registry
        .execute("SetSession", &mut state, &ctx, &serde_json::json!({}))
        .await;
    assert_eq!(res_set.unwrap()["status"], "session_saved");

    let res_login = registry
        .execute("Login", &mut state, &ctx, &serde_json::json!({}))
        .await;
    assert_eq!(res_login.unwrap()["status"], "session_saved");

    let sync_empty = serde_json::to_value(sw_vault::SyncData::default()).unwrap();
    let res_sd = registry
        .execute("SyncData", &mut state, &ctx, &sync_empty)
        .await;
    assert_eq!(res_sd.unwrap()["status"], "synced");

    let res_rv = registry
        .execute("ReloadVault", &mut state, &ctx, &sync_empty)
        .await;
    assert_eq!(res_rv.unwrap()["status"], "synced");
}

#[tokio::test]
async fn test_pin_cache_store_and_get() {
    let mut cache = PinCache::new(Duration::from_secs(900));
    assert!(!cache.is_valid());
    assert!(cache.get().is_none());
    assert!(cache.remaining().is_none());

    let key = [55u8; 32];
    cache.store(&key);

    assert!(cache.is_valid());
    assert!(cache.remaining().is_some());
    let retrieved = cache.get();
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap(), [55u8; 32]);
}

#[tokio::test]
async fn test_pin_cache_expires_after_ttl() {
    let clock = Arc::new(FakeClock::new());
    let ttl = Duration::from_secs(60);
    let mut cache = PinCache::with_clock(ttl, clock.clone());
    let key = [42u8; 32];
    cache.store(&key);
    assert!(cache.is_valid());

    clock.advance(Duration::from_secs(61));

    assert!(!cache.is_valid());
    assert!(cache.get().is_none());
    assert!(cache.remaining().is_none());
}

#[tokio::test]
async fn test_pin_cache_ttl_resets_on_get() {
    let clock = Arc::new(FakeClock::new());
    let ttl = Duration::from_secs(60);
    let mut cache = PinCache::with_clock(ttl, clock.clone());
    let key = [77u8; 32];
    cache.store(&key);

    // Avanzar la mitad del TTL (30s)
    clock.advance(Duration::from_secs(30));
    assert!(cache.is_valid());
    let rem1 = cache.remaining().unwrap();
    assert_eq!(rem1, Duration::from_secs(30));

    // get() reinicia el TTL a 60s
    let ret = cache.get();
    assert!(ret.is_some());

    // Avanzar 40s más (total 70s desde store, pero 40s desde get)
    clock.advance(Duration::from_secs(40));
    assert!(cache.is_valid());
    assert!(cache.get().is_some());

    // Avanzar 65s más -> como pasaron más de los 60s de TTL desde el último get, expira
    clock.advance(Duration::from_secs(65));
    assert!(!cache.is_valid());
    assert!(cache.get().is_none());
}

#[tokio::test]
async fn test_pin_cache_clear() {
    let mut cache = PinCache::new(Duration::from_secs(900));
    let key = [88u8; 32];
    cache.store(&key);
    assert!(cache.is_valid());

    cache.clear();
    assert!(!cache.is_valid());
    assert!(cache.get().is_none());
    assert!(cache.remaining().is_none());
}

#[tokio::test]
async fn test_unlock_uses_pin_cache_when_valid() {
    let registry = default_registry();
    let (_state, temp_dir) = temp_state();
    let mut state = AgentState::new(
        ConfigFile {
            device_uuid: "test-dev-uuid".to_string(),
            ..Default::default()
        },
        Arc::new(VaultAgentServer::default()),
    )
    .with_config_directory(temp_dir.path());
    let ctx = test_ctx();

    // 1. Configurar PIN
    let set_res = registry
        .execute(
            "PinSet",
            &mut state,
            &ctx,
            &serde_json::json!({ "pin": "cache_pin_123" }),
        )
        .await
        .unwrap();
    assert_eq!(set_res["status"], "pin_set");

    // 2. Primer Unlock con PIN: cache miss
    let unlock1 = registry
        .execute(
            "Unlock",
            &mut state,
            &ctx,
            &serde_json::json!({ "pin": "cache_pin_123" }),
        )
        .await
        .unwrap();
    assert_eq!(unlock1["status"], "unlocked");
    assert_eq!(unlock1["from_cache"], false);
    assert!(state.security.pin_cache.is_valid());

    // Simulamos bloqueo del agente sin llamar a Lock (ej. bloqueo por inactividad o cambio de bandera)
    state.session.is_locked = true;

    // 3. Segundo Unlock sin PIN: cache hit (no ejecuta Argon2i)
    let unlock2 = registry
        .execute("Unlock", &mut state, &ctx, &serde_json::json!({}))
        .await
        .unwrap();
    assert_eq!(unlock2["status"], "unlocked");
    assert_eq!(unlock2["from_cache"], true);
    assert!(!state.session.is_locked);
}

#[tokio::test]
async fn test_unlock_falls_back_to_argon2_when_cache_miss() {
    let registry = default_registry();
    let (_state, temp_dir) = temp_state();
    let mut state = AgentState::new(
        ConfigFile {
            device_uuid: "test-dev-uuid".to_string(),
            ..Default::default()
        },
        Arc::new(VaultAgentServer::default()),
    )
    .with_config_directory(temp_dir.path());
    let ctx = test_ctx();

    registry
        .execute(
            "PinSet",
            &mut state,
            &ctx,
            &serde_json::json!({ "pin": "my_pin_456" }),
        )
        .await
        .unwrap();

    // Limpiamos explícitamente el caché para forzar cache miss
    state.security.pin_cache.clear();
    assert!(!state.security.pin_cache.is_valid());

    // Intento de Unlock sin PIN debe fallar al no haber caché
    let err_no_pin = registry
        .execute("Unlock", &mut state, &ctx, &serde_json::json!({}))
        .await
        .unwrap_err();
    assert_eq!(
        err_no_pin,
        "Campo 'pin' requerido en payload (no hay caché válido)"
    );

    // Unlock con PIN ejecuta Argon2i y llena el caché
    let unlock_res = registry
        .execute(
            "Unlock",
            &mut state,
            &ctx,
            &serde_json::json!({ "pin": "my_pin_456" }),
        )
        .await
        .unwrap();
    assert_eq!(unlock_res["status"], "unlocked");
    assert_eq!(unlock_res["from_cache"], false);
    assert!(state.security.pin_cache.is_valid());
}

#[tokio::test]
async fn test_lock_clears_pin_cache() {
    let registry = default_registry();
    let (_state, temp_dir) = temp_state();
    let mut state = AgentState::new(
        ConfigFile {
            device_uuid: "test-dev-uuid".to_string(),
            ..Default::default()
        },
        Arc::new(VaultAgentServer::default()),
    )
    .with_config_directory(temp_dir.path());
    let ctx = test_ctx();

    registry
        .execute(
            "PinSet",
            &mut state,
            &ctx,
            &serde_json::json!({ "pin": "lock_pin_789" }),
        )
        .await
        .unwrap();

    let unlock = registry
        .execute(
            "Unlock",
            &mut state,
            &ctx,
            &serde_json::json!({ "pin": "lock_pin_789" }),
        )
        .await
        .unwrap();
    assert_eq!(unlock["status"], "unlocked");
    assert!(state.security.pin_cache.is_valid());

    // Lock debe limpiar el pin_cache por seguridad
    let lock_res = registry
        .execute("Lock", &mut state, &ctx, &serde_json::json!({}))
        .await
        .unwrap();
    assert_eq!(lock_res["status"], "locked");
    assert!(!state.security.pin_cache.is_valid());
    assert!(state.security.pin_cache.get().is_none());

    // Posterior Unlock sin PIN falla porque el caché fue limpiado
    let unlock_fail = registry
        .execute("Unlock", &mut state, &ctx, &serde_json::json!({}))
        .await;
    assert!(unlock_fail.is_err());
}

#[tokio::test]
async fn test_pin_update_clears_and_stores_new() {
    let registry = default_registry();
    let (_state, temp_dir) = temp_state();
    let mut state = AgentState::new(
        ConfigFile {
            device_uuid: "test-dev-uuid".to_string(),
            ..Default::default()
        },
        Arc::new(VaultAgentServer::default()),
    )
    .with_config_directory(temp_dir.path());
    let ctx = test_ctx();

    registry
        .execute(
            "PinSet",
            &mut state,
            &ctx,
            &serde_json::json!({ "pin": "old_pin_111" }),
        )
        .await
        .unwrap();

    let _ = registry
        .execute(
            "Unlock",
            &mut state,
            &ctx,
            &serde_json::json!({ "pin": "old_pin_111" }),
        )
        .await
        .unwrap();
    assert!(state.security.pin_cache.is_valid());

    // PinUpdate debe limpiar el caché previo y almacenar la nueva clave derivada
    let update_res = registry
        .execute(
            "PinUpdate",
            &mut state,
            &ctx,
            &serde_json::json!({
                "old_pin": "old_pin_111",
                "new_pin": "new_pin_222"
            }),
        )
        .await
        .unwrap();
    assert_eq!(update_res["status"], "pin_updated");
    assert!(state.security.pin_cache.is_valid());

    // El nuevo PIN está en caché y permite Unlock inmediato sin enviar PIN
    state.session.is_locked = true;
    let unlock_cache = registry
        .execute("Unlock", &mut state, &ctx, &serde_json::json!({}))
        .await
        .unwrap();
    assert_eq!(unlock_cache["status"], "unlocked");
    assert_eq!(unlock_cache["from_cache"], true);
}

#[tokio::test]
async fn test_status_reports_pin_cached() {
    let registry = default_registry();
    let (_state, temp_dir) = temp_state();
    let mut state = AgentState::new(
        ConfigFile {
            device_uuid: "test-dev-uuid".to_string(),
            ..Default::default()
        },
        Arc::new(VaultAgentServer::default()),
    )
    .with_config_directory(temp_dir.path());
    let ctx = test_ctx();

    // Status inicial antes de configurar PIN
    let st_init = registry
        .execute("Status", &mut state, &ctx, &serde_json::json!({}))
        .await
        .unwrap();
    assert_eq!(st_init["pin_cached"], false);
    assert_eq!(st_init["pin_cached_remaining_secs"], 0);

    registry
        .execute(
            "PinSet",
            &mut state,
            &ctx,
            &serde_json::json!({ "pin": "status_pin_333" }),
        )
        .await
        .unwrap();

    let _ = registry
        .execute(
            "Unlock",
            &mut state,
            &ctx,
            &serde_json::json!({ "pin": "status_pin_333" }),
        )
        .await
        .unwrap();

    let st_after = registry
        .execute("Status", &mut state, &ctx, &serde_json::json!({}))
        .await
        .unwrap();
    assert_eq!(st_after["pin_cached"], true);
    let remaining = st_after["pin_cached_remaining_secs"].as_u64().unwrap();
    assert!(remaining > 0 && remaining <= 900);
}

#[tokio::test]
async fn test_pin_cache_constant_time_no_panic() {
    let mut cache = PinCache::new(Duration::from_secs(900));

    // Intento de almacenar clave de tamaño incorrecto (ej. 64 bytes o 16 bytes)
    cache.store(&[1u8; 64]);
    assert!(!cache.is_valid());
    assert!(cache.get().is_none());

    cache.store(&[1u8; 16]);
    assert!(!cache.is_valid());
    assert!(cache.get().is_none());

    // Con clave válida de 32 bytes
    let valid_key = [9u8; 32];
    cache.store(&valid_key);
    assert!(cache.is_valid());

    let retrieved = cache.get();
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap(), [9u8; 32]);
}

#[tokio::test]
async fn test_unlock_cache_hit_decrypts_token_and_symmetric_key() {
    let registry = default_registry();
    let (_state, temp_dir) = temp_state();
    let ctx = test_ctx();

    let device_uuid = "test-device-uuid-1234";
    let pin = "correct_secret_pin";
    let config_key =
        sw_config::derive_config_key_with_params(pin, device_uuid, AGENT_KDF_MEMORY_KIB).unwrap();
    let config_key_hash = sw_config::hash_config_key(&config_key);

    // Preparamos token sintético y lo ciframos con config_key
    let original_token = sw_config::LoginToken {
        access_token: "mock_access_token_123".to_string(),
        expires_in: 3600,
        token_type: "Bearer".to_string(),
        refresh_token: "mock_refresh_token_456".to_string(),
        key: "mock_key_789".to_string(),
        ..Default::default()
    };
    let token_json = serde_json::to_string(&original_token).unwrap();
    let enc_token = sw_config::encrypt_string(&token_json, &config_key).unwrap();

    // Preparamos clave simétrica de usuario (64 bytes) y la ciframos con config_key
    use base64::Engine;
    let original_user_sym_key = [77u8; 64];
    let user_sym_b64 = base64::engine::general_purpose::STANDARD.encode(original_user_sym_key);
    let enc_user_sym = sw_config::encrypt_string(&user_sym_b64, &config_key).unwrap();

    let (va, _) = test_agent(1);
    let cfg = ConfigFile {
        device_uuid: device_uuid.to_string(),
        config_key_hash,
        encrypted_token: enc_token,
        encrypted_user_symmetric_key: enc_user_sym,
        identity_url: "https://identity.bitwarden.test".to_string(),
        api_url: "https://api.bitwarden.test".to_string(),
        ..Default::default()
    };

    let mut state = AgentState::new(cfg, va.clone()).with_config_directory(temp_dir.path());

    // 1. Primer Unlock con PIN: cache miss
    let unlock1 = registry
        .execute(
            "Unlock",
            &mut state,
            &ctx,
            &serde_json::json!({ "pin": pin }),
        )
        .await
        .unwrap();
    assert_eq!(unlock1["status"], "unlocked");
    assert_eq!(unlock1["from_cache"], false);
    assert!(!va.is_locked());
    assert!(state.services.api_client.is_some());

    // 2. Simular bloqueo del agente
    state.session.is_locked = true;
    va.lock().await;
    assert!(va.is_locked());

    // 3. Segundo Unlock sin PIN: cache hit. Debe descifrar token y user_symmetric_key idénticos
    let unlock2 = registry
        .execute("Unlock", &mut state, &ctx, &serde_json::json!({}))
        .await
        .unwrap();
    assert_eq!(unlock2["status"], "unlocked");
    assert_eq!(unlock2["from_cache"], true);
    assert!(!state.session.is_locked);
    assert!(!va.is_locked());

    // Verificar que el token descifrado coincide exactamente
    let cached_cfg_key = state.security.pin_cache.get().unwrap();
    let decrypted_token = state.services.config.decrypt_token(&cached_cfg_key).unwrap();
    assert_eq!(decrypted_token.access_token, original_token.access_token);
    assert_eq!(decrypted_token.refresh_token, original_token.refresh_token);

    // Verificar que la user_symmetric_key descifrada coincide exactamente
    let dec_user_sym_b64 =
        sw_config::decrypt_string(&state.services.config.encrypted_user_symmetric_key, &cached_cfg_key)
            .unwrap();
    let dec_user_sym_bytes = base64::engine::general_purpose::STANDARD
        .decode(dec_user_sym_b64.trim())
        .unwrap();
    assert_eq!(dec_user_sym_bytes, original_user_sym_key);
}

#[tokio::test]
async fn test_unlock_cache_hit_empty_encrypted_token() {
    let registry = default_registry();
    let (_state, temp_dir) = temp_state();
    let ctx = test_ctx();

    let device_uuid = "test-device-uuid-empty-tok";
    let pin = "correct_secret_pin";
    let config_key =
        sw_config::derive_config_key_with_params(pin, device_uuid, AGENT_KDF_MEMORY_KIB).unwrap();
    let config_key_hash = sw_config::hash_config_key(&config_key);

    use base64::Engine;
    let original_user_sym_key = [77u8; 64];
    let user_sym_b64 = base64::engine::general_purpose::STANDARD.encode(original_user_sym_key);
    let enc_user_sym = sw_config::encrypt_string(&user_sym_b64, &config_key).unwrap();

    let (va, _) = test_agent(1);
    let cfg = ConfigFile {
        device_uuid: device_uuid.to_string(),
        config_key_hash,
        encrypted_token: String::new(),
        encrypted_user_symmetric_key: enc_user_sym,
        ..Default::default()
    };

    let mut state = AgentState::new(cfg, va.clone()).with_config_directory(temp_dir.path());

    // 1. Primer Unlock con PIN (cache miss): encrypted_token está vacío -> no crea api_client
    let unlock1 = registry
        .execute(
            "Unlock",
            &mut state,
            &ctx,
            &serde_json::json!({ "pin": pin }),
        )
        .await
        .unwrap();
    assert_eq!(unlock1["status"], "unlocked");
    assert_eq!(unlock1["from_cache"], false);
    assert!(!va.is_locked());
    assert!(state.services.api_client.is_none());

    // 2. Simular bloqueo
    state.session.is_locked = true;
    va.lock().await;
    assert!(va.is_locked());

    // 3. Segundo Unlock sin PIN (cache hit): encrypted_token sigue vacío -> api_client permanece None
    let unlock2 = registry
        .execute("Unlock", &mut state, &ctx, &serde_json::json!({}))
        .await
        .unwrap();
    assert_eq!(unlock2["status"], "unlocked");
    assert_eq!(unlock2["from_cache"], true);
    assert!(!state.session.is_locked);
    assert!(!va.is_locked());
    assert!(state.services.api_client.is_none());
}

#[tokio::test]
async fn test_unlock_cache_hit_empty_encrypted_user_symmetric_key() {
    let registry = default_registry();
    let (_state, temp_dir) = temp_state();
    let ctx = test_ctx();

    let device_uuid = "test-device-uuid-empty-sym";
    let pin = "correct_secret_pin";
    let config_key =
        sw_config::derive_config_key_with_params(pin, device_uuid, AGENT_KDF_MEMORY_KIB).unwrap();
    let config_key_hash = sw_config::hash_config_key(&config_key);

    let (va, _) = test_agent(1);
    let cfg = ConfigFile {
        device_uuid: device_uuid.to_string(),
        config_key_hash,
        encrypted_token: String::new(),
        encrypted_user_symmetric_key: String::new(),
        ..Default::default()
    };

    let mut state = AgentState::new(cfg, va.clone()).with_config_directory(temp_dir.path());

    // 1. Primer Unlock con PIN (cache miss): enc_sym vacío -> fallback a from_parts
    let unlock1 = registry
        .execute(
            "Unlock",
            &mut state,
            &ctx,
            &serde_json::json!({ "pin": pin }),
        )
        .await
        .unwrap();
    assert_eq!(unlock1["status"], "unlocked");
    assert_eq!(unlock1["from_cache"], false);
    assert!(!va.is_locked());

    // 2. Simular bloqueo
    state.session.is_locked = true;
    va.lock().await;
    assert!(va.is_locked());

    // 3. Segundo Unlock sin PIN (cache hit): enc_sym vacío -> fallback a from_parts
    let unlock2 = registry
        .execute("Unlock", &mut state, &ctx, &serde_json::json!({}))
        .await
        .unwrap();
    assert_eq!(unlock2["status"], "unlocked");
    assert_eq!(unlock2["from_cache"], true);
    assert!(!state.session.is_locked);
    assert!(!va.is_locked());
}

#[tokio::test]
async fn test_unlock_cache_hit_decrypt_string_fails() {
    let registry = default_registry();
    let (_state, temp_dir) = temp_state();
    let ctx = test_ctx();

    let device_uuid = "test-device-uuid-corrupt-sym";
    let pin = "correct_secret_pin";
    let config_key =
        sw_config::derive_config_key_with_params(pin, device_uuid, AGENT_KDF_MEMORY_KIB).unwrap();
    let config_key_hash = sw_config::hash_config_key(&config_key);

    // Generar un EncString válido y corromperlo cambiando el último carácter (MAC inválida)
    let valid_enc =
        sw_config::encrypt_string("dummy_user_symmetric_key_payload", &config_key).unwrap();
    let mut chars: Vec<char> = valid_enc.chars().collect();
    let last_idx = chars.len() - 1;
    chars[last_idx] = if chars[last_idx] == 'A' { 'B' } else { 'A' };
    let corrupted_enc: String = chars.into_iter().collect();

    let (va, _) = test_agent(1);
    let cfg = ConfigFile {
        device_uuid: device_uuid.to_string(),
        config_key_hash,
        encrypted_token: String::new(),
        encrypted_user_symmetric_key: corrupted_enc,
        ..Default::default()
    };

    let mut state = AgentState::new(cfg, va.clone()).with_config_directory(temp_dir.path());

    // 1. Primer Unlock con PIN (cache miss): decrypt_string falla -> fallback a from_parts
    let unlock1 = registry
        .execute(
            "Unlock",
            &mut state,
            &ctx,
            &serde_json::json!({ "pin": pin }),
        )
        .await
        .unwrap();
    assert_eq!(unlock1["status"], "unlocked");
    assert_eq!(unlock1["from_cache"], false);
    assert!(!va.is_locked());

    // 2. Simular bloqueo
    state.session.is_locked = true;
    va.lock().await;
    assert!(va.is_locked());

    // 3. Segundo Unlock sin PIN (cache hit): decrypt_string falla -> fallback a from_parts sin pánico
    let unlock2 = registry
        .execute("Unlock", &mut state, &ctx, &serde_json::json!({}))
        .await
        .unwrap();
    assert_eq!(unlock2["status"], "unlocked");
    assert_eq!(unlock2["from_cache"], true);
    assert!(!state.session.is_locked);
    assert!(!va.is_locked());
}

#[tokio::test]
async fn test_unlock_cache_hit_base64_decode_fails() {
    let registry = default_registry();
    let (_state, temp_dir) = temp_state();
    let ctx = test_ctx();

    let device_uuid = "test-device-uuid-bad-b64";
    let pin = "correct_secret_pin";
    let config_key =
        sw_config::derive_config_key_with_params(pin, device_uuid, AGENT_KDF_MEMORY_KIB).unwrap();
    let config_key_hash = sw_config::hash_config_key(&config_key);

    // 1. Cifrar un string que se descifra correctamente pero NO es base64 válido
    let not_base64 = "this string is definitely NOT valid base64!!! @@##";
    let enc_not_b64 = sw_config::encrypt_string(not_base64, &config_key).unwrap();

    let (va, _) = test_agent(1);
    let cfg = ConfigFile {
        device_uuid: device_uuid.to_string(),
        config_key_hash,
        encrypted_token: String::new(),
        encrypted_user_symmetric_key: enc_not_b64,
        ..Default::default()
    };

    let mut state = AgentState::new(cfg, va.clone()).with_config_directory(temp_dir.path());

    // Unlock con PIN (cache miss): base64 decode falla -> fallback a from_parts
    let unlock1 = registry
        .execute(
            "Unlock",
            &mut state,
            &ctx,
            &serde_json::json!({ "pin": pin }),
        )
        .await
        .unwrap();
    assert_eq!(unlock1["status"], "unlocked");
    assert_eq!(unlock1["from_cache"], false);
    assert!(!va.is_locked());

    // Simular bloqueo
    state.session.is_locked = true;
    va.lock().await;
    assert!(va.is_locked());

    // Unlock sin PIN (cache hit): base64 decode falla -> fallback a from_parts
    let unlock2 = registry
        .execute("Unlock", &mut state, &ctx, &serde_json::json!({}))
        .await
        .unwrap();
    assert_eq!(unlock2["status"], "unlocked");
    assert_eq!(unlock2["from_cache"], true);
    assert!(!state.session.is_locked);
    assert!(!va.is_locked());

    // 2. Probar rama adicional: base64 decode es válido pero longitud no es 64 bytes (falla from_bytes)
    use base64::Engine;
    let short_key_b64 = base64::engine::general_purpose::STANDARD.encode([42u8; 16]);
    let enc_short_key = sw_config::encrypt_string(&short_key_b64, &config_key).unwrap();
    state.services.config.encrypted_user_symmetric_key = enc_short_key;

    // Simular bloqueo
    state.session.is_locked = true;
    va.lock().await;
    assert!(va.is_locked());

    // Unlock sin PIN (cache hit): decode ok, from_bytes falla (16 != 64) -> fallback a from_parts
    let unlock3 = registry
        .execute("Unlock", &mut state, &ctx, &serde_json::json!({}))
        .await
        .unwrap();
    assert_eq!(unlock3["status"], "unlocked");
    assert_eq!(unlock3["from_cache"], true);
    assert!(!state.session.is_locked);
    assert!(!va.is_locked());
}

#[tokio::test]
async fn test_unlock_cache_hit_no_vault_agent() {
    let registry = default_registry();
    let (_state, temp_dir) = temp_state();
    let ctx = test_ctx();

    let device_uuid = "test-device-uuid-no-va";
    let pin = "correct_secret_pin";
    let config_key =
        sw_config::derive_config_key_with_params(pin, device_uuid, AGENT_KDF_MEMORY_KIB).unwrap();
    let config_key_hash = sw_config::hash_config_key(&config_key);

    let cfg = ConfigFile {
        device_uuid: device_uuid.to_string(),
        config_key_hash,
        encrypted_token: String::new(),
        encrypted_user_symmetric_key: String::new(),
        ..Default::default()
    };

    let va = Arc::new(VaultAgentServer::default());
    let mut state = AgentState::new(cfg, va).with_config_directory(temp_dir.path());

    // 1. Unlock con PIN: cache miss
    let unlock1 = registry
        .execute(
            "Unlock",
            &mut state,
            &ctx,
            &serde_json::json!({ "pin": pin }),
        )
        .await
        .unwrap();
    assert_eq!(unlock1["status"], "unlocked");
    assert_eq!(unlock1["from_cache"], false);
    assert!(!state.session.is_locked);

    // 2. Simular bloqueo
    state.session.is_locked = true;

    // 3. Unlock sin PIN: cache hit
    let unlock2 = registry
        .execute("Unlock", &mut state, &ctx, &serde_json::json!({}))
        .await
        .unwrap();
    assert_eq!(unlock2["status"], "unlocked");
    assert_eq!(unlock2["from_cache"], true);
    assert!(!state.session.is_locked);
}

#[tokio::test]
async fn test_lock_notifies_via_notifier() {
    let registry = default_registry();
    let (state, _temp_dir) = temp_state();
    let mock_notifier = Arc::new(sw_notify::MockNotifier::new());
    let mut state = state.with_notifier(mock_notifier.clone());
    let ctx = test_ctx();

    let lock_res = registry
        .execute("Lock", &mut state, &ctx, &serde_json::json!({}))
        .await
        .unwrap();
    assert_eq!(lock_res["status"], "locked");
    assert!(state.session.is_locked);

    let notifs = mock_notifier.notifications();
    assert_eq!(notifs.len(), 1);
    assert_eq!(
        notifs[0],
        ("SilverWarden".to_string(), "Bóveda bloqueada".to_string())
    );
}

#[tokio::test]
async fn test_lock_succeeds_even_if_notifier_fails() {
    let registry = default_registry();
    let (state, _temp_dir) = temp_state();
    let mock_notifier = Arc::new(sw_notify::MockNotifier::failing());
    let mut state = state.with_notifier(mock_notifier.clone());
    let ctx = test_ctx();

    let lock_res = registry
        .execute("Lock", &mut state, &ctx, &serde_json::json!({}))
        .await
        .expect("Lock should succeed even if notifier fails (silent fallback)");
    assert_eq!(lock_res["status"], "locked");
    assert!(state.session.is_locked);
    assert!(mock_notifier.notifications().is_empty());
}

#[tokio::test]
async fn test_last_activity_updates_on_ipc() {
    let (mut state, _temp_dir) = temp_state();
    state.session.is_locked = false;
    let daemon = AgentDaemon::with_state(state);
    let ctx = test_ctx();

    let past = std::time::Instant::now() - Duration::from_secs(60);
    *daemon.state.read().await.security.last_activity.write().await = past;

    let idle_before = daemon.state.read().await.idle_duration().await;
    assert!(idle_before >= Duration::from_secs(59));

    let msg = Request::Status;
    let _ = daemon.handle_message(&ctx, msg).await;

    let idle_after = daemon.state.read().await.idle_duration().await;
    assert!(idle_after < Duration::from_secs(5));
}

#[tokio::test]
async fn test_idle_monitor_locks_after_ttl() {
    let (mut state, _temp_dir) = temp_state();
    state.session.is_locked = false;
    let mock_notifier = Arc::new(sw_notify::MockNotifier::new());
    state.security.notifier = mock_notifier.clone();
    state.services.config.runtime_config.idle_ttl_secs = 10;
    let state_arc = Arc::new(RwLock::new(state));

    let past = std::time::Instant::now() - Duration::from_secs(20);
    *state_arc.read().await.security.last_activity.write().await = past;

    let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let monitor_handle = spawn_idle_monitor(
        state_arc.clone(),
        shutdown_tx.subscribe(),
        Duration::from_millis(10),
        Some(ready_tx),
    );

    ready_rx.await.unwrap();
    let _ = shutdown_tx.send(());
    let _ = monitor_handle.await;

    assert!(state_arc.read().await.session.is_locked);
    let notifs = mock_notifier.notifications();
    assert_eq!(notifs.len(), 1);
    assert_eq!(
        notifs[0],
        (
            "SilverWarden".to_string(),
            "Bóveda bloqueada por inactividad".to_string()
        )
    );
}

#[tokio::test]
async fn test_idle_monitor_resets_on_activity() {
    let (mut state, _temp_dir) = temp_state();
    state.session.is_locked = false;
    let mock_notifier = Arc::new(sw_notify::MockNotifier::new());
    state.security.notifier = mock_notifier.clone();
    state.services.config.runtime_config.idle_ttl_secs = 100;
    let state_arc = Arc::new(RwLock::new(state));

    *state_arc.read().await.security.last_activity.write().await =
        std::time::Instant::now() - Duration::from_secs(50);

    state_arc.read().await.touch_activity().await;

    let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let monitor_handle = spawn_idle_monitor(
        state_arc.clone(),
        shutdown_tx.subscribe(),
        Duration::from_millis(10),
        Some(ready_tx),
    );

    ready_rx.await.unwrap();
    let _ = shutdown_tx.send(());
    let _ = monitor_handle.await;

    assert!(!state_arc.read().await.session.is_locked);
    assert!(mock_notifier.notifications().is_empty());
}

#[tokio::test]
async fn test_logind_prepare_for_sleep_locks() {
    let (mut state, _temp_dir) = temp_state();
    state.session.is_locked = false;
    let mock_notifier = Arc::new(sw_notify::MockNotifier::new());
    state.security.notifier = mock_notifier.clone();
    let state_arc = Arc::new(RwLock::new(state));

    // PrepareForSleep(false) should not lock
    handle_logind_event(&state_arc, LogindEvent::PrepareForSleep(false)).await;
    assert!(!state_arc.read().await.session.is_locked);
    assert!(mock_notifier.notifications().is_empty());

    // PrepareForSleep(true) should lock
    handle_logind_event(&state_arc, LogindEvent::PrepareForSleep(true)).await;
    assert!(state_arc.read().await.session.is_locked);
    let notifs = mock_notifier.notifications();
    assert_eq!(notifs.len(), 1);
    assert_eq!(
        notifs[0],
        (
            "SilverWarden".to_string(),
            "Bóveda bloqueada por suspensión del sistema".to_string()
        )
    );
}

#[tokio::test]
async fn test_logind_lock_signal_locks() {
    let (mut state, _temp_dir) = temp_state();
    state.session.is_locked = false;
    let mock_notifier = Arc::new(sw_notify::MockNotifier::new());
    state.security.notifier = mock_notifier.clone();
    let state_arc = Arc::new(RwLock::new(state));

    handle_logind_event(&state_arc, LogindEvent::Lock).await;
    assert!(state_arc.read().await.session.is_locked);
    let notifs = mock_notifier.notifications();
    assert_eq!(notifs.len(), 1);
    assert_eq!(
        notifs[0],
        (
            "SilverWarden".to_string(),
            "Bóveda bloqueada por bloqueo de pantalla".to_string()
        )
    );
}

#[tokio::test]
async fn test_idle_monitor_does_not_lock_when_already_locked() {
    let (mut state, _temp_dir) = temp_state();
    state.session.is_locked = true;
    let mock_notifier = Arc::new(sw_notify::MockNotifier::new());
    state.security.notifier = mock_notifier.clone();
    state.services.config.runtime_config.idle_ttl_secs = 1;
    let state_arc = Arc::new(RwLock::new(state));

    *state_arc.read().await.security.last_activity.write().await =
        std::time::Instant::now() - Duration::from_secs(10);

    let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let monitor_handle = spawn_idle_monitor(
        state_arc.clone(),
        shutdown_tx.subscribe(),
        Duration::from_millis(10),
        Some(ready_tx),
    );
    ready_rx.await.unwrap();
    let _ = shutdown_tx.send(());
    let _ = monitor_handle.await;

    handle_logind_event(&state_arc, LogindEvent::Lock).await;
    handle_logind_event(&state_arc, LogindEvent::PrepareForSleep(true)).await;

    assert!(state_arc.read().await.session.is_locked);
    assert!(mock_notifier.notifications().is_empty());
}

#[tokio::test]
async fn test_spawn_logind_monitor_shutdown() {
    let state = Arc::new(RwLock::new(AgentState::default()));
    let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
    let handle = spawn_logind_monitor(state, shutdown_tx.subscribe());
    let _ = shutdown_tx.send(());
    let res = tokio::time::timeout(Duration::from_secs(2), handle).await;
    assert!(res.is_ok());
}

#[tokio::test]
async fn test_biometrics_trait_mock_ok() {
    use sw_systemauth::biometrics::{Biometrics, MockBiometrics};
    let mock = MockBiometrics::new(true);
    let ctx = test_ctx();
    let res = mock.authenticate("test", &ctx).await;
    assert!(res.unwrap());
    assert_eq!(mock.call_count(), 1);
}

#[tokio::test]
async fn test_biometrics_trait_mock_fail() {
    use sw_systemauth::biometrics::{Biometrics, BiometricsError, MockBiometrics};
    let mock = MockBiometrics::failing();
    let ctx = test_ctx();
    let res = mock.authenticate("test", &ctx).await;
    assert!(matches!(res, Err(BiometricsError::Failed(_))));
    assert_eq!(mock.call_count(), 1);
}

#[tokio::test]
async fn test_unlock_with_biometrics_success() {
    let registry = default_registry();
    let (state, _temp_dir) = temp_state();
    let mock_bio = Arc::new(sw_systemauth::biometrics::MockBiometrics::new(true));
    let mut state = state.with_biometrics(mock_bio.clone());
    state.services.config.runtime_config.biometrics_enabled = true;
    let ctx = test_ctx();
    let pin = "bio_pin_123";

    let _ = registry
        .execute(
            "PinSet",
            &mut state,
            &ctx,
            &serde_json::json!({ "pin": pin }),
        )
        .await
        .unwrap();

    let unlock1 = registry
        .execute(
            "Unlock",
            &mut state,
            &ctx,
            &serde_json::json!({ "pin": pin }),
        )
        .await
        .unwrap();
    assert_eq!(unlock1["status"], "unlocked");
    assert_eq!(mock_bio.call_count(), 0);

    state.session.is_locked = true;

    let unlock2 = registry
        .execute("Unlock", &mut state, &ctx, &serde_json::json!({}))
        .await
        .unwrap();
    assert_eq!(unlock2["status"], "unlocked");
    assert_eq!(unlock2["from_cache"], true);
    assert_eq!(unlock2["biometrics"], true);
    assert!(!state.session.is_locked);
    assert_eq!(mock_bio.call_count(), 1);
}

#[tokio::test]
async fn test_unlock_with_biometrics_denied() {
    let registry = default_registry();
    let (state, _temp_dir) = temp_state();
    let mock_bio = Arc::new(sw_systemauth::biometrics::MockBiometrics::new(false));
    let mut state = state.with_biometrics(mock_bio.clone());
    state.services.config.runtime_config.biometrics_enabled = true;
    let ctx = test_ctx();
    let pin = "bio_pin_denied";

    let _ = registry
        .execute(
            "PinSet",
            &mut state,
            &ctx,
            &serde_json::json!({ "pin": pin }),
        )
        .await
        .unwrap();

    let _ = registry
        .execute(
            "Unlock",
            &mut state,
            &ctx,
            &serde_json::json!({ "pin": pin }),
        )
        .await
        .unwrap();

    state.session.is_locked = true;

    let err = registry
        .execute("Unlock", &mut state, &ctx, &serde_json::json!({}))
        .await
        .unwrap_err();
    assert_eq!(err, "Biometría cancelada o fallida");
    assert!(state.session.is_locked);
    assert_eq!(mock_bio.call_count(), 1);
}

#[tokio::test]
async fn test_unlock_with_biometrics_disabled() {
    let registry = default_registry();
    let (state, _temp_dir) = temp_state();
    let mock_bio = Arc::new(sw_systemauth::biometrics::MockBiometrics::new(true));
    let mut state = state.with_biometrics(mock_bio.clone());
    state.services.config.runtime_config.biometrics_enabled = false;
    let ctx = test_ctx();
    let pin = "bio_pin_disabled";

    let _ = registry
        .execute(
            "PinSet",
            &mut state,
            &ctx,
            &serde_json::json!({ "pin": pin }),
        )
        .await
        .unwrap();

    let _ = registry
        .execute(
            "Unlock",
            &mut state,
            &ctx,
            &serde_json::json!({ "pin": pin }),
        )
        .await
        .unwrap();

    state.session.is_locked = true;

    let unlock2 = registry
        .execute("Unlock", &mut state, &ctx, &serde_json::json!({}))
        .await
        .unwrap();
    assert_eq!(unlock2["status"], "unlocked");
    assert_eq!(unlock2["from_cache"], true);
    assert_eq!(unlock2["biometrics"], false);
    assert!(!state.session.is_locked);
    assert_eq!(mock_bio.call_count(), 0);
}

#[tokio::test]
async fn test_status_logged_in_false_when_locked() {
    let registry = default_registry();
    let (mut state, _temp_dir) = temp_state();
    let ctx = test_ctx();

    // Configurado como logueado
    state.services.config.encrypted_token = "some_encrypted_token".into();

    // 1. Desbloqueado: Status reporta logged_in: true
    state.session.is_locked = false;
    let st_unlocked = registry
        .execute("Status", &mut state, &ctx, &serde_json::json!({}))
        .await
        .unwrap();
    assert_eq!(st_unlocked["locked"], false);
    assert_eq!(st_unlocked["logged_in"], true);

    // 2. Ejecutar Lock
    let lock_res = registry
        .execute("Lock", &mut state, &ctx, &serde_json::json!({}))
        .await
        .unwrap();
    assert_eq!(lock_res["status"], "locked");
    assert!(state.session.is_locked);

    // 3. Bloqueado: Status reporta logged_in: false aunque config.encrypted_token exista
    let st_locked = registry
        .execute("Status", &mut state, &ctx, &serde_json::json!({}))
        .await
        .unwrap();
    assert_eq!(st_locked["locked"], true);
    assert_eq!(st_locked["logged_in"], false);
}

#[tokio::test]
async fn test_list_logins_includes_all_logins_even_with_cipher_key_and_corrupt_notes() {
    let registry = default_registry();
    let (mut state, _temp_dir) = temp_state();
    let ctx = test_ctx();
    state.session.is_locked = false;

    let user_key = sw_crypto::SymmetricKey::from_bytes(&[0x42u8; 64]).unwrap();
    let org_key = sw_crypto::SymmetricKey::from_bytes(&[0x88u8; 64]).unwrap();

    let agent = Arc::new(VaultAgentServer::default());
    agent.unlock(user_key.clone()).await;
    state.services.vault_agent = agent.clone();

    // Login 1: Standard user cipher
    let l1 = sw_vault::Cipher {
        id: Some(uuid::Uuid::new_v4()),
        r#type: sw_vault::CipherType::Login,
        name: sw_crypto::encrypt_with(
            b"Standard Login",
            sw_crypto::EncStringType::AesCbc256HmacSha256B64,
            &user_key,
        )
        .unwrap(),
        login: Some(sw_vault::LoginCipher {
            username: Some(
                sw_crypto::encrypt_with(
                    b"std_user",
                    sw_crypto::EncStringType::AesCbc256HmacSha256B64,
                    &user_key,
                )
                .unwrap(),
            ),
            ..Default::default()
        }),
        ..Default::default()
    };

    // Login 2: Org cipher with cipher.key and corrupt notes
    let enc_org_key = sw_crypto::encrypt_with(
        &org_key.bytes(),
        sw_crypto::EncStringType::AesCbc256HmacSha256B64,
        &user_key,
    )
    .unwrap();
    let l2 = sw_vault::Cipher {
        id: Some(uuid::Uuid::new_v4()),
        r#type: sw_vault::CipherType::Login,
        key: Some(enc_org_key),
        name: sw_crypto::encrypt_with(
            b"Org Login",
            sw_crypto::EncStringType::AesCbc256HmacSha256B64,
            &org_key,
        )
        .unwrap(),
        login: Some(sw_vault::LoginCipher {
            username: Some(
                sw_crypto::encrypt_with(
                    b"org_user",
                    sw_crypto::EncStringType::AesCbc256HmacSha256B64,
                    &org_key,
                )
                .unwrap(),
            ),
            ..Default::default()
        }),
        // Corrupt notes that would fail decryption with wrong key
        notes: Some(sw_crypto::EncString::new(
            sw_crypto::EncStringType::AesCbc256HmacSha256B64,
            vec![1, 2, 3],
            vec![4, 5, 6],
            vec![],
        )),
        ..Default::default()
    };

    agent.vault().insert(l1).await;
    agent.vault().insert(l2).await;

    let res = registry
        .execute("ListLogins", &mut state, &ctx, &serde_json::json!({}))
        .await
        .unwrap();

    let arr = res.as_array().unwrap();
    assert_eq!(arr.len(), 2);
    let names: Vec<_> = arr
        .iter()
        .map(|item| item["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"Standard Login"));
    assert!(names.contains(&"Org Login"));
}

#[tokio::test]
async fn test_list_logins_resolves_organization_key_via_keyring() {
    let registry = default_registry();
    let (mut state, _temp_dir) = temp_state();
    let ctx = test_ctx();
    state.session.is_locked = false;

    let user_key = sw_crypto::SymmetricKey::from_bytes(&[0x11u8; 64]).unwrap();
    let org_key = sw_crypto::SymmetricKey::from_bytes(&[0x22u8; 64]).unwrap();

    let agent = Arc::new(VaultAgentServer::default());
    agent.unlock(user_key.clone()).await;
    state.services.vault_agent = agent.clone();

    let org_id = uuid::Uuid::new_v4();
    let enc_org_key_str = sw_crypto::encrypt_with_to_string(
        &org_key.bytes(),
        sw_crypto::EncStringType::AesCbc256HmacSha256B64,
        &user_key,
    )
    .unwrap();

    let profile = sw_vault::Profile {
        id: Some(uuid::Uuid::new_v4()),
        organizations: vec![sw_vault::Organization {
            id: Some(org_id),
            key: Some(enc_org_key_str),
            name: Some("Test Org".to_string()),
            enabled: true,
            ..Default::default()
        }],
        ..Default::default()
    };
    let sync_data = sw_vault::SyncData {
        profile,
        folders: vec![],
        ciphers: vec![],
    };
    agent.vault().load_sync_data(sync_data).await;

    let cipher_item_key = sw_crypto::SymmetricKey::from_bytes(&[0x33u8; 64]).unwrap();
    let enc_cipher_key = sw_crypto::encrypt_with(
        &cipher_item_key.bytes(),
        sw_crypto::EncStringType::AesCbc256HmacSha256B64,
        &org_key,
    )
    .unwrap();

    let cipher = sw_vault::Cipher {
        id: Some(uuid::Uuid::new_v4()),
        organization_id: Some(org_id),
        r#type: sw_vault::CipherType::Login,
        key: Some(enc_cipher_key),
        name: sw_crypto::encrypt_with(
            b"Secret Org System",
            sw_crypto::EncStringType::AesCbc256HmacSha256B64,
            &cipher_item_key,
        )
        .unwrap(),
        login: Some(sw_vault::LoginCipher {
            username: Some(
                sw_crypto::encrypt_with(
                    b"admin@org.com",
                    sw_crypto::EncStringType::AesCbc256HmacSha256B64,
                    &cipher_item_key,
                )
                .unwrap(),
            ),
            password: Some(
                sw_crypto::encrypt_with(
                    b"SuperSecretPassword",
                    sw_crypto::EncStringType::AesCbc256HmacSha256B64,
                    &cipher_item_key,
                )
                .unwrap(),
            ),
            ..Default::default()
        }),
        ..Default::default()
    };
    agent.vault().insert(cipher).await;

    let res = registry
        .execute("ListLogins", &mut state, &ctx, &serde_json::json!({}))
        .await
        .unwrap();

    let arr = res.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["name"], "Secret Org System");
    assert_eq!(arr[0]["username"], "admin@org.com");

    let get_res = registry
        .execute(
            "GetLogin",
            &mut state,
            &ctx,
            &serde_json::json!({ "name": "Secret Org System" }),
        )
        .await
        .unwrap();
    assert_eq!(get_res["name"], "Secret Org System");
    assert_eq!(get_res["username"], "admin@org.com");
    assert_eq!(get_res["password"], "SuperSecretPassword");
}

#[tokio::test]
async fn test_shared_vault_between_daemon_and_ssh_agent() {
    use sw_crypto::SymmetricKey;
    use sw_ssh_agent::SshAgentServer;

    let temp_dir = tempfile::tempdir().unwrap();
    let _agent_sock = temp_dir.path().join("agent.sock");
    let ssh_sock = temp_dir.path().join("ssh.sock");

    // 1. Instancia compartida única de VaultAgentServer
    let vault_agent = Arc::new(VaultAgentServer::default());
    let key = SymmetricKey::from_bytes(&[88u8; 64]).unwrap();
    vault_agent.unlock(key).await;

    // 2. Composición: el daemon y el SSH agent reciben la misma instancia
    let state = AgentState::default().with_vault_agent(vault_agent.clone());
    let daemon = AgentDaemon::with_vault_agent(state, vault_agent.clone());
    let ssh_server = SshAgentServer::new(&ssh_sock, (*vault_agent).clone());

    // Verificar identidad en memoria: ambos apuntan al mismo VaultStore subyacente
    assert!(Arc::ptr_eq(
        daemon.state.read().await.services.vault_agent.vault(),
        ssh_server.agent().vault()
    ));

    // 3. Crear una clave SSH a través del daemon (IPC)
    let ctx = CallingContext {
        username: "tester".into(),
        process_name: "test".into(),
        parent_process_name: "test_runner".into(),
        grandparent_process_name: "cargo".into(),
        process_pid: 10,
        parent_process_pid: 5,
        grandparent_process_pid: 1,
        error: false,
        authenticated: true,
    };
    let new_key_req = Request::NewSshKey {
        name: "shared-agent-key".into(),
        key_type: "Ed25519".into(),
    };
    let resp = daemon.handle_message(&ctx, new_key_req).await;
    assert!(resp.is_ok());

    // 4. El SSH agent ve la clave inmediatamente a través del VaultStore compartido
    let identities = ssh_server.agent().request_identities().await.unwrap();
    assert_eq!(identities.len(), 1);
    assert_eq!(identities[0].comment(), "shared-agent-key");

    // 5. El daemon bloquea el vault_agent compartido
    let lock_resp = daemon.handle_message(&ctx, Request::Lock).await;
    assert!(lock_resp.is_ok());

    // El SSH agent ahora está bloqueado y no lista identidades
    assert!(ssh_server.agent().is_locked());
    let locked_ids = ssh_server.agent().request_identities().await.unwrap();
    assert_eq!(locked_ids.len(), 0);
}
