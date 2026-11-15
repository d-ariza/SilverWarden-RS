use super::*;
use tokio::io::AsyncWriteExt;

#[tokio::test]
async fn test_golden_json_contract_unlock() {
    let req = Request::Unlock {
        pin: Some("1234".to_string()),
    };
    let serialized = serde_json::to_string(&req).expect("Serialization failed");
    assert_eq!(
        serialized,
        r#"{"action":"Unlock","payload":{"pin":"1234"}}"#
    );

    let deserialized: Request = serde_json::from_str(&serialized).expect("Deserialization failed");
    assert_eq!(deserialized, req);
}

#[tokio::test]
async fn test_golden_json_contract_status_and_lock() {
    let req = Request::Status;
    let serialized = serde_json::to_string(&req).expect("Serialization failed");
    assert_eq!(serialized, r#"{"action":"Status"}"#);

    let deserialized: Request = serde_json::from_str(&serialized).expect("Deserialization failed");
    assert_eq!(deserialized, req);

    let lock_req = Request::Lock;
    let lock_ser = serde_json::to_string(&lock_req).expect("Serialization failed");
    assert_eq!(lock_ser, r#"{"action":"Lock"}"#);
}

#[tokio::test]
async fn test_golden_json_contract_response() {
    let ok_resp = Response::ok(OperationAck::status("unlocked"));
    let ok_json = serde_json::to_string(&ok_resp).expect("Serialization failed");
    assert_eq!(ok_json, r#"{"status":"Ok","data":{"status":"unlocked"}}"#);

    let deserialized_ok: Response = serde_json::from_str(&ok_json).expect("Deserialization failed");
    assert_eq!(deserialized_ok, ok_resp);

    let err_resp = Response::Error {
        code: "AUTH_FAILED".into(),
        message: "PIN incorrecto".into(),
    };
    let err_json = serde_json::to_string(&err_resp).expect("Serialization failed");
    assert_eq!(
        err_json,
        r#"{"status":"Error","data":{"code":"AUTH_FAILED","message":"PIN incorrecto"}}"#
    );

    let deserialized_err: Response =
        serde_json::from_str(&err_json).expect("Deserialization failed");
    assert_eq!(deserialized_err, err_resp);
}

#[tokio::test]
async fn test_roundtrip_duplex_request_response() {
    let (mut client, mut server) = tokio::io::duplex(8192);

    let client_req = Request::Status;

    write_message(&mut client, &client_req)
        .await
        .expect("Client write should succeed");

    let received_by_server: Request = read_message(&mut server)
        .await
        .expect("Server read should succeed");
    assert_eq!(received_by_server, client_req);

    let server_response = Response::ok(AgentStatus {
        locked: true,
        version: "0.1.0".to_string(),
        ..Default::default()
    });
    write_message(&mut server, &server_response)
        .await
        .expect("Server write should succeed");

    let received_by_client: Response = read_message(&mut client)
        .await
        .expect("Client read response should succeed");
    assert_eq!(received_by_client, server_response);
}

#[tokio::test]
async fn test_write_message_too_large_fails() {
    let (mut client, _server) = tokio::io::duplex(8192);

    let large_string = "a".repeat(MAX_IPC_MESSAGE_SIZE + 10);
    let large_msg = Request::GetLogin { name: large_string };

    let result = write_message(&mut client, &large_msg).await;
    assert!(matches!(result, Err(IpcError::MessageTooLarge)));
}

#[tokio::test]
async fn test_read_message_too_large_fails() {
    let (mut client, mut server) = tokio::io::duplex(1024);

    let invalid_len = ((MAX_IPC_MESSAGE_SIZE + 100) as u32).to_be_bytes();
    client.write_all(&invalid_len).await.unwrap();

    let result: Result<Request, _> = read_message(&mut server).await;
    assert!(matches!(result, Err(IpcError::MessageTooLarge)));
}

#[tokio::test]
async fn test_read_malformed_json_fails() {
    let (mut client, mut server) = tokio::io::duplex(1024);

    let bad_json = b"{not_valid_json:";
    let len_bytes = (bad_json.len() as u32).to_be_bytes();
    client.write_all(&len_bytes).await.unwrap();
    client.write_all(bad_json).await.unwrap();

    let result: Result<Request, _> = read_message(&mut server).await;
    assert!(matches!(result, Err(IpcError::Json(_))));
}

#[test]
fn test_ipc_error_display() {
    let io_err = IpcError::Io(std::io::Error::new(
        std::io::ErrorKind::ConnectionReset,
        "conn reset",
    ));
    assert!(io_err.to_string().contains("conn reset"));

    let large_err = IpcError::MessageTooLarge;
    assert!(large_err.to_string().contains("4194304"));

    let eof_err = IpcError::UnexpectedEof;
    assert!(eof_err.to_string().contains("Unexpected end of stream"));

    let proto_err = IpcError::Protocol("version mismatch".to_string());
    assert!(proto_err.to_string().contains("version mismatch"));
}

#[test]
fn test_contrato_sync_payload_empty_and_partial_deserialize() {
    let empty_req: Request = serde_json::from_str(r#"{"action":"SyncData","payload":{}}"#).unwrap();
    assert_eq!(empty_req, Request::SyncData(SyncPayload::default()));

    let reload_req: Request =
        serde_json::from_str(r#"{"action":"ReloadVault","payload":{"api_url":"https://a.test"}}"#)
            .unwrap();
    assert_eq!(
        reload_req,
        Request::ReloadVault(SyncPayload {
            api_url: Some("https://a.test".to_string()),
            ..Default::default()
        })
    );

    let ser = serde_json::to_string(&SyncPayload::default()).unwrap();
    assert_eq!(ser, "{}");
}

#[test]
fn test_contrato_dto_roundtrip_all_seven() {
    let status = AgentStatus {
        locked: false,
        has_pin: true,
        logged_in: true,
        pin_cached: true,
        pin_cached_remaining_secs: 420,
        version: "0.1.0".to_string(),
    };
    let summary = LoginSummary {
        id: Some("uuid-1".to_string()),
        name: "GitHub".to_string(),
        username: "octocat".to_string(),
    };
    let detail = LoginDetail {
        id: Some("uuid-1".to_string()),
        name: "GitHub".to_string(),
        username: "octocat".to_string(),
        password: "secret".to_string(),
        totp: "123456".to_string(),
    };
    let sync = SyncResult {
        status: "synced".to_string(),
        total: 5,
        logins: 2,
        ssh_keys: 1,
        notes: 1,
        cards: 1,
        identities: 0,
    };
    let ssh = SshKeySummary {
        id: Some("uuid-2".to_string()),
        name: "work-ed25519".to_string(),
        fingerprint: "SHA256:abc".to_string(),
        public_key: "ssh-ed25519 AAAA...".to_string(),
        key_type: "Ed25519".to_string(),
    };
    let cfg = ConfigView {
        api_url: "https://api.bitwarden.com".to_string(),
        identity_url: "https://identity.bitwarden.com".to_string(),
        notifications_url: "https://notifications.bitwarden.com".to_string(),
        danger_accept_invalid_certs: false,
    };
    let pin_res = PinChangeResult {
        updated: true,
        status: "pin_updated".to_string(),
    };

    for resp in [
        Response::ok(status.clone()),
        Response::ok(summary.clone()),
        Response::ok(detail.clone()),
        Response::ok(sync.clone()),
        Response::ok(ssh.clone()),
        Response::ok(vec![ssh.clone()]),
        Response::ok(vec![summary.clone()]),
        Response::ok(cfg.clone()),
        Response::ok(pin_res.clone()),
    ] {
        let json = serde_json::to_string(&resp).expect("serialize DTO response");
        let parsed: Response = serde_json::from_str(&json).expect("deserialize DTO response");
        assert_eq!(parsed, resp);
    }

    // Check individual target extraction via deserialize_into
    let data_status: AgentStatus = Response::ok(status.clone())
        .unwrap_ok()
        .unwrap()
        .deserialize_into()
        .unwrap();
    assert_eq!(data_status, status);

    let data_empty_ssh: Vec<SshKeySummary> = Response::ok(Vec::<LoginSummary>::new())
        .unwrap_ok()
        .unwrap()
        .deserialize_into()
        .unwrap();
    assert!(data_empty_ssh.is_empty());
}

#[test]
fn test_contrato_legacy_json_compatibility_and_error_envelope() {
    let legacy_status = r#"{"status":"Ok","data":{"locked":true,"version":"0.1.0"}}"#;
    let parsed: Response = serde_json::from_str(legacy_status).unwrap();
    let dto: AgentStatus = parsed.unwrap_ok().unwrap().deserialize_into().unwrap();
    assert!(dto.locked);
    assert_eq!(dto.version, "0.1.0");
    assert!(!dto.has_pin);

    let legacy_login_created =
        r#"{"status":"Ok","data":{"status":"created","id":"abc","name":"GitHub"}}"#;
    let parsed_ack: Response = serde_json::from_str(legacy_login_created).unwrap();
    assert!(matches!(
        parsed_ack,
        Response::Ok(ResponseData::Ack(OperationAck::LoginCreated { .. }))
    ));

    let err_resp = Response::error("LOCKED", "Bóveda bloqueada");
    let err_json = serde_json::to_string(&err_resp).unwrap();
    assert_eq!(
        err_json,
        r#"{"status":"Error","data":{"code":"LOCKED","message":"Bóveda bloqueada"}}"#
    );
    let parsed_err: Response = serde_json::from_str(&err_json).unwrap();
    assert_eq!(parsed_err, err_resp);
}

#[cfg(feature = "ts")]
#[test]
fn export_dto_ts_types() {
    use ts_rs::TS;
    let base_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("bindings");
    let out_dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../sw-gui/src/lib/types/generated");
    std::fs::create_dir_all(&out_dir).expect("create generated types dir");

    AgentStatus::export_all_to(&base_dir).expect("export AgentStatus");
    LoginSummary::export_all_to(&base_dir).expect("export LoginSummary");
    LoginDetail::export_all_to(&base_dir).expect("export LoginDetail");
    SyncResult::export_all_to(&base_dir).expect("export SyncResult");
    SshKeySummary::export_all_to(&base_dir).expect("export SshKeySummary");
    ConfigView::export_all_to(&base_dir).expect("export ConfigView");
    PinChangeResult::export_all_to(&base_dir).expect("export PinChangeResult");

    for name in [
        "AgentStatus.ts",
        "LoginSummary.ts",
        "LoginDetail.ts",
        "SyncResult.ts",
        "SshKeySummary.ts",
        "ConfigView.ts",
        "PinChangeResult.ts",
    ] {
        let p = out_dir.join(name);
        assert!(p.exists(), "Missing exported TS file: {}", p.display());
        let content = std::fs::read_to_string(&p).expect("read exported TS file");
        assert!(
            !content.contains(" any"),
            "Generated TS file {} contains forbidden `any` type",
            p.display()
        );
    }
}

#[test]
fn test_contrato_get_and_set_config_request_roundtrip() {
    let get_req = Request::GetConfig;
    let get_json = serde_json::to_string(&get_req).unwrap();
    assert_eq!(get_json, r#"{"action":"GetConfig"}"#);
    assert_eq!(serde_json::from_str::<Request>(&get_json).unwrap(), get_req);
    assert_eq!(
        serde_json::from_str::<Request>(r#"{"action":"get_config"}"#).unwrap(),
        get_req
    );

    let cfg = ConfigView {
        api_url: "https://vault.example/api".to_string(),
        identity_url: "https://vault.example/identity".to_string(),
        notifications_url: "https://vault.example/notifications".to_string(),
        danger_accept_invalid_certs: true,
    };
    let set_req = Request::SetConfig(cfg.clone());
    let set_json = serde_json::to_string(&set_req).unwrap();
    let parsed: Request = serde_json::from_str(&set_json).unwrap();
    assert_eq!(parsed, Request::SetConfig(cfg));
}
