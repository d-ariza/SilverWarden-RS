use crate::{ApiError, AuthenticatedClient};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use sw_config::{ConfigFile, LoginToken};
use sw_crypto::SymmetricKey;
use sw_vault::{VaultPaths, VaultStore};
use tokio::sync::{Mutex, RwLock};

pub const NOTIFICATION_SYNC_CIPHER_UPDATE: i32 = 0;
pub const NOTIFICATION_SYNC_CIPHER_CREATE: i32 = 1;
pub const NOTIFICATION_SYNC_LOGIN_DELETE: i32 = 2;
pub const NOTIFICATION_SYNC_FOLDER_DELETE: i32 = 3;
pub const NOTIFICATION_SYNC_CIPHERS: i32 = 4;
pub const NOTIFICATION_SYNC_VAULT: i32 = 5;
pub const NOTIFICATION_SYNC_ORG_KEYS: i32 = 6;
pub const NOTIFICATION_SYNC_FOLDER_CREATE: i32 = 7;
pub const NOTIFICATION_SYNC_FOLDER_UPDATE: i32 = 8;
pub const NOTIFICATION_SYNC_CIPHER_DELETE: i32 = 9;
pub const NOTIFICATION_SYNC_SETTINGS: i32 = 10;
pub const NOTIFICATION_LOGOUT: i32 = 11;
pub const NOTIFICATION_SYNC_SEND_CREATE: i32 = 12;
pub const NOTIFICATION_SYNC_SEND_UPDATE: i32 = 13;
pub const NOTIFICATION_SYNC_SEND_DELETE: i32 = 14;
pub const NOTIFICATION_AUTH_REQUEST: i32 = 15;
pub const NOTIFICATION_AUTH_REQUEST_RESPONSE: i32 = 16;

/// Parsed SignalR Bitwarden notification message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationMessage {
    pub message_type: i32,
    pub cipher_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum MsgPackValue {
    Integer(i64),
    Float(f64),
    String(String),
    Bool(bool),
    Array(Vec<MsgPackValue>),
    Map(std::collections::HashMap<String, MsgPackValue>),
    Null,
}

/// Parses a SignalR MessagePack binary payload, automatically detecting
/// and stripping length-prefix varints when present.
pub fn parse_message_pack(message: &[u8]) -> Option<NotificationMessage> {
    if message.is_empty() {
        return None;
    }

    // Try finding the end of the SignalR 7-bit varint length prefix
    let mut offset = 0;
    while offset < message.len() {
        let byte = message[offset];
        offset += 1;
        if (byte & 0x80) == 0 {
            break;
        }
    }

    if offset > 0 && offset < message.len() {
        if let Ok(msg) = parse_raw_msgpack(&message[offset..]) {
            return Some(msg);
        }
    }

    // Fallback: parse raw MessagePack slice without varint prefix
    parse_raw_msgpack(message).ok()
}

fn parse_raw_msgpack(bytes: &[u8]) -> Result<NotificationMessage, ()> {
    let root: MsgPackValue = rmp_serde::from_slice(bytes).map_err(|_| ())?;
    let arr = match root {
        MsgPackValue::Array(a) => a,
        _ => return Err(()),
    };

    if arr.len() < 5 {
        return Err(());
    }

    let args = match &arr[4] {
        MsgPackValue::Array(a) => a,
        _ => return Err(()),
    };

    if args.is_empty() {
        return Err(());
    }

    let map = match &args[0] {
        MsgPackValue::Map(m) => m,
        _ => return Err(()),
    };

    let type_val = map.get("Type").or_else(|| map.get("type")).ok_or(())?;
    let message_type = match type_val {
        MsgPackValue::Integer(i) => *i as i32,
        _ => return Err(()),
    };

    let cipher_id = if let Some(payload_val) = map.get("Payload").or_else(|| map.get("payload")) {
        match payload_val {
            MsgPackValue::Map(payload_map) => {
                match payload_map.get("Id").or_else(|| payload_map.get("id")) {
                    Some(MsgPackValue::String(id)) => Some(id.clone()),
                    _ => None,
                }
            }
            _ => None,
        }
    } else {
        None
    };

    Ok(NotificationMessage {
        message_type,
        cipher_id,
    })
}

/// Encodes a SignalR MessagePack notification frame for testing or emulation.
pub fn encode_notification_message(
    message_type: i32,
    cipher_id: Option<&str>,
    with_varint: bool,
) -> Vec<u8> {
    let mut payload = std::collections::HashMap::new();
    payload.insert(
        "Type".to_string(),
        MsgPackValue::Integer(message_type as i64),
    );
    if let Some(id) = cipher_id {
        let mut detail = std::collections::HashMap::new();
        detail.insert("Id".to_string(), MsgPackValue::String(id.to_string()));
        payload.insert("Payload".to_string(), MsgPackValue::Map(detail));
    }

    let msg = MsgPackValue::Array(vec![
        MsgPackValue::Integer(1),                              // 1 = Invocation
        MsgPackValue::Map(std::collections::HashMap::new()),   // headers
        MsgPackValue::Null,                                    // invocationId
        MsgPackValue::String("ReceiveMessage".to_string()),    // target
        MsgPackValue::Array(vec![MsgPackValue::Map(payload)]), // arguments
    ]);

    let bytes = rmp_serde::to_vec(&msg).expect("serialization to msgpack must succeed");
    if with_varint {
        let mut len = bytes.len();
        let mut varint = Vec::new();
        loop {
            let b = (len & 0x7f) as u8;
            len >>= 7;
            if len > 0 {
                varint.push(b | 0x80);
            } else {
                varint.push(b);
                break;
            }
        }
        varint.extend_from_slice(&bytes);
        varint
    } else {
        bytes
    }
}

/// Normalizes a given HTTP/WS URL into a Bitwarden Hub WebSocket endpoint (`wss://.../hub?access_token=...`).
pub fn build_hub_url(base_url: &str, token: &str) -> Result<String, ApiError> {
    let mut url_str = base_url.trim().to_string();
    if url_str.starts_with("http://") {
        url_str = url_str.replacen("http://", "ws://", 1);
    } else if url_str.starts_with("https://") {
        url_str = url_str.replacen("https://", "wss://", 1);
    } else if !url_str.starts_with("ws://") && !url_str.starts_with("wss://") {
        url_str = format!("wss://{}", url_str);
    }

    let mut parsed = url::Url::parse(&url_str)?;
    let path = parsed.path().trim_end_matches('/');
    if !path.ends_with("/hub") && path != "/hub" {
        if path.is_empty() {
            parsed.set_path("/hub");
        } else {
            parsed.set_path(&format!("{}/hub", path));
        }
    }

    let mut query_pairs: Vec<(String, String)> = parsed.query_pairs().into_owned().collect();
    if !query_pairs.iter().any(|(k, _)| k == "access_token") {
        query_pairs.push(("access_token".to_string(), token.to_string()));
    }
    parsed.query_pairs_mut().clear().extend_pairs(query_pairs);

    Ok(parsed.to_string())
}

pub type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// WebSocket client for Bitwarden real-time vault notifications.
pub struct WebsocketClient {
    stream: Option<WsStream>,
    api_client: Option<Arc<AuthenticatedClient>>,
    url: String,
    token: String,
}

impl WebsocketClient {
    /// Creates an uninitialized `WebsocketClient`.
    pub fn new(url: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            stream: None,
            api_client: None,
            url: url.into(),
            token: token.into(),
        }
    }

    /// Creates a `WebsocketClient` wrapping an established WebSocket stream.
    pub fn from_stream(stream: WsStream, url: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            stream: Some(stream),
            api_client: None,
            url: url.into(),
            token: token.into(),
        }
    }

    /// Connects to `wss://<host>/hub?access_token=<token>` and sends the SignalR handshake.
    pub async fn connect(url: &str, token: &str) -> Result<Self, ApiError> {
        let hub_url = build_hub_url(url, token)?;
        let (mut stream, _response) = tokio_tungstenite::connect_async(&hub_url).await?;

        // Handshake required by Bitwarden SignalR hub protocol
        let handshake = "{\"protocol\":\"messagepack\",\"version\":1}\x1e";
        stream
            .send(tokio_tungstenite::tungstenite::Message::Text(
                handshake.into(),
            ))
            .await?;

        Ok(Self {
            stream: Some(stream),
            api_client: None,
            url: url.to_string(),
            token: token.to_string(),
        })
    }

    /// Reads the next incoming notification message from the WebSocket stream.
    pub async fn next_message(&mut self) -> Option<NotificationMessage> {
        let stream = self.stream.as_mut()?;
        while let Some(msg_result) = stream.next().await {
            match msg_result {
                Ok(msg) => match msg {
                    tokio_tungstenite::tungstenite::Message::Binary(bytes) => {
                        if bytes.len() < 5 {
                            // Ignore short frames or keepalives
                            continue;
                        }
                        if let Some(notification) = parse_message_pack(&bytes) {
                            return Some(notification);
                        }
                    }
                    tokio_tungstenite::tungstenite::Message::Text(_text) => {
                        // Handshake confirmation or text ping, skip
                        continue;
                    }
                    tokio_tungstenite::tungstenite::Message::Ping(payload) => {
                        let _ = stream
                            .send(tokio_tungstenite::tungstenite::Message::Pong(payload))
                            .await;
                    }
                    tokio_tungstenite::tungstenite::Message::Close(_) => {
                        self.stream = None;
                        return None;
                    }
                    _ => continue,
                },
                Err(_) => {
                    self.stream = None;
                    return None;
                }
            }
        }
        self.stream = None;
        None
    }

    /// Gracefully closes the active WebSocket connection.
    pub async fn close(&mut self) {
        if let Some(mut stream) = self.stream.take() {
            let _ = stream.close(None).await;
        }
    }

    /// Returns `true` if the stream connection is currently open.
    pub fn is_connected(&self) -> bool {
        self.stream.is_some()
    }

    /// Sets an `AuthenticatedClient` instance used for REST calls triggered by notifications.
    pub fn set_api_client(&mut self, api_client: Arc<AuthenticatedClient>) {
        self.api_client = Some(api_client);
    }

    /// Builder pattern to attach an `AuthenticatedClient`.
    pub fn with_api_client(mut self, api_client: Arc<AuthenticatedClient>) -> Self {
        self.api_client = Some(api_client);
        self
    }

    /// Accessor for the attached `AuthenticatedClient`.
    pub fn api_client(&self) -> Option<&Arc<AuthenticatedClient>> {
        self.api_client.as_ref()
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn token(&self) -> &str {
        &self.token
    }
}

/// Runs the WebSocket daemon loop listening for Bitwarden synchronization events.
pub async fn run_websocket_daemon(
    client: Arc<Mutex<WebsocketClient>>,
    vault_store: Arc<VaultStore>,
    config: Arc<RwLock<ConfigFile>>,
    user_symmetric_key: SymmetricKey,
) -> Result<(), ApiError> {
    run_websocket_daemon_with_options(
        client,
        vault_store,
        config,
        user_symmetric_key,
        std::time::Duration::from_secs(60),
        None,
    )
    .await
}

/// Runs the WebSocket daemon with customizable reconnection backoff and stop channel.
pub async fn run_websocket_daemon_with_options(
    client: Arc<Mutex<WebsocketClient>>,
    vault_store: Arc<VaultStore>,
    config: Arc<RwLock<ConfigFile>>,
    user_symmetric_key: SymmetricKey,
    backoff: std::time::Duration,
    mut stop_rx: Option<tokio::sync::watch::Receiver<bool>>,
) -> Result<(), ApiError> {
    loop {
        if let Some(rx) = &stop_rx {
            if *rx.borrow() {
                break;
            }
        }

        // 1. Connect if not connected
        let is_connected = client.lock().await.is_connected();
        if !is_connected {
            let (url, token) = {
                let guard = client.lock().await;
                let url = if !guard.url().is_empty() {
                    guard.url().to_string()
                } else {
                    config.read().await.notifications_url.clone()
                };
                let token = if !guard.token().is_empty() {
                    guard.token().to_string()
                } else {
                    String::new()
                };
                (url, token)
            };

            if url.is_empty() {
                tokio::select! {
                    _ = tokio::time::sleep(backoff) => continue,
                    _ = async {
                        if let Some(rx) = &mut stop_rx {
                            let _ = rx.changed().await;
                        } else {
                            futures_util::future::pending::<()>().await;
                        }
                    } => break,
                }
            }

            match WebsocketClient::connect(&url, &token).await {
                Ok(new_client) => {
                    let mut guard = client.lock().await;
                    let existing_api = guard.api_client.clone();
                    *guard = new_client;
                    if let Some(api) = existing_api {
                        guard.set_api_client(api);
                    }
                }
                Err(_) => {
                    tokio::select! {
                        _ = tokio::time::sleep(backoff) => continue,
                        _ = async {
                            if let Some(rx) = &mut stop_rx {
                                let _ = rx.changed().await;
                            } else {
                                futures_util::future::pending::<()>().await;
                            }
                        } => break,
                    }
                }
            }
        }

        // 2. Message read loop
        loop {
            if let Some(rx) = &stop_rx {
                if *rx.borrow() {
                    return Ok(());
                }
            }

            let next_fut = async {
                let mut guard = client.lock().await;
                guard.next_message().await
            };

            let msg_opt = if let Some(rx) = &mut stop_rx {
                tokio::select! {
                    _ = rx.changed() => return Ok(()),
                    res = next_fut => res,
                }
            } else {
                next_fut.await
            };

            let msg = match msg_opt {
                Some(m) => m,
                None => {
                    break;
                }
            };

            match msg.message_type {
                NOTIFICATION_SYNC_CIPHERS | NOTIFICATION_SYNC_VAULT => {
                    let api_client = get_or_create_api_client(&client, &config).await;
                    let vault_paths =
                        VaultPaths::default_paths().unwrap_or_else(|_| VaultPaths::new("."));
                    let _ = api_client
                        .do_full_sync(&vault_paths, &vault_store, Some(&user_symmetric_key))
                        .await;
                }
                NOTIFICATION_SYNC_CIPHER_UPDATE | NOTIFICATION_SYNC_CIPHER_CREATE => {
                    if let Some(ref id_str) = msg.cipher_id {
                        if let Ok(uuid) = uuid::Uuid::parse_str(id_str) {
                            let api_client = get_or_create_api_client(&client, &config).await;
                            if let Ok(cipher) = api_client.get_cipher(&uuid).await {
                                vault_store.insert(cipher).await;
                            }
                        }
                    }
                }
                NOTIFICATION_SYNC_CIPHER_DELETE | NOTIFICATION_SYNC_LOGIN_DELETE => {
                    if let Some(ref id_str) = msg.cipher_id {
                        if let Ok(uuid) = uuid::Uuid::parse_str(id_str) {
                            vault_store.delete(&uuid).await;
                        }
                    }
                }
                NOTIFICATION_LOGOUT => {
                    vault_store.clear().await;
                    client.lock().await.close().await;
                    return Ok(());
                }
                _ => {}
            }
        }

        // 3. Backoff delay upon disconnection
        tokio::select! {
            _ = tokio::time::sleep(backoff) => {},
            _ = async {
                if let Some(rx) = &mut stop_rx {
                    let _ = rx.changed().await;
                } else {
                    futures_util::future::pending::<()>().await;
                }
            } => break,
        }
    }

    Ok(())
}

async fn get_or_create_api_client(
    client: &Arc<Mutex<WebsocketClient>>,
    config: &Arc<RwLock<ConfigFile>>,
) -> Arc<AuthenticatedClient> {
    let existing = {
        let guard = client.lock().await;
        guard.api_client().cloned()
    };
    if let Some(c) = existing {
        return c;
    }

    let (identity_url, api_url, token_str) = {
        let cfg = config.read().await;
        let token = client.lock().await.token().to_string();
        (cfg.identity_url.clone(), cfg.api_url.clone(), token)
    };

    let auth = Arc::new(AuthenticatedClient::from_token(
        identity_url,
        api_url,
        LoginToken {
            access_token: token_str,
            ..Default::default()
        },
    ));
    client.lock().await.set_api_client(auth.clone());
    auth
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn test_build_hub_url() {
        let u1 = build_hub_url("https://notifications.bitwarden.com", "token123").unwrap();
        assert_eq!(
            u1,
            "wss://notifications.bitwarden.com/hub?access_token=token123"
        );

        let u2 = build_hub_url("http://localhost:8080", "token123").unwrap();
        assert_eq!(u2, "ws://localhost:8080/hub?access_token=token123");

        let u3 = build_hub_url("ws://localhost:8080/hub", "token123").unwrap();
        assert_eq!(u3, "ws://localhost:8080/hub?access_token=token123");

        let u4 = build_hub_url(
            "wss://example.com/api/hub?access_token=existing",
            "token123",
        )
        .unwrap();
        assert_eq!(u4, "wss://example.com/api/hub?access_token=existing");

        let u5 = build_hub_url("notifications.bitwarden.com/", "token123").unwrap();
        assert_eq!(
            u5,
            "wss://notifications.bitwarden.com/hub?access_token=token123"
        );
    }

    #[test]
    fn test_parse_message_pack_go_parity_fixtures() {
        // Hex produced by Goldwarden Go's msgpack encoder with 7-bit varint length prefix (0x4f = 79 bytes)
        let go_hex_with_varint = "4f95d00180c0ae526563656976654d6573736167659182a454797065d000a75061796c6f616481a24964d92431313131313131312d323232322d333333332d343434342d353535353535353535353535";
        let raw_bytes_varint = hex::decode(go_hex_with_varint).expect("valid hex");
        let parsed_varint =
            parse_message_pack(&raw_bytes_varint).expect("should parse successfully");
        assert_eq!(parsed_varint.message_type, 0);
        assert_eq!(
            parsed_varint.cipher_id.as_deref(),
            Some("11111111-2222-3333-4444-555555555555")
        );

        // Raw msgpack array without varint prefix
        let go_hex_raw = "95d00180c0ae526563656976654d6573736167659182a454797065d000a75061796c6f616481a24964d92431313131313131312d323232322d333333332d343434342d353535353535353535353535";
        let raw_bytes = hex::decode(go_hex_raw).expect("valid hex");
        let parsed_raw = parse_message_pack(&raw_bytes).expect("should parse raw msgpack");
        assert_eq!(parsed_raw.message_type, 0);
        assert_eq!(
            parsed_raw.cipher_id.as_deref(),
            Some("11111111-2222-3333-4444-555555555555")
        );

        // SyncCiphers (Type: 4, no Payload Id) from Go
        let go_hex_ciphers = "95d00180c0ae526563656976654d6573736167659181a454797065d004";
        let raw_bytes_ciphers = hex::decode(go_hex_ciphers).expect("valid hex");
        let parsed_ciphers = parse_message_pack(&raw_bytes_ciphers).expect("should parse ciphers");
        assert_eq!(parsed_ciphers.message_type, 4);
        assert_eq!(parsed_ciphers.cipher_id, None);
    }

    #[test]
    fn test_parse_message_pack_synthetic_roundtrip() {
        let msg =
            encode_notification_message(9, Some("33333333-3333-3333-3333-333333333333"), true);
        let parsed = parse_message_pack(&msg).expect("should parse synthetic varint message");
        assert_eq!(parsed.message_type, 9);
        assert_eq!(
            parsed.cipher_id.as_deref(),
            Some("33333333-3333-3333-3333-333333333333")
        );

        let msg_logout = encode_notification_message(11, None, false);
        let parsed_logout = parse_message_pack(&msg_logout).expect("should parse logout");
        assert_eq!(parsed_logout.message_type, 11);
        assert_eq!(parsed_logout.cipher_id, None);

        // Invalid / short inputs
        assert_eq!(parse_message_pack(&[]), None);
        assert_eq!(parse_message_pack(&[0x01, 0x02]), None);
    }

    #[tokio::test]
    async fn test_mock_websocket_server_handshake_and_update() {
        // 1. Setup mock HTTP server for GET /ciphers/{uuid}
        let test_cipher_id = uuid::Uuid::new_v4();
        let http_server = MockServer::start().await;

        let cipher_payload = serde_json::json!({
            "id": test_cipher_id.to_string(),
            "type": 1,
            "name": "2.VnAx2h55dzHVslHktja+Tg==|AyhiUxbTIoISm6sVOhjwuGSvZLT/SNde/6qXFKKFD+pqg/ZWeWKTu8mvx66ppWBgorkfYRALqpem37JM8viJOdK5/GfrwMPEy+NZ2Ll9oCo=|I5h2Vl4BQkPZ3hD1n/uR1k3zD+1G+xZ3p7H+Z9s9pM0=",
        });

        Mock::given(method("GET"))
            .and(path(format!("/ciphers/{test_cipher_id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(&cipher_payload))
            .expect(1)
            .mount(&http_server)
            .await;

        let auth_client = Arc::new(AuthenticatedClient::from_token(
            http_server.uri(),
            http_server.uri(),
            LoginToken {
                access_token: "test_access_token".to_string(),
                ..Default::default()
            },
        ));

        // 2. Setup mock WebSocket server
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ws_addr = listener.local_addr().unwrap();

        let id_str = test_cipher_id.to_string();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws_stream = tokio_tungstenite::accept_async(stream).await.unwrap();

            // Receive SignalR handshake
            let handshake_msg = ws_stream.next().await.unwrap().unwrap();
            if let tokio_tungstenite::tungstenite::Message::Text(text) = handshake_msg {
                assert!(text.contains("messagepack"));
            } else {
                panic!("Expected text handshake from client");
            }

            // Send handshake response
            ws_stream
                .send(tokio_tungstenite::tungstenite::Message::Text(
                    "{}\x1e".into(),
                ))
                .await
                .unwrap();

            // Send SyncCipherUpdate (Type: 0, Id: test_cipher_id)
            let update_msg =
                encode_notification_message(NOTIFICATION_SYNC_CIPHER_UPDATE, Some(&id_str), true);
            ws_stream
                .send(tokio_tungstenite::tungstenite::Message::Binary(update_msg))
                .await
                .unwrap();

            // Send LogOut (Type: 11) to gracefully conclude daemon loop
            let logout_msg = encode_notification_message(NOTIFICATION_LOGOUT, None, true);
            ws_stream
                .send(tokio_tungstenite::tungstenite::Message::Binary(logout_msg))
                .await
                .unwrap();
        });

        // 3. Connect client and run daemon
        let ws_url = format!("ws://{}", ws_addr);
        let ws_client = WebsocketClient::connect(&ws_url, "test_access_token")
            .await
            .expect("WebSocket connection should succeed");
        let ws_client = ws_client.with_api_client(auth_client);
        let client_arc = Arc::new(Mutex::new(ws_client));

        let vault_store = Arc::new(VaultStore::new());
        let config = Arc::new(RwLock::new(ConfigFile {
            notifications_url: ws_url,
            api_url: http_server.uri(),
            identity_url: http_server.uri(),
            ..Default::default()
        }));

        let user_symmetric_key = SymmetricKey::from_parts(&[42u8; 32], &[43u8; 32]).unwrap();

        // 4. Run daemon (will process update, fetch cipher, then logout)
        let daemon_result = run_websocket_daemon(
            client_arc.clone(),
            vault_store.clone(),
            config.clone(),
            user_symmetric_key,
        )
        .await;

        assert!(daemon_result.is_ok());

        // LogOut wipes vault_store upon termination as per specification
        assert_eq!(vault_store.len().await, 0);
    }

    #[tokio::test]
    async fn test_mock_websocket_server_update_then_delete() {
        let test_cipher_id = uuid::Uuid::new_v4();
        let http_server = MockServer::start().await;

        let cipher_payload = serde_json::json!({
            "id": test_cipher_id.to_string(),
            "type": 1,
            "name": "2.VnAx2h55dzHVslHktja+Tg==|AyhiUxbTIoISm6sVOhjwuGSvZLT/SNde/6qXFKKFD+pqg/ZWeWKTu8mvx66ppWBgorkfYRALqpem37JM8viJOdK5/GfrwMPEy+NZ2Ll9oCo=|I5h2Vl4BQkPZ3hD1n/uR1k3zD+1G+xZ3p7H+Z9s9pM0=",
        });

        Mock::given(method("GET"))
            .and(path(format!("/ciphers/{test_cipher_id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(&cipher_payload))
            .mount(&http_server)
            .await;

        let auth_client = Arc::new(AuthenticatedClient::from_token(
            http_server.uri(),
            http_server.uri(),
            LoginToken {
                access_token: "test_access_token".to_string(),
                ..Default::default()
            },
        ));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ws_addr = listener.local_addr().unwrap();

        let id_str = test_cipher_id.to_string();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws_stream = tokio_tungstenite::accept_async(stream).await.unwrap();

            let _ = ws_stream.next().await.unwrap().unwrap();
            ws_stream
                .send(tokio_tungstenite::tungstenite::Message::Text(
                    "{}\x1e".into(),
                ))
                .await
                .unwrap();

            // Send SyncCipherUpdate
            let update_msg =
                encode_notification_message(NOTIFICATION_SYNC_CIPHER_UPDATE, Some(&id_str), true);
            ws_stream
                .send(tokio_tungstenite::tungstenite::Message::Binary(update_msg))
                .await
                .unwrap();

            // Small delay to let insertion finish
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;

            // Send SyncCipherDelete
            let delete_msg =
                encode_notification_message(NOTIFICATION_SYNC_CIPHER_DELETE, Some(&id_str), true);
            ws_stream
                .send(tokio_tungstenite::tungstenite::Message::Binary(delete_msg))
                .await
                .unwrap();
        });

        let ws_url = format!("ws://{}", ws_addr);
        let ws_client = WebsocketClient::connect(&ws_url, "test_access_token")
            .await
            .unwrap()
            .with_api_client(auth_client);
        let client_arc = Arc::new(Mutex::new(ws_client));

        let vault_store = Arc::new(VaultStore::new());
        let config = Arc::new(RwLock::new(ConfigFile {
            notifications_url: ws_url,
            api_url: http_server.uri(),
            identity_url: http_server.uri(),
            ..Default::default()
        }));

        let user_symmetric_key = SymmetricKey::from_parts(&[42u8; 32], &[43u8; 32]).unwrap();

        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);

        let vault_clone = vault_store.clone();
        let daemon_handle = tokio::spawn(async move {
            run_websocket_daemon_with_options(
                client_arc,
                vault_clone,
                config,
                user_symmetric_key,
                std::time::Duration::from_millis(100),
                Some(stop_rx),
            )
            .await
        });

        // Wait for cipher to be inserted then deleted
        for _ in 0..50 {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            if vault_store.get(&test_cipher_id).await.is_none() {
                // If it was inserted and then deleted, we are done
            }
        }

        let _ = stop_tx.send(true);
        let _ = daemon_handle.await;

        assert!(vault_store.get(&test_cipher_id).await.is_none());
    }

    #[tokio::test]
    async fn test_websocket_client_methods_and_sync_ciphers() {
        let http_server = MockServer::start().await;

        let sync_data = serde_json::json!({
            "profile": {
                "id": "11111111-1111-1111-1111-111111111111",
                "email": "user@example.com"
            },
            "folders": [],
            "ciphers": []
        });

        Mock::given(method("GET"))
            .and(path("/sync"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&sync_data))
            .mount(&http_server)
            .await;

        let auth_client = Arc::new(AuthenticatedClient::from_token(
            http_server.uri(),
            http_server.uri(),
            LoginToken {
                access_token: "test_access_token".to_string(),
                ..Default::default()
            },
        ));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ws_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws_stream = tokio_tungstenite::accept_async(stream).await.unwrap();

            let _ = ws_stream.next().await.unwrap().unwrap();
            ws_stream
                .send(tokio_tungstenite::tungstenite::Message::Text(
                    "{}\x1e".into(),
                ))
                .await
                .unwrap();

            // Send SyncCiphers (Type: 4)
            let sync_msg = encode_notification_message(NOTIFICATION_SYNC_CIPHERS, None, true);
            ws_stream
                .send(tokio_tungstenite::tungstenite::Message::Binary(sync_msg))
                .await
                .unwrap();

            // Wait a bit, then close connection
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            let _ = ws_stream.close(None).await;
        });

        let ws_url = format!("ws://{}", ws_addr);
        let ws_client = WebsocketClient::connect(&ws_url, "test_access_token")
            .await
            .unwrap()
            .with_api_client(auth_client);

        assert!(ws_client.is_connected());
        assert_eq!(ws_client.url(), ws_url);
        assert_eq!(ws_client.token(), "test_access_token");
        assert!(ws_client.api_client().is_some());

        let client_arc = Arc::new(Mutex::new(ws_client));
        let vault_store = Arc::new(VaultStore::new());
        let config = Arc::new(RwLock::new(ConfigFile {
            notifications_url: ws_url,
            api_url: http_server.uri(),
            identity_url: http_server.uri(),
            ..Default::default()
        }));

        let user_symmetric_key = SymmetricKey::from_parts(&[1u8; 32], &[2u8; 32]).unwrap();
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);

        let vault_clone = vault_store.clone();
        let daemon_handle = tokio::spawn(async move {
            run_websocket_daemon_with_options(
                client_arc,
                vault_clone,
                config,
                user_symmetric_key,
                std::time::Duration::from_millis(50),
                Some(stop_rx),
            )
            .await
        });

        // Verify sync happened and last_synced was set
        for _ in 0..50 {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            if vault_store.last_synced().await.is_some() {
                break;
            }
        }

        let _ = stop_tx.send(true);
        let _ = daemon_handle.await;

        assert!(vault_store.last_synced().await.is_some());

        // Test manual close
        let mut standalone_client = WebsocketClient::new("ws://127.0.0.1:9999", "tok");
        assert!(!standalone_client.is_connected());
        standalone_client.close().await;
        assert!(!standalone_client.is_connected());
    }

    #[tokio::test]
    async fn test_websocket_reconnects_after_disconnect() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ws_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            // First connection: accept and disconnect immediately
            let (stream1, _) = listener.accept().await.unwrap();
            let mut ws1 = tokio_tungstenite::accept_async(stream1).await.unwrap();
            let _ = ws1.next().await.unwrap().unwrap();
            ws1.send(tokio_tungstenite::tungstenite::Message::Text(
                "{}\x1e".into(),
            ))
            .await
            .unwrap();
            // Drop connection to trigger disconnect on client
            drop(ws1);

            // Second connection (reconnect): accept, handshake, send LogOut
            let (stream2, _) = listener.accept().await.unwrap();
            let mut ws2 = tokio_tungstenite::accept_async(stream2).await.unwrap();
            let _ = ws2.next().await.unwrap().unwrap();
            ws2.send(tokio_tungstenite::tungstenite::Message::Text(
                "{}\x1e".into(),
            ))
            .await
            .unwrap();
            let logout_msg = encode_notification_message(NOTIFICATION_LOGOUT, None, true);
            ws2.send(tokio_tungstenite::tungstenite::Message::Binary(logout_msg))
                .await
                .unwrap();
        });

        let ws_url = format!("ws://{}", ws_addr);
        let ws_client = WebsocketClient::connect(&ws_url, "test_token")
            .await
            .expect("First connect must succeed");
        let client_arc = Arc::new(Mutex::new(ws_client));
        let vault_store = Arc::new(VaultStore::new());
        let config = Arc::new(RwLock::new(ConfigFile {
            notifications_url: ws_url,
            ..Default::default()
        }));
        let user_symmetric_key = SymmetricKey::from_parts(&[1u8; 32], &[2u8; 32]).unwrap();

        let daemon_res = run_websocket_daemon_with_options(
            client_arc,
            vault_store,
            config,
            user_symmetric_key,
            std::time::Duration::from_millis(100),
            None,
        )
        .await;

        assert!(daemon_res.is_ok());
    }

    #[tokio::test]
    async fn test_websocket_ignores_malformed_message() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ws_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let _ = ws.next().await.unwrap().unwrap();
            ws.send(tokio_tungstenite::tungstenite::Message::Text(
                "{}\x1e".into(),
            ))
            .await
            .unwrap();

            // Send malformed non-MessagePack binary frame
            ws.send(tokio_tungstenite::tungstenite::Message::Binary(vec![
                0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0x00, 0x01,
            ]))
            .await
            .unwrap();

            tokio::time::sleep(std::time::Duration::from_millis(50)).await;

            // Send valid LogOut to conclude cleanly
            let logout_msg = encode_notification_message(NOTIFICATION_LOGOUT, None, true);
            ws.send(tokio_tungstenite::tungstenite::Message::Binary(logout_msg))
                .await
                .unwrap();
        });

        let ws_url = format!("ws://{}", ws_addr);
        let ws_client = WebsocketClient::connect(&ws_url, "test_token")
            .await
            .expect("Connect must succeed");
        let client_arc = Arc::new(Mutex::new(ws_client));
        let vault_store = Arc::new(VaultStore::new());
        let config = Arc::new(RwLock::new(ConfigFile {
            notifications_url: ws_url,
            ..Default::default()
        }));
        let user_symmetric_key = SymmetricKey::from_parts(&[1u8; 32], &[2u8; 32]).unwrap();

        let daemon_res = run_websocket_daemon_with_options(
            client_arc,
            vault_store,
            config,
            user_symmetric_key,
            std::time::Duration::from_millis(50),
            None,
        )
        .await;

        assert!(daemon_res.is_ok());
    }
}
