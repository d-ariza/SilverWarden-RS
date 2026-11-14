use crate::ApiError;
use serde::{Deserialize, Serialize};

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
