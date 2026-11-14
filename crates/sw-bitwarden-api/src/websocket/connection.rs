use super::protocol::{build_hub_url, parse_message_pack, NotificationMessage};
use crate::{ApiError, AuthenticatedClient};
use futures_util::{SinkExt, StreamExt};
use std::sync::Arc;

pub type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// WebSocket client for Bitwarden real-time vault notifications.
pub struct WebsocketClient {
    stream: Option<WsStream>,
    pub(super) api_client: Option<Arc<AuthenticatedClient>>,
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
