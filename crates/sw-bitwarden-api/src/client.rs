use base64::Engine;
use reqwest::Response;
use std::sync::Arc;
use sw_config::LoginToken;
use thiserror::Error;
use tokio::sync::Mutex;

use crate::ciphers;

pub const BITWARDEN_USER_AGENT: &str = "silverwarden/0.0.1";
pub const BITWARDEN_DEVICE_TYPE: &str = "10";
pub const BITWARDEN_CLIENT_NAME: &str = "silverwarden";
pub const BITWARDEN_CLIENT_VERSION: &str = "2024.12.0";

#[derive(Error, Debug)]
pub enum ApiError {
    #[error("HTTP request error: {0}")]
    Reqwest(#[from] reqwest::Error),

    #[error("Authentication error: {0}")]
    Auth(String),

    #[error("JSON decode error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("URL parse error: {0}")]
    Url(#[from] url::ParseError),

    #[error("Crypto error: {0}")]
    Crypto(#[from] sw_crypto::CryptoError),

    #[error("Vault error: {0}")]
    Vault(#[from] sw_vault::VaultError),

    #[error("WebSocket error: {0}")]
    WebSocket(Box<tokio_tungstenite::tungstenite::Error>),

    #[error("MessagePack decode error: {0}")]
    MsgPack(#[from] rmp_serde::decode::Error),

    #[error("Two-factor authentication required")]
    TwoFactorRequired { providers: Vec<i32>, token: String },

    #[error("Not implemented: {0}")]
    NotImplemented(String),

    #[error("El servidor ha bloqueado temporalmente tu IP por demasiados intentos de login. Espera unos minutos o cambia de red (por ejemplo, usa datos móviles).")]
    RateLimitExceeded,

    #[error("Credenciales inválidas. Comprueba tu correo y contraseña maestra.")]
    InvalidCredentials,

    #[error("Server error ({status}): {message}")]
    Status {
        status: reqwest::StatusCode,
        message: String,
    },
}

impl From<tokio_tungstenite::tungstenite::Error> for ApiError {
    fn from(err: tokio_tungstenite::tungstenite::Error) -> Self {
        Self::WebSocket(Box::new(err))
    }
}

/// Request body payloads supported by `fetch_with_auth`.
#[derive(Debug, Clone)]
pub enum RequestBody {
    Empty,
    Json(serde_json::Value),
    Form(Vec<(String, String)>),
    RawForm {
        data: String,
        auth_email: Option<String>,
    },
}

impl RequestBody {
    pub fn empty() -> Self {
        Self::Empty
    }

    pub fn json(v: serde_json::Value) -> Self {
        Self::Json(v)
    }

    pub fn form(pairs: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>) -> Self {
        Self::Form(
            pairs
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
        )
    }
}

impl From<serde_json::Value> for RequestBody {
    fn from(v: serde_json::Value) -> Self {
        Self::Json(v)
    }
}

/// Authenticated Bitwarden HTTP client with automatic token refresh on 401 responses.
#[derive(Clone)]
pub struct AuthenticatedClient {
    pub(crate) client: reqwest::Client,
    pub(crate) token: Arc<Mutex<LoginToken>>,
    pub(crate) identity_url: String,
    pub(crate) api_url: String,
}

impl std::fmt::Debug for AuthenticatedClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthenticatedClient")
            .field("identity_url", &self.identity_url)
            .field("api_url", &self.api_url)
            .finish()
    }
}

impl AuthenticatedClient {
    /// Builds a `reqwest::Client` with optional acceptance of invalid / self-signed TLS certificates.
    pub fn build_http_client(danger_accept_invalid_certs: bool) -> reqwest::Client {
        reqwest::Client::builder()
            .danger_accept_invalid_certs(danger_accept_invalid_certs)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    }

    /// Creates a new `AuthenticatedClient` with the given endpoints and shared `LoginToken`.
    pub fn new(
        identity_url: impl Into<String>,
        api_url: impl Into<String>,
        token: Arc<Mutex<LoginToken>>,
    ) -> Self {
        Self::new_with_options(identity_url, api_url, token, false)
    }

    /// Creates a new `AuthenticatedClient` with options (e.g. accepting self-signed / invalid certs).
    pub fn new_with_options(
        identity_url: impl Into<String>,
        api_url: impl Into<String>,
        token: Arc<Mutex<LoginToken>>,
        danger_accept_invalid_certs: bool,
    ) -> Self {
        let client = Self::build_http_client(danger_accept_invalid_certs);
        Self::with_client(client, identity_url, api_url, token)
    }

    /// Creates a new `AuthenticatedClient` from a concrete `LoginToken` value.
    pub fn from_token(
        identity_url: impl Into<String>,
        api_url: impl Into<String>,
        token: LoginToken,
    ) -> Self {
        Self::from_token_with_options(identity_url, api_url, token, false)
    }

    /// Creates a new `AuthenticatedClient` from a concrete `LoginToken` value with options.
    pub fn from_token_with_options(
        identity_url: impl Into<String>,
        api_url: impl Into<String>,
        token: LoginToken,
        danger_accept_invalid_certs: bool,
    ) -> Self {
        Self::new_with_options(
            identity_url,
            api_url,
            Arc::new(Mutex::new(token)),
            danger_accept_invalid_certs,
        )
    }

    /// Creates an `AuthenticatedClient` with a custom `reqwest::Client`.
    pub fn with_client(
        client: reqwest::Client,
        identity_url: impl Into<String>,
        api_url: impl Into<String>,
        token: Arc<Mutex<LoginToken>>,
    ) -> Self {
        Self {
            client,
            token,
            identity_url: identity_url.into(),
            api_url: api_url.into(),
        }
    }

    /// Reference to the underlying `reqwest::Client`.
    pub fn http_client(&self) -> &reqwest::Client {
        &self.client
    }

    /// Reference to the shared, mutable `LoginToken`.
    pub fn token(&self) -> &Arc<Mutex<LoginToken>> {
        &self.token
    }

    /// Base URL of the Bitwarden identity service.
    pub fn identity_url(&self) -> &str {
        &self.identity_url
    }

    /// Base URL of the Bitwarden API service.
    pub fn api_url(&self) -> &str {
        &self.api_url
    }

    /// Resolves an absolute or relative API URL without duplicating `/api`.
    pub fn resolve_api_url(&self, endpoint: &str) -> String {
        if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
            endpoint.to_string()
        } else {
            let base = self.api_url.trim_end_matches('/');
            let ep = endpoint.trim_start_matches('/');
            if base.ends_with("/api") && (ep == "api" || ep.starts_with("api/")) {
                let rest = ep.strip_prefix("api/").unwrap_or("");
                if rest.is_empty() {
                    base.to_string()
                } else {
                    format!("{base}/{rest}")
                }
            } else {
                format!("{base}/{ep}")
            }
        }
    }

    /// Refreshes the OAuth access token using `grant_type=refresh_token`.
    ///
    /// Synchronized via `Mutex` to prevent concurrent refresh races.
    pub async fn refresh_token(&self) -> Result<(), ApiError> {
        let mut token_guard = self.token.lock().await;
        let refresh_token = token_guard.refresh_token.clone();
        if refresh_token.is_empty() {
            return Err(ApiError::Auth("No refresh token available".to_string()));
        }

        let url = format!("{}/connect/token", self.identity_url.trim_end_matches('/'));
        let params = [
            ("grant_type", "refresh_token"),
            ("client_id", "connector"),
            ("refresh_token", refresh_token.as_str()),
        ];

        let resp = self
            .client
            .post(&url)
            .header("User-Agent", BITWARDEN_USER_AGENT)
            .header("Device-Type", BITWARDEN_DEVICE_TYPE)
            .header("Bitwarden-Client-Name", BITWARDEN_CLIENT_NAME)
            .header("Bitwarden-Client-Version", BITWARDEN_CLIENT_VERSION)
            .form(&params)
            .send()
            .await
            .map_err(ApiError::Reqwest)?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(ApiError::Auth(format!(
                "Token refresh failed with status {status}: {body}"
            )));
        }

        let new_token: LoginToken = resp.json().await.map_err(|e| {
            ApiError::Auth(format!("Failed to parse refreshed token response: {e}"))
        })?;

        // Preserve key if the refresh response did not include it
        let key = if new_token.key.is_empty() {
            token_guard.key.clone()
        } else {
            new_token.key
        };

        *token_guard = LoginToken { key, ..new_token };

        Ok(())
    }

    /// Builds and executes an authenticated HTTP request.
    ///
    /// Automatically applies standard Bitwarden client headers and bearer authorization.
    /// If the server responds with 401 Unauthorized, automatically triggers `refresh_token()`
    /// and retries the request once.
    pub async fn fetch_with_auth(
        &self,
        method: reqwest::Method,
        url: &str,
        body: RequestBody,
    ) -> Result<Response, ApiError> {
        let full_url = self.resolve_api_url(url);

        let access_token = {
            let t = self.token.lock().await;
            t.access_token.clone()
        };

        let resp = self
            .send_request_internal(&method, &full_url, &access_token, &body)
            .await?;

        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            // Token expired: refresh under lock and retry once
            self.refresh_token().await?;

            let new_token = {
                let t = self.token.lock().await;
                t.access_token.clone()
            };

            let retry_resp = self
                .send_request_internal(&method, &full_url, &new_token, &body)
                .await?;

            Ok(retry_resp)
        } else {
            Ok(resp)
        }
    }

    async fn send_request_internal(
        &self,
        method: &reqwest::Method,
        url: &str,
        access_token: &str,
        body: &RequestBody,
    ) -> Result<Response, ApiError> {
        let mut req = self
            .client
            .request(method.clone(), url)
            .header("Authorization", format!("Bearer {access_token}"))
            .header("User-Agent", BITWARDEN_USER_AGENT)
            .header("Device-Type", BITWARDEN_DEVICE_TYPE)
            .header("Bitwarden-Client-Name", BITWARDEN_CLIENT_NAME)
            .header("Bitwarden-Client-Version", BITWARDEN_CLIENT_VERSION);

        match body {
            RequestBody::Empty => {}
            RequestBody::Json(json_val) => {
                req = req
                    .header("Content-Type", "application/json")
                    .body(json_val.to_string());
            }
            RequestBody::Form(pairs) => {
                req = req.header("Content-Type", "application/x-www-form-urlencoded");

                if let Some((_, email)) = pairs.iter().find(|(k, _)| k == "username") {
                    let b64 =
                        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(email.as_bytes());
                    req = req.header("Auth-Email", b64);
                }

                let form_str = url::form_urlencoded::Serializer::new(String::new())
                    .extend_pairs(pairs)
                    .finish();
                req = req.body(form_str);
            }
            RequestBody::RawForm { data, auth_email } => {
                req = req.header("Content-Type", "application/x-www-form-urlencoded");
                if let Some(email) = auth_email {
                    let b64 =
                        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(email.as_bytes());
                    req = req.header("Auth-Email", b64);
                }
                req = req.body(data.clone());
            }
        }

        let resp = req.send().await.map_err(ApiError::Reqwest)?;
        Ok(resp)
    }

    /// Retrieves a single cipher by UUID from the Bitwarden API.
    pub async fn get_cipher(&self, uuid: &uuid::Uuid) -> Result<sw_vault::Cipher, ApiError> {
        ciphers::get_cipher(self, uuid).await
    }

    /// Creates a new cipher in the Bitwarden vault.
    pub async fn post_cipher(
        &self,
        cipher: &sw_vault::Cipher,
    ) -> Result<sw_vault::Cipher, ApiError> {
        ciphers::post_cipher(self, cipher).await
    }

    /// Updates an existing cipher in the Bitwarden vault.
    pub async fn put_cipher(
        &self,
        uuid: &uuid::Uuid,
        cipher: &sw_vault::Cipher,
    ) -> Result<sw_vault::Cipher, ApiError> {
        ciphers::put_cipher(self, uuid, cipher).await
    }

    /// Deletes a cipher by UUID from the Bitwarden vault.
    pub async fn delete_cipher(&self, uuid: &uuid::Uuid) -> Result<(), ApiError> {
        ciphers::delete_cipher(self, uuid).await
    }
}
