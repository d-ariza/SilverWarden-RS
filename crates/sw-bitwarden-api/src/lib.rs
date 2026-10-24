use base64::Engine;
use reqwest::Response;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::Mutex;
use zeroize::Zeroize;

pub use sw_config::LoginToken;
pub use sw_crypto::{KdfConfig, KdfType};

pub const BITWARDEN_USER_AGENT: &str = "silverwarden/0.0.1";
pub const BITWARDEN_DEVICE_TYPE: &str = "10";
pub const BITWARDEN_CLIENT_NAME: &str = "silverwarden";
pub const BITWARDEN_CLIENT_VERSION: &str = "0.0.1";

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

    #[error("Server error ({status}): {message}")]
    Status {
        status: reqwest::StatusCode,
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreloginResponse {
    pub kdf: i32,
    pub kdf_iterations: Option<u32>,
    pub kdf_memory: Option<u32>,
    pub kdf_parallelism: Option<u32>,
}

impl TryFrom<PreloginResponse> for sw_crypto::KdfConfig {
    type Error = ApiError;

    fn try_from(resp: PreloginResponse) -> Result<Self, Self::Error> {
        let kdf_type = sw_crypto::KdfType::from_i32(resp.kdf)
            .map_err(|e| ApiError::Auth(format!("Unsupported KDF type {}: {e}", resp.kdf)))?;
        let iterations = resp
            .kdf_iterations
            .unwrap_or(if kdf_type == sw_crypto::KdfType::Pbkdf2 {
                100_000
            } else {
                3
            });
        Ok(sw_crypto::KdfConfig {
            kdf_type,
            iterations,
            memory: resp.kdf_memory,
            parallelism: resp.kdf_parallelism,
        })
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
    client: reqwest::Client,
    token: Arc<Mutex<LoginToken>>,
    identity_url: String,
    api_url: String,
}

impl AuthenticatedClient {
    /// Creates a new `AuthenticatedClient` with the given endpoints and shared `LoginToken`.
    pub fn new(
        identity_url: impl Into<String>,
        api_url: impl Into<String>,
        token: Arc<Mutex<LoginToken>>,
    ) -> Self {
        Self::with_client(reqwest::Client::new(), identity_url, api_url, token)
    }

    /// Creates a new `AuthenticatedClient` from a concrete `LoginToken` value.
    pub fn from_token(
        identity_url: impl Into<String>,
        api_url: impl Into<String>,
        token: LoginToken,
    ) -> Self {
        Self::new(identity_url, api_url, Arc::new(Mutex::new(token)))
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

    /// Resolves an absolute or relative API URL.
    pub fn resolve_api_url(&self, endpoint: &str) -> String {
        if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
            endpoint.to_string()
        } else {
            format!(
                "{}/{}",
                self.api_url.trim_end_matches('/'),
                endpoint.trim_start_matches('/')
            )
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

    /// Queries the prelogin endpoint to obtain the account's KDF configuration.
    pub async fn prelogin(&self, email: &str) -> Result<sw_crypto::KdfConfig, ApiError> {
        let url = format!(
            "{}/api/accounts/prelogin",
            self.api_url.trim_end_matches('/')
        );
        let mut resp = self
            .client
            .post(&url)
            .header("User-Agent", BITWARDEN_USER_AGENT)
            .header("Device-Type", BITWARDEN_DEVICE_TYPE)
            .header("Bitwarden-Client-Name", BITWARDEN_CLIENT_NAME)
            .header("Bitwarden-Client-Version", BITWARDEN_CLIENT_VERSION)
            .json(&serde_json::json!({ "email": email }))
            .send()
            .await?;

        // Fallback for self-hosted / identity endpoint mount
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            let alt_url = format!(
                "{}/accounts/prelogin",
                self.identity_url.trim_end_matches('/')
            );
            resp = self
                .client
                .post(&alt_url)
                .header("User-Agent", BITWARDEN_USER_AGENT)
                .header("Device-Type", BITWARDEN_DEVICE_TYPE)
                .header("Bitwarden-Client-Name", BITWARDEN_CLIENT_NAME)
                .header("Bitwarden-Client-Version", BITWARDEN_CLIENT_VERSION)
                .json(&serde_json::json!({ "email": email }))
                .send()
                .await?;
        }

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(ApiError::Status {
                status,
                message: body,
            });
        }

        let prelogin_resp: PreloginResponse = resp.json().await?;
        let kdf_config: sw_crypto::KdfConfig = prelogin_resp.try_into()?;
        Ok(kdf_config)
    }

    /// Authenticates with email and derived master password hash against `/connect/token`.
    pub async fn login_with_password(
        &self,
        email: &str,
        master_password_hash: &str,
        device_uuid: &str,
    ) -> Result<LoginToken, ApiError> {
        let url = format!("{}/connect/token", self.identity_url.trim_end_matches('/'));

        let b64_email = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(email.as_bytes());

        let params = [
            ("scope", "api offline_access"),
            ("client_id", "web"),
            ("deviceType", BITWARDEN_DEVICE_TYPE),
            ("deviceIdentifier", device_uuid),
            ("deviceName", "firefox"),
            ("grant_type", "password"),
            ("username", email),
            ("password", master_password_hash),
        ];

        let resp = self
            .client
            .post(&url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Auth-Email", b64_email)
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
                "Login with password failed with status {status}: {body}"
            )));
        }

        let token: LoginToken = resp
            .json()
            .await
            .map_err(|e| ApiError::Auth(format!("Failed to parse login token response: {e}")))?;

        // Update stored token in client
        *self.token.lock().await = token.clone();

        Ok(token)
    }

    /// Full end-to-end login orchestration:
    /// prelogin -> derive master key -> derive master password hash -> stretch key ->
    /// login_with_password -> decrypt_enc_key.
    ///
    /// Returns the active `LoginToken` and the decrypted 64-byte user symmetric key.
    pub async fn login(
        &self,
        email: &str,
        password: &str,
        device_uuid: &str,
    ) -> Result<(LoginToken, Vec<u8>), ApiError> {
        let kdf_config = self.prelogin(email).await?;
        let master_key = sw_crypto::derive_master_key(password.as_bytes(), email, &kdf_config)?;
        let master_password_hash = derive_master_password_hash(master_key.as_slice(), password);
        let stretched_sym_key = sw_crypto::stretch_key(&master_key)?;
        let stretched_bytes = stretched_sym_key.bytes();

        let token = self
            .login_with_password(email, &master_password_hash, device_uuid)
            .await?;

        if token.key.is_empty() {
            return Err(ApiError::Auth(
                "Login succeeded but server did not return an encryption key".to_string(),
            ));
        }

        let user_symmetric_key = decrypt_enc_key(&token.key, &stretched_bytes)?;
        Ok((token, user_symmetric_key))
    }
}

/// Derives the master password hash used to authenticate against Bitwarden.
///
/// Uses PBKDF2-HMAC-SHA256 with 1 iteration over the derived master key bytes
/// and the password as salt, encoded as standard Base64.
/// Parity with Goldwarden Go: `pbkdf2.Key(masterKey.GetBytes(), []byte(password), 1, 32, sha256.New)`
pub fn derive_master_password_hash(master_key: &[u8], password: &str) -> String {
    let mut hash = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(master_key, password.as_bytes(), 1, &mut hash);
    let encoded = base64::engine::general_purpose::STANDARD.encode(hash);
    hash.zeroize();
    encoded
}

/// Decrypts the user symmetric key from the wire EncString returned during login or sync.
///
/// Parses `enc_key_wire` as `sw_crypto::EncString` and decrypts using the stretched master key.
pub fn decrypt_enc_key(
    enc_key_wire: &str,
    stretched_master_key: &[u8],
) -> Result<Vec<u8>, ApiError> {
    if enc_key_wire.is_empty() {
        return Err(ApiError::Auth("enc_key is empty".to_string()));
    }

    let enc_string = sw_crypto::EncString::from_str(enc_key_wire)
        .map_err(|e| ApiError::Auth(format!("Failed to parse EncString from wire: {e}")))?;

    let sym_key = sw_crypto::SymmetricKey::from_bytes(stretched_master_key)
        .map_err(|e| ApiError::Auth(format!("Invalid stretched master key: {e}")))?;

    let decrypted = sw_crypto::decrypt_with(&enc_string, &sym_key)
        .map_err(|e| ApiError::Auth(format!("Failed to decrypt enc_key: {e}")))?;

    Ok(decrypted)
}

/// Standalone convenience wrapper for `AuthenticatedClient::prelogin`.
pub async fn prelogin(
    client: &AuthenticatedClient,
    email: &str,
) -> Result<sw_crypto::KdfConfig, ApiError> {
    client.prelogin(email).await
}

/// Standalone convenience wrapper for `AuthenticatedClient::login_with_password`.
pub async fn login_with_password(
    client: &AuthenticatedClient,
    email: &str,
    master_password_hash: &str,
    device_uuid: &str,
) -> Result<LoginToken, ApiError> {
    client
        .login_with_password(email, master_password_hash, device_uuid)
        .await
}

/// Standalone convenience wrapper for `AuthenticatedClient::login`.
pub async fn login(
    client: &AuthenticatedClient,
    email: &str,
    password: &str,
    device_uuid: &str,
) -> Result<(LoginToken, Vec<u8>), ApiError> {
    client.login(email, password, device_uuid).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::Method;
    use wiremock::matchers::{body_string_contains, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn test_fetch_with_auth_success_200() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/sync"))
            .and(header("Authorization", "Bearer valid_access_token"))
            .and(header("User-Agent", BITWARDEN_USER_AGENT))
            .and(header("Device-Type", BITWARDEN_DEVICE_TYPE))
            .and(header("Bitwarden-Client-Name", BITWARDEN_CLIENT_NAME))
            .and(header("Bitwarden-Client-Version", BITWARDEN_CLIENT_VERSION))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "profile": {} })),
            )
            .mount(&server)
            .await;

        let token = LoginToken {
            access_token: "valid_access_token".to_string(),
            expires_in: 3600,
            token_type: "Bearer".to_string(),
            refresh_token: "refresh_123".to_string(),
            key: "key_abc".to_string(),
        };

        let client = AuthenticatedClient::from_token(server.uri(), server.uri(), token);
        let resp = client
            .fetch_with_auth(Method::GET, "/api/sync", RequestBody::Empty)
            .await
            .expect("Request should succeed");

        assert_eq!(resp.status(), reqwest::StatusCode::OK);
        let json: serde_json::Value = resp.json().await.unwrap();
        assert!(json.get("profile").is_some());
    }

    #[tokio::test]
    async fn test_fetch_with_auth_401_then_refresh_and_retry_200() {
        let server = MockServer::start().await;

        // Step 1: Initial call with expired token returns 401
        Mock::given(method("GET"))
            .and(path("/api/sync"))
            .and(header("Authorization", "Bearer expired_access_token"))
            .respond_with(ResponseTemplate::new(401))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Step 2: Refresh token request with grant_type=refresh_token
        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .and(body_string_contains("grant_type=refresh_token"))
            .and(body_string_contains("client_id=connector"))
            .and(body_string_contains("refresh_token=valid_refresh_token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "newly_refreshed_access_token",
                "expires_in": 3600,
                "token_type": "Bearer",
                "refresh_token": "next_refresh_token",
                "key": ""
            })))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Step 3: Re-executed call with new token returns 200
        Mock::given(method("GET"))
            .and(path("/api/sync"))
            .and(header(
                "Authorization",
                "Bearer newly_refreshed_access_token",
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "refreshed": true })),
            )
            .mount(&server)
            .await;

        let token = LoginToken {
            access_token: "expired_access_token".to_string(),
            expires_in: 0,
            token_type: "Bearer".to_string(),
            refresh_token: "valid_refresh_token".to_string(),
            key: "preserved_key".to_string(),
        };

        let client = AuthenticatedClient::from_token(server.uri(), server.uri(), token);
        let resp = client
            .fetch_with_auth(Method::GET, "/api/sync", RequestBody::Empty)
            .await
            .expect("Request should succeed after auto-refresh");

        assert_eq!(resp.status(), reqwest::StatusCode::OK);

        // Verify token in client was updated and existing key was preserved
        let token_guard = client.token().lock().await;
        assert_eq!(token_guard.access_token, "newly_refreshed_access_token");
        assert_eq!(token_guard.refresh_token, "next_refresh_token");
        assert_eq!(token_guard.key, "preserved_key");
    }

    #[tokio::test]
    async fn test_fetch_with_auth_refresh_fails_returns_error() {
        let server = MockServer::start().await;

        // 401 on initial request
        Mock::given(method("GET"))
            .and(path("/api/data"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;

        // 400 Bad Request on refresh token
        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_json(serde_json::json!({ "error": "invalid_grant" })),
            )
            .mount(&server)
            .await;

        let token = LoginToken {
            access_token: "bad_access_token".to_string(),
            expires_in: 0,
            token_type: "Bearer".to_string(),
            refresh_token: "invalid_refresh_token".to_string(),
            key: "key".to_string(),
        };

        let client = AuthenticatedClient::from_token(server.uri(), server.uri(), token);
        let res = client
            .fetch_with_auth(Method::GET, "/api/data", RequestBody::Empty)
            .await;

        assert!(res.is_err());
        match res.unwrap_err() {
            ApiError::Auth(msg) => {
                assert!(msg.contains("Token refresh failed"));
            }
            other => panic!("Expected ApiError::Auth, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_fetch_with_auth_form_sets_auth_email_header() {
        let server = MockServer::start().await;

        // Expect Auth-Email base64 header
        let expected_auth_email =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("user@example.com".as_bytes());

        Mock::given(method("POST"))
            .and(path("/api/form-endpoint"))
            .and(header("Content-Type", "application/x-www-form-urlencoded"))
            .and(header("Auth-Email", expected_auth_email.as_str()))
            .and(body_string_contains("username=user%40example.com"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&server)
            .await;

        let token = LoginToken {
            access_token: "tok".to_string(),
            ..Default::default()
        };

        let client = AuthenticatedClient::from_token(server.uri(), server.uri(), token);
        let body = RequestBody::form([
            ("username", "user@example.com"),
            ("scope", "api offline_access"),
        ]);

        let resp = client
            .fetch_with_auth(Method::POST, "/api/form-endpoint", body)
            .await
            .expect("Form request should succeed");

        assert_eq!(resp.status(), reqwest::StatusCode::OK);
    }

    #[tokio::test]
    async fn test_fetch_with_auth_json_body() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/api/json-endpoint"))
            .and(header("Content-Type", "application/json"))
            .and(body_string_contains("\"query\":\"search\""))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&server)
            .await;

        let token = LoginToken {
            access_token: "tok".to_string(),
            ..Default::default()
        };

        let client = AuthenticatedClient::from_token(server.uri(), server.uri(), token);
        let body = RequestBody::json(serde_json::json!({ "query": "search" }));

        let resp = client
            .fetch_with_auth(Method::POST, "/api/json-endpoint", body)
            .await
            .expect("Json request should succeed");

        assert_eq!(resp.status(), reqwest::StatusCode::OK);
    }

    #[tokio::test]
    async fn test_refresh_token_missing_returns_auth_error() {
        let token = LoginToken {
            access_token: "tok".to_string(),
            refresh_token: "".to_string(),
            ..Default::default()
        };

        let client = AuthenticatedClient::from_token("http://localhost", "http://localhost", token);
        let res = client.refresh_token().await;
        assert!(matches!(res, Err(ApiError::Auth(_))));
    }

    #[tokio::test]
    async fn test_prelogin_success() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/api/accounts/prelogin"))
            .and(header("Content-Type", "application/json"))
            .and(body_string_contains("\"email\":\"test@domain.com\""))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "kdf": 1,
                "kdfIterations": 600000,
                "kdfMemory": null,
                "kdfParallelism": null
            })))
            .mount(&server)
            .await;

        let client =
            AuthenticatedClient::from_token(server.uri(), server.uri(), LoginToken::default());
        let prelogin_resp = client
            .prelogin("test@domain.com")
            .await
            .expect("Prelogin should succeed");

        assert_eq!(prelogin_resp.kdf_type, sw_crypto::KdfType::Argon2id);
        assert_eq!(prelogin_resp.iterations, 600000);
    }

    #[tokio::test]
    async fn test_derive_master_password_hash_rfc6070_vector() {
        // Known RFC 6070 test vector 1 for PBKDF2-HMAC-SHA256:
        // password = "password", salt = "salt", c = 1, dkLen = 32
        // In Bitwarden parity: master_key is passed as PBKDF2 password, and user password as salt.
        let master_key = b"password";
        let password = "salt";
        let hash = derive_master_password_hash(master_key, password);

        // Expected base64 of the 32-byte RFC 6070 PBKDF2-HMAC-SHA256 output:
        // [0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c, 0x43, 0xe7, 0x22, 0x52, 0x56, 0xc4,
        //  0xf8, 0x37, 0xa8, 0x65, 0x48, 0xc9, 0x2c, 0xcc, 0x35, 0x48, 0x08, 0x05, 0x98, 0x7c,
        //  0xb7, 0x0b, 0xe1, 0x7b]
        assert_eq!(hash, "Eg+2z/z4syxD5yJSVsT4N6hlSMkszDVICAWYfLcL4Xs=");
    }

    #[test]
    fn test_decrypt_enc_key_synthetic() {
        // Create 64-byte stretched master key (32 bytes enc + 32 bytes mac)
        let mut stretched_key_bytes = [0u8; 64];
        for (i, b) in stretched_key_bytes.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(1);
        }
        let sym_key = sw_crypto::SymmetricKey::from_bytes(&stretched_key_bytes).unwrap();

        // 64-byte secret account symmetric key to encrypt
        let user_key_plaintext =
            b"super_secret_64_byte_account_symmetric_key_payload_for_testing!!";
        let enc_key_wire = sw_crypto::encrypt_with_to_string(
            user_key_plaintext,
            sw_crypto::EncStringType::AesCbc256HmacSha256B64,
            &sym_key,
        )
        .expect("Synthetic encryption should succeed");

        assert!(enc_key_wire.starts_with("2."));

        let decrypted = decrypt_enc_key(&enc_key_wire, &stretched_key_bytes)
            .expect("Decryption should succeed");
        assert_eq!(decrypted, user_key_plaintext);
    }

    #[test]
    fn test_decrypt_enc_key_error_cases() {
        let valid_key = [5u8; 64];

        // Empty wire string
        assert!(matches!(
            decrypt_enc_key("", &valid_key),
            Err(ApiError::Auth(_))
        ));

        // Invalid format
        assert!(matches!(
            decrypt_enc_key("not-an-enc-string", &valid_key),
            Err(ApiError::Auth(_))
        ));

        // Invalid key length (e.g. 32 bytes instead of 64)
        assert!(matches!(
            decrypt_enc_key("2.aXZfMTY=|Y3Q=|bWFj", &[1u8; 32]),
            Err(ApiError::Auth(_))
        ));

        // Tampered MAC / wrong key
        let sym_key = sw_crypto::SymmetricKey::from_bytes(&valid_key).unwrap();
        let enc_wire = sw_crypto::encrypt_with_to_string(
            b"secret",
            sw_crypto::EncStringType::AesCbc256HmacSha256B64,
            &sym_key,
        )
        .unwrap();

        let wrong_key = [6u8; 64];
        assert!(matches!(
            decrypt_enc_key(&enc_wire, &wrong_key),
            Err(ApiError::Auth(_))
        ));
    }

    #[tokio::test]
    async fn test_login_with_password_success() {
        let server = MockServer::start().await;

        let expected_auth_email =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("user@example.com".as_bytes());

        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .and(header("Content-Type", "application/x-www-form-urlencoded"))
            .and(header("Auth-Email", expected_auth_email.as_str()))
            .and(header("User-Agent", BITWARDEN_USER_AGENT))
            .and(header("Device-Type", BITWARDEN_DEVICE_TYPE))
            .and(header("Bitwarden-Client-Name", BITWARDEN_CLIENT_NAME))
            .and(header("Bitwarden-Client-Version", BITWARDEN_CLIENT_VERSION))
            .and(body_string_contains("grant_type=password"))
            .and(body_string_contains("username=user%40example.com"))
            .and(body_string_contains("password=test_master_hash"))
            .and(body_string_contains("deviceIdentifier=device-uuid-123"))
            .and(body_string_contains("deviceName=firefox"))
            .and(body_string_contains("client_id=web"))
            .and(body_string_contains("scope=api+offline_access"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "token_abc_123",
                "expires_in": 3600,
                "token_type": "Bearer",
                "refresh_token": "refresh_xyz_789",
                "key": "2.iv|ct|mac"
            })))
            .mount(&server)
            .await;

        let client =
            AuthenticatedClient::from_token(server.uri(), server.uri(), LoginToken::default());

        let token = client
            .login_with_password("user@example.com", "test_master_hash", "device-uuid-123")
            .await
            .expect("Login with password should succeed");

        assert_eq!(token.access_token, "token_abc_123");
        assert_eq!(token.refresh_token, "refresh_xyz_789");
        assert_eq!(token.key, "2.iv|ct|mac");

        // Verify stored token was updated
        let stored_token = client.token().lock().await.clone();
        assert_eq!(stored_token.access_token, "token_abc_123");
    }

    #[tokio::test]
    async fn test_login_with_password_error_400() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_json(serde_json::json!({ "error": "invalid_grant" })),
            )
            .mount(&server)
            .await;

        let client =
            AuthenticatedClient::from_token(server.uri(), server.uri(), LoginToken::default());

        let res = client
            .login_with_password("user@example.com", "bad_hash", "device-uuid-123")
            .await;

        assert!(matches!(res, Err(ApiError::Auth(_))));
    }

    #[tokio::test]
    async fn test_login_full_orchestration_success() {
        let server = MockServer::start().await;

        let email = "user@example.com";
        let password = "MyMasterPassword123!";
        let device_uuid = "device-555";

        // Step 1: Prelogin mock
        Mock::given(method("POST"))
            .and(path("/api/accounts/prelogin"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "kdf": 0,
                "kdfIterations": 100000,
                "kdfMemory": null,
                "kdfParallelism": null
            })))
            .mount(&server)
            .await;

        // Compute expected master key and stretched key
        let kdf_config = sw_crypto::KdfConfig {
            kdf_type: sw_crypto::KdfType::Pbkdf2,
            iterations: 100000,
            memory: None,
            parallelism: None,
        };
        let master_key =
            sw_crypto::derive_master_key(password.as_bytes(), email, &kdf_config).unwrap();
        let expected_master_hash = derive_master_password_hash(master_key.as_slice(), password);
        let stretched_key = sw_crypto::stretch_key(&master_key).unwrap();

        // Synthetic 64-byte account symmetric key
        let expected_user_sym_key =
            b"0123456789012345678901234567890101234567890123456789012345678901";
        let enc_key_wire = sw_crypto::encrypt_with_to_string(
            expected_user_sym_key,
            sw_crypto::EncStringType::AesCbc256HmacSha256B64,
            &stretched_key,
        )
        .unwrap();

        let encoded_password_param =
            url::form_urlencoded::byte_serialize(expected_master_hash.as_bytes())
                .collect::<String>();
        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .and(body_string_contains("grant_type=password"))
            .and(body_string_contains(format!(
                "password={}",
                encoded_password_param
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "full_login_access_token",
                "expires_in": 3600,
                "token_type": "Bearer",
                "refresh_token": "full_login_refresh_token",
                "key": enc_key_wire
            })))
            .mount(&server)
            .await;

        let client =
            AuthenticatedClient::from_token(server.uri(), server.uri(), LoginToken::default());

        let (token, decrypted_key) = client
            .login(email, password, device_uuid)
            .await
            .expect("Full login orchestration should succeed");

        assert_eq!(token.access_token, "full_login_access_token");
        assert_eq!(token.refresh_token, "full_login_refresh_token");
        assert_eq!(decrypted_key, expected_user_sym_key);

        // Verify client token updated and fetch_with_auth uses the new token
        Mock::given(method("GET"))
            .and(path("/api/sync"))
            .and(header("Authorization", "Bearer full_login_access_token"))
            .respond_with(ResponseTemplate::new(200).set_body_string("sync ok"))
            .mount(&server)
            .await;

        let sync_resp = client
            .fetch_with_auth(Method::GET, "/api/sync", RequestBody::Empty)
            .await
            .unwrap();
        assert_eq!(sync_resp.status(), reqwest::StatusCode::OK);
    }

    #[tokio::test]
    async fn test_login_full_orchestration_prelogin_fails() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/api/accounts/prelogin"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal error"))
            .mount(&server)
            .await;

        // When /api/accounts/prelogin is 500, fallback is NOT triggered (only 404 falls back)
        let client =
            AuthenticatedClient::from_token(server.uri(), server.uri(), LoginToken::default());

        let res = client
            .login("user@example.com", "pass", "device-uuid")
            .await;

        assert!(matches!(res, Err(ApiError::Status { .. })));
    }

    #[tokio::test]
    async fn test_prelogin_404_fallback_to_identity_mount() {
        let server = MockServer::start().await;

        // /api/accounts/prelogin returns 404
        Mock::given(method("POST"))
            .and(path("/api/accounts/prelogin"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        // /accounts/prelogin returns 200
        Mock::given(method("POST"))
            .and(path("/accounts/prelogin"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "kdf": 0,
                "kdfIterations": 100000,
                "kdfMemory": null,
                "kdfParallelism": null
            })))
            .mount(&server)
            .await;

        let client =
            AuthenticatedClient::from_token(server.uri(), server.uri(), LoginToken::default());

        let kdf_config = client.prelogin("user@example.com").await.unwrap();
        assert_eq!(kdf_config.kdf_type, sw_crypto::KdfType::Pbkdf2);
        assert_eq!(kdf_config.iterations, 100000);
    }

    #[tokio::test]
    async fn test_login_missing_key_returns_auth_error() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/api/accounts/prelogin"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "kdf": 0,
                "kdfIterations": 100000
            })))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "token",
                "expires_in": 3600,
                "token_type": "Bearer",
                "refresh_token": "refresh",
                "key": ""
            })))
            .mount(&server)
            .await;

        let client =
            AuthenticatedClient::from_token(server.uri(), server.uri(), LoginToken::default());

        let res = client
            .login("user@example.com", "pass", "device-uuid")
            .await;

        assert!(matches!(res, Err(ApiError::Auth(_))));
    }

    #[tokio::test]
    async fn test_standalone_functions() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/api/accounts/prelogin"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "kdf": 0,
                "kdfIterations": 5000
            })))
            .mount(&server)
            .await;

        let client =
            AuthenticatedClient::from_token(server.uri(), server.uri(), LoginToken::default());

        let cfg = prelogin(&client, "standalone@example.com").await.unwrap();
        assert_eq!(cfg.iterations, 5000);
    }

    #[tokio::test]
    async fn test_fetch_with_auth_raw_form() {
        let server = MockServer::start().await;

        let expected_auth_email =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("raw@example.com".as_bytes());

        Mock::given(method("POST"))
            .and(path("/api/raw-form"))
            .and(header("Content-Type", "application/x-www-form-urlencoded"))
            .and(header("Auth-Email", expected_auth_email.as_str()))
            .and(body_string_contains("custom=payload"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&server)
            .await;

        let client =
            AuthenticatedClient::from_token(server.uri(), server.uri(), LoginToken::default());
        let body = RequestBody::RawForm {
            data: "custom=payload".to_string(),
            auth_email: Some("raw@example.com".to_string()),
        };

        let resp = client
            .fetch_with_auth(Method::POST, "/api/raw-form", body)
            .await
            .expect("Raw form request should succeed");

        assert_eq!(resp.status(), reqwest::StatusCode::OK);
    }

    #[tokio::test]
    async fn test_client_accessors_and_resolve_api_url() {
        let token = LoginToken {
            access_token: "tok1".into(),
            ..Default::default()
        };
        let client = AuthenticatedClient::from_token(
            "https://identity.bitwarden.com",
            "https://api.bitwarden.com",
            token,
        );

        assert_eq!(client.identity_url(), "https://identity.bitwarden.com");
        assert_eq!(client.api_url(), "https://api.bitwarden.com");

        // Relative path resolution
        assert_eq!(
            client.resolve_api_url("/sync"),
            "https://api.bitwarden.com/sync"
        );
        assert_eq!(
            client.resolve_api_url("sync"),
            "https://api.bitwarden.com/sync"
        );

        // Absolute path resolution
        assert_eq!(
            client.resolve_api_url("https://other.com/api/test"),
            "https://other.com/api/test"
        );
        assert_eq!(
            client.resolve_api_url("http://insecure.com/api/test"),
            "http://insecure.com/api/test"
        );

        // RequestBody empty & From
        let empty_body = RequestBody::empty();
        assert!(matches!(empty_body, RequestBody::Empty));

        let json_body: RequestBody = serde_json::json!({"a": 1}).into();
        assert!(matches!(json_body, RequestBody::Json(_)));
    }

    #[tokio::test]
    async fn test_refresh_updates_new_key_when_provided() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "refreshed_access",
                "expires_in": 7200,
                "token_type": "Bearer",
                "refresh_token": "refreshed_refresh",
                "key": "new_updated_key"
            })))
            .mount(&server)
            .await;

        let token = LoginToken {
            access_token: "old_access".into(),
            refresh_token: "old_refresh".into(),
            key: "old_key".into(),
            ..Default::default()
        };

        let client = AuthenticatedClient::from_token(server.uri(), server.uri(), token);
        client.refresh_token().await.unwrap();

        let token_guard = client.token().lock().await;
        assert_eq!(token_guard.access_token, "refreshed_access");
        assert_eq!(token_guard.key, "new_updated_key");
    }

    // =========================================================================
    // Go <-> Rust Parity Tests for SW-033 Login
    // =========================================================================

    const TEST_EMAIL: &str = "3227908@tcs.com";
    const TEST_PASSWORD: &str = "Unloader-Woof";
    const TEST_KDF_ITERATIONS: u32 = 600000;
    const TEST_DEVICE_UUID: &str = "1f5ef996-82f0-11f1-bc18-80304903a0d9";

    const EXPECTED_MASTER_KEY_HEX: &str =
        "199221c920d67649464da15df7b019bd4df1accc0c90e0cea2d68a358c254afe";
    const EXPECTED_MASTER_PASSWORD_HASH_B64: &str = "n9L+3LdK2Z1IhAPRnLzerrdLBKjMhhr3LSpXfIDNLUQ=";
    const EXPECTED_STRETCHED_KEY_HEX: &str =
        "d173d39056e02e5ae2af53316d6cc21492db044de5641a2230bb4e2a33933566f4b7362e746996055d1b31cddd2be0c43bfb79b7c667013d7e4cc99d497532f0";
    const EXPECTED_ENC_KEY: &str =
        "2.VnAx2h55dzHVslHktja+Tg==|AyhiUxbTIoISm6sVOhjwuGSvZLT/SNde/6qXFKKFD+pqg/ZWeWKTu8mvx66ppWBgorkfYRALqpem37JM8viJOdK5/GfrwMPEy+NZ2Ll9oCo=|I5h2Vl4BQkPZ3hD1nwNmaCug+PfS6YjfDB0L6S0ekz8=";
    const EXPECTED_USER_SYMMETRIC_KEY_HEX: &str =
        "f7e4fce1ebe2b9af92bfd98aea39b0705410b59277ba3efce9034896610e3fd6fdb48d82574e3db63252bc14fe40a9cdd81038074a1cada65cf8413c11919830";

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[test]
    fn test_parity_master_key() {
        let config = sw_crypto::KdfConfig {
            kdf_type: sw_crypto::KdfType::Pbkdf2,
            iterations: TEST_KDF_ITERATIONS,
            memory: None,
            parallelism: None,
        };
        let master_key =
            sw_crypto::derive_master_key(TEST_PASSWORD.as_bytes(), TEST_EMAIL, &config)
                .expect("Master key derivation should succeed");
        assert_eq!(hex_encode(master_key.as_slice()), EXPECTED_MASTER_KEY_HEX);
    }

    #[test]
    fn test_parity_master_password_hash() {
        let config = sw_crypto::KdfConfig {
            kdf_type: sw_crypto::KdfType::Pbkdf2,
            iterations: TEST_KDF_ITERATIONS,
            memory: None,
            parallelism: None,
        };
        let master_key =
            sw_crypto::derive_master_key(TEST_PASSWORD.as_bytes(), TEST_EMAIL, &config)
                .expect("Master key derivation should succeed");
        let hash = derive_master_password_hash(master_key.as_slice(), TEST_PASSWORD);
        assert_eq!(hash, EXPECTED_MASTER_PASSWORD_HASH_B64);
    }

    #[test]
    fn test_parity_stretch_key() {
        let config = sw_crypto::KdfConfig {
            kdf_type: sw_crypto::KdfType::Pbkdf2,
            iterations: TEST_KDF_ITERATIONS,
            memory: None,
            parallelism: None,
        };
        let master_key =
            sw_crypto::derive_master_key(TEST_PASSWORD.as_bytes(), TEST_EMAIL, &config)
                .expect("Master key derivation should succeed");
        let stretched_key =
            sw_crypto::stretch_key(&master_key).expect("Stretch key derivation should succeed");
        assert_eq!(
            hex_encode(&stretched_key.bytes()),
            EXPECTED_STRETCHED_KEY_HEX
        );
    }

    #[test]
    fn test_parity_decrypt_enc_key() {
        let config = sw_crypto::KdfConfig {
            kdf_type: sw_crypto::KdfType::Pbkdf2,
            iterations: TEST_KDF_ITERATIONS,
            memory: None,
            parallelism: None,
        };
        let master_key =
            sw_crypto::derive_master_key(TEST_PASSWORD.as_bytes(), TEST_EMAIL, &config)
                .expect("Master key derivation should succeed");
        let stretched_key =
            sw_crypto::stretch_key(&master_key).expect("Stretch key derivation should succeed");

        // Verify with decrypt_enc_key
        let decrypted = decrypt_enc_key(EXPECTED_ENC_KEY, &stretched_key.bytes())
            .expect("Decryption of enc_key should succeed");
        assert_eq!(hex_encode(&decrypted), EXPECTED_USER_SYMMETRIC_KEY_HEX);

        // Verify directly with sw_crypto::EncString and decrypt_with
        let enc_string = sw_crypto::EncString::from_str(EXPECTED_ENC_KEY)
            .expect("EncString parsing should succeed");
        let decrypted_direct = sw_crypto::decrypt_with(&enc_string, &stretched_key)
            .expect("Direct decrypt_with should succeed");
        assert_eq!(
            hex_encode(&decrypted_direct),
            EXPECTED_USER_SYMMETRIC_KEY_HEX
        );
    }

    #[tokio::test]
    async fn test_parity_full_login_pipeline() {
        let server = MockServer::start().await;

        // Prelogin returning the exact Go parity parameters
        Mock::given(method("POST"))
            .and(path("/api/accounts/prelogin"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "kdf": 0,
                "kdfIterations": TEST_KDF_ITERATIONS,
                "kdfMemory": null,
                "kdfParallelism": null
            })))
            .mount(&server)
            .await;

        // Connect token returning the exact Go parity enc_key
        let encoded_password_param =
            url::form_urlencoded::byte_serialize(EXPECTED_MASTER_PASSWORD_HASH_B64.as_bytes())
                .collect::<String>();

        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .and(body_string_contains("grant_type=password"))
            .and(body_string_contains(format!(
                "username={}",
                url::form_urlencoded::byte_serialize(TEST_EMAIL.as_bytes()).collect::<String>()
            )))
            .and(body_string_contains(format!(
                "password={}",
                encoded_password_param
            )))
            .and(body_string_contains(format!(
                "deviceIdentifier={}",
                TEST_DEVICE_UUID
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "parity_access_token",
                "expires_in": 3600,
                "token_type": "Bearer",
                "refresh_token": "parity_refresh_token",
                "key": EXPECTED_ENC_KEY
            })))
            .mount(&server)
            .await;

        let client =
            AuthenticatedClient::from_token(server.uri(), server.uri(), LoginToken::default());

        let (token, user_symmetric_key) = client
            .login(TEST_EMAIL, TEST_PASSWORD, TEST_DEVICE_UUID)
            .await
            .expect("Full login with parity vectors should succeed");

        assert_eq!(token.access_token, "parity_access_token");
        assert_eq!(token.key, EXPECTED_ENC_KEY);
        assert_eq!(
            hex_encode(&user_symmetric_key),
            EXPECTED_USER_SYMMETRIC_KEY_HEX
        );
    }
}
