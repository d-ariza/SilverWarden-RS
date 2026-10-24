use base64::Engine;
use reqwest::Response;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::Mutex;

pub use sw_config::LoginToken;

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

    /// Helper for prelogin endpoint (SW-033 integration).
    pub async fn prelogin(&self, email: &str) -> Result<PreloginResponse, ApiError> {
        let url = format!(
            "{}/api/accounts/prelogin",
            self.api_url.trim_end_matches('/')
        );
        let resp = self
            .client
            .post(&url)
            .header("User-Agent", BITWARDEN_USER_AGENT)
            .header("Device-Type", BITWARDEN_DEVICE_TYPE)
            .header("Bitwarden-Client-Name", BITWARDEN_CLIENT_NAME)
            .header("Bitwarden-Client-Version", BITWARDEN_CLIENT_VERSION)
            .json(&serde_json::json!({ "email": email }))
            .send()
            .await?
            .json::<PreloginResponse>()
            .await?;
        Ok(resp)
    }
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

        assert_eq!(prelogin_resp.kdf, 1);
        assert_eq!(prelogin_resp.kdf_iterations, Some(600000));
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
}
