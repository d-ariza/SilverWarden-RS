use crate::{
    ApiError, AuthenticatedClient, BITWARDEN_CLIENT_NAME, BITWARDEN_CLIENT_VERSION,
    BITWARDEN_DEVICE_TYPE, BITWARDEN_USER_AGENT,
};
use base64::Engine;
use sw_config::LoginToken;

/// Two-factor authentication provider types in Bitwarden.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TwoFactorProvider {
    Authenticator = 0,
    Email = 1,
    Duo = 2,
    YubiKey = 3,
    U2f = 4,
    Remember = 5,
    OrganizationDuo = 6,
    WebAuthn = 7,
}

impl TwoFactorProvider {
    pub fn from_i32(val: i32) -> Option<Self> {
        match val {
            0 => Some(Self::Authenticator),
            1 => Some(Self::Email),
            2 => Some(Self::Duo),
            3 => Some(Self::YubiKey),
            4 => Some(Self::U2f),
            5 => Some(Self::Remember),
            6 => Some(Self::OrganizationDuo),
            7 => Some(Self::WebAuthn),
            _ => None,
        }
    }

    pub fn to_i32(self) -> i32 {
        self as i32
    }
}

/// Parses a 2FA challenge response body and extracts supported provider IDs and token.
pub fn parse_two_factor_error(body: &str) -> Option<(Vec<i32>, String)> {
    if !body.contains("TwoFactor") && !body.contains("twoFactor") {
        return None;
    }

    let val: serde_json::Value = serde_json::from_str(body).ok()?;

    let mut providers = Vec::new();
    if let Some(arr) = val
        .get("TwoFactorProviders")
        .or_else(|| val.get("twoFactorProviders"))
        .and_then(|v| v.as_array())
    {
        for item in arr {
            if let Some(n) = item.as_i64() {
                providers.push(n as i32);
            }
        }
    } else {
        let map = val
            .get("TwoFactorProviders2")
            .or_else(|| val.get("twoFactorProviders2"))
            .and_then(|v| v.as_object())?;
        let mut keys: Vec<i32> = map.keys().filter_map(|k| k.parse::<i32>().ok()).collect();
        keys.sort_unstable();
        providers = keys;
    }

    let token = val
        .get("TwoFactorToken")
        .or_else(|| val.get("twoFactorToken"))
        .or_else(|| val.get("authRequest"))
        .and_then(|v| v.as_str())?
        .to_string();

    Some((providers, token))
}

/// Completes 2FA login using an Authenticator/TOTP verification code (provider 0).
pub async fn complete_totp(
    client: &AuthenticatedClient,
    email: &str,
    master_password_hash: &str,
    two_factor_token: &str,
    totp_code: &str,
    device_uuid: &str,
) -> Result<LoginToken, ApiError> {
    complete_two_factor(
        client,
        email,
        master_password_hash,
        two_factor_token,
        totp_code,
        0,
        device_uuid,
    )
    .await
}

/// Completes 2FA login using an Email verification code (provider 1).
pub async fn complete_email(
    client: &AuthenticatedClient,
    email: &str,
    master_password_hash: &str,
    two_factor_token: &str,
    email_code: &str,
    device_uuid: &str,
) -> Result<LoginToken, ApiError> {
    complete_two_factor(
        client,
        email,
        master_password_hash,
        two_factor_token,
        email_code,
        1,
        device_uuid,
    )
    .await
}

/// Sends an email with a login verification code (`POST /two-factor/send-email-login`).
pub async fn send_two_factor_email_login(
    client: &AuthenticatedClient,
    email: &str,
    device_uuid: &str,
) -> Result<(), ApiError> {
    let url = format!(
        "{}/two-factor/send-email-login",
        client.api_url().trim_end_matches('/')
    );
    let body = serde_json::json!({
        "email": email,
        "deviceIdentifier": device_uuid,
    });

    let resp = client
        .http_client()
        .post(&url)
        .header("User-Agent", BITWARDEN_USER_AGENT)
        .header("Device-Type", BITWARDEN_DEVICE_TYPE)
        .header("Bitwarden-Client-Name", BITWARDEN_CLIENT_NAME)
        .header("Bitwarden-Client-Version", BITWARDEN_CLIENT_VERSION)
        .json(&body)
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let message = resp.text().await.unwrap_or_default();
        return Err(ApiError::Status { status, message });
    }

    Ok(())
}

/// Completes 2FA login via FIDO2 / WebAuthn (stub postponed to post-MVP).
pub async fn complete_fido2(
    _client: &AuthenticatedClient,
    _email: &str,
    _master_password_hash: &str,
    _two_factor_token: &str,
    _device_uuid: &str,
) -> Result<LoginToken, ApiError> {
    Err(ApiError::NotImplemented(
        "FIDO2 requires hardware and is postponed to post-MVP".into(),
    ))
}

async fn complete_two_factor(
    client: &AuthenticatedClient,
    email: &str,
    master_password_hash: &str,
    two_factor_token: &str,
    code: &str,
    provider: i32,
    device_uuid: &str,
) -> Result<LoginToken, ApiError> {
    let url = format!(
        "{}/connect/token",
        client.identity_url().trim_end_matches('/')
    );
    let b64_email = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(email.as_bytes());

    let provider_str = provider.to_string();
    let params = [
        ("grant_type", "password"),
        ("client_id", "web"),
        ("deviceType", BITWARDEN_DEVICE_TYPE),
        ("deviceIdentifier", device_uuid),
        ("deviceName", "firefox"),
        ("username", email),
        ("password", master_password_hash),
        ("twoFactorToken", code),
        ("twoFactorProvider", &provider_str),
        ("twoFactorRemember", "0"),
        ("authRequest", two_factor_token),
    ];

    let resp = client
        .http_client()
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
        return Err(ApiError::Status {
            status,
            message: body,
        });
    }

    let token: LoginToken = resp
        .json()
        .await
        .map_err(|e| ApiError::Auth(format!("Failed to parse two-factor login token: {e}")))?;

    *client.token().lock().await = token.clone();
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derive_master_password_hash;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn test_login_detects_two_factor_required() {
        let server = MockServer::start().await;

        let two_factor_body = serde_json::json!({
            "TwoFactorProviders": [0, 1],
            "TwoFactorToken": "abc"
        });

        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(ResponseTemplate::new(401).set_body_json(&two_factor_body))
            .mount(&server)
            .await;

        let client =
            AuthenticatedClient::from_token(server.uri(), server.uri(), LoginToken::default());

        let res = client
            .login_with_password("user@example.com", "hash123", "device-123")
            .await;

        match res {
            Err(ApiError::TwoFactorRequired { providers, token }) => {
                assert_eq!(providers, vec![0, 1]);
                assert_eq!(token, "abc");
            }
            other => panic!("Expected TwoFactorRequired, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_login_two_factor_unrecognized_format_returns_status() {
        let server = MockServer::start().await;

        // Contains "TwoFactor" but is missing TwoFactorToken
        let bad_body = serde_json::json!({
            "TwoFactorProviders": [0, 1]
        });

        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(ResponseTemplate::new(401).set_body_json(&bad_body))
            .mount(&server)
            .await;

        let client =
            AuthenticatedClient::from_token(server.uri(), server.uri(), LoginToken::default());

        let res = client
            .login_with_password("user@example.com", "hash123", "device-123")
            .await;

        match res {
            Err(ApiError::Status { status, .. }) => {
                assert_eq!(status, reqwest::StatusCode::UNAUTHORIZED);
            }
            other => panic!("Expected ApiError::Status, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_complete_totp_success() {
        let server = MockServer::start().await;

        let token_resp = serde_json::json!({
            "access_token": "totp_access_token_123",
            "expires_in": 3600,
            "token_type": "Bearer",
            "refresh_token": "totp_refresh_token_123",
            "key": "2.enc_key_wire_format=="
        });

        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&token_resp))
            .mount(&server)
            .await;

        let client =
            AuthenticatedClient::from_token(server.uri(), server.uri(), LoginToken::default());

        let token = complete_totp(
            &client,
            "user@example.com",
            "master_hash",
            "2fa_challenge_token",
            "123456",
            "device_uuid_xyz",
        )
        .await
        .expect("complete_totp should succeed");

        assert_eq!(token.access_token, "totp_access_token_123");
        assert_eq!(token.key, "2.enc_key_wire_format==");
        assert_eq!(
            client.token().lock().await.access_token,
            "totp_access_token_123"
        );
    }

    #[tokio::test]
    async fn test_complete_email_success() {
        let server = MockServer::start().await;

        let token_resp = serde_json::json!({
            "access_token": "email_access_token_456",
            "expires_in": 3600,
            "token_type": "Bearer",
            "refresh_token": "email_refresh_token_456",
            "key": "2.enc_key_wire_format=="
        });

        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&token_resp))
            .mount(&server)
            .await;

        let client =
            AuthenticatedClient::from_token(server.uri(), server.uri(), LoginToken::default());

        let token = complete_email(
            &client,
            "user@example.com",
            "master_hash",
            "2fa_challenge_token",
            "987654",
            "device_uuid_xyz",
        )
        .await
        .expect("complete_email should succeed");

        assert_eq!(token.access_token, "email_access_token_456");
        assert_eq!(
            client.token().lock().await.access_token,
            "email_access_token_456"
        );
    }

    #[tokio::test]
    async fn test_complete_email_send_step() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/two-factor/send-email-login"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let client =
            AuthenticatedClient::from_token(server.uri(), server.uri(), LoginToken::default());

        let send_res = send_two_factor_email_login(&client, "user@example.com", "device-123").await;
        assert!(send_res.is_ok());

        // Test error status
        let server_err = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/two-factor/send-email-login"))
            .respond_with(ResponseTemplate::new(400).set_body_string("rate limited"))
            .mount(&server_err)
            .await;

        let client_err = AuthenticatedClient::from_token(
            server_err.uri(),
            server_err.uri(),
            LoginToken::default(),
        );

        let err_res =
            send_two_factor_email_login(&client_err, "user@example.com", "device-123").await;
        match err_res {
            Err(ApiError::Status { status, message }) => {
                assert_eq!(status, reqwest::StatusCode::BAD_REQUEST);
                assert_eq!(message, "rate limited");
            }
            other => panic!("Expected ApiError::Status, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_complete_fido2_not_implemented() {
        let client = AuthenticatedClient::from_token(
            "https://identity.bitwarden.com",
            "https://api.bitwarden.com",
            LoginToken::default(),
        );

        let res = complete_fido2(&client, "user@example.com", "hash", "tok", "dev").await;
        match res {
            Err(ApiError::NotImplemented(msg)) => {
                assert!(msg.contains("FIDO2 requires hardware"));
            }
            other => panic!("Expected ApiError::NotImplemented, got {other:?}"),
        }
    }

    #[test]
    fn test_two_factor_providers_parsing() {
        // Standard array
        let body1 = r#"{"TwoFactorProviders":[0,1,5],"TwoFactorToken":"tok_abc"}"#;
        let (p1, t1) = parse_two_factor_error(body1).unwrap();
        assert_eq!(p1, vec![0, 1, 5]);
        assert_eq!(t1, "tok_abc");

        // CamelCase array
        let body2 = r#"{"twoFactorProviders":[1,7],"twoFactorToken":"tok_xyz"}"#;
        let (p2, t2) = parse_two_factor_error(body2).unwrap();
        assert_eq!(p2, vec![1, 7]);
        assert_eq!(t2, "tok_xyz");

        // Dictionary map TwoFactorProviders2
        let body3 = r#"{"TwoFactorProviders2":{"0":{"name":"authenticator"},"1":{}},"TwoFactorToken":"tok_map"}"#;
        let (p3, t3) = parse_two_factor_error(body3).unwrap();
        assert_eq!(p3, vec![0, 1]);
        assert_eq!(t3, "tok_map");

        // Provider enum conversions
        assert_eq!(
            TwoFactorProvider::from_i32(0),
            Some(TwoFactorProvider::Authenticator)
        );
        assert_eq!(
            TwoFactorProvider::from_i32(1),
            Some(TwoFactorProvider::Email)
        );
        assert_eq!(
            TwoFactorProvider::from_i32(7),
            Some(TwoFactorProvider::WebAuthn)
        );
        assert_eq!(TwoFactorProvider::from_i32(99), None);
        assert_eq!(TwoFactorProvider::Authenticator.to_i32(), 0);

        // Missing fields or no TwoFactor
        assert!(parse_two_factor_error(r#"{"error":"invalid_grant"}"#).is_none());
        assert!(parse_two_factor_error(r#"{"TwoFactorProviders":[0]}"#).is_none());
        assert!(parse_two_factor_error("not json").is_none());
    }

    #[tokio::test]
    async fn test_login_full_orchestration_two_factor() {
        let server = MockServer::start().await;

        // 1. Prelogin
        let prelogin_resp = serde_json::json!({
            "kdf": 0,
            "kdfIterations": 100000
        });
        Mock::given(method("POST"))
            .and(path("/accounts/prelogin"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&prelogin_resp))
            .mount(&server)
            .await;

        // 2. First /connect/token -> 401 TwoFactor challenge
        let challenge_body = serde_json::json!({
            "TwoFactorProviders": [0, 1],
            "TwoFactorToken": "challenge_token_step1"
        });
        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(ResponseTemplate::new(401).set_body_json(&challenge_body))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // 3. Second /connect/token -> 200 with LoginToken
        let token_resp = serde_json::json!({
            "access_token": "orchestration_2fa_token",
            "expires_in": 3600,
            "token_type": "Bearer",
            "refresh_token": "orchestration_2fa_refresh",
            "key": "2.enc_key_wire_format=="
        });
        Mock::given(method("POST"))
            .and(path("/connect/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&token_resp))
            .mount(&server)
            .await;

        let client =
            AuthenticatedClient::from_token(server.uri(), server.uri(), LoginToken::default());

        let email = "user@example.com";
        let password = "SuperSecretPassword123!";
        let device_uuid = "device-uuid-test";

        let kdf_config = client.prelogin(email).await.unwrap();
        let master_key =
            sw_crypto::derive_master_key(password.as_bytes(), email, &kdf_config).unwrap();
        let master_password_hash = derive_master_password_hash(master_key.as_slice(), password);

        // First login attempt triggers 2FA challenge
        let initial_res = client
            .login_with_password(email, &master_password_hash, device_uuid)
            .await;

        let (providers, token) = match initial_res {
            Err(ApiError::TwoFactorRequired { providers, token }) => (providers, token),
            other => panic!("Expected TwoFactorRequired, got {other:?}"),
        };

        assert!(providers.contains(&0));

        // Complete 2FA via complete_totp
        let final_token = complete_totp(
            &client,
            email,
            &master_password_hash,
            &token,
            "123456",
            device_uuid,
        )
        .await
        .expect("complete_totp should succeed");

        assert_eq!(final_token.access_token, "orchestration_2fa_token");
        assert_eq!(final_token.key, "2.enc_key_wire_format==");
    }
}
