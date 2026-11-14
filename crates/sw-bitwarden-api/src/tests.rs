use super::*;
use base64::Engine;
use reqwest::Method;
use std::str::FromStr;
use std::sync::Arc;
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
        ..Default::default()
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
        ..Default::default()
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
        ..Default::default()
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
        .and(path("/accounts/prelogin"))
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

    let client = AuthenticatedClient::from_token(server.uri(), server.uri(), LoginToken::default());
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
    let user_key_plaintext = b"super_secret_64_byte_account_symmetric_key_payload_for_testing!!";
    let enc_key_wire = sw_crypto::encrypt_with_to_string(
        user_key_plaintext,
        sw_crypto::EncStringType::AesCbc256HmacSha256B64,
        &sym_key,
    )
    .expect("Synthetic encryption should succeed");

    assert!(enc_key_wire.starts_with("2."));

    let decrypted =
        decrypt_enc_key(&enc_key_wire, &stretched_key_bytes).expect("Decryption should succeed");
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

    let client = AuthenticatedClient::from_token(server.uri(), server.uri(), LoginToken::default());

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

    let client = AuthenticatedClient::from_token(server.uri(), server.uri(), LoginToken::default());

    let res = client
        .login_with_password("user@example.com", "bad_hash", "device-uuid-123")
        .await;

    assert!(matches!(res, Err(ApiError::Auth(_))));
}

#[tokio::test]
async fn test_login_with_password_error_429() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/connect/token"))
        .respond_with(ResponseTemplate::new(429).set_body_string("Rate limit exceeded"))
        .mount(&server)
        .await;

    let client = AuthenticatedClient::from_token(server.uri(), server.uri(), LoginToken::default());

    let res = client
        .login_with_password("user@example.com", "any_hash", "device-uuid-123")
        .await;

    match res {
        Err(ApiError::RateLimitExceeded) => {}
        other => panic!("Expected ApiError::RateLimitExceeded, got {:?}", other),
    }
}

#[tokio::test]
async fn test_login_with_password_error_401() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/connect/token"))
        .respond_with(ResponseTemplate::new(401).set_body_string("Unauthorized"))
        .mount(&server)
        .await;

    let client = AuthenticatedClient::from_token(server.uri(), server.uri(), LoginToken::default());

    let res = client
        .login_with_password("user@example.com", "bad_hash", "device-uuid-123")
        .await;

    match res {
        Err(ApiError::InvalidCredentials) => {}
        other => panic!("Expected ApiError::InvalidCredentials, got {:?}", other),
    }
}

#[tokio::test]
async fn test_login_full_orchestration_success() {
    let server = MockServer::start().await;

    let email = "user@example.com";
    let password = "MyMasterPassword123!";
    let device_uuid = "device-555";

    // Step 1: Prelogin mock
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

    // Compute expected master key and stretched key
    let kdf_config = sw_crypto::KdfConfig {
        kdf_type: sw_crypto::KdfType::Pbkdf2,
        iterations: 100000,
        memory: None,
        parallelism: None,
    };
    let master_key = sw_crypto::derive_master_key(password.as_bytes(), email, &kdf_config).unwrap();
    let expected_master_hash = derive_master_password_hash(master_key.as_slice(), password);
    let stretched_key = sw_crypto::stretch_key(&master_key).unwrap();

    // Synthetic 64-byte account symmetric key
    let expected_user_sym_key = b"0123456789012345678901234567890101234567890123456789012345678901";
    let enc_key_wire = sw_crypto::encrypt_with_to_string(
        expected_user_sym_key,
        sw_crypto::EncStringType::AesCbc256HmacSha256B64,
        &stretched_key,
    )
    .unwrap();

    let encoded_password_param =
        url::form_urlencoded::byte_serialize(expected_master_hash.as_bytes()).collect::<String>();
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

    let client = AuthenticatedClient::from_token(server.uri(), server.uri(), LoginToken::default());

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
        .and(path("/accounts/prelogin"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal error"))
        .mount(&server)
        .await;

    let client = AuthenticatedClient::from_token(server.uri(), server.uri(), LoginToken::default());

    let res = client
        .login("user@example.com", "pass", "device-uuid")
        .await;

    assert!(matches!(res, Err(ApiError::Status { .. })));
}

#[tokio::test]
async fn test_prelogin_builds_url_using_identity_url() {
    let server = MockServer::start().await;

    let custom_identity = format!("{}/custom_identity/mount", server.uri());
    let dummy_api = format!("{}/dummy_api", server.uri());

    // /custom_identity/mount/accounts/prelogin returns 200
    Mock::given(method("POST"))
        .and(path("/custom_identity/mount/accounts/prelogin"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "kdf": 0,
            "kdfIterations": 100000,
            "kdfMemory": null,
            "kdfParallelism": null
        })))
        .mount(&server)
        .await;

    let client =
        AuthenticatedClient::from_token(&custom_identity, &dummy_api, LoginToken::default());

    let kdf_config = client.prelogin("user@example.com").await.unwrap();
    assert_eq!(kdf_config.kdf_type, sw_crypto::KdfType::Pbkdf2);
    assert_eq!(kdf_config.iterations, 100000);
}

#[tokio::test]
async fn test_login_missing_key_returns_auth_error() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/accounts/prelogin"))
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

    let client = AuthenticatedClient::from_token(server.uri(), server.uri(), LoginToken::default());

    let res = client
        .login("user@example.com", "pass", "device-uuid")
        .await;

    assert!(matches!(res, Err(ApiError::Auth(_))));
}

#[tokio::test]
async fn test_standalone_functions() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/accounts/prelogin"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "kdf": 0,
            "kdfIterations": 5000
        })))
        .mount(&server)
        .await;

    let client = AuthenticatedClient::from_token(server.uri(), server.uri(), LoginToken::default());

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

    let client = AuthenticatedClient::from_token(server.uri(), server.uri(), LoginToken::default());
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
        token.clone(),
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

    // Self-hosted / Vaultwarden style: base ends with /api
    let self_hosted = AuthenticatedClient::from_token(
        "http://localhost:8080/identity",
        "http://localhost:8080/api",
        token,
    );
    assert_eq!(
        self_hosted.resolve_api_url("/sync"),
        "http://localhost:8080/api/sync"
    );
    assert_eq!(
        self_hosted.resolve_api_url("/api/sync"),
        "http://localhost:8080/api/sync"
    );
    assert_eq!(
        self_hosted.resolve_api_url("api/sync"),
        "http://localhost:8080/api/sync"
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
    let master_key = sw_crypto::derive_master_key(TEST_PASSWORD.as_bytes(), TEST_EMAIL, &config)
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
    let master_key = sw_crypto::derive_master_key(TEST_PASSWORD.as_bytes(), TEST_EMAIL, &config)
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
    let master_key = sw_crypto::derive_master_key(TEST_PASSWORD.as_bytes(), TEST_EMAIL, &config)
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
    let master_key = sw_crypto::derive_master_key(TEST_PASSWORD.as_bytes(), TEST_EMAIL, &config)
        .expect("Master key derivation should succeed");
    let stretched_key =
        sw_crypto::stretch_key(&master_key).expect("Stretch key derivation should succeed");

    // Verify with decrypt_enc_key
    let decrypted = decrypt_enc_key(EXPECTED_ENC_KEY, &stretched_key.bytes())
        .expect("Decryption of enc_key should succeed");
    assert_eq!(hex_encode(&decrypted), EXPECTED_USER_SYMMETRIC_KEY_HEX);

    // Verify directly with sw_crypto::EncString and decrypt_with
    let enc_string =
        sw_crypto::EncString::from_str(EXPECTED_ENC_KEY).expect("EncString parsing should succeed");
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
        .and(path("/accounts/prelogin"))
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

    let client = AuthenticatedClient::from_token(server.uri(), server.uri(), LoginToken::default());

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

#[tokio::test]
async fn test_sync_success() {
    let server = MockServer::start().await;

    let valid_enc = "2.aXZfMTZfYnl0ZXNfbG9uZw==|Y2lwaGVydGV4dF9ieXRlcw==|bWFjXzMyX2J5dGVzX2xvbmdfaGFzaF9zdHJpbmchIQ==";

    let sample_sync_json = serde_json::json!({
        "profile": {
            "id": "11111111-1111-1111-1111-111111111111",
            "name": "Test User",
            "email": "user@example.com"
        },
        "folders": [
            {
                "id": "22222222-2222-2222-2222-222222222222",
                "name": "Personal"
            }
        ],
        "ciphers": [
            {
                "id": "33333333-3333-3333-3333-333333333333",
                "type": 1,
                "name": valid_enc,
                "notes": null,
                "login": {
                    "username": valid_enc,
                    "password": valid_enc
                }
            }
        ]
    });

    Mock::given(method("GET"))
        .and(path("/sync"))
        .and(header("Authorization", "Bearer sync_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_sync_json))
        .mount(&server)
        .await;

    let token = LoginToken {
        access_token: "sync_token".to_string(),
        ..LoginToken::default()
    };
    let client = AuthenticatedClient::from_token(server.uri(), server.uri(), token);

    let sync_data = client.sync().await.expect("Sync should succeed");
    assert_eq!(sync_data.profile.email.as_deref(), Some("user@example.com"));
    assert_eq!(sync_data.folders.len(), 1);
    assert_eq!(sync_data.ciphers.len(), 1);
    assert_eq!(sync_data.ciphers[0].r#type, sw_vault::CipherType::Login);
}

#[tokio::test]
async fn test_sync_sends_modern_client_version_header() {
    let server = MockServer::start().await;

    let sample_sync_json = serde_json::json!({
        "profile": {
            "id": "11111111-1111-1111-1111-111111111111",
            "name": "Test User",
            "email": "user@example.com"
        },
        "folders": [],
        "ciphers": []
    });

    Mock::given(method("GET"))
        .and(path("/sync"))
        .and(header("Authorization", "Bearer sync_token"))
        .and(header("Bitwarden-Client-Version", "2024.12.0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_sync_json))
        .mount(&server)
        .await;

    let token = LoginToken {
        access_token: "sync_token".to_string(),
        ..LoginToken::default()
    };

    let client = AuthenticatedClient::from_token(server.uri(), server.uri(), token);
    let res = client.sync().await;
    assert!(
        res.is_ok(),
        "Sync must send Bitwarden-Client-Version: 2024.12.0 and succeed"
    );
}

#[tokio::test]
async fn test_sync_error_status() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/sync"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal error"))
        .mount(&server)
        .await;

    let client = AuthenticatedClient::from_token(server.uri(), server.uri(), LoginToken::default());
    let err = client.sync().await.unwrap_err();
    match err {
        ApiError::Status { status, message } => {
            assert_eq!(status, reqwest::StatusCode::INTERNAL_SERVER_ERROR);
            assert_eq!(message, "Internal error");
        }
        other => panic!("Expected Status error, got {other:?}"),
    }
}

#[tokio::test]
async fn test_sync_fallback_to_api_sync() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/sync"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/sync"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "profile": { "email": "fallback@example.com" },
            "folders": [],
            "ciphers": []
        })))
        .mount(&server)
        .await;

    let client = AuthenticatedClient::from_token(server.uri(), server.uri(), LoginToken::default());
    let sync_data = client.sync().await.expect("Sync fallback should succeed");
    assert_eq!(
        sync_data.profile.email.as_deref(),
        Some("fallback@example.com")
    );
}

#[tokio::test]
async fn test_do_full_sync_wiremock_cache_and_memory() {
    let server = MockServer::start().await;
    let valid_enc = "2.aXZfMTZfYnl0ZXNfbG9uZw==|Y2lwaGVydGV4dF9ieXRlcw==|bWFjXzMyX2J5dGVzX2xvbmdfaGFzaF9zdHJpbmchIQ==";

    let sample_sync_json = serde_json::json!({
        "profile": {
            "id": "11111111-1111-1111-1111-111111111111",
            "name": "Synced User",
            "email": "synced@example.com"
        },
        "folders": [
            {
                "id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                "name": "Folder 1"
            }
        ],
        "ciphers": [
            {
                "id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
                "type": 1,
                "name": valid_enc,
                "login": {
                    "username": valid_enc,
                    "password": valid_enc
                }
            },
            {
                "id": "cccccccc-cccc-cccc-cccc-cccccccccccc",
                "type": 5,
                "name": valid_enc,
                "sshKey": {
                    "publicKey": valid_enc
                }
            }
        ]
    });

    Mock::given(method("GET"))
        .and(path("/sync"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_sync_json))
        .mount(&server)
        .await;

    let temp_dir = tempfile::tempdir().expect("tempdir failed");
    let vault_paths = sw_vault::VaultPaths::new(temp_dir.path().join("silverwarden_cache"));
    let vault_store = sw_vault::VaultStore::new();

    let client = AuthenticatedClient::from_token(server.uri(), server.uri(), LoginToken::default());

    let sym_key = sw_crypto::SymmetricKey::from_parts(&[42u8; 32], &[43u8; 32]).unwrap();
    let sync_result = client
        .do_full_sync(&vault_paths, &vault_store, Some(&sym_key))
        .await
        .expect("do_full_sync should succeed");

    assert_eq!(sync_result.ciphers.len(), 2);

    // 1. Check file exists on disk
    let vault_file = vault_paths.vault_file();
    assert!(vault_file.exists());

    // 2. Check 0600 permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(&vault_file).expect("metadata failed");
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "Cache file must have 0600 permissions");
    }

    // 3. Check load_vault roundtrip from disk
    let loaded_from_disk = sw_vault::load_vault(&vault_file).expect("load_vault failed");
    assert_eq!(loaded_from_disk, sync_result);

    // 4. Check memory store populated
    assert_eq!(vault_store.len().await, 2);
    let id1 = uuid::Uuid::parse_str("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb").unwrap();
    let cipher1 = vault_store
        .get(&id1)
        .await
        .expect("cipher1 should be in store");
    assert_eq!(cipher1.r#type, sw_vault::CipherType::Login);

    let id2 = uuid::Uuid::parse_str("cccccccc-cccc-cccc-cccc-cccccccccccc").unwrap();
    let cipher2 = vault_store
        .get(&id2)
        .await
        .expect("cipher2 should be in store");
    assert_eq!(cipher2.r#type, sw_vault::CipherType::SshKey);

    let profile = vault_store.profile().await;
    assert_eq!(
        profile.unwrap().email.as_deref(),
        Some("synced@example.com")
    );

    let folders = vault_store.folders().await;
    assert_eq!(folders.len(), 1);

    assert!(vault_store.last_synced().await.is_some());
}

#[tokio::test]
async fn test_standalone_sync_and_do_full_sync() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/sync"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "profile": { "email": "standalone@example.com" },
            "folders": [],
            "ciphers": []
        })))
        .mount(&server)
        .await;

    let temp_dir = tempfile::tempdir().expect("tempdir failed");
    let vault_paths = sw_vault::VaultPaths::new(temp_dir.path().join("cache"));
    let vault_store = sw_vault::VaultStore::new();

    let client = AuthenticatedClient::from_token(server.uri(), server.uri(), LoginToken::default());

    // Test standalone sync
    let s1 = sync(&client).await.expect("sync standalone should succeed");
    assert_eq!(s1.profile.email.as_deref(), Some("standalone@example.com"));

    // Test standalone do_full_sync
    let s2 = do_full_sync(&client, &vault_paths, &vault_store, None)
        .await
        .expect("do_full_sync standalone should succeed");
    assert_eq!(s2.profile.email.as_deref(), Some("standalone@example.com"));
    assert!(vault_paths.vault_file().exists());
    assert!(vault_store.last_synced().await.is_some());
}

#[tokio::test]
async fn test_get_cipher_mock() {
    let server = MockServer::start().await;
    let test_id = uuid::Uuid::new_v4();

    let valid_enc = "2.aXZfMTZfYnl0ZXNfbG9uZw==|Y2lwaGVydGV4dF9ieXRlcw==|bWFjXzMyX2J5dGVzX2xvbmdfaGFzaF9zdHJpbmchIQ==";

    Mock::given(method("GET"))
        .and(path(format!("/ciphers/{test_id}")))
        .and(header("Authorization", "Bearer cipher_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": test_id.to_string(),
            "type": 1,
            "name": valid_enc,
            "login": {
                "username": valid_enc,
                "password": valid_enc
            }
        })))
        .mount(&server)
        .await;

    let token = LoginToken {
        access_token: "cipher_token".to_string(),
        ..LoginToken::default()
    };
    let client = AuthenticatedClient::from_token(server.uri(), server.uri(), token);

    let cipher = get_cipher(&client, &test_id)
        .await
        .expect("get_cipher should succeed");
    assert_eq!(cipher.id, Some(test_id));
    assert_eq!(cipher.r#type, sw_vault::CipherType::Login);
    assert!(cipher.login.is_some());

    // Also test method on client
    let cipher_method = client
        .get_cipher(&test_id)
        .await
        .expect("client.get_cipher should succeed");
    assert_eq!(cipher_method.id, Some(test_id));
}

#[tokio::test]
async fn test_post_cipher_mock() {
    let server = MockServer::start().await;
    let created_id = uuid::Uuid::new_v4();
    let valid_enc = "2.aXZfMTZfYnl0ZXNfbG9uZw==|Y2lwaGVydGV4dF9ieXRlcw==|bWFjXzMyX2J5dGVzX2xvbmdfaGFzaF9zdHJpbmchIQ==";

    Mock::given(method("POST"))
        .and(path("/ciphers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": created_id.to_string(),
            "type": 1,
            "name": valid_enc
        })))
        .mount(&server)
        .await;

    let client = AuthenticatedClient::from_token(server.uri(), server.uri(), LoginToken::default());
    let to_create = sw_vault::Cipher {
        r#type: sw_vault::CipherType::Login,
        ..Default::default()
    };

    let result = post_cipher(&client, &to_create)
        .await
        .expect("post_cipher should succeed");
    assert_eq!(result.id, Some(created_id));

    // Also test method on client
    let result_method = client
        .post_cipher(&to_create)
        .await
        .expect("client.post_cipher should succeed");
    assert_eq!(result_method.id, Some(created_id));
}

#[tokio::test]
async fn test_put_cipher_mock() {
    let server = MockServer::start().await;
    let test_id = uuid::Uuid::new_v4();
    let valid_enc = "2.aXZfMTZfYnl0ZXNfbG9uZw==|Y2lwaGVydGV4dF9ieXRlcw==|bWFjXzMyX2J5dGVzX2xvbmdfaGFzaF9zdHJpbmchIQ==";

    Mock::given(method("PUT"))
        .and(path(format!("/ciphers/{test_id}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": test_id.to_string(),
            "type": 2,
            "name": valid_enc
        })))
        .mount(&server)
        .await;

    let client = AuthenticatedClient::from_token(server.uri(), server.uri(), LoginToken::default());
    let to_update = sw_vault::Cipher {
        id: Some(test_id),
        r#type: sw_vault::CipherType::Note,
        ..Default::default()
    };

    let result = put_cipher(&client, &test_id, &to_update)
        .await
        .expect("put_cipher should succeed");
    assert_eq!(result.id, Some(test_id));
    assert_eq!(result.r#type, sw_vault::CipherType::Note);

    // Also test method on client
    let result_method = client
        .put_cipher(&test_id, &to_update)
        .await
        .expect("client.put_cipher should succeed");
    assert_eq!(result_method.id, Some(test_id));
}

#[tokio::test]
async fn test_delete_cipher_mock() {
    let server = MockServer::start().await;
    let test_id = uuid::Uuid::new_v4();

    Mock::given(method("DELETE"))
        .and(path(format!("/ciphers/{test_id}")))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let client = AuthenticatedClient::from_token(server.uri(), server.uri(), LoginToken::default());
    delete_cipher(&client, &test_id)
        .await
        .expect("delete_cipher should succeed");

    // Also test method on client
    client
        .delete_cipher(&test_id)
        .await
        .expect("client.delete_cipher should succeed");
}

#[tokio::test]
async fn test_cipher_404_error() {
    let server = MockServer::start().await;
    let test_id = uuid::Uuid::new_v4();

    Mock::given(method("GET"))
        .and(path(format!("/ciphers/{test_id}")))
        .respond_with(ResponseTemplate::new(404).set_body_string("Cipher not found"))
        .mount(&server)
        .await;

    let client = AuthenticatedClient::from_token(server.uri(), server.uri(), LoginToken::default());
    let err = get_cipher(&client, &test_id).await.unwrap_err();
    match err {
        ApiError::Status { status, message } => {
            assert_eq!(status, reqwest::StatusCode::NOT_FOUND);
            assert_eq!(message, "Cipher not found");
        }
        other => panic!("Expected ApiError::Status, got {other:?}"),
    }
}

#[tokio::test]
async fn test_cipher_api_fallback_mock() {
    let server = MockServer::start().await;
    let test_id = uuid::Uuid::new_v4();

    // 404 on /ciphers/... but 200 on /api/ciphers/...
    Mock::given(method("GET"))
        .and(path(format!("/ciphers/{test_id}")))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let cipher_payload = serde_json::json!({
        "id": test_id.to_string(),
        "type": 1,
        "name": "2.aXZfMTZfYnl0ZXNfbG9uZw==|Y2lwaGVydGV4dF9ieXRlcw==|bWFjXzMyX2J5dGVzX2xvbmdfaGFzaF9zdHJpbmchIQ=="
    });

    Mock::given(method("GET"))
        .and(path(format!("/api/ciphers/{test_id}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(&cipher_payload))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/ciphers"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/api/ciphers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&cipher_payload))
        .mount(&server)
        .await;

    Mock::given(method("PUT"))
        .and(path(format!("/ciphers/{test_id}")))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    Mock::given(method("PUT"))
        .and(path(format!("/api/ciphers/{test_id}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(&cipher_payload))
        .mount(&server)
        .await;

    Mock::given(method("DELETE"))
        .and(path(format!("/ciphers/{test_id}")))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    Mock::given(method("DELETE"))
        .and(path(format!("/api/ciphers/{test_id}")))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let client = AuthenticatedClient::from_token(server.uri(), server.uri(), LoginToken::default());

    let cipher = get_cipher(&client, &test_id).await.unwrap();
    assert_eq!(cipher.id, Some(test_id));

    let created = post_cipher(&client, &cipher).await.unwrap();
    assert_eq!(created.id, Some(test_id));

    let updated = put_cipher(&client, &test_id, &cipher).await.unwrap();
    assert_eq!(updated.id, Some(test_id));

    delete_cipher(&client, &test_id).await.unwrap();
}

#[tokio::test]
async fn test_danger_accept_invalid_certs() {
    use rustls_pki_types::{CertificateDer, PrivateKeyDer};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let _ = rustls::crypto::ring::default_provider().install_default();

    let cert_bytes = include_bytes!("../tests/fixtures/test_cert.der");
    let key_bytes = include_bytes!("../tests/fixtures/test_key.der");

    let cert_der = CertificateDer::from(cert_bytes.as_slice());
    let key_der = PrivateKeyDer::try_from(key_bytes.as_slice()).unwrap();

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut tls_stream) = acceptor.accept(stream).await {
                    let mut buf = [0u8; 1024];
                    let _ = tls_stream.read(&mut buf).await;
                    let response = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 15\r\nConnection: close\r\n\r\n{\"status\":\"ok\"}";
                    let _ = tls_stream.write_all(response).await;
                    let _ = tls_stream.flush().await;
                }
            });
        }
    });

    let target_url = format!("https://localhost:{port}/api/accounts/prelogin");

    // 1. Without flag (danger_accept_invalid_certs = false): Must reject invalid certificate
    let client_secure = AuthenticatedClient::from_token_with_options(
        &target_url,
        &target_url,
        LoginToken::default(),
        false,
    );
    let secure_res = client_secure.http_client().get(&target_url).send().await;
    assert!(
        secure_res.is_err(),
        "Default client should reject self-signed/invalid certificate"
    );

    // 2. With flag (danger_accept_invalid_certs = true): Must accept certificate
    let client_insecure = AuthenticatedClient::from_token_with_options(
        &target_url,
        &target_url,
        LoginToken::default(),
        true,
    );
    let insecure_res = client_insecure.http_client().get(&target_url).send().await;
    assert!(
        insecure_res.is_ok(),
        "Client with danger_accept_invalid_certs=true should accept self-signed certificate: {:?}",
        insecure_res.err()
    );
    let resp = insecure_res.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
}

#[tokio::test]
async fn test_login_with_api_key_success() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/connect/token"))
        .and(body_string_contains("grant_type=client_credentials"))
        .and(body_string_contains("client_id=user.test-client-id"))
        .and(body_string_contains("client_secret=test-client-secret"))
        .and(body_string_contains("scope=api"))
        .and(body_string_contains("deviceType=10"))
        .and(body_string_contains("deviceIdentifier=test-device-uuid"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "api_key_access_token_123",
            "expires_in": 3600,
            "token_type": "Bearer",
            "refresh_token": "api_key_refresh_token_456",
            "Key": "sample_enc_key"
        })))
        .mount(&server)
        .await;

    let client = AuthenticatedClient::from_token(server.uri(), server.uri(), LoginToken::default());

    let token = client
        .login_with_api_key(
            "user.test-client-id",
            "test-client-secret",
            "test-device-uuid",
        )
        .await
        .expect("login_with_api_key should succeed");

    assert_eq!(token.access_token, "api_key_access_token_123");
    assert_eq!(token.expires_in, 3600);
    assert_eq!(token.token_type, "Bearer");
    assert_eq!(token.key, "sample_enc_key");
    assert_eq!(
        client.token().lock().await.access_token,
        "api_key_access_token_123"
    );
}

#[tokio::test]
async fn test_login_with_api_key_error() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/connect/token"))
        .respond_with(ResponseTemplate::new(400).set_body_string("{\"error\":\"invalid_client\"}"))
        .mount(&server)
        .await;

    let client = AuthenticatedClient::from_token(server.uri(), server.uri(), LoginToken::default());

    let res = client
        .login_with_api_key("bad_id", "bad_secret", "uuid")
        .await;
    assert!(res.is_err());
    let err = res.unwrap_err().to_string();
    assert!(err.contains("invalid_client"));
}

#[tokio::test]
async fn test_login_api_key_orchestration_success() {
    let server = MockServer::start().await;
    let email = "user@example.com";
    let password = "masterpassword123";
    let device_uuid = "device-1234";

    let kdf_config = sw_crypto::KdfConfig {
        kdf_type: sw_crypto::KdfType::Pbkdf2,
        iterations: 600_000,
        memory: None,
        parallelism: None,
    };
    let master_key =
        sw_crypto::derive_master_key(password.as_bytes(), email, &kdf_config).expect("master key");
    let stretched = sw_crypto::stretch_key(&master_key).expect("stretched");

    let raw_user_sym_key = [77u8; 64];
    let enc_key = sw_vault::encrypt_with(
        &raw_user_sym_key,
        sw_vault::EncStringType::AesCbc256HmacSha256B64,
        &stretched,
    )
    .expect("encrypted enc_key")
    .to_string_repr()
    .expect("repr");

    Mock::given(method("POST"))
        .and(path("/connect/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "mock_api_token",
            "expires_in": 3600,
            "token_type": "Bearer",
            "refresh_token": "mock_api_refresh",
            "Key": enc_key
        })))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/accounts/prelogin"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "kdf": 0,
            "kdfIterations": 600000
        })))
        .mount(&server)
        .await;

    let client = AuthenticatedClient::from_token(server.uri(), server.uri(), LoginToken::default());

    let (token, user_sym_key) = client
        .login_api_key("client_id", "client_secret", email, password, device_uuid)
        .await
        .expect("login_api_key orchestration should succeed");

    assert_eq!(token.access_token, "mock_api_token");
    assert_eq!(user_sym_key, raw_user_sym_key);
}

// ---------------------------------------------------------------------------
// Tests de caracterización (orden 2.2.4)
//
// Congelan el contrato observable antes del split de `sw-bitwarden-api`:
// mensajes de error, JSON de `PreloginResponse`, parseo de 2FA y constantes.
// ---------------------------------------------------------------------------

#[test]
fn caracterizacion_api_error_display() {
    assert_eq!(
        ApiError::Auth("boom".to_string()).to_string(),
        "Authentication error: boom"
    );
    assert_eq!(
        ApiError::NotImplemented("fido2".to_string()).to_string(),
        "Not implemented: fido2"
    );
    assert_eq!(
        ApiError::TwoFactorRequired {
            providers: vec![0, 1],
            token: "tok".to_string(),
        }
        .to_string(),
        "Two-factor authentication required"
    );
    assert_eq!(
        ApiError::RateLimitExceeded.to_string(),
        "El servidor ha bloqueado temporalmente tu IP por demasiados intentos de login. Espera unos minutos o cambia de red (por ejemplo, usa datos móviles)."
    );
    assert_eq!(
        ApiError::InvalidCredentials.to_string(),
        "Credenciales inválidas. Comprueba tu correo y contraseña maestra."
    );
    assert_eq!(
        ApiError::Status {
            status: reqwest::StatusCode::NOT_FOUND,
            message: "no existe".to_string(),
        }
        .to_string(),
        "Server error (404 Not Found): no existe"
    );
}

#[test]
fn caracterizacion_prelogin_response_json() {
    let response = PreloginResponse {
        kdf: 0,
        kdf_iterations: Some(600_000),
        kdf_memory: None,
        kdf_parallelism: None,
    };
    assert_eq!(
        serde_json::to_value(&response).unwrap(),
        serde_json::json!({
            "kdf": 0,
            "kdfIterations": 600000,
            "kdfMemory": null,
            "kdfParallelism": null
        })
    );

    let parsed: PreloginResponse = serde_json::from_str(
        r#"{ "kdf": 1, "kdfIterations": 3, "kdfMemory": 64, "kdfParallelism": 4 }"#,
    )
    .unwrap();
    assert_eq!(parsed.kdf, 1);
    assert_eq!(parsed.kdf_memory, Some(64));
    assert_eq!(parsed.kdf_parallelism, Some(4));
}

#[test]
fn caracterizacion_prelogin_defaults_de_iteraciones() {
    // PBKDF2 sin `kdfIterations` → 100.000 por defecto.
    let pbkdf2: sw_crypto::KdfConfig = PreloginResponse {
        kdf: 0,
        kdf_iterations: None,
        kdf_memory: None,
        kdf_parallelism: None,
    }
    .try_into()
    .unwrap();
    assert_eq!(pbkdf2.kdf_type, sw_crypto::KdfType::Pbkdf2);
    assert_eq!(pbkdf2.iterations, 100_000);

    // Argon2id sin `kdfIterations` → 3 por defecto.
    let argon2: sw_crypto::KdfConfig = PreloginResponse {
        kdf: 1,
        kdf_iterations: None,
        kdf_memory: Some(64),
        kdf_parallelism: Some(4),
    }
    .try_into()
    .unwrap();
    assert_eq!(argon2.kdf_type, sw_crypto::KdfType::Argon2id);
    assert_eq!(argon2.iterations, 3);

    // KDF desconocido → `ApiError::Auth`.
    let unknown: Result<sw_crypto::KdfConfig, ApiError> = PreloginResponse {
        kdf: 9,
        kdf_iterations: None,
        kdf_memory: None,
        kdf_parallelism: None,
    }
    .try_into();
    assert!(matches!(unknown, Err(ApiError::Auth(_))));
}

#[test]
fn caracterizacion_parse_two_factor_error() {
    // Array numérico.
    assert_eq!(
        parse_two_factor_error(r#"{ "TwoFactorProviders": [1, 0], "TwoFactorToken": "abc" }"#),
        Some((vec![0, 1], "abc".to_string()))
    );

    // Array de cadenas.
    assert_eq!(
        parse_two_factor_error(r#"{ "twoFactorProviders": ["2", "0"], "twoFactorToken": "tok" }"#),
        Some((vec![0, 2], "tok".to_string()))
    );

    // Mapa `TwoFactorProviders2`.
    assert_eq!(
        parse_two_factor_error(r#"{ "TwoFactorProviders2": { "7": {}, "0": {} } }"#),
        Some((vec![0, 7], String::new()))
    );

    // `authRequest` como token (requiere un mapa de proveedores).
    assert_eq!(
        parse_two_factor_error(r#"{ "TwoFactorProviders2": { "0": {} }, "authRequest": "req-1" }"#),
        Some((vec![0], "req-1".to_string()))
    );

    // Menciona 2FA pero no hay proveedores → None.
    assert_eq!(
        parse_two_factor_error(r#"{ "TwoFactor": true, "authRequest": "req-1" }"#),
        None
    );

    // Sin mención de 2FA → None.
    assert_eq!(parse_two_factor_error(r#"{ "error": "nope" }"#), None);

    // Menciona 2FA pero el JSON es inválido → None.
    assert_eq!(parse_two_factor_error("TwoFactor"), None);
}

#[test]
fn caracterizacion_two_factor_provider_mapping() {
    assert_eq!(
        TwoFactorProvider::from_i32(0),
        Some(TwoFactorProvider::Authenticator)
    );
    assert_eq!(
        TwoFactorProvider::from_i32(1),
        Some(TwoFactorProvider::Email)
    );
    assert_eq!(TwoFactorProvider::from_i32(2), Some(TwoFactorProvider::Duo));
    assert_eq!(
        TwoFactorProvider::from_i32(3),
        Some(TwoFactorProvider::YubiKey)
    );
    assert_eq!(TwoFactorProvider::from_i32(4), Some(TwoFactorProvider::U2f));
    assert_eq!(
        TwoFactorProvider::from_i32(5),
        Some(TwoFactorProvider::Remember)
    );
    assert_eq!(
        TwoFactorProvider::from_i32(6),
        Some(TwoFactorProvider::OrganizationDuo)
    );
    assert_eq!(
        TwoFactorProvider::from_i32(7),
        Some(TwoFactorProvider::WebAuthn)
    );
    assert_eq!(TwoFactorProvider::from_i32(8), None);
    assert_eq!(TwoFactorProvider::WebAuthn.to_i32(), 7);
}

#[test]
fn caracterizacion_constantes_de_cliente() {
    assert_eq!(BITWARDEN_USER_AGENT, "silverwarden/0.0.1");
    assert_eq!(BITWARDEN_DEVICE_TYPE, "10");
    assert_eq!(BITWARDEN_CLIENT_NAME, "silverwarden");
    assert_eq!(BITWARDEN_CLIENT_VERSION, "2024.12.0");
}

#[test]
fn caracterizacion_request_body_constructors() {
    assert!(matches!(RequestBody::empty(), RequestBody::Empty));

    match RequestBody::json(serde_json::json!({ "a": 1 })) {
        RequestBody::Json(v) => assert_eq!(v, serde_json::json!({ "a": 1 })),
        other => panic!("se esperaba Json, llegó {other:?}"),
    }

    match RequestBody::form([("a", "1"), ("b", "2")]) {
        RequestBody::Form(pairs) => assert_eq!(
            pairs,
            vec![
                ("a".to_string(), "1".to_string()),
                ("b".to_string(), "2".to_string())
            ]
        ),
        other => panic!("se esperaba Form, llegó {other:?}"),
    }
}

#[test]
fn caracterizacion_decrypt_enc_key_vacio() {
    let err = decrypt_enc_key("", &[0u8; 64]).expect_err("vacío debe fallar");
    assert_eq!(err.to_string(), "Authentication error: enc_key is empty");
}
