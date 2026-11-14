use super::*;
use base64::Engine;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use std::path::Path;

const EXPECTED_KEY_HEX: &str = "46d690a92d1b2e76b901b5221dc296ebe7a9ff6ee76b8615ede85a1323aac17a";
const EXPECTED_HASH_HEX: &str = "e65f3b70990b3bb58a5fc7dc4d35bfaab58b87b81424b26f7a45dac85b2f01b3";

#[test]
fn test_argon2i_derivation() {
    // Fast test vector using 4 MiB memory
    let key = derive_config_key_with_params(
        "synthetic_unit_pin_123",
        "synthetic_device_uuid_456",
        KDF_MEMORY_KIB_TEST,
    )
    .expect("Argon2i derivation should succeed");
    assert_eq!(key.len(), 32);
}

#[test]
fn test_verify_pin_logic() {
    let key_bytes: [u8; 32] = hex::decode(EXPECTED_KEY_HEX).unwrap().try_into().unwrap();
    assert_eq!(hash_config_key(&key_bytes), EXPECTED_HASH_HEX);

    let test_pin = "test_pin_verify_999";
    let test_salt = "test_uuid_verify_999";
    let key = derive_config_key_with_params(test_pin, test_salt, KDF_MEMORY_KIB_TEST)
        .expect("Key derived");
    let expected_hash = hash_config_key(&key);

    assert!(
        verify_pin_with_params(test_pin, test_salt, &expected_hash, KDF_MEMORY_KIB_TEST)
            .expect("Verification succeeds")
    );
    assert!(
        !verify_pin_with_params("wrong_pin", test_salt, &expected_hash, KDF_MEMORY_KIB_TEST)
            .expect("Verification succeeds")
    );
    assert!(
        !verify_pin_with_params(test_pin, "other-uuid", &expected_hash, KDF_MEMORY_KIB_TEST)
            .expect("Verification succeeds")
    );
}

#[test]
fn test_encrypt_decrypt_roundtrip() {
    let key_bytes: [u8; 32] = hex::decode(EXPECTED_KEY_HEX)
        .expect("Valid hex")
        .try_into()
        .expect("32 bytes");

    let plaintext = "secret goldwarden config payload 12345!@#$%^&*()";
    let encrypted_b64 = encrypt_string(plaintext, &key_bytes).expect("Encryption should succeed");

    // Verify Tink wire format: Base64 decodes to [0x00, 0x00, 0x00, 0x00, 0x00] + 12B nonce + CT
    let raw = base64::engine::general_purpose::STANDARD
        .decode(&encrypted_b64)
        .expect("Should decode base64");
    assert!(raw.len() > 17);
    assert_eq!(&raw[..5], &[0x00, 0x00, 0x00, 0x00, 0x00]);

    let decrypted = decrypt_string(&encrypted_b64, &key_bytes).expect("Decryption should succeed");
    assert_eq!(decrypted, plaintext);

    // Subtle Tink wire format without 5-byte header
    let cipher = ChaCha20Poly1305::new_from_slice(&key_bytes).unwrap();
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), b"subtle payload".as_ref())
        .unwrap();
    let mut raw_subtle = Vec::new();
    raw_subtle.extend_from_slice(&nonce);
    raw_subtle.extend_from_slice(&ct);
    let b64_subtle = base64::engine::general_purpose::STANDARD.encode(&raw_subtle);
    let dec_subtle = decrypt_string(&b64_subtle, &key_bytes).unwrap();
    assert_eq!(dec_subtle, "subtle payload");
}

#[test]
fn test_decrypt_go_token() {
    let key_bytes: [u8; 32] = hex::decode(EXPECTED_KEY_HEX)
        .expect("Valid hex")
        .try_into()
        .expect("32 bytes");

    // Deterministic synthetic Go token decryption
    let sample_token = r#"{"access_token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9","expires_in":3600,"token_type":"Bearer","refresh_token":"ref"}"#;
    let enc_token = encrypt_string(sample_token, &key_bytes).unwrap();
    let config = ConfigFile {
        device_uuid: "1f5ef996-82f0-11f1-bc18-80304903a0d9".to_string(),
        encrypted_token: enc_token,
        ..Default::default()
    };
    let decrypted = decrypt_string(&config.encrypted_token, &key_bytes)
        .expect("Should decrypt synthetic token with derived key");
    assert!(decrypted.starts_with(r#"{"access_token":"eyJ0eXAi"#));

    let token = config
        .decrypt_token(&key_bytes)
        .expect("Should parse decrypted LoginToken");
    assert!(token.access_token.starts_with("eyJ0eXAi"));
}

#[test]
fn test_update_pin() {
    let test_pin_old = "old_pin_123";
    let test_salt = "mock_salt_uuid_999";
    let initial_key =
        derive_config_key_with_params(test_pin_old, test_salt, KDF_MEMORY_KIB_TEST).unwrap();
    let mut cfg = ConfigFile {
        device_uuid: test_salt.to_string(),
        config_key_hash: hash_config_key(&initial_key),
        encrypted_client_id: encrypt_string("client_secret_data", &initial_key).unwrap(),
        ..Default::default()
    };

    assert!(cfg
        .verify_pin_with_params(test_pin_old, KDF_MEMORY_KIB_TEST)
        .unwrap());

    let test_pin_new = "new_pin_456";
    cfg.update_pin_with_params(test_pin_old, test_pin_new, KDF_MEMORY_KIB_TEST)
        .expect("Pin update succeeds");

    assert!(!cfg
        .verify_pin_with_params(test_pin_old, KDF_MEMORY_KIB_TEST)
        .unwrap());
    assert!(cfg
        .verify_pin_with_params(test_pin_new, KDF_MEMORY_KIB_TEST)
        .unwrap());

    let new_key = cfg
        .unlock_with_params(test_pin_new, KDF_MEMORY_KIB_TEST)
        .expect("Unlock with new pin succeeds");
    let decrypted_client_id = decrypt_string(&cfg.encrypted_client_id, &new_key).unwrap();
    assert_eq!(decrypted_client_id, "client_secret_data");
}

#[test]
fn test_deserialize_config_file_from_json() {
    let json_data = r#"{
  "IdentityUrl": "https://test.com",
  "ApiUrl": "https://api.test.com",
  "NotificationsUrl": "https://notif.test.com",
  "VaultUrl": "https://vault.test.com",
  "EncryptedClientID": "client_id",
  "EncryptedClientSecret": "client_secret",
  "DeviceUUID": "123e4567-e89b-12d3-a456-426614174000",
  "ConfigKeyHash": "hash123",
  "EncryptedToken": "token",
  "EncryptedUserSymmetricKey": "sym_key",
  "EncryptedMasterPasswordHash": "pass_hash",
  "EncryptedMasterKey": "master_key"
}"#;

    let config: ConfigFile =
        serde_json::from_str(json_data).expect("Should deserialize valid ConfigFile JSON");

    assert_eq!(config.identity_url, "https://test.com");
    assert_eq!(config.api_url, "https://api.test.com");
    assert_eq!(config.notifications_url, "https://notif.test.com");
    assert_eq!(config.vault_url, "https://vault.test.com");
    assert_eq!(config.encrypted_client_id, "client_id");
    assert_eq!(config.encrypted_client_secret, "client_secret");
    assert_eq!(config.device_uuid, "123e4567-e89b-12d3-a456-426614174000");
    assert_eq!(config.config_key_hash, "hash123");
    assert_eq!(config.encrypted_token, "token");
    assert_eq!(config.encrypted_user_symmetric_key, "sym_key");
    assert_eq!(config.encrypted_master_password_hash, "pass_hash");
    assert_eq!(config.encrypted_master_key, "master_key");
}

#[test]
fn test_roundtrip_config_file_default() {
    let original = ConfigFile::default();

    assert_eq!(original.identity_url, "https://identity.bitwarden.com");
    assert_eq!(original.api_url, "https://api.bitwarden.com");
    assert_eq!(
        original.notifications_url,
        "https://notifications.bitwarden.com"
    );
    assert_eq!(original.vault_url, "https://vault.bitwarden.com");
    assert!(original.encrypted_client_id.is_empty());
    assert!(original.encrypted_client_secret.is_empty());
    assert!(original.config_key_hash.is_empty());
    assert!(original.encrypted_token.is_empty());
    assert!(original.encrypted_user_symmetric_key.is_empty());
    assert!(original.encrypted_master_password_hash.is_empty());
    assert!(original.encrypted_master_key.is_empty());
    assert!(!original.device_uuid.is_empty());
    assert!(uuid::Uuid::parse_str(&original.device_uuid).is_ok());

    let serialized =
        serde_json::to_string(&original).expect("Serialization of ConfigFile should succeed");

    assert!(serialized.contains("\"IdentityUrl\":"));
    assert!(serialized.contains("\"ApiUrl\":"));
    assert!(serialized.contains("\"NotificationsUrl\":"));
    assert!(serialized.contains("\"VaultUrl\":"));
    assert!(serialized.contains("\"EncryptedClientID\":"));
    assert!(serialized.contains("\"EncryptedClientSecret\":"));
    assert!(serialized.contains("\"DeviceUUID\":"));
    assert!(serialized.contains("\"ConfigKeyHash\":"));
    assert!(serialized.contains("\"EncryptedToken\":"));
    assert!(serialized.contains("\"EncryptedUserSymmetricKey\":"));
    assert!(serialized.contains("\"EncryptedMasterPasswordHash\":"));
    assert!(serialized.contains("\"EncryptedMasterKey\":"));
    assert!(serialized.contains("\"RuntimeConfig\":"));
    assert!(serialized.contains("\"DangerAcceptInvalidCerts\":"));
    assert!(serialized.contains("\"ServerUrl\":"));

    let deserialized: ConfigFile = serde_json::from_str(&serialized)
        .expect("Deserialization of serialized ConfigFile should succeed");

    assert_eq!(original, deserialized);
}

#[test]
fn test_login_token_roundtrip() {
    let token_json = r#"{
  "access_token": "eySAMPLEtoken123",
  "expires_in": 3600,
  "token_type": "Bearer",
  "refresh_token": "def456refreshtoken",
  "key": "base64encsymmetricmasterkey"
}"#;

    let token: LoginToken =
        serde_json::from_str(token_json).expect("Should deserialize LoginToken JSON");

    assert_eq!(token.access_token, "eySAMPLEtoken123");
    assert_eq!(token.expires_in, 3600);
    assert_eq!(token.token_type, "Bearer");
    assert_eq!(token.refresh_token, "def456refreshtoken");
    assert_eq!(token.key, "base64encsymmetricmasterkey");

    let serialized =
        serde_json::to_string(&token).expect("Serialization of LoginToken should succeed");
    assert!(serialized.contains("\"access_token\":"));
    assert!(serialized.contains("\"expires_in\":3600"));

    let deserialized: LoginToken = serde_json::from_str(&serialized)
        .expect("Deserialization of serialized LoginToken should succeed");

    assert_eq!(token, deserialized);
}

#[test]
fn test_parse_real_goldwarden_json_if_exists() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let fake_path = temp_dir.path().join("goldwarden.json");
    let sample_json = r#"{
        "IdentityUrl": "https://identity.bitwarden.com",
        "ApiUrl": "https://api.bitwarden.com",
        "DeviceUUID": "test-uuid-val",
        "ConfigKeyHash": "testhashval"
    }"#;
    std::fs::write(&fake_path, sample_json).unwrap();
    let content = std::fs::read_to_string(&fake_path).unwrap();
    let parsed: ConfigFile = serde_json::from_str(&content).unwrap();
    assert_eq!(parsed.device_uuid, "test-uuid-val");
    assert_eq!(parsed.config_key_hash, "testhashval");
    let serialized = serde_json::to_string(&parsed).unwrap();
    let roundtripped: ConfigFile = serde_json::from_str(&serialized).unwrap();
    assert_eq!(parsed, roundtripped);
}

#[test]
fn test_migrate_old_path_success() {
    let temp_home = tempfile::tempdir().expect("Create temp dir");
    let old_path = get_old_config_path(temp_home.path());
    let new_path = get_new_config_path(temp_home.path());

    std::fs::create_dir_all(old_path.parent().unwrap()).unwrap();
    std::fs::write(&old_path, r#"{"ConfigKeyHash":"testhash"}"#).unwrap();

    assert!(old_path.exists());
    assert!(!new_path.exists());

    migrate_old_path_in(temp_home.path()).expect("Migration should succeed");

    assert!(!old_path.exists());
    assert!(new_path.exists());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let parent_meta = std::fs::metadata(new_path.parent().unwrap()).unwrap();
        let file_meta = std::fs::metadata(&new_path).unwrap();
        assert_eq!(parent_meta.permissions().mode() & 0o777, 0o700);
        assert_eq!(file_meta.permissions().mode() & 0o777, 0o600);
    }
}

#[test]
fn test_migrate_old_path_new_already_exists() {
    let temp_home = tempfile::tempdir().expect("Create temp dir");
    let old_path = get_old_config_path(temp_home.path());
    let new_path = get_new_config_path(temp_home.path());

    std::fs::create_dir_all(old_path.parent().unwrap()).unwrap();
    std::fs::create_dir_all(new_path.parent().unwrap()).unwrap();
    std::fs::write(&old_path, "old_content").unwrap();
    std::fs::write(&new_path, "new_content").unwrap();

    migrate_old_path_in(temp_home.path()).expect("Should do nothing and succeed");

    assert!(old_path.exists());
    assert_eq!(std::fs::read_to_string(&new_path).unwrap(), "new_content");
}

#[test]
fn test_backup_config_creates_timestamped_file() {
    let temp_dir = tempfile::tempdir().expect("Create temp dir");
    let file_path = temp_dir.path().join("goldwarden.json");
    std::fs::write(&file_path, "original_content").unwrap();

    let backup_path = backup_config(&file_path).expect("Backup should succeed");
    assert!(backup_path.exists());
    assert!(backup_path
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("goldwarden.json.bak-"));
    assert_eq!(
        std::fs::read_to_string(&backup_path).unwrap(),
        "original_content"
    );
}

#[test]
fn test_run_migration_full_flow() {
    let temp_home = tempfile::tempdir().expect("Create temp dir");
    let old_path = get_old_config_path(temp_home.path());

    std::fs::create_dir_all(old_path.parent().unwrap()).unwrap();
    let valid_json = r#"{
  "ConfigKeyHash": "testhash12345",
  "IdentityUrl": "https://identity.bitwarden.com",
  "DeviceUUID": "test-uuid"
}"#;
    std::fs::write(&old_path, valid_json).unwrap();

    let result = run_migration_in(temp_home.path()).expect("Migration should succeed");
    assert_eq!(result, MIGRATION_SUCCESS_MSG);

    let new_path = get_new_config_path(temp_home.path());
    assert!(new_path.exists());
    assert!(!old_path.exists());

    let backups: Vec<_> = std::fs::read_dir(old_path.parent().unwrap())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_str()
                .unwrap()
                .starts_with("goldwarden.json.bak-")
        })
        .collect();
    assert_eq!(backups.len(), 1);
}

#[test]
fn test_run_migration_missing_hash_fails() {
    let temp_home = tempfile::tempdir().expect("Create temp dir");
    let old_path = get_old_config_path(temp_home.path());

    std::fs::create_dir_all(old_path.parent().unwrap()).unwrap();
    let invalid_json = r#"{
  "ConfigKeyHash": "",
  "IdentityUrl": "https://identity.bitwarden.com"
}"#;
    std::fs::write(&old_path, invalid_json).unwrap();

    let result = run_migration_in(temp_home.path());
    assert!(result.is_err());
}

#[test]
fn test_verify_pin_mismatched_length() {
    assert!(!verify_pin("test_pin", "test_uuid", "short_hash").unwrap());
    assert!(
        !verify_pin_with_params("test_pin", "test_uuid", "short_hash", KDF_MEMORY_KIB_TEST)
            .unwrap()
    );

    let cfg = ConfigFile {
        device_uuid: "test_uuid".to_string(),
        config_key_hash: "short_hash".to_string(),
        ..Default::default()
    };
    assert!(!cfg.verify_pin("test_pin").unwrap());
    assert!(matches!(
        cfg.unlock("test_pin"),
        Err(ConfigError::InvalidPin)
    ));
    let mut cfg2 = cfg.clone();
    assert!(matches!(
        cfg2.update_pin("test_pin", "new_pin"),
        Err(ConfigError::InvalidPin)
    ));
}

#[test]
fn test_decrypt_string_errors() {
    let key = [42u8; 32];
    assert!(decrypt_string("not_base_64?!", &key).is_err());

    let too_short = base64::engine::general_purpose::STANDARD.encode([1u8, 2, 3]);
    assert!(decrypt_string(&too_short, &key).is_err());

    let fake_payload = vec![0u8; 35];
    let fake_b64 = base64::engine::general_purpose::STANDARD.encode(&fake_payload);
    assert!(decrypt_string(&fake_b64, &key).is_err());
}

#[test]
fn test_config_file_unlock_and_decrypt_token_errors() {
    let cfg = ConfigFile::default();
    assert!(matches!(
        cfg.unlock_with_params("bad_pin", KDF_MEMORY_KIB_TEST),
        Err(ConfigError::InvalidPin)
    ));

    let key = [0u8; 32];
    assert!(matches!(
        cfg.decrypt_token(&key),
        Err(ConfigError::Crypto(_))
    ));

    let enc_bad_json = encrypt_string("not_a_json", &key).unwrap();
    let cfg_bad_json = ConfigFile {
        encrypted_token: enc_bad_json,
        ..Default::default()
    };
    assert!(matches!(
        cfg_bad_json.decrypt_token(&key),
        Err(ConfigError::Json(_))
    ));

    let mut cfg_update = ConfigFile::default();
    assert!(matches!(
        cfg_update.update_pin_with_params("wrong_old", "new", KDF_MEMORY_KIB_TEST),
        Err(ConfigError::InvalidPin)
    ));
}

#[test]
fn test_decrypt_token_synthetic_success() {
    let key = [77u8; 32];
    let token = LoginToken {
        access_token: "mock_access".to_string(),
        expires_in: 7200,
        token_type: "Bearer".to_string(),
        refresh_token: "mock_refresh".to_string(),
        key: "mock_key".to_string(),
        ..Default::default()
    };
    let token_json = serde_json::to_string(&token).unwrap();
    let enc_token = encrypt_string(&token_json, &key).unwrap();

    let cfg = ConfigFile {
        encrypted_token: enc_token,
        ..Default::default()
    };

    let decrypted = cfg
        .decrypt_token(&key)
        .expect("Should decrypt synthetic token");
    assert_eq!(decrypted, token);
}

#[test]
fn test_backup_config_non_existent() {
    let non_existent = Path::new("/path/that/does/not/exist/9999999");
    assert!(backup_config(non_existent).is_err());
}

#[test]
fn test_run_migration_new_already_exists() {
    let temp_home = tempfile::tempdir().expect("Create temp dir");
    let new_path = get_new_config_path(temp_home.path());
    std::fs::create_dir_all(new_path.parent().unwrap()).unwrap();

    let valid_json = r#"{
  "ConfigKeyHash": "validhash123",
  "IdentityUrl": "https://identity.bitwarden.com"
}"#;
    std::fs::write(&new_path, valid_json).unwrap();

    let result =
        run_migration_in(temp_home.path()).expect("Should succeed when new path already exists");
    assert_eq!(result, MIGRATION_SUCCESS_MSG);

    let backups: Vec<_> = std::fs::read_dir(new_path.parent().unwrap())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_str()
                .unwrap()
                .starts_with("goldwarden.json.bak-")
        })
        .collect();
    assert_eq!(backups.len(), 1);
}

#[test]
fn test_run_migration_no_config_found() {
    let temp_home = tempfile::tempdir().expect("Create temp dir");
    let result = run_migration_in(temp_home.path());
    assert!(result.is_err());
}

#[test]
fn test_migrate_old_path_no_old_path_is_noop() {
    let temp_home = tempfile::tempdir().expect("Create temp dir");
    let res = migrate_old_path_in(temp_home.path());
    assert!(res.is_ok());
}

#[test]
fn test_env_home_migration_wrappers() {
    let temp_home = tempfile::tempdir().expect("Create temp dir");
    let old_path = get_old_config_path(temp_home.path());
    std::fs::create_dir_all(old_path.parent().unwrap()).unwrap();
    std::fs::write(&old_path, r#"{"ConfigKeyHash":"env_hash"}"#).unwrap();

    let original_home = std::env::var("HOME").ok();
    std::env::set_var("HOME", temp_home.path());

    let res = migrate_old_path();
    assert!(res.is_ok());

    let mig_res = run_migration();
    assert!(mig_res.is_ok());

    if let Some(h) = original_home {
        std::env::set_var("HOME", h);
    }
}

#[test]
fn test_config_error_display_coverage() {
    let err_io = ConfigError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "io msg"));
    assert!(err_io.to_string().contains("io msg"));

    let err_json = ConfigError::Json(serde_json::from_str::<ConfigFile>("bad").unwrap_err());
    assert!(err_json.to_string().contains("JSON error"));

    let err_kdf = ConfigError::Kdf("kdf msg".to_string());
    assert!(err_kdf.to_string().contains("kdf msg"));

    let err_crypto = ConfigError::Crypto("crypto msg".to_string());
    assert!(err_crypto.to_string().contains("crypto msg"));

    let err_pin = ConfigError::InvalidPin;
    assert!(err_pin.to_string().contains("Invalid PIN"));

    let err_lock = ConfigError::Lock("lock msg".to_string());
    assert!(err_lock.to_string().contains("lock msg"));
}

#[test]
fn test_error_branches_and_edge_cases() {
    // Invalid argon2 params error
    assert!(matches!(
        derive_config_key_with_params("pin", "uuid", 0),
        Err(ConfigError::Kdf(_))
    ));

    // decrypt_string invalid UTF-8
    let key = [99u8; 32];
    let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
    let nonce = [0u8; 12];
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), b"\xFF\xFE\xFD".as_ref())
        .unwrap();
    let mut raw = Vec::new();
    raw.extend_from_slice(&TINK_HEADER);
    raw.extend_from_slice(&nonce);
    raw.extend_from_slice(&ct);
    let b64 = base64::engine::general_purpose::STANDARD.encode(&raw);
    assert!(matches!(
        decrypt_string(&b64, &key),
        Err(ConfigError::Crypto(_))
    ));

    // ConfigFile default fields
    let cfg = ConfigFile::default();
    assert!(cfg.encrypted_client_id.is_empty());
    assert!(cfg.encrypted_client_secret.is_empty());
    assert!(cfg.encrypted_token.is_empty());
    assert!(cfg.encrypted_user_symmetric_key.is_empty());
    assert!(cfg.encrypted_master_password_hash.is_empty());
    assert!(cfg.encrypted_master_key.is_empty());

    // LoginToken default fields
    let tok = LoginToken::default();
    assert!(tok.access_token.is_empty());
    assert_eq!(tok.expires_in, 0);
    assert!(tok.token_type.is_empty());
    assert!(tok.refresh_token.is_empty());
    assert!(tok.key.is_empty());

    // Parent dir creation in migrate_old_path_in
    let temp_home = tempfile::tempdir().expect("Create temp dir");
    let old_path = get_old_config_path(temp_home.path());
    std::fs::create_dir_all(old_path.parent().unwrap()).unwrap();
    std::fs::write(&old_path, r#"{"ConfigKeyHash":"testhash"}"#).unwrap();

    let new_path = get_new_config_path(temp_home.path());
    // Parent does not exist yet:
    assert!(!new_path.parent().unwrap().exists());
    migrate_old_path_in(temp_home.path()).unwrap();
    assert!(new_path.exists());
}

#[test]
fn test_derived_traits_coverage() {
    let default_cfg = ConfigFile::default();
    let mut cfgs = Vec::new();
    let mut c1 = default_cfg.clone();
    c1.identity_url = "a".into();
    cfgs.push(c1);
    let mut c2 = default_cfg.clone();
    c2.api_url = "a".into();
    cfgs.push(c2);
    let mut c3 = default_cfg.clone();
    c3.notifications_url = "a".into();
    cfgs.push(c3);
    let mut c4 = default_cfg.clone();
    c4.vault_url = "a".into();
    cfgs.push(c4);
    let mut c5 = default_cfg.clone();
    c5.encrypted_client_id = "a".into();
    cfgs.push(c5);
    let mut c6 = default_cfg.clone();
    c6.encrypted_client_secret = "a".into();
    cfgs.push(c6);
    let mut c7 = default_cfg.clone();
    c7.device_uuid = "a".into();
    cfgs.push(c7);
    let mut c8 = default_cfg.clone();
    c8.config_key_hash = "a".into();
    cfgs.push(c8);
    let mut c9 = default_cfg.clone();
    c9.encrypted_token = "a".into();
    cfgs.push(c9);
    let mut c10 = default_cfg.clone();
    c10.encrypted_user_symmetric_key = "a".into();
    cfgs.push(c10);
    let mut c11 = default_cfg.clone();
    c11.encrypted_master_password_hash = "a".into();
    cfgs.push(c11);
    let mut c12 = default_cfg.clone();
    c12.encrypted_master_key = "a".into();
    cfgs.push(c12);

    for c in &cfgs {
        assert_ne!(&default_cfg, c);
        assert!(default_cfg.ne(c));
    }

    let debug_cfg = format!("{default_cfg:?}");
    assert!(debug_cfg.contains("ConfigFile"));

    let default_tok = LoginToken::default();
    let mut toks = Vec::new();
    let mut t1 = default_tok.clone();
    t1.access_token = "a".into();
    toks.push(t1);
    let mut t2 = default_tok.clone();
    t2.expires_in = 99;
    toks.push(t2);
    let mut t3 = default_tok.clone();
    t3.token_type = "a".into();
    toks.push(t3);
    let mut t4 = default_tok.clone();
    t4.refresh_token = "a".into();
    toks.push(t4);
    let mut t5 = default_tok.clone();
    t5.key = "a".into();
    toks.push(t5);

    for t in &toks {
        assert_ne!(&default_tok, t);
        assert!(default_tok.ne(t));
    }

    let debug_tok = format!("{default_tok:?}");
    assert!(debug_tok.contains("LoginToken"));

    let json_with_aliases = r#"{
        "EncryptedClientId": "alias_id",
        "DeviceUuid": "alias_uuid",
        "access_token": "token123",
        "expires_in": 3600,
        "token_type": "Bearer",
        "refresh_token": "ref123",
        "Key": "alias_key"
    }"#;
    let cfg_alias: ConfigFile = serde_json::from_str(json_with_aliases).unwrap();
    assert_eq!(cfg_alias.encrypted_client_id, "alias_id");
    assert_eq!(cfg_alias.device_uuid, "alias_uuid");

    let tok_alias: LoginToken = serde_json::from_str(json_with_aliases).unwrap();
    assert_eq!(tok_alias.key, "alias_key");
    assert_eq!(tok_alias.access_token, "token123");

    let cfg_empty: ConfigFile = serde_json::from_str("{}").unwrap();
    assert_eq!(cfg_empty.identity_url, "https://identity.bitwarden.com");

    let cfg_extra: ConfigFile = serde_json::from_str(r#"{"unknown_field": 123}"#).unwrap();
    assert_eq!(cfg_extra.identity_url, "https://identity.bitwarden.com");

    let err = ConfigError::InvalidPin;
    let debug_err = format!("{err:?}");
    assert!(debug_err.contains("InvalidPin"));
}

#[test]
fn test_derive_server_urls_and_set_server() {
    let (id, api, notif) = derive_server_urls("http://localhost:8080");
    assert_eq!(id, "http://localhost:8080/identity");
    assert_eq!(api, "http://localhost:8080/api");
    assert_eq!(notif, "http://localhost:8080/notifications");

    // Trailing slash
    let (id2, api2, notif2) = derive_server_urls("http://localhost:8080/");
    assert_eq!(id2, "http://localhost:8080/identity");
    assert_eq!(api2, "http://localhost:8080/api");
    assert_eq!(notif2, "http://localhost:8080/notifications");

    // Already has /identity or /api
    let (id3, api3, notif3) = derive_server_urls("http://localhost:8080/identity");
    assert_eq!(id3, "http://localhost:8080/identity");
    assert_eq!(api3, "http://localhost:8080/identity/api");
    assert_eq!(notif3, "http://localhost:8080/identity/notifications");

    let mut cfg = ConfigFile::default();
    cfg.set_server("https://vaultwarden.local:8443");
    assert_eq!(cfg.server_url, "https://vaultwarden.local:8443");
    assert_eq!(cfg.identity_url, "https://vaultwarden.local:8443/identity");
    assert_eq!(cfg.api_url, "https://vaultwarden.local:8443/api");
    assert_eq!(
        cfg.notifications_url,
        "https://vaultwarden.local:8443/notifications"
    );
}

#[test]
fn test_client_id_and_secret_encryption_helpers() {
    let key = [88u8; 32];
    let mut cfg = ConfigFile::default();
    assert!(cfg.decrypt_client_id(&key).is_err());
    assert!(cfg.decrypt_client_secret(&key).is_err());

    cfg.set_client_id("user.client-id-1234", &key).unwrap();
    cfg.set_client_secret("secret_token_5678", &key).unwrap();

    assert_eq!(cfg.decrypt_client_id(&key).unwrap(), "user.client-id-1234");
    assert_eq!(
        cfg.decrypt_client_secret(&key).unwrap(),
        "secret_token_5678"
    );
}

#[test]
fn test_config_file_all_15_fields_and_go_compat() {
    let cfg = ConfigFile {
        identity_url: "https://id.example.com".to_string(),
        api_url: "https://api.example.com".to_string(),
        notifications_url: "https://notif.example.com".to_string(),
        vault_url: "https://vault.example.com".to_string(),
        encrypted_client_id: "enc_id".to_string(),
        encrypted_client_secret: "enc_secret".to_string(),
        device_uuid: "custom-device-uuid".to_string(),
        config_key_hash: "custom-key-hash".to_string(),
        encrypted_token: "enc_token".to_string(),
        encrypted_user_symmetric_key: "enc_sym".to_string(),
        encrypted_master_password_hash: "enc_mph".to_string(),
        encrypted_master_key: "enc_mk".to_string(),
        runtime_config: RuntimeConfig {
            auth_method: "password".to_string(),
            do_not_persist_config: false,
            config_directory: "/tmp/gw".to_string(),
            disable_ssh_agent: true,
            websocket_disabled: false,
            device_uuid: "custom-device-uuid".to_string(),
            user: "user@example.com".to_string(),
            password: "mypassword".to_string(),
            pin: "1234".to_string(),
            use_memguard: true,
            ssh_agent_socket_path: "/tmp/gw-ssh.sock".to_string(),
            goldwarden_socket_path: "/tmp/gw.sock".to_string(),
            daemon_auth_token: "token123".to_string(),
            pin_cache_ttl_secs: 900,
            idle_ttl_secs: 600,
            biometrics_enabled: true,
        },
        danger_accept_invalid_certs: true,
        server_url: "https://vw.local".to_string(),
    };

    let json_value: serde_json::Value =
        serde_json::to_value(&cfg).expect("Serialization to Value must succeed");
    let map = json_value.as_object().expect("Must be a JSON object");

    // Exactly 15 fields: 13 original Go fields + 2 new SilverWarden fields
    assert_eq!(map.len(), 15);

    let expected_keys = [
        "IdentityUrl",
        "ApiUrl",
        "NotificationsUrl",
        "VaultUrl",
        "EncryptedClientID",
        "EncryptedClientSecret",
        "DeviceUUID",
        "ConfigKeyHash",
        "EncryptedToken",
        "EncryptedUserSymmetricKey",
        "EncryptedMasterPasswordHash",
        "EncryptedMasterKey",
        "RuntimeConfig",
        "DangerAcceptInvalidCerts",
        "ServerUrl",
    ];

    for key in expected_keys {
        assert!(
            map.contains_key(key),
            "Missing expected PascalCase key in JSON: {key}"
        );
    }

    // Check RuntimeConfig inner keys match Go names
    let rt_map = map
        .get("RuntimeConfig")
        .unwrap()
        .as_object()
        .expect("RuntimeConfig must be object");
    assert!(rt_map.contains_key("DisableSSHAgent"));
    assert!(rt_map.contains_key("DeviceUUID"));
    assert!(rt_map.contains_key("SSHAgentSocketPath"));
    assert!(rt_map.contains_key("PinCacheTtlSecs"));
    assert!(rt_map.contains_key("IdleTtlSecs"));
    assert!(rt_map.contains_key("BiometricsEnabled"));

    // Test reading from a Go sample without the 2 new fields or RuntimeConfig
    let go_json = r#"{
        "IdentityUrl": "https://vault.bitwarden.com/identity",
        "ApiUrl": "https://api.bitwarden.com",
        "NotificationsUrl": "https://notifications.bitwarden.com",
        "VaultUrl": "https://vault.bitwarden.com",
        "EncryptedClientID": "go_client_id",
        "EncryptedClientSecret": "go_client_secret",
        "DeviceUUID": "go-device-uuid-1234",
        "ConfigKeyHash": "go_key_hash",
        "EncryptedToken": "go_token",
        "EncryptedUserSymmetricKey": "go_sym_key",
        "EncryptedMasterPasswordHash": "go_mph",
        "EncryptedMasterKey": "go_mk"
    }"#;

    let parsed_go: ConfigFile = serde_json::from_str(go_json).expect("Should parse Go json");
    assert_eq!(parsed_go.encrypted_client_id, "go_client_id");
    assert_eq!(parsed_go.encrypted_client_secret, "go_client_secret");
    assert_eq!(parsed_go.device_uuid, "go-device-uuid-1234");
    assert_eq!(parsed_go.config_key_hash, "go_key_hash");
    assert_eq!(parsed_go.encrypted_token, "go_token");
    assert_eq!(parsed_go.encrypted_user_symmetric_key, "go_sym_key");
    assert_eq!(parsed_go.encrypted_master_password_hash, "go_mph");
    assert_eq!(parsed_go.encrypted_master_key, "go_mk");
    assert!(!parsed_go.danger_accept_invalid_certs);
    assert_eq!(parsed_go.server_url, "");
    assert_eq!(parsed_go.runtime_config, RuntimeConfig::default());

    // Test file persistence roundtrip
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let file_path = temp_dir.path().join("goldwarden.json");
    cfg.save_to_file(&file_path).expect("save_to_file");
    let loaded = ConfigFile::load_from_file(&file_path).expect("load_from_file");
    assert_eq!(cfg, loaded);
}

#[test]
fn test_runtime_config_pin_cache_ttl_secs_default_and_roundtrip() {
    // Default applies 900
    let default_rt = RuntimeConfig::default();
    assert_eq!(default_rt.pin_cache_ttl_secs, 900);

    // Deserializing empty JSON object produces default 900
    let from_empty: RuntimeConfig = serde_json::from_str("{}").expect("empty json object");
    assert_eq!(from_empty.pin_cache_ttl_secs, 900);

    // Deserializing with PascalCase key
    let with_pascal: RuntimeConfig =
        serde_json::from_str(r#"{"PinCacheTtlSecs": 1200}"#).expect("pascal json");
    assert_eq!(with_pascal.pin_cache_ttl_secs, 1200);

    // Deserializing with alias snake_case
    let with_snake: RuntimeConfig =
        serde_json::from_str(r#"{"pin_cache_ttl_secs": 600}"#).expect("snake json");
    assert_eq!(with_snake.pin_cache_ttl_secs, 600);

    // Deserializing with alias camelCase
    let with_camel: RuntimeConfig =
        serde_json::from_str(r#"{"pinCacheTtlSecs": 300}"#).expect("camel json");
    assert_eq!(with_camel.pin_cache_ttl_secs, 300);

    // Roundtrip serialization
    let custom = RuntimeConfig {
        pin_cache_ttl_secs: 1800,
        ..Default::default()
    };
    let serialized = serde_json::to_string(&custom).expect("serialize");
    assert!(serialized.contains(r#""PinCacheTtlSecs":1800"#));
    let roundtrip: RuntimeConfig = serde_json::from_str(&serialized).expect("deserialize");
    assert_eq!(custom, roundtrip);
}

#[test]
fn test_runtime_config_idle_ttl_secs_default_and_roundtrip() {
    // Default applies 600
    let default_rt = RuntimeConfig::default();
    assert_eq!(default_rt.idle_ttl_secs, 600);

    // Deserializing empty JSON object produces default 600
    let from_empty: RuntimeConfig = serde_json::from_str("{}").expect("empty json object");
    assert_eq!(from_empty.idle_ttl_secs, 600);

    // Deserializing with PascalCase key
    let with_pascal: RuntimeConfig =
        serde_json::from_str(r#"{"IdleTtlSecs": 900}"#).expect("pascal json");
    assert_eq!(with_pascal.idle_ttl_secs, 900);

    // Deserializing with alias snake_case
    let with_snake: RuntimeConfig =
        serde_json::from_str(r#"{"idle_ttl_secs": 300}"#).expect("snake json");
    assert_eq!(with_snake.idle_ttl_secs, 300);

    // Deserializing with alias camelCase
    let with_camel: RuntimeConfig =
        serde_json::from_str(r#"{"idleTtlSecs": 120}"#).expect("camel json");
    assert_eq!(with_camel.idle_ttl_secs, 120);

    // Roundtrip serialization
    let custom = RuntimeConfig {
        idle_ttl_secs: 1800,
        ..Default::default()
    };
    let serialized = serde_json::to_string(&custom).expect("serialize");
    assert!(serialized.contains(r#""IdleTtlSecs":1800"#));
    let roundtrip: RuntimeConfig = serde_json::from_str(&serialized).expect("deserialize");
    assert_eq!(custom, roundtrip);
}

#[test]
fn test_runtime_config_biometrics_enabled_default_and_roundtrip() {
    // Default applies false
    let default_rt = RuntimeConfig::default();
    assert!(!default_rt.biometrics_enabled);

    // Deserializing empty JSON object produces default false
    let from_empty: RuntimeConfig = serde_json::from_str("{}").expect("empty json object");
    assert!(!from_empty.biometrics_enabled);

    // Deserializing with PascalCase key
    let with_pascal: RuntimeConfig =
        serde_json::from_str(r#"{"BiometricsEnabled": true}"#).expect("pascal json");
    assert!(with_pascal.biometrics_enabled);

    // Deserializing with alias snake_case
    let with_snake: RuntimeConfig =
        serde_json::from_str(r#"{"biometrics_enabled": true}"#).expect("snake json");
    assert!(with_snake.biometrics_enabled);

    // Deserializing with alias camelCase
    let with_camel: RuntimeConfig =
        serde_json::from_str(r#"{"biometricsEnabled": true}"#).expect("camel json");
    assert!(with_camel.biometrics_enabled);

    // Roundtrip serialization
    let custom = RuntimeConfig {
        biometrics_enabled: true,
        ..Default::default()
    };
    let serialized = serde_json::to_string(&custom).expect("serialize");
    assert!(serialized.contains(r#""BiometricsEnabled":true"#));
    let roundtrip: RuntimeConfig = serde_json::from_str(&serialized).expect("deserialize");
    assert_eq!(custom, roundtrip);
}
