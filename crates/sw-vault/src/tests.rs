use super::*;
use std::path::PathBuf;

#[test]
fn test_sync_data_full_deserialization() {
    let json_str = r#"{
            "profile": {
                "id": "11111111-1111-1111-1111-111111111111",
                "name": "Alice Tester",
                "email": "alice@example.com",
                "emailVerified": true,
                "premium": false,
                "masterPasswordHint": "favorite color",
                "culture": "en-US",
                "twoFactorEnabled": false,
                "key": "2.aXZfMTZfYnl0ZXNfbG9uZw==|Y2lwaGVydGV4dF9ieXRlcw==|bWFjXzMyX2J5dGVzX2xvbmdfaGFzaF9zdHJpbmchIQ==",
                "privateKey": "4.Y2lwaGVydGV4dF9ieXRlcw==",
                "securityStamp": "stamp123",
                "organizations": [
                    {
                        "object": "organization",
                        "id": "22222222-2222-2222-2222-222222222222",
                        "name": "Acme Corp",
                        "useGroups": true,
                        "useDirectory": false,
                        "useEvents": false,
                        "useTotp": true,
                        "use2fa": true,
                        "useApi": false,
                        "usersGetPremium": true,
                        "selfHost": false,
                        "seats": 10,
                        "maxCollections": 5,
                        "maxStorageGb": 100,
                        "key": "org_key_base64",
                        "status": 1,
                        "type": 1,
                        "enabled": true
                    }
                ]
            },
            "folders": [
                {
                    "id": "33333333-3333-3333-3333-333333333333",
                    "name": "Work Logins",
                    "revisionDate": "2026-10-24T12:00:00Z"
                }
            ],
            "ciphers": [
                {
                    "type": 1,
                    "id": "44444444-4444-4444-4444-444444444444",
                    "name": "2.aXZfMTZfYnl0ZXNfbG9uZw==|Y2lwaGVydGV4dF9ieXRlcw==|bWFjXzMyX2J5dGVzX2xvbmdfaGFzaF9zdHJpbmchIQ==",
                    "notes": "2.aXZfMTZfYnl0ZXNfbG9uZw==|Y2lwaGVydGV4dF9ieXRlcw==|bWFjXzMyX2J5dGVzX2xvbmdfaGFzaF9zdHJpbmchIQ==",
                    "folderId": "33333333-3333-3333-3333-333333333333",
                    "favorite": true,
                    "organizationUseTotp": false,
                    "collectionIds": ["col1", "col2"],
                    "fields": [
                        {
                            "type": 0,
                            "name": "2.aXZfMTZfYnl0ZXNfbG9uZw==|Y2lwaGVydGV4dF9ieXRlcw==|bWFjXzMyX2J5dGVzX2xvbmdfaGFzaF9zdHJpbmchIQ==",
                            "value": "2.aXZfMTZfYnl0ZXNfbG9uZw==|Y2lwaGVydGV4dF9ieXRlcw==|bWFjXzMyX2J5dGVzX2xvbmdfaGFzaF9zdHJpbmchIQ=="
                        }
                    ],
                    "login": {
                        "username": "2.aXZfMTZfYnl0ZXNfbG9uZw==|Y2lwaGVydGV4dF9ieXRlcw==|bWFjXzMyX2J5dGVzX2xvbmdfaGFzaF9zdHJpbmchIQ==",
                        "password": "2.aXZfMTZfYnl0ZXNfbG9uZw==|Y2lwaGVydGV4dF9ieXRlcw==|bWFjXzMyX2J5dGVzX2xvbmdfaGFzaF9zdHJpbmchIQ==",
                        "totp": "2.aXZfMTZfYnl0ZXNfbG9uZw==|Y2lwaGVydGV4dF9ieXRlcw==|bWFjXzMyX2J5dGVzX2xvbmdfaGFzaF9zdHJpbmchIQ==",
                        "uri": "2.aXZfMTZfYnl0ZXNfbG9uZw==|Y2lwaGVydGV4dF9ieXRlcw==|bWFjXzMyX2J5dGVzX2xvbmdfaGFzaF9zdHJpbmchIQ==",
                        "uris": [
                            {
                                "uri": "https://example.com/login",
                                "match": 0
                            }
                        ]
                    },
                    "key": "2.aXZfMTZfYnl0ZXNfbG9uZw==|Y2lwaGVydGV4dF9ieXRlcw==|bWFjXzMyX2J5dGVzX2xvbmdfaGFzaF9zdHJpbmchIQ=="
                },
                {
                    "type": 5,
                    "id": "55555555-5555-5555-5555-555555555555",
                    "name": "2.aXZfMTZfYnl0ZXNfbG9uZw==|Y2lwaGVydGV4dF9ieXRlcw==|bWFjXzMyX2J5dGVzX2xvbmdfaGFzaF9zdHJpbmchIQ==",
                    "sshKey": {
                        "privateKey": "2.aXZfMTZfYnl0ZXNfbG9uZw==|Y2lwaGVydGV4dF9ieXRlcw==|bWFjXzMyX2J5dGVzX2xvbmdfaGFzaF9zdHJpbmchIQ==",
                        "publicKey": "2.aXZfMTZfYnl0ZXNfbG9uZw==|Y2lwaGVydGV4dF9ieXRlcw==|bWFjXzMyX2J5dGVzX2xvbmdfaGFzaF9zdHJpbmchIQ==",
                        "keyFingerprint": "2.aXZfMTZfYnl0ZXNfbG9uZw==|Y2lwaGVydGV4dF9ieXRlcw==|bWFjXzMyX2J5dGVzX2xvbmdfaGFzaF9zdHJpbmchIQ=="
                    }
                }
            ]
        }"#;

    let sync_data: SyncData = serde_json::from_str(json_str).expect("SyncData must deserialize");

    // Profile checks
    assert_eq!(sync_data.profile.name, Some("Alice Tester".to_string()));
    assert_eq!(
        sync_data.profile.email,
        Some("alice@example.com".to_string())
    );
    assert_eq!(sync_data.profile.organizations.len(), 1);
    assert_eq!(
        sync_data.profile.organizations[0].name,
        Some("Acme Corp".to_string())
    );

    // Folders checks
    assert_eq!(sync_data.folders.len(), 1);
    assert_eq!(sync_data.folders[0].name, Some("Work Logins".to_string()));

    // Ciphers checks
    assert_eq!(sync_data.ciphers.len(), 2);

    // Cipher 1: Login
    let login_cipher = &sync_data.ciphers[0];
    assert_eq!(login_cipher.r#type, CipherType::Login);
    assert!(login_cipher.favorite);
    assert_eq!(login_cipher.collection_ids, vec!["col1", "col2"]);
    assert!(login_cipher.login.is_some());

    let login_data = login_cipher.login.as_ref().unwrap();
    assert!(login_data.username.is_some());
    assert!(login_data.password.is_some());
    assert_eq!(login_data.uris.len(), 1);
    assert_eq!(
        login_data.uris[0].uri,
        Some("https://example.com/login".to_string())
    );
    assert_eq!(login_data.uris[0].r#match, Some(URIMatch::Domain));

    // Cipher 2: SSH Key
    let ssh_cipher = &sync_data.ciphers[1];
    assert_eq!(ssh_cipher.r#type, CipherType::SshKey);
    assert!(ssh_cipher.ssh_key.is_some());
    let ssh_data = ssh_cipher.ssh_key.as_ref().unwrap();
    assert!(ssh_data.private_key.is_some());
    assert!(ssh_data.public_key.is_some());
    assert!(ssh_data.key_fingerprint.is_some());
}

#[test]
fn test_roundtrip_serialization() {
    let original = SyncData {
        profile: Profile {
            id: Some(Uuid::new_v4()),
            email: Some("roundtrip@test.com".into()),
            organizations: vec![],
            ..Default::default()
        },
        folders: vec![Folder {
            id: Some(Uuid::new_v4()),
            name: Some("Personal".into()),
            revision_date: None,
        }],
        ciphers: vec![
            Cipher {
                r#type: CipherType::Card,
                id: Some(Uuid::new_v4()),
                name: EncString::default(),
                card: Some(Card {
                    brand: None,
                    cardholder_name: None,
                    number: None,
                    exp_month: None,
                    exp_year: None,
                    code: None,
                }),
                ..Default::default()
            },
            Cipher {
                r#type: CipherType::Identity,
                id: Some(Uuid::new_v4()),
                identity: Some(Identity {
                    first_name: None,
                    last_name: None,
                    ..Default::default()
                }),
                ..Default::default()
            },
            Cipher {
                r#type: CipherType::Note,
                id: Some(Uuid::new_v4()),
                secure_note: Some(SecureNoteCipher {
                    r#type: Some(SecureNoteType::Generic),
                }),
                ..Default::default()
            },
        ],
    };

    let serialized = serde_json::to_string(&original).expect("Must serialize SyncData");
    let deserialized: SyncData =
        serde_json::from_str(&serialized).expect("Must deserialize serialized SyncData");

    assert_eq!(original, deserialized);
}

#[tokio::test]
async fn test_vault_store_operations() {
    let store = VaultStore::new();
    assert!(store.is_empty().await);

    let id1 = Uuid::new_v4();
    let c1 = Cipher {
        id: Some(id1),
        r#type: CipherType::Login,
        ..Default::default()
    };

    let id2 = Uuid::new_v4();
    let c2 = Cipher {
        id: Some(id2),
        r#type: CipherType::SshKey,
        ..Default::default()
    };

    store.insert(c1).await;
    store.insert(c2).await;

    assert_eq!(store.len().await, 2);
    assert!(!store.is_empty().await);

    assert_eq!(store.get(&id1).await.unwrap().r#type, CipherType::Login);
    assert_eq!(store.get(&id2).await.unwrap().r#type, CipherType::SshKey);
    assert_eq!(store.all().await.len(), 2);

    // Delete test
    let deleted = store.delete(&id1).await;
    assert!(deleted.is_some());
    assert_eq!(store.len().await, 1);
    assert!(store.get(&id1).await.is_none());

    // SyncData load & export
    let sync_data = SyncData {
        profile: Profile {
            name: Some("Bob".to_string()),
            ..Default::default()
        },
        folders: vec![Folder {
            name: Some("Folder1".to_string()),
            ..Default::default()
        }],
        ciphers: vec![Cipher {
            id: Some(id1),
            r#type: CipherType::Card,
            ..Default::default()
        }],
    };

    store.load_sync_data(sync_data).await;
    assert_eq!(store.len().await, 1);
    assert_eq!(store.folders().await.len(), 1);
    assert_eq!(store.profile().await.unwrap().name.as_deref(), Some("Bob"));

    let exported = store.to_sync_data().await;
    assert_eq!(exported.ciphers.len(), 1);
    assert_eq!(exported.folders.len(), 1);

    // Timestamps
    store.set_last_synced(1234567890).await;
    assert_eq!(store.last_synced().await, Some(1234567890));

    store.clear().await;
    assert!(store.is_empty().await);
    assert_eq!(store.len().await, 0);
}

#[tokio::test]
async fn test_vault_store_delete_cipher() {
    let store = VaultStore::new();
    let id = Uuid::new_v4();
    let cipher = Cipher {
        id: Some(id),
        r#type: CipherType::SshKey,
        ..Default::default()
    };
    store.insert(cipher).await;
    assert_eq!(store.len().await, 1);
    let removed = store.delete_cipher(&id).await;
    assert!(removed.is_some());
    assert_eq!(removed.unwrap().id, Some(id));
    assert!(store.get(&id).await.is_none());
    assert!(store.is_empty().await);
    assert!(store.delete_cipher(&id).await.is_none());
}

#[test]
fn test_vault_store_blocking_operations() {
    let store = VaultStore::new();
    let id1 = Uuid::new_v4();

    assert!(store.blocking_is_empty());
    assert_eq!(store.blocking_len(), 0);

    store.blocking_insert(Cipher {
        id: Some(id1),
        r#type: CipherType::Note,
        ..Default::default()
    });

    assert_eq!(store.blocking_len(), 1);
    assert_eq!(store.blocking_get(&id1).unwrap().r#type, CipherType::Note);
    assert_eq!(store.blocking_all().len(), 1);
    assert!(store.blocking_delete_cipher(&id1).is_some());
    assert_eq!(store.blocking_len(), 0);

    store.blocking_load_sync_data(SyncData {
        ciphers: vec![Cipher {
            id: Some(id1),
            ..Default::default()
        }],
        ..Default::default()
    });
    assert_eq!(store.blocking_len(), 1);
    store.blocking_clear();
    assert_eq!(store.blocking_len(), 0);

    // try_load_sync_data works synchronously outside a Tokio runtime and skips atomically if contended
    assert!(store.try_load_sync_data(SyncData {
        ciphers: vec![Cipher {
            id: Some(id1),
            ..Default::default()
        }],
        ..Default::default()
    }));
    assert_eq!(store.blocking_len(), 1);

    let _guard = store.folders.blocking_write();
    assert!(!store.try_load_sync_data(SyncData::default()));
    drop(_guard);
    assert_eq!(store.blocking_len(), 1);
}

#[test]
fn test_vault_save_and_load_roundtrip() {
    let temp_dir = tempfile::tempdir().unwrap();
    let vault_path = temp_dir.path().join("sub").join("vault.json");

    let id = Uuid::new_v4();
    let original_data = SyncData {
        profile: Profile {
            id: Some(Uuid::new_v4()),
            email: Some("test@example.com".to_string()),
            name: Some("Tester".to_string()),
            ..Default::default()
        },
        folders: vec![Folder {
            id: Some(Uuid::new_v4()),
            name: Some("Personal".to_string()),
            revision_date: Some("2026-10-24T12:00:00Z".to_string()),
        }],
        ciphers: vec![Cipher {
            id: Some(id),
            r#type: CipherType::Login,
            favorite: true,
            ..Default::default()
        }],
    };

    // Atomic write
    save_vault(&vault_path, &original_data).expect("save_vault should succeed");
    assert!(vault_path.exists());

    // Load back
    let loaded_data = load_vault(&vault_path).expect("load_vault should succeed");
    assert_eq!(original_data, loaded_data);
}

#[test]
#[cfg(unix)]
fn test_vault_file_permissions_0600() {
    use std::os::unix::fs::PermissionsExt;

    let temp_dir = tempfile::tempdir().unwrap();
    let vault_paths = VaultPaths::new(temp_dir.path().join("secure_vault"));
    vault_paths.ensure_dirs().unwrap();

    // Check directory perms 0700
    let dir_meta = std::fs::metadata(vault_paths.base_dir()).unwrap();
    let dir_mode = dir_meta.permissions().mode() & 0o777;
    assert_eq!(dir_mode, 0o700, "Directory permissions must be 0700");

    let data = SyncData::default();
    let vault_file = vault_paths.vault_file();
    save_vault(&vault_file, &data).unwrap();

    let file_meta = std::fs::metadata(&vault_file).unwrap();
    let file_mode = file_meta.permissions().mode() & 0o777;
    assert_eq!(
        file_mode, 0o600,
        "Vault file permissions must be exactly 0600"
    );
}

#[tokio::test]
async fn test_vault_store_rwlock_concurrency() {
    use std::sync::Arc;

    let store = Arc::new(VaultStore::new());
    let mut handles = Vec::new();

    // Spawn 5 concurrent writers
    for i in 0..5 {
        let s = Arc::clone(&store);
        handles.push(tokio::spawn(async move {
            let id = Uuid::new_v4();
            let cipher = Cipher {
                id: Some(id),
                r#type: CipherType::Login,
                notes: Some(EncString::default()),
                ..Default::default()
            };
            s.insert(cipher).await;
            s.set_last_synced(1000 + i).await;
        }));
    }

    // Spawn 10 concurrent readers
    for _ in 0..10 {
        let s = Arc::clone(&store);
        handles.push(tokio::spawn(async move {
            let _len = s.len().await;
            let _all = s.all().await;
            let _sync = s.last_synced().await;
            let _snap = s.to_sync_data().await;
        }));
    }

    for h in handles {
        h.await.expect("Task should join cleanly without deadlocks");
    }

    assert_eq!(store.len().await, 5);
    assert!(store.last_synced().await.is_some());
}

#[test]
fn test_vault_load_nonexistent_and_corrupt_errors() {
    let temp_dir = tempfile::tempdir().unwrap();

    // Nonexistent
    let missing_path = temp_dir.path().join("does_not_exist.json");
    let res = load_vault(&missing_path);
    assert!(matches!(res, Err(VaultError::NotFound(_))));

    // Corrupted JSON
    let corrupt_path = temp_dir.path().join("corrupt.json");
    std::fs::write(&corrupt_path, b"{ this is invalid json ]").unwrap();
    let res_corrupt = load_vault(&corrupt_path);
    assert!(matches!(res_corrupt, Err(VaultError::Json(_))));
}

#[tokio::test]
async fn test_vault_paths_custom_and_default() {
    let temp_dir = tempfile::tempdir().unwrap();
    let paths = VaultPaths::new(temp_dir.path());
    assert_eq!(paths.base_dir(), temp_dir.path());
    assert_eq!(paths.vault_file(), temp_dir.path().join("vault.json"));

    let def_paths = VaultPaths::default();
    assert!(def_paths.vault_file().ends_with("vault.json"));
}

#[tokio::test]
async fn test_vault_async_save_and_load() {
    let temp_dir = tempfile::tempdir().unwrap();
    let path = temp_dir.path().join("async_vault.json");

    let sync_data = SyncData {
        profile: Profile {
            name: Some("Async User".to_string()),
            ..Default::default()
        },
        ..Default::default()
    };

    save_vault_async(path.clone(), sync_data.clone())
        .await
        .unwrap();
    let loaded = load_vault_async(path).await.unwrap();
    assert_eq!(loaded.profile.name.as_deref(), Some("Async User"));
}

#[test]
fn test_cipher_type_conversion_and_fallback() {
    assert_eq!(CipherType::try_from(1).unwrap(), CipherType::Login);
    assert_eq!(CipherType::try_from(2).unwrap(), CipherType::Note);
    assert_eq!(CipherType::try_from(3).unwrap(), CipherType::Card);
    assert_eq!(CipherType::try_from(4).unwrap(), CipherType::Identity);
    assert_eq!(CipherType::try_from(5).unwrap(), CipherType::SshKey);
    assert!(CipherType::try_from(99).is_err());

    assert_eq!(i32::from(CipherType::Login), 1);
    assert_eq!(i32::from(CipherType::SshKey), 5);

    // FieldType conversion
    assert_eq!(FieldType::from(0), FieldType::Text);
    assert_eq!(FieldType::from(1), FieldType::Hidden);
    assert_eq!(FieldType::from(2), FieldType::Boolean);
    assert_eq!(FieldType::from(3), FieldType::Linked);
    assert_eq!(FieldType::from(42), FieldType::Other(42));
    assert_eq!(i32::from(FieldType::Text), 0);
    assert_eq!(i32::from(FieldType::Other(42)), 42);

    // URIMatch conversion
    assert_eq!(URIMatch::from(0), URIMatch::Domain);
    assert_eq!(URIMatch::from(1), URIMatch::Host);
    assert_eq!(URIMatch::from(2), URIMatch::StartsWith);
    assert_eq!(URIMatch::from(3), URIMatch::Exact);
    assert_eq!(URIMatch::from(4), URIMatch::RegularExpression);
    assert_eq!(URIMatch::from(5), URIMatch::Never);
    assert_eq!(URIMatch::from(77), URIMatch::Other(77));
    assert_eq!(i32::from(URIMatch::Domain), 0);
    assert_eq!(i32::from(URIMatch::Other(77)), 77);

    // SecureNoteType conversion
    assert_eq!(SecureNoteType::from(0), SecureNoteType::Generic);
    assert_eq!(SecureNoteType::from(10), SecureNoteType::Other(10));
    assert_eq!(i32::from(SecureNoteType::Generic), 0);
    assert_eq!(i32::from(SecureNoteType::Other(10)), 10);
}

// --- SW-036 Test Helpers and Tests ---

pub(crate) fn make_test_key() -> SymmetricKey {
    SymmetricKey::from_bytes(&[0x42u8; 64]).expect("Failed to create 64-byte symmetric key")
}

pub(crate) fn make_encrypted_cipher(
    key: &SymmetricKey,
    name: &str,
    username: &str,
    password: &str,
) -> Cipher {
    let enc_name = encrypt_with(name.as_bytes(), EncStringType::AesCbc256HmacSha256B64, key)
        .expect("encrypt name");
    let enc_user = encrypt_with(
        username.as_bytes(),
        EncStringType::AesCbc256HmacSha256B64,
        key,
    )
    .expect("encrypt username");
    let enc_pass = encrypt_with(
        password.as_bytes(),
        EncStringType::AesCbc256HmacSha256B64,
        key,
    )
    .expect("encrypt password");

    Cipher {
        id: Some(Uuid::new_v4()),
        r#type: CipherType::Login,
        name: enc_name,
        login: Some(LoginCipher {
            username: Some(enc_user),
            password: Some(enc_pass),
            ..Default::default()
        }),
        deleted_date: None,
        ..Default::default()
    }
}

#[tokio::test]
async fn test_vault_store_get_logins() {
    let store = VaultStore::new();
    let key = make_test_key();

    // 3 logins
    let l1 = make_encrypted_cipher(&key, "Site 1", "user1", "pass1");
    let l2 = make_encrypted_cipher(&key, "Site 2", "user2", "pass2");
    let l3 = make_encrypted_cipher(&key, "Site 3", "user3", "pass3");

    // 1 note
    let mut note = make_encrypted_cipher(&key, "My Note", "user", "pass");
    note.r#type = CipherType::Note;
    note.login = None;

    // 1 deleted cipher
    let mut deleted = make_encrypted_cipher(&key, "Deleted Site", "user", "pass");
    deleted.deleted_date = Some("2026-10-24T00:00:00Z".to_string());

    store.insert(l1).await;
    store.insert(l2).await;
    store.insert(l3).await;
    store.insert(note).await;
    store.insert(deleted).await;

    let logins = store.get_logins().await;
    assert_eq!(logins.len(), 3);
    for login in &logins {
        assert_eq!(login.r#type, CipherType::Login);
        assert!(login.deleted_date.is_none());
    }
}

#[tokio::test]
async fn test_vault_store_get_notes() {
    let store = VaultStore::new();
    let key = make_test_key();

    // 3 notes
    let mut n1 = make_encrypted_cipher(&key, "Note 1", "u", "p");
    n1.r#type = CipherType::Note;
    n1.login = None;

    let mut n2 = make_encrypted_cipher(&key, "Note 2", "u", "p");
    n2.r#type = CipherType::Note;
    n2.login = None;

    let mut n3 = make_encrypted_cipher(&key, "Note 3", "u", "p");
    n3.r#type = CipherType::Note;
    n3.login = None;

    // 1 login
    let l1 = make_encrypted_cipher(&key, "Site 1", "user1", "pass1");

    // 1 deleted note
    let mut deleted_note = make_encrypted_cipher(&key, "Deleted Note", "u", "p");
    deleted_note.r#type = CipherType::Note;
    deleted_note.deleted_date = Some("2026-10-24T00:00:00Z".to_string());

    store.insert(n1).await;
    store.insert(n2).await;
    store.insert(n3).await;
    store.insert(l1).await;
    store.insert(deleted_note).await;

    let notes = store.get_notes().await;
    assert_eq!(notes.len(), 3);
    for note in &notes {
        assert_eq!(note.r#type, CipherType::Note);
        assert!(note.deleted_date.is_none());
    }
}

#[tokio::test]
async fn test_get_login_by_filter_name() {
    let store = VaultStore::new();
    let key = make_test_key();

    let l1 = make_encrypted_cipher(&key, "GitHub", "octocat", "pass1");
    let l2 = make_encrypted_cipher(&key, "GitLab", "gitlab_user", "pass2");
    let l1_id = l1.id;

    store.insert(l1).await;
    store.insert(l2).await;

    // Matching name
    let found = store
        .get_login_by_filter(None, None, Some("GitHub"), None, &key)
        .await;
    assert!(found.is_some());
    assert_eq!(found.unwrap().id, l1_id);

    // Non-matching name
    let not_found = store
        .get_login_by_filter(None, None, Some("Bitbucket"), None, &key)
        .await;
    assert!(not_found.is_none());
}

#[tokio::test]
async fn test_get_login_by_filter_username() {
    let store = VaultStore::new();
    let key = make_test_key();

    let l1 = make_encrypted_cipher(&key, "Service A", "alice@example.com", "pass1");
    let l2 = make_encrypted_cipher(&key, "Service B", "bob@example.com", "pass2");
    let l2_id = l2.id;

    store.insert(l1).await;
    store.insert(l2).await;

    // Matching username
    let found = store
        .get_login_by_filter(None, None, None, Some("bob@example.com"), &key)
        .await;
    assert!(found.is_some());
    assert_eq!(found.unwrap().id, l2_id);

    // Filter by uuid and username matching
    let found_with_id = store
        .get_login_by_filter(l2_id.as_ref(), None, None, Some("bob@example.com"), &key)
        .await;
    assert!(found_with_id.is_some());

    // Non-matching username
    let not_found = store
        .get_login_by_filter(None, None, None, Some("charlie@example.com"), &key)
        .await;
    assert!(not_found.is_none());
}

#[tokio::test]
async fn test_get_note_by_filter() {
    let store = VaultStore::new();
    let key = make_test_key();

    let mut n1 = make_encrypted_cipher(&key, "Meeting Notes", "u", "p");
    n1.r#type = CipherType::Note;
    n1.login = None;
    let org_uuid = Uuid::new_v4();
    n1.organization_id = Some(org_uuid);
    let n1_id = n1.id;

    store.insert(n1).await;

    // Filter by name and org
    let found = store
        .get_note_by_filter(None, Some(&org_uuid), Some("Meeting Notes"), &key)
        .await;
    assert!(found.is_some());
    assert_eq!(found.unwrap().id, n1_id);

    // Non-matching
    let not_found = store
        .get_note_by_filter(None, None, Some("Other Note"), &key)
        .await;
    assert!(not_found.is_none());
}

#[test]
fn test_decrypt_cipher_full() {
    let key = make_test_key();
    let cipher_id = Uuid::new_v4();

    let enc_name =
        encrypt_with(b"Bank Login", EncStringType::AesCbc256HmacSha256B64, &key).unwrap();
    let enc_user = encrypt_with(b"bankuser", EncStringType::AesCbc256HmacSha256B64, &key).unwrap();
    let enc_pass =
        encrypt_with(b"P@ssword123!", EncStringType::AesCbc256HmacSha256B64, &key).unwrap();
    let enc_uri = encrypt_with(
        b"https://bank.example.com",
        EncStringType::AesCbc256HmacSha256B64,
        &key,
    )
    .unwrap();
    let enc_notes =
        encrypt_with(b"PIN: 9876", EncStringType::AesCbc256HmacSha256B64, &key).unwrap();
    let enc_totp = encrypt_with(
        b"JBSWY3DPEHPK3PXP",
        EncStringType::AesCbc256HmacSha256B64,
        &key,
    )
    .unwrap();

    let cipher = Cipher {
        id: Some(cipher_id),
        r#type: CipherType::Login,
        name: enc_name,
        favorite: true,
        notes: Some(enc_notes),
        login: Some(LoginCipher {
            username: Some(enc_user),
            password: Some(enc_pass),
            uri: Some(enc_uri),
            totp: Some(enc_totp),
            ..Default::default()
        }),
        ..Default::default()
    };

    // Decrypt using VaultStore::decrypt_cipher
    let dec = VaultStore::decrypt_cipher(&cipher, &key).expect("Decryption must succeed");

    assert_eq!(dec.id, cipher_id);
    assert_eq!(dec.name, "Bank Login");
    assert_eq!(dec.cipher_type, CipherType::Login);
    assert_eq!(dec.username.as_deref(), Some("bankuser"));
    assert_eq!(dec.password.as_deref(), Some("P@ssword123!"));
    assert_eq!(dec.uri.as_deref(), Some("https://bank.example.com"));
    assert_eq!(dec.notes.as_deref(), Some("PIN: 9876"));
    assert_eq!(dec.totp.as_deref(), Some("JBSWY3DPEHPK3PXP"));
    assert!(dec.favorite);

    // Also test cipher.decrypt(&key) convenience method
    let dec2 = cipher
        .decrypt(&key)
        .expect("Convenience decrypt must succeed");
    assert_eq!(dec, dec2);
}

#[test]
fn test_decrypt_cipher_with_null_fields() {
    let key = make_test_key();
    let cipher_id = Uuid::new_v4();

    let enc_name =
        encrypt_with(b"Empty Note", EncStringType::AesCbc256HmacSha256B64, &key).unwrap();

    let cipher = Cipher {
        id: Some(cipher_id),
        r#type: CipherType::Note,
        name: enc_name,
        favorite: false,
        notes: None,
        login: None,
        ..Default::default()
    };

    let dec = VaultStore::decrypt_cipher(&cipher, &key).expect("Decryption must succeed");

    assert_eq!(dec.id, cipher_id);
    assert_eq!(dec.name, "Empty Note");
    assert_eq!(dec.cipher_type, CipherType::Note);
    assert_eq!(dec.username, None);
    assert_eq!(dec.password, None);
    assert_eq!(dec.uri, None);
    assert_eq!(dec.notes, None);
    assert_eq!(dec.totp, None);
    assert!(!dec.favorite);
}

#[test]
fn test_decrypt_cipher_error_on_null_name() {
    let key = make_test_key();
    let cipher = Cipher {
        id: Some(Uuid::new_v4()),
        r#type: CipherType::Note,
        name: EncString::default(),
        ..Default::default()
    };

    let res = VaultStore::decrypt_cipher(&cipher, &key);
    assert!(res.is_err());
}

#[test]
fn test_decrypt_cipher_with_organization_cipher_key() {
    let user_key = make_test_key();
    let org_cipher_key = SymmetricKey::from_bytes(&[0x99u8; 64]).unwrap();
    let cipher_id = Uuid::new_v4();

    // Encrypt the cipher key with user key
    let enc_cipher_key = encrypt_with(
        &org_cipher_key.bytes(),
        EncStringType::AesCbc256HmacSha256B64,
        &user_key,
    )
    .unwrap();

    // Encrypt name and username with the org_cipher_key
    let enc_name = encrypt_with(
        b"Org Item",
        EncStringType::AesCbc256HmacSha256B64,
        &org_cipher_key,
    )
    .unwrap();
    let enc_user = encrypt_with(
        b"org_user",
        EncStringType::AesCbc256HmacSha256B64,
        &org_cipher_key,
    )
    .unwrap();

    let cipher = Cipher {
        id: Some(cipher_id),
        r#type: CipherType::Login,
        key: Some(enc_cipher_key),
        name: enc_name,
        login: Some(LoginCipher {
            username: Some(enc_user),
            ..Default::default()
        }),
        ..Default::default()
    };

    let dec =
        VaultStore::decrypt_cipher(&cipher, &user_key).expect("Should decrypt using cipher.key");
    assert_eq!(dec.id, cipher_id);
    assert_eq!(dec.name, "Org Item");
    assert_eq!(dec.username.as_deref(), Some("org_user"));
}

#[tokio::test]
async fn test_search_matches_name_and_username() {
    let store = VaultStore::new();
    let key = make_test_key();

    let l1 = make_encrypted_cipher(&key, "GitHub Production", "devops_lead", "pass1");
    let l2 = make_encrypted_cipher(&key, "AWS Console", "github-sync-bot", "pass2");
    let mut note = make_encrypted_cipher(&key, "Secret Database Notes", "none", "none");
    note.r#type = CipherType::Note;
    note.login = None;

    let mut deleted = make_encrypted_cipher(&key, "GitHub Staging", "staging_user", "pass");
    deleted.deleted_date = Some("2026-10-24T00:00:00Z".to_string());

    store.insert(l1).await;
    store.insert(l2).await;
    store.insert(note).await;
    store.insert(deleted).await;

    // Search matching name ("GitHub") -> should match l1 by name and l2 by username ("github-sync-bot"), ignoring deleted
    let results = store.search("GitHub", &key).await;
    assert_eq!(results.len(), 2);
    let names: Vec<&str> = results.iter().map(|r| r.name.as_str()).collect();
    assert!(names.contains(&"GitHub Production"));
    assert!(names.contains(&"AWS Console"));

    // Search matching username ("devops") -> should match l1
    let devops_results = store.search("devops", &key).await;
    assert_eq!(devops_results.len(), 1);
    assert_eq!(devops_results[0].name, "GitHub Production");

    // Search matching note by name ("Database")
    let db_results = store.search("Database", &key).await;
    assert_eq!(db_results.len(), 1);
    assert_eq!(db_results[0].name, "Secret Database Notes");

    // Search non-existent
    let empty_results = store.search("NoSuchEntry12345", &key).await;
    assert!(empty_results.is_empty());
}

#[test]
fn test_vault_store_blocking_filtering_and_search() {
    let store = VaultStore::new();
    let key = make_test_key();

    let l1 = make_encrypted_cipher(&key, "GitHub", "octocat", "pass1");
    let mut n1 = make_encrypted_cipher(&key, "Meeting Notes", "u", "p");
    n1.r#type = CipherType::Note;
    n1.login = None;
    let n1_id = n1.id;
    let l1_id = l1.id;

    store.blocking_insert(l1);
    store.blocking_insert(n1);

    assert_eq!(store.blocking_get_logins().len(), 1);
    assert_eq!(store.blocking_get_notes().len(), 1);

    let found_login = store.blocking_get_login_by_filter(None, None, Some("GitHub"), None, &key);
    assert_eq!(found_login.unwrap().id, l1_id);

    let found_note = store.blocking_get_note_by_filter(n1_id.as_ref(), None, None, &key);
    assert_eq!(found_note.unwrap().id, n1_id);

    let search_res = store.blocking_search("Git", &key);
    assert_eq!(search_res.len(), 1);
    assert_eq!(search_res[0].name, "GitHub");
}

#[test]
fn test_vault_errors_display() {
    let err_api = VaultError::Api("sync timeout".into());
    assert!(format!("{err_api}").contains("sync timeout"));

    let err_other = VaultError::Other("custom error".into());
    assert!(format!("{err_other}").contains("custom error"));

    let err_crypto = VaultError::Crypto(sw_crypto::CryptoError::InvalidKeyLength(
        "32 bytes expected".into(),
    ));
    assert!(format!("{err_crypto}").contains("32 bytes expected"));

    let utf8_err = String::from_utf8(vec![0xFF]).unwrap_err();
    let err_utf8 = VaultError::Utf8(utf8_err);
    assert!(format!("{err_utf8}").contains("UTF-8"));
}

#[test]
fn test_vault_paths_default_paths() {
    let paths = VaultPaths::default_paths();
    if let Ok(p) = paths {
        assert!(p.vault_file().ends_with("vault.json"));
    }
}

#[test]
fn test_decrypt_cipher_uri_fallback_and_login_cases() {
    let key = make_test_key();
    let id = Uuid::new_v4();

    // Case 1: login.uri is null EncString, but login.uris has a URI
    let enc_name = encrypt_with(
        b"Test URI Fallback",
        EncStringType::AesCbc256HmacSha256B64,
        &key,
    )
    .unwrap();
    let cipher1 = Cipher {
        id: Some(id),
        r#type: CipherType::Login,
        name: enc_name.clone(),
        login: Some(LoginCipher {
            uri: Some(EncString::default()),
            uris: vec![URI {
                uri: Some("https://uris-fallback.example.com".into()),
                r#match: Some(URIMatch::Domain),
            }],
            ..Default::default()
        }),
        ..Default::default()
    };
    let dec1 = VaultStore::decrypt_cipher(&cipher1, &key).unwrap();
    assert_eq!(
        dec1.uri.as_deref(),
        Some("https://uris-fallback.example.com")
    );

    // Case 2: login.uri is None, and login.uris has a URI
    let cipher2 = Cipher {
        id: Some(id),
        r#type: CipherType::Login,
        name: enc_name.clone(),
        login: Some(LoginCipher {
            uri: None,
            uris: vec![URI {
                uri: Some("https://uris-none.example.com".into()),
                r#match: None,
            }],
            ..Default::default()
        }),
        ..Default::default()
    };
    let dec2 = VaultStore::decrypt_cipher(&cipher2, &key).unwrap();
    assert_eq!(dec2.uri.as_deref(), Some("https://uris-none.example.com"));

    // Case 3: login.uri is None, login.uris is empty
    let cipher3 = Cipher {
        id: Some(id),
        r#type: CipherType::Login,
        name: enc_name,
        login: Some(LoginCipher {
            uri: None,
            uris: vec![],
            ..Default::default()
        }),
        ..Default::default()
    };
    let dec3 = VaultStore::decrypt_cipher(&cipher3, &key).unwrap();
    assert_eq!(dec3.uri, None);
}

#[tokio::test]
async fn test_filter_edge_cases() {
    let store = VaultStore::new();
    let key = make_test_key();
    let org_a = Uuid::new_v4();
    let org_b = Uuid::new_v4();

    let mut l1 = make_encrypted_cipher(&key, "Alpha", "user_alpha", "pass");
    l1.organization_id = Some(org_a);

    let mut l2 = make_encrypted_cipher(&key, "Beta", "user_beta", "pass");
    l2.organization_id = Some(org_b);

    // Cipher with no login
    let mut l_no_login = make_encrypted_cipher(&key, "NoLogin", "none", "pass");
    l_no_login.login = None;

    // Cipher with null username
    let mut l_null_un = make_encrypted_cipher(&key, "NullUser", "none", "pass");
    l_null_un.login = Some(LoginCipher {
        username: Some(EncString::default()),
        ..Default::default()
    });

    // Cipher with null name
    let l_null_name = Cipher {
        id: Some(Uuid::new_v4()),
        r#type: CipherType::Login,
        name: EncString::default(),
        ..Default::default()
    };

    store.insert(l1.clone()).await;
    store.insert(l2.clone()).await;
    store.insert(l_no_login).await;
    store.insert(l_null_un).await;
    store.insert(l_null_name).await;

    // Match with org_id
    let found_org = store
        .get_login_by_filter(None, Some(&org_a), None, None, &key)
        .await;
    assert_eq!(found_org.unwrap().id, l1.id);

    // Org mismatch
    let nonexistent_org = Uuid::new_v4();
    let not_found_org = store
        .get_login_by_filter(None, Some(&nonexistent_org), None, None, &key)
        .await;
    assert!(not_found_org.is_none());

    // Username filter on cipher without login
    let not_found_user = store
        .get_login_by_filter(None, None, Some("NoLogin"), Some("any"), &key)
        .await;
    assert!(not_found_user.is_none());

    // Username filter on cipher with null username
    let not_found_null_user = store
        .get_login_by_filter(None, None, Some("NullUser"), Some("any"), &key)
        .await;
    assert!(not_found_null_user.is_none());

    // Note filter edge cases
    let mut note = make_encrypted_cipher(&key, "Special Note", "u", "p");
    note.r#type = CipherType::Note;
    note.login = None;
    note.organization_id = Some(org_a);
    let note_id = note.id.unwrap();
    store.insert(note).await;

    // Note filter with uuid
    let found_note_id = store
        .get_note_by_filter(Some(&note_id), None, None, &key)
        .await;
    assert!(found_note_id.is_some());

    // Note filter with mismatched uuid
    let wrong_id = Uuid::new_v4();
    let not_found_note_id = store
        .get_note_by_filter(Some(&wrong_id), None, None, &key)
        .await;
    assert!(not_found_note_id.is_none());

    // Note filter with mismatched org
    let not_found_note_org = store
        .get_note_by_filter(None, Some(&org_b), None, &key)
        .await;
    assert!(not_found_note_org.is_none());
}

#[test]
fn test_all_enum_conversions() {
    // CipherType
    for (i, ct) in [
        (1, CipherType::Login),
        (2, CipherType::Note),
        (3, CipherType::Card),
        (4, CipherType::Identity),
        (5, CipherType::SshKey),
    ] {
        assert_eq!(CipherType::try_from(i).unwrap(), ct);
        assert_eq!(i32::from(ct), i);
    }
    assert!(CipherType::try_from(0).is_err());
    assert!(CipherType::try_from(6).is_err());

    // FieldType
    for (i, ft) in [
        (0, FieldType::Text),
        (1, FieldType::Hidden),
        (2, FieldType::Boolean),
        (3, FieldType::Linked),
        (99, FieldType::Other(99)),
    ] {
        assert_eq!(FieldType::from(i), ft);
        assert_eq!(i32::from(ft), i);
    }

    // URIMatch
    for (i, um) in [
        (0, URIMatch::Domain),
        (1, URIMatch::Host),
        (2, URIMatch::StartsWith),
        (3, URIMatch::Exact),
        (4, URIMatch::RegularExpression),
        (5, URIMatch::Never),
        (99, URIMatch::Other(99)),
    ] {
        assert_eq!(URIMatch::from(i), um);
        assert_eq!(i32::from(um), i);
    }

    // SecureNoteType
    assert_eq!(SecureNoteType::from(0), SecureNoteType::Generic);
    assert_eq!(i32::from(SecureNoteType::Generic), 0);
    assert_eq!(SecureNoteType::from(99), SecureNoteType::Other(99));
    assert_eq!(i32::from(SecureNoteType::Other(99)), 99);
}

#[tokio::test]
async fn test_get_ssh_keys_extraction() {
    let key = make_test_key();
    let store = VaultStore::new();

    let priv_key_1 =
        "-----BEGIN OPENSSH PRIVATE KEY-----\ntestkey1\n-----END OPENSSH PRIVATE KEY-----\n";
    let pub_key_1 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... user@test1";
    let enc_name_1 = encrypt_with(
        b"id_ed25519_test",
        EncStringType::AesCbc256HmacSha256B64,
        &key,
    )
    .unwrap();
    let enc_priv_1 = encrypt_with(
        priv_key_1.as_bytes(),
        EncStringType::AesCbc256HmacSha256B64,
        &key,
    )
    .unwrap();
    let enc_pub_1 = encrypt_with(
        pub_key_1.as_bytes(),
        EncStringType::AesCbc256HmacSha256B64,
        &key,
    )
    .unwrap();

    let cipher_ssh = Cipher {
        id: Some(Uuid::new_v4()),
        r#type: CipherType::SshKey,
        name: enc_name_1,
        ssh_key: Some(SSHKeyCipher {
            private_key: Some(enc_priv_1),
            public_key: Some(enc_pub_1),
            key_fingerprint: None,
        }),
        ..Default::default()
    };

    // Note-based SSH key
    let priv_key_2 = "-----BEGIN RSA PRIVATE KEY----- AAAA BBBB -----END RSA PRIVATE KEY-----";
    let pub_key_2 = "ssh-rsa AAAAB3NzaC1yc2E... user@test2";
    let enc_name_2 =
        encrypt_with(b"id_rsa_note", EncStringType::AesCbc256HmacSha256B64, &key).unwrap();
    let enc_fn_custom =
        encrypt_with(b"custom-type", EncStringType::AesCbc256HmacSha256B64, &key).unwrap();
    let enc_fv_custom =
        encrypt_with(b"ssh-key", EncStringType::AesCbc256HmacSha256B64, &key).unwrap();
    let enc_fn_priv =
        encrypt_with(b"private-key", EncStringType::AesCbc256HmacSha256B64, &key).unwrap();
    let enc_fv_priv = encrypt_with(
        priv_key_2.as_bytes(),
        EncStringType::AesCbc256HmacSha256B64,
        &key,
    )
    .unwrap();
    let enc_fn_pub =
        encrypt_with(b"public-key", EncStringType::AesCbc256HmacSha256B64, &key).unwrap();
    let enc_fv_pub = encrypt_with(
        pub_key_2.as_bytes(),
        EncStringType::AesCbc256HmacSha256B64,
        &key,
    )
    .unwrap();

    let cipher_note = Cipher {
        id: Some(Uuid::new_v4()),
        r#type: CipherType::Note,
        name: enc_name_2,
        fields: vec![
            Field {
                r#type: Some(FieldType::Text),
                name: Some(enc_fn_custom),
                value: Some(enc_fv_custom),
            },
            Field {
                r#type: Some(FieldType::Hidden),
                name: Some(enc_fn_priv),
                value: Some(enc_fv_priv),
            },
            Field {
                r#type: Some(FieldType::Text),
                name: Some(enc_fn_pub),
                value: Some(enc_fv_pub),
            },
        ],
        ..Default::default()
    };

    // Deleted cipher should be ignored
    let mut cipher_deleted = cipher_ssh.clone();
    cipher_deleted.id = Some(Uuid::new_v4());
    cipher_deleted.deleted_date = Some("2026-10-26T00:00:00Z".to_string());

    store.insert(cipher_ssh).await;
    store.insert(cipher_note).await;
    store.insert(cipher_deleted).await;

    // get_ssh_keys extracts Type 5 ciphers
    let type5_keys = store.get_ssh_keys(&key).await.unwrap();
    assert_eq!(type5_keys.len(), 1);
    let key1 = &type5_keys[0];
    assert_eq!(key1.name, "id_ed25519_test");
    assert_eq!(key1.private_key, priv_key_1.trim());
    assert_eq!(key1.public_key.as_deref(), Some(pub_key_1));

    // extract_ssh_keys extracts legacy Secure Notes
    let legacy_keys = store.extract_ssh_keys(&key).await.unwrap();
    assert_eq!(legacy_keys.len(), 1);
    let key2 = &legacy_keys[0];
    assert_eq!(key2.name, "id_rsa_note");
    assert!(key2.private_key.contains("-----BEGIN RSA PRIVATE KEY-----"));
    assert!(key2.private_key.contains("-----END RSA PRIVATE KEY-----"));
    assert_eq!(key2.public_key.as_deref(), Some(pub_key_2));

    // Blocking variants
    let store_arc = std::sync::Arc::new(store);
    let key_bytes = key.bytes();
    let (blocking_type5, blocking_legacy) = tokio::task::spawn_blocking(move || {
        let k = SymmetricKey::from_bytes(&key_bytes).unwrap();
        (
            store_arc.blocking_get_ssh_keys(&k).unwrap(),
            store_arc.blocking_extract_ssh_keys(&k).unwrap(),
        )
    })
    .await
    .unwrap();
    assert_eq!(blocking_type5.len(), 1);
    assert_eq!(blocking_legacy.len(), 1);
}

#[tokio::test]
async fn test_sync_regression_all_cipher_types_including_ssh_keys() {
    let key = SymmetricKey::from_bytes(&[0x77u8; 64]).unwrap();

    let enc_name =
        |s: &str| encrypt_with(s.as_bytes(), EncStringType::AesCbc256HmacSha256B64, &key).unwrap();

    let cipher_login = Cipher {
        id: Some(Uuid::new_v4()),
        r#type: CipherType::Login,
        name: enc_name("Login Item"),
        login: Some(LoginCipher {
            username: Some(enc_name("user")),
            password: Some(enc_name("pass")),
            ..Default::default()
        }),
        ..Default::default()
    };

    let cipher_note = Cipher {
        id: Some(Uuid::new_v4()),
        r#type: CipherType::Note,
        name: enc_name("Note Item"),
        ..Default::default()
    };

    let cipher_card = Cipher {
        id: Some(Uuid::new_v4()),
        r#type: CipherType::Card,
        name: enc_name("Card Item"),
        ..Default::default()
    };

    let cipher_identity = Cipher {
        id: Some(Uuid::new_v4()),
        r#type: CipherType::Identity,
        name: enc_name("Identity Item"),
        ..Default::default()
    };

    let cipher_ssh_1 = Cipher {
        id: Some(Uuid::new_v4()),
        r#type: CipherType::SshKey,
        name: enc_name("SSH Key 1"),
        ssh_key: Some(SSHKeyCipher {
            private_key: Some(enc_name("priv_key_1")),
            public_key: Some(enc_name("pub_key_1")),
            key_fingerprint: None,
        }),
        ..Default::default()
    };

    let cipher_ssh_2 = Cipher {
        id: Some(Uuid::new_v4()),
        r#type: CipherType::SshKey,
        name: enc_name("SSH Key 2"),
        ssh_key: Some(SSHKeyCipher {
            private_key: Some(enc_name("priv_key_2")),
            public_key: Some(enc_name("pub_key_2")),
            key_fingerprint: None,
        }),
        ..Default::default()
    };

    let sync_data = SyncData {
        ciphers: vec![
            cipher_login,
            cipher_note,
            cipher_card,
            cipher_identity,
            cipher_ssh_1,
            cipher_ssh_2,
        ],
        ..Default::default()
    };

    let store = VaultStore::new();
    store.load_sync_data(sync_data).await;

    // Verify that load_sync_data inserted all 6 items
    assert_eq!(store.len().await, 6);

    // Verify get_logins() returns 1
    let logins = store.get_logins().await;
    assert_eq!(logins.len(), 1);
    assert_eq!(logins[0].r#type, CipherType::Login);

    // Verify get_ssh_keys() returns 2
    let ssh_keys = store.get_ssh_keys(&key).await.unwrap();
    assert_eq!(ssh_keys.len(), 2);
    let mut names: Vec<String> = ssh_keys.into_iter().map(|k| k.name).collect();
    names.sort();
    assert_eq!(names, vec!["SSH Key 1", "SSH Key 2"]);
}

// ---------------------------------------------------------------------------
// Tests de caracterización (orden 2.2.4)
//
// Congelan el contrato observable antes del split de `sw-vault`: nombres de
// campo JSON, mapeo numérico de enums, tolerancia a `null` y mensajes de error.
// No describen lo que el código *debería* hacer, sino lo que hace hoy.
// ---------------------------------------------------------------------------

/// Ordena una lista de claves para compararla con `serde_json::Value`, que
/// ordena las claves alfabéticamente.
fn sorted(keys: &[&'static str]) -> Vec<&'static str> {
    let mut v = keys.to_vec();
    v.sort_unstable();
    v
}

#[test]
fn caracterizacion_enums_numericos() {
    // CipherType: 1..=5, el resto es error (no hay variante `Other`).
    assert_eq!(i32::from(CipherType::Login), 1);
    assert_eq!(i32::from(CipherType::Note), 2);
    assert_eq!(i32::from(CipherType::Card), 3);
    assert_eq!(i32::from(CipherType::Identity), 4);
    assert_eq!(i32::from(CipherType::SshKey), 5);
    assert_eq!(CipherType::try_from(1), Ok(CipherType::Login));
    assert_eq!(
        CipherType::try_from(99),
        Err("Unknown CipherType: 99".to_string())
    );

    // FieldType: 0..=3 conocidos, el resto cae en `Other`.
    assert_eq!(i32::from(FieldType::Text), 0);
    assert_eq!(i32::from(FieldType::Hidden), 1);
    assert_eq!(i32::from(FieldType::Boolean), 2);
    assert_eq!(i32::from(FieldType::Linked), 3);
    assert_eq!(FieldType::from(42), FieldType::Other(42));
    assert_eq!(i32::from(FieldType::Other(42)), 42);

    // URIMatch: 0..=5 conocidos, el resto cae en `Other`.
    assert_eq!(i32::from(URIMatch::Domain), 0);
    assert_eq!(i32::from(URIMatch::Host), 1);
    assert_eq!(i32::from(URIMatch::StartsWith), 2);
    assert_eq!(i32::from(URIMatch::Exact), 3);
    assert_eq!(i32::from(URIMatch::RegularExpression), 4);
    assert_eq!(i32::from(URIMatch::Never), 5);
    assert_eq!(URIMatch::from(9), URIMatch::Other(9));
    assert_eq!(i32::from(URIMatch::Other(9)), 9);

    // SecureNoteType: 0 conocido, el resto cae en `Other`.
    assert_eq!(i32::from(SecureNoteType::Generic), 0);
    assert_eq!(SecureNoteType::from(7), SecureNoteType::Other(7));
    assert_eq!(i32::from(SecureNoteType::Other(7)), 7);
}

#[test]
fn caracterizacion_json_uri_y_field() {
    let uri = URI {
        uri: Some("https://example.com".to_string()),
        r#match: Some(URIMatch::Domain),
    };
    assert_eq!(
        serde_json::to_value(&uri).unwrap(),
        serde_json::json!({ "uri": "https://example.com", "match": 0 })
    );

    let field = Field {
        r#type: Some(FieldType::Hidden),
        name: Some(EncString::default()),
        value: Some(EncString::default()),
    };
    assert_eq!(
        serde_json::to_value(&field).unwrap(),
        serde_json::json!({ "type": 1, "name": "", "value": "" })
    );
}

#[test]
fn caracterizacion_json_login_cipher() {
    let login = LoginCipher::default();
    assert_eq!(
        serde_json::to_value(&login).unwrap(),
        serde_json::json!({
            "password": null,
            "uris": [],
            "username": null,
            "totp": null
        })
    );

    // `uri` se omite cuando es `None`, pero aparece como cadena vacía con `Some(default)`.
    let with_uri = LoginCipher {
        uri: Some(EncString::default()),
        ..Default::default()
    };
    assert_eq!(
        serde_json::to_value(&with_uri).unwrap()["uri"],
        serde_json::json!("")
    );
}

#[test]
fn caracterizacion_json_payloads_de_cipher() {
    assert_eq!(
        serde_json::to_value(SSHKeyCipher::default()).unwrap(),
        serde_json::json!({
            "privateKey": null,
            "publicKey": null,
            "keyFingerprint": null
        })
    );

    assert_eq!(
        serde_json::to_value(Card::default()).unwrap(),
        serde_json::json!({
            "cardholderName": null,
            "brand": null,
            "number": null,
            "expMonth": null,
            "expYear": null,
            "code": null
        })
    );

    assert_eq!(
        serde_json::to_value(SecureNoteCipher {
            r#type: Some(SecureNoteType::Generic)
        })
        .unwrap(),
        serde_json::json!({ "type": 0 })
    );

    let identity = serde_json::to_value(Identity::default()).unwrap();
    let mut keys: Vec<&str> = identity
        .as_object()
        .unwrap()
        .keys()
        .map(|k| k.as_str())
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        sorted(&[
            "title",
            "firstName",
            "middleName",
            "lastName",
            "username",
            "company",
            "ssn",
            "passportNumber",
            "licenseNumber",
            "email",
            "phone",
            "address1",
            "address2",
            "address3",
            "city",
            "state",
            "postalCode",
            "country"
        ])
    );
    assert!(identity.as_object().unwrap().values().all(|v| v.is_null()));
}

#[test]
fn caracterizacion_json_folder_organization_profile() {
    assert_eq!(
        serde_json::to_value(Folder::default()).unwrap(),
        serde_json::json!({ "id": null, "name": null, "revisionDate": null })
    );

    let org = serde_json::to_value(Organization::default()).unwrap();
    let mut keys: Vec<&str> = org
        .as_object()
        .unwrap()
        .keys()
        .map(|k| k.as_str())
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        sorted(&[
            "object",
            "id",
            "name",
            "useGroups",
            "useDirectory",
            "useEvents",
            "useTotp",
            "use2fa",
            "useApi",
            "usersGetPremium",
            "selfHost",
            "seats",
            "maxCollections",
            "maxStorageGb",
            "key",
            "status",
            "type",
            "enabled"
        ])
    );
    assert_eq!(org["enabled"], serde_json::json!(false));

    let profile = serde_json::to_value(Profile::default()).unwrap();
    let mut keys: Vec<&str> = profile
        .as_object()
        .unwrap()
        .keys()
        .map(|k| k.as_str())
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        sorted(&[
            "id",
            "name",
            "email",
            "emailVerified",
            "premium",
            "masterPasswordHint",
            "culture",
            "twoFactorEnabled",
            "key",
            "privateKey",
            "securityStamp",
            "organizations"
        ])
    );
    assert_eq!(profile["organizations"], serde_json::json!([]));
}

#[test]
fn caracterizacion_json_cipher_default_omite_opcionales() {
    let value = serde_json::to_value(Cipher::default()).unwrap();
    let mut keys: Vec<&str> = value
        .as_object()
        .unwrap()
        .keys()
        .map(|k| k.as_str())
        .collect();
    keys.sort_unstable();

    // `id`, `encryptedFor`, `sshKey`, `key`, `edit`, `revisionDate`,
    // `deletedDate`, `attachments`, `organizationUseTotp` y `collectionIds`
    // se omiten por `skip_serializing_if`.
    assert_eq!(
        keys,
        sorted(&[
            "type",
            "name",
            "notes",
            "favorite",
            "reprompt",
            "folderId",
            "organizationId",
            "fields",
            "login",
            "secureNote",
            "card",
            "identity"
        ])
    );
    assert_eq!(value["type"], serde_json::json!(1));
    assert_eq!(value["name"], serde_json::json!(""));
    assert_eq!(value["fields"], serde_json::json!([]));
}

#[test]
fn caracterizacion_json_sync_data() {
    assert_eq!(
        serde_json::to_value(SyncData::default()).unwrap(),
        serde_json::json!({
            "profile": {
                "id": null,
                "name": null,
                "email": null,
                "emailVerified": false,
                "premium": false,
                "masterPasswordHint": null,
                "culture": null,
                "twoFactorEnabled": false,
                "key": null,
                "privateKey": null,
                "securityStamp": null,
                "organizations": []
            },
            "folders": [],
            "ciphers": []
        })
    );
}

#[test]
fn caracterizacion_json_decrypted_cipher_y_vault_ssh_key() {
    let decrypted = DecryptedCipher {
        id: Uuid::nil(),
        name: "Ejemplo".to_string(),
        cipher_type: CipherType::Login,
        username: Some("user".to_string()),
        password: Some("pass".to_string()),
        uri: Some("https://example.com".to_string()),
        notes: None,
        totp: None,
        favorite: false,
    };
    // Sin `rename_all`: las claves son snake_case.
    assert_eq!(
        serde_json::to_value(&decrypted).unwrap(),
        serde_json::json!({
            "id": "00000000-0000-0000-0000-000000000000",
            "name": "Ejemplo",
            "cipher_type": 1,
            "username": "user",
            "password": "pass",
            "uri": "https://example.com",
            "notes": null,
            "totp": null,
            "favorite": false
        })
    );

    let ssh_key = VaultSshKey {
        id: None,
        name: "id_ed25519".to_string(),
        private_key: "PRIVATE".to_string(),
        public_key: Some("ssh-ed25519 AAAA".to_string()),
    };
    assert_eq!(
        serde_json::to_value(&ssh_key).unwrap(),
        serde_json::json!({
            "id": null,
            "name": "id_ed25519",
            "private_key": "PRIVATE",
            "public_key": "ssh-ed25519 AAAA"
        })
    );
}

#[test]
fn caracterizacion_deserializa_null_como_vec_vacio() {
    let cipher: Cipher = serde_json::from_str(
        r#"{
            "type": 1,
            "name": "",
            "fields": null,
            "collectionIds": null,
            "login": { "uris": null }
        }"#,
    )
    .expect("null debe tolerarse en fields/collectionIds/uris");

    assert!(cipher.fields.is_empty());
    assert!(cipher.collection_ids.is_empty());
    assert!(cipher.login.unwrap().uris.is_empty());
}

#[test]
fn caracterizacion_deserializa_tipos_numericos() {
    let cipher: Cipher = serde_json::from_str(r#"{ "type": 5, "name": "" }"#).unwrap();
    assert_eq!(cipher.r#type, CipherType::SshKey);

    let err = serde_json::from_str::<Cipher>(r#"{ "type": 99, "name": "" }"#)
        .expect_err("99 no es un CipherType válido");
    assert!(
        err.to_string().contains("Unknown CipherType: 99"),
        "mensaje inesperado: {err}"
    );
}

#[test]
fn caracterizacion_errores_display() {
    assert_eq!(
        VaultError::Api("boom".to_string()).to_string(),
        "API error during sync: boom"
    );
    assert_eq!(
        VaultError::Other("raro".to_string()).to_string(),
        "Vault error: raro"
    );
    assert_eq!(
        VaultError::NotFound(PathBuf::from("/tmp/vault.json")).to_string(),
        "Vault file not found at: /tmp/vault.json"
    );
    assert_eq!(
        VaultError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "nope")).to_string(),
        "IO error: nope"
    );
}
