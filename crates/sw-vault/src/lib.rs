use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use sw_crypto::EncString;
use uuid::Uuid;

/// Bitwarden cipher types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(try_from = "i32", into = "i32")]
pub enum CipherType {
    #[default]
    Login = 1,
    Note = 2,
    Card = 3,
    Identity = 4,
    SshKey = 5,
}

impl TryFrom<i32> for CipherType {
    type Error = String;

    fn try_from(v: i32) -> Result<Self, Self::Error> {
        match v {
            1 => Ok(Self::Login),
            2 => Ok(Self::Note),
            3 => Ok(Self::Card),
            4 => Ok(Self::Identity),
            5 => Ok(Self::SshKey),
            other => Err(format!("Unknown CipherType: {other}")),
        }
    }
}

impl From<CipherType> for i32 {
    fn from(c: CipherType) -> Self {
        c as i32
    }
}

/// Bitwarden custom field types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(from = "i32", into = "i32")]
pub enum FieldType {
    #[default]
    Text,
    Hidden,
    Boolean,
    Linked,
    Other(i32),
}

impl From<i32> for FieldType {
    fn from(v: i32) -> Self {
        match v {
            0 => Self::Text,
            1 => Self::Hidden,
            2 => Self::Boolean,
            3 => Self::Linked,
            other => Self::Other(other),
        }
    }
}

impl From<FieldType> for i32 {
    fn from(f: FieldType) -> Self {
        match f {
            FieldType::Text => 0,
            FieldType::Hidden => 1,
            FieldType::Boolean => 2,
            FieldType::Linked => 3,
            FieldType::Other(o) => o,
        }
    }
}

/// Bitwarden URI matching algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(from = "i32", into = "i32")]
pub enum URIMatch {
    #[default]
    Domain,
    Host,
    StartsWith,
    Exact,
    RegularExpression,
    Never,
    Other(i32),
}

impl From<i32> for URIMatch {
    fn from(v: i32) -> Self {
        match v {
            0 => Self::Domain,
            1 => Self::Host,
            2 => Self::StartsWith,
            3 => Self::Exact,
            4 => Self::RegularExpression,
            5 => Self::Never,
            other => Self::Other(other),
        }
    }
}

impl From<URIMatch> for i32 {
    fn from(u: URIMatch) -> Self {
        match u {
            URIMatch::Domain => 0,
            URIMatch::Host => 1,
            URIMatch::StartsWith => 2,
            URIMatch::Exact => 3,
            URIMatch::RegularExpression => 4,
            URIMatch::Never => 5,
            URIMatch::Other(o) => o,
        }
    }
}

/// Bitwarden secure note types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(from = "i32", into = "i32")]
pub enum SecureNoteType {
    #[default]
    Generic,
    Other(i32),
}

impl From<i32> for SecureNoteType {
    fn from(v: i32) -> Self {
        match v {
            0 => Self::Generic,
            other => Self::Other(other),
        }
    }
}

impl From<SecureNoteType> for i32 {
    fn from(s: SecureNoteType) -> Self {
        match s {
            SecureNoteType::Generic => 0,
            SecureNoteType::Other(o) => o,
        }
    }
}

/// URI entry associated with a login cipher
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct URI {
    #[serde(default)]
    pub uri: Option<String>,
    #[serde(default, rename = "match")]
    pub r#match: Option<URIMatch>,
}

/// Custom field in a cipher
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Field {
    #[serde(default, rename = "type")]
    pub r#type: Option<FieldType>,
    #[serde(default)]
    pub name: Option<EncString>,
    #[serde(default)]
    pub value: Option<EncString>,
}

/// Login specific payload of a cipher
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct LoginCipher {
    #[serde(default)]
    pub password: Option<EncString>,
    #[serde(default)]
    pub uri: Option<EncString>,
    #[serde(default)]
    pub uris: Vec<URI>,
    #[serde(default)]
    pub username: Option<EncString>,
    #[serde(default)]
    pub totp: Option<EncString>,
}

/// SSH key specific payload of a cipher
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SSHKeyCipher {
    #[serde(default)]
    pub private_key: Option<EncString>,
    #[serde(default)]
    pub public_key: Option<EncString>,
    #[serde(default)]
    pub key_fingerprint: Option<EncString>,
}

/// Payment card payload of a cipher
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Card {
    #[serde(default)]
    pub cardholder_name: Option<EncString>,
    #[serde(default)]
    pub brand: Option<EncString>,
    #[serde(default)]
    pub number: Option<EncString>,
    #[serde(default)]
    pub exp_month: Option<EncString>,
    #[serde(default)]
    pub exp_year: Option<EncString>,
    #[serde(default)]
    pub code: Option<EncString>,
}

/// Personal identity payload of a cipher
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Identity {
    #[serde(default)]
    pub title: Option<EncString>,
    #[serde(default)]
    pub first_name: Option<EncString>,
    #[serde(default)]
    pub middle_name: Option<EncString>,
    #[serde(default)]
    pub last_name: Option<EncString>,
    #[serde(default)]
    pub username: Option<EncString>,
    #[serde(default)]
    pub company: Option<EncString>,
    #[serde(default)]
    pub ssn: Option<EncString>,
    #[serde(default)]
    pub passport_number: Option<EncString>,
    #[serde(default)]
    pub license_number: Option<EncString>,
    #[serde(default)]
    pub email: Option<EncString>,
    #[serde(default)]
    pub phone: Option<EncString>,
    #[serde(default)]
    pub address1: Option<EncString>,
    #[serde(default)]
    pub address2: Option<EncString>,
    #[serde(default)]
    pub address3: Option<EncString>,
    #[serde(default)]
    pub city: Option<EncString>,
    #[serde(default)]
    pub state: Option<EncString>,
    #[serde(default)]
    pub postal_code: Option<EncString>,
    #[serde(default)]
    pub country: Option<EncString>,
}

/// Secure note specific payload
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SecureNoteCipher {
    #[serde(default, rename = "type")]
    pub r#type: Option<SecureNoteType>,
}

/// Folder representation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Folder {
    #[serde(default)]
    pub id: Option<Uuid>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub revision_date: Option<String>,
}

/// Organization representation in user profile
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Organization {
    #[serde(default)]
    pub object: Option<String>,
    #[serde(default)]
    pub id: Option<Uuid>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub use_groups: bool,
    #[serde(default)]
    pub use_directory: bool,
    #[serde(default)]
    pub use_events: bool,
    #[serde(default)]
    pub use_totp: bool,
    #[serde(default)]
    pub use2fa: bool,
    #[serde(default)]
    pub use_api: bool,
    #[serde(default)]
    pub users_get_premium: bool,
    #[serde(default)]
    pub self_host: bool,
    #[serde(default)]
    pub seats: Option<i32>,
    #[serde(default)]
    pub max_collections: Option<i32>,
    #[serde(default)]
    pub max_storage_gb: Option<i32>,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub status: Option<i32>,
    #[serde(default, rename = "type")]
    pub r#type: Option<i32>,
    #[serde(default)]
    pub enabled: bool,
}

/// User profile received during sync
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    #[serde(default)]
    pub id: Option<Uuid>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: bool,
    #[serde(default)]
    pub premium: bool,
    #[serde(default)]
    pub master_password_hint: Option<String>,
    #[serde(default)]
    pub culture: Option<String>,
    #[serde(default)]
    pub two_factor_enabled: bool,
    #[serde(default)]
    pub key: Option<EncString>,
    #[serde(default)]
    pub private_key: Option<EncString>,
    #[serde(default)]
    pub security_stamp: Option<String>,
    #[serde(default)]
    pub organizations: Vec<Organization>,
}

/// Complete Bitwarden Cipher representation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Cipher {
    #[serde(default, rename = "type")]
    pub r#type: CipherType,
    #[serde(default)]
    pub id: Option<Uuid>,
    #[serde(default)]
    pub name: EncString,
    #[serde(default)]
    pub edit: bool,
    #[serde(default)]
    pub revision_date: Option<String>,
    #[serde(default)]
    pub deleted_date: Option<String>,

    #[serde(default)]
    pub folder_id: Option<Uuid>,
    #[serde(default)]
    pub organization_id: Option<Uuid>,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default)]
    pub attachments: Option<serde_json::Value>,
    #[serde(default)]
    pub organization_use_totp: bool,
    #[serde(default)]
    pub collection_ids: Vec<String>,
    #[serde(default)]
    pub fields: Vec<Field>,

    #[serde(default)]
    pub card: Option<Card>,
    #[serde(default)]
    pub identity: Option<Identity>,
    #[serde(default)]
    pub login: Option<LoginCipher>,
    #[serde(default)]
    pub notes: Option<EncString>,
    #[serde(default)]
    pub secure_note: Option<SecureNoteCipher>,
    #[serde(default)]
    pub ssh_key: Option<SSHKeyCipher>,

    #[serde(default)]
    pub key: Option<EncString>,
}

/// Root data structure returned by Bitwarden `/sync`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SyncData {
    #[serde(default)]
    pub profile: Profile,
    #[serde(default)]
    pub folders: Vec<Folder>,
    #[serde(default)]
    pub ciphers: Vec<Cipher>,
}

/// In-memory secure vault store indexed by cipher UUID
#[derive(Debug, Default, Clone)]
pub struct VaultStore {
    ciphers: HashMap<Uuid, Cipher>,
}

impl VaultStore {
    pub fn new() -> Self {
        Self {
            ciphers: HashMap::new(),
        }
    }

    pub fn insert(&mut self, cipher: Cipher) {
        if let Some(id) = cipher.id {
            self.ciphers.insert(id, cipher);
        }
    }

    pub fn get(&self, id: &Uuid) -> Option<&Cipher> {
        self.ciphers.get(id)
    }

    pub fn all(&self) -> Vec<&Cipher> {
        self.ciphers.values().collect()
    }

    pub fn len(&self) -> usize {
        self.ciphers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ciphers.is_empty()
    }

    pub fn clear(&mut self) {
        self.ciphers.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let sync_data: SyncData =
            serde_json::from_str(json_str).expect("SyncData must deserialize");

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

    #[test]
    fn test_vault_store_operations() {
        let mut store = VaultStore::new();
        assert!(store.is_empty());

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

        store.insert(c1);
        store.insert(c2);

        assert_eq!(store.len(), 2);
        assert!(!store.is_empty());

        assert_eq!(store.get(&id1).unwrap().r#type, CipherType::Login);
        assert_eq!(store.get(&id2).unwrap().r#type, CipherType::SshKey);
        assert_eq!(store.all().len(), 2);

        store.clear();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
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
}
