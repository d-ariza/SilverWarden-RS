use uuid::Uuid;

/// Public summary of an SSH key stored in the vault.
///
/// **Security Notice:** This struct intentionally never contains private key material.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct SshKeySummary {
    pub id: Option<Uuid>,
    pub name: String,
    pub fingerprint: String,
    pub public_key: String,
}
