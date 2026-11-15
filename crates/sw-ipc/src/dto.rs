use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
#[cfg(feature = "ts")]
use ts_rs::TS;

use crate::IpcError;

/// Alias used by legacy optional token fields without exposing `serde_json::Value` in `sw-ipc::lib`.
pub type OpaqueValue = serde_json::Value;

fn default_synced_status() -> String {
    "synced".to_string()
}

/// Public status of the SilverWarden agent daemon.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(TS))] // deriveTS
#[cfg_attr(
    feature = "ts",
    ts(export, export_to = "../../sw-gui/src/lib/types/generated/")
)]
pub struct AgentStatus {
    pub locked: bool,
    #[serde(default)]
    pub has_pin: bool,
    #[serde(default)]
    pub logged_in: bool,
    #[serde(default)]
    pub pin_cached: bool,
    #[serde(default)]
    #[cfg_attr(feature = "ts", ts(type = "number"))]
    pub pin_cached_remaining_secs: u64,
    #[serde(default)]
    pub version: String,
}

/// Summary of a vault login item returned by `ListLogins`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(TS))] // deriveTS
#[cfg_attr(
    feature = "ts",
    ts(export, export_to = "../../sw-gui/src/lib/types/generated/")
)]
pub struct LoginSummary {
    #[serde(default)]
    pub id: Option<String>,
    pub name: String,
    pub username: String,
}

/// Detailed vault login item returned by `GetLogin`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(TS))] // deriveTS
#[cfg_attr(
    feature = "ts",
    ts(export, export_to = "../../sw-gui/src/lib/types/generated/")
)]
pub struct LoginDetail {
    #[serde(default)]
    pub id: Option<String>,
    pub name: String,
    pub username: String,
    pub password: String,
    pub totp: String,
}

/// Summary counts returned after a vault synchronization (`Sync`, `SyncData`, `ReloadVault`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(TS))] // deriveTS
#[cfg_attr(
    feature = "ts",
    ts(export, export_to = "../../sw-gui/src/lib/types/generated/")
)]
pub struct SyncResult {
    #[serde(default = "default_synced_status")]
    pub status: String,
    #[cfg_attr(feature = "ts", ts(type = "number"))]
    pub total: usize,
    #[cfg_attr(feature = "ts", ts(type = "number"))]
    pub logins: usize,
    #[serde(default)]
    #[cfg_attr(feature = "ts", ts(type = "number"))]
    pub ssh_keys: usize,
    #[serde(default)]
    #[cfg_attr(feature = "ts", ts(type = "number"))]
    pub notes: usize,
    #[serde(default)]
    #[cfg_attr(feature = "ts", ts(type = "number"))]
    pub cards: usize,
    #[serde(default)]
    #[cfg_attr(feature = "ts", ts(type = "number"))]
    pub identities: usize,
}

/// Summary of an SSH key stored in the vault.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(TS))] // deriveTS
#[cfg_attr(
    feature = "ts",
    ts(export, export_to = "../../sw-gui/src/lib/types/generated/")
)]
pub struct SshKeySummary {
    #[serde(default)]
    pub id: Option<String>,
    pub name: String,
    #[serde(default)]
    pub fingerprint: String,
    #[serde(default)]
    pub public_key: String,
    #[serde(default)]
    pub key_type: String,
}

/// Public (non-secret) configuration view exposed over IPC.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(TS))] // deriveTS
#[cfg_attr(
    feature = "ts",
    ts(export, export_to = "../../sw-gui/src/lib/types/generated/")
)]
pub struct ConfigView {
    pub api_url: String,
    pub identity_url: String,
    pub notifications_url: String,
    pub danger_accept_invalid_certs: bool,
}

/// Result of setting or updating the configuration PIN (`PinSet`, `PinUpdate`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(TS))] // deriveTS
#[cfg_attr(
    feature = "ts",
    ts(export, export_to = "../../sw-gui/src/lib/types/generated/")
)]
pub struct PinChangeResult {
    pub updated: bool,
    #[serde(default)]
    pub status: String,
}

/// Typed payload for `Sync`, `SyncData`, and `ReloadVault` IPC requests.
///
/// Supports both session/config sync parameters and pre-fetched vault sync data fields
/// (`profile`, `folders`, `ciphers`, `domains`) for backward compatibility.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncPayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_user_symmetric_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub danger_accept_invalid_certs: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<sw_config::LoginToken>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folders: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ciphers: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domains: Option<serde_json::Value>,
}

/// Typed acknowledgements for mutating/session operations without dedicated top-level DTOs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum OperationAck {
    LoginCreated {
        status: String,
        id: Option<String>,
        name: String,
    },
    SshKeyDeleted {
        status: String,
        id: String,
    },
    LoginDeleted {
        status: String,
        name: String,
    },
    Status {
        status: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        from_cache: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        biometrics: Option<bool>,
    },
}

impl OperationAck {
    pub fn status(status: impl Into<String>) -> Self {
        Self::Status {
            status: status.into(),
            from_cache: None,
            biometrics: None,
        }
    }

    pub fn unlocked(from_cache: bool, biometrics: Option<bool>) -> Self {
        Self::Status {
            status: "unlocked".to_string(),
            from_cache: Some(from_cache),
            biometrics,
        }
    }

    pub fn login_created(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self::LoginCreated {
            status: "created".to_string(),
            id: Some(id.into()),
            name: name.into(),
        }
    }

    pub fn login_deleted(name: impl Into<String>) -> Self {
        Self::LoginDeleted {
            status: "deleted".to_string(),
            name: name.into(),
        }
    }

    pub fn ssh_key_deleted(id: impl Into<String>) -> Self {
        Self::SshKeyDeleted {
            status: "deleted".to_string(),
            id: id.into(),
        }
    }
}

/// Strongly-typed payload carried inside `Response::Ok(ResponseData)`.
///
/// Deserialized as `#[serde(untagged)]`. Variant ordering avoids ambiguity:
/// 1. `AgentStatus` (requires `locked: bool`)
/// 2. `SyncResult` (requires `total: usize` and `logins: usize`)
/// 3. `ConfigView` (requires `api_url`, `identity_url`, `notifications_url`, `danger_accept_invalid_certs`)
/// 4. `PinChangeResult` (requires `updated: bool`)
/// 5. `LoginDetail` (requires `name`, `username`, `password`, `totp`)
/// 6. `LoginSummary` (requires `name`, `username`)
/// 7. `LoginList(Vec<LoginSummary>)` (matches `[]` or login arrays; empty `[]` also converts cleanly to `Vec<SshKeySummary>` via `deserialize_into`)
/// 8. `SshKeyList(Vec<SshKeySummary>)` (non-empty SSH key arrays without `username`)
/// 9. `Ack(OperationAck)` (uses `deny_unknown_fields` on each variant so SSH keys do not collide)
/// 10. `SshKey(SshKeySummary)` (single SSH key summary with `name`)
/// 11. `Raw(serde_json::Value)` (fallback for legacy/arbitrary test payloads)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ResponseData {
    AgentStatus(AgentStatus),
    SyncResult(SyncResult),
    ConfigView(ConfigView),
    PinChangeResult(PinChangeResult),
    LoginDetail(LoginDetail),
    LoginSummary(LoginSummary),
    LoginList(Vec<LoginSummary>),
    SshKeyList(Vec<SshKeySummary>),
    Ack(OperationAck),
    SshKey(SshKeySummary),
    Raw(serde_json::Value),
}

impl ResponseData {
    /// Converts this response payload into the expected target type `T`.
    pub fn deserialize_into<T: DeserializeOwned>(&self) -> Result<T, IpcError> {
        let val = serde_json::to_value(self)?;
        serde_json::from_value(val).map_err(IpcError::Json)
    }

    /// Converts this response payload into a generic JSON value.
    pub fn to_value(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
    }
}

impl From<AgentStatus> for ResponseData {
    fn from(v: AgentStatus) -> Self {
        Self::AgentStatus(v)
    }
}

impl From<SyncResult> for ResponseData {
    fn from(v: SyncResult) -> Self {
        Self::SyncResult(v)
    }
}

impl From<ConfigView> for ResponseData {
    fn from(v: ConfigView) -> Self {
        Self::ConfigView(v)
    }
}

impl From<PinChangeResult> for ResponseData {
    fn from(v: PinChangeResult) -> Self {
        Self::PinChangeResult(v)
    }
}

impl From<LoginDetail> for ResponseData {
    fn from(v: LoginDetail) -> Self {
        Self::LoginDetail(v)
    }
}

impl From<LoginSummary> for ResponseData {
    fn from(v: LoginSummary) -> Self {
        Self::LoginSummary(v)
    }
}

impl From<Vec<LoginSummary>> for ResponseData {
    fn from(v: Vec<LoginSummary>) -> Self {
        Self::LoginList(v)
    }
}

impl From<Vec<SshKeySummary>> for ResponseData {
    fn from(v: Vec<SshKeySummary>) -> Self {
        Self::SshKeyList(v)
    }
}

impl From<SshKeySummary> for ResponseData {
    fn from(v: SshKeySummary) -> Self {
        Self::SshKey(v)
    }
}

impl From<OperationAck> for ResponseData {
    fn from(v: OperationAck) -> Self {
        Self::Ack(v)
    }
}

impl From<serde_json::Value> for ResponseData {
    fn from(v: serde_json::Value) -> Self {
        serde_json::from_value(v.clone()).unwrap_or(Self::Raw(v))
    }
}
