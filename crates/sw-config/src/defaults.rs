use serde::{Deserialize, Serialize};

pub(crate) const TINK_HEADER: [u8; 5] = [0x00, 0x00, 0x00, 0x00, 0x00];
pub(crate) const NONCE_LEN: usize = 12;

pub const KDF_ITERATIONS: u32 = 2;
pub const KDF_MEMORY_KIB: u32 = 2 * 1024 * 1024; // 2 GiB (2048 MiB), matches Goldwarden Go KDFMemory
pub const KDF_PARALLELISM: u32 = 8;

pub const KDF_MEMORY_KIB_TEST: u32 = 4 * 1024;

pub const DEFAULT_PIN_CACHE_TTL_SECS: u64 = 900;

pub fn default_pin_cache_ttl_secs() -> u64 {
    DEFAULT_PIN_CACHE_TTL_SECS
}

pub const DEFAULT_IDLE_TTL_SECS: u64 = 600;

pub fn default_idle_ttl_secs() -> u64 {
    DEFAULT_IDLE_TTL_SECS
}

/// Derives identity, api, and notifications URLs from a base server URL.
///
/// Prevents duplicating `/identity`, `/api`, or `/notifications` if already present.
pub fn derive_server_urls(server: &str) -> (String, String, String) {
    let base = server.trim().trim_end_matches('/');
    let identity_url = if base.ends_with("/identity") {
        base.to_string()
    } else {
        format!("{base}/identity")
    };
    let api_url = if base.ends_with("/api") {
        base.to_string()
    } else {
        format!("{base}/api")
    };
    let notifications_url = if base.ends_with("/notifications") {
        base.to_string()
    } else {
        format!("{base}/notifications")
    };
    (identity_url, api_url, notifications_url)
}

/// Runtime configuration matching Goldwarden Go RuntimeConfig.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct RuntimeConfig {
    pub auth_method: String,
    pub do_not_persist_config: bool,
    pub config_directory: String,
    #[serde(rename = "DisableSSHAgent", alias = "DisableSshAgent")]
    pub disable_ssh_agent: bool,
    pub websocket_disabled: bool,
    #[serde(rename = "DeviceUUID", alias = "DeviceUuid")]
    pub device_uuid: String,
    pub user: String,
    pub password: String,
    pub pin: String,
    pub use_memguard: bool,
    #[serde(rename = "SSHAgentSocketPath", alias = "SshAgentSocketPath")]
    pub ssh_agent_socket_path: String,
    pub goldwarden_socket_path: String,
    pub daemon_auth_token: String,
    #[serde(
        default = "default_pin_cache_ttl_secs",
        alias = "pin_cache_ttl_secs",
        alias = "pinCacheTtlSecs"
    )]
    pub pin_cache_ttl_secs: u64,
    #[serde(
        default = "default_idle_ttl_secs",
        alias = "idle_ttl_secs",
        alias = "idleTtlSecs"
    )]
    pub idle_ttl_secs: u64,
    #[serde(default, alias = "biometrics_enabled", alias = "biometricsEnabled")]
    pub biometrics_enabled: bool,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            auth_method: String::new(),
            do_not_persist_config: false,
            config_directory: String::new(),
            disable_ssh_agent: false,
            websocket_disabled: false,
            device_uuid: String::new(),
            user: String::new(),
            password: String::new(),
            pin: String::new(),
            use_memguard: false,
            ssh_agent_socket_path: String::new(),
            goldwarden_socket_path: String::new(),
            daemon_auth_token: String::new(),
            pin_cache_ttl_secs: default_pin_cache_ttl_secs(),
            idle_ttl_secs: default_idle_ttl_secs(),
            biometrics_enabled: false,
        }
    }
}
