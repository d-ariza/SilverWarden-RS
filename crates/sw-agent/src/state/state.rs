#[allow(unused_imports)]
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use sw_config::ConfigFile;
use sw_crypto::mem::{LockedBuffer, MemLockedBuffer};
use sw_ssh_agent::VaultAgentServer;
use sw_systemauth::SessionStore;

use crate::ports::{Clock, SystemClock};

impl std::fmt::Debug for dyn Clock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Clock")
    }
}

/// In-memory cache for the derived 32-byte config key (in locked RAM).
/// Protects against repeated Argon2i executions (which consume ~2-5s and 2 GiB RAM).
/// Does NOT store the user's PIN or the user symmetric key.
pub struct PinCache {
    config_key: Option<MemLockedBuffer>,
    expires_at: Option<Instant>,
    ttl: Duration,
    clock: Arc<dyn Clock>,
}

impl PinCache {
    pub fn new(ttl: Duration) -> Self {
        Self::with_clock(ttl, Arc::new(SystemClock))
    }

    pub fn with_clock(ttl: Duration, clock: Arc<dyn Clock>) -> Self {
        Self {
            config_key: None,
            expires_at: None,
            ttl,
            clock,
        }
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    pub fn clock(&self) -> &Arc<dyn Clock> {
        &self.clock
    }

    pub fn store(&mut self, key: &[u8]) {
        if key.len() != 32 {
            return;
        }
        if let Ok(buf) = MemLockedBuffer::new(key) {
            self.config_key = Some(buf);
            self.expires_at = Some(self.clock.now() + self.ttl);
        }
    }

    pub fn get(&mut self) -> Option<[u8; 32]> {
        if !self.is_valid() {
            return None;
        }
        // Sliding TTL: resets expires_at on each successful get
        self.expires_at = Some(self.clock.now() + self.ttl);
        self.config_key.as_ref().and_then(|buf| {
            let slice = buf.as_slice();
            if slice.len() != 32 {
                None
            } else {
                let mut out = [0u8; 32];
                out.copy_from_slice(slice);
                Some(out)
            }
        })
    }

    pub fn is_valid(&self) -> bool {
        match (self.expires_at, &self.config_key) {
            (Some(exp), Some(buf)) => self.clock.now() < exp && buf.len() == 32,
            _ => false,
        }
    }

    pub fn remaining(&self) -> Option<Duration> {
        if !self.is_valid() {
            return None;
        }
        self.expires_at.and_then(|exp| {
            let now = self.clock.now();
            if exp > now {
                Some(exp - now)
            } else {
                None
            }
        })
    }

    pub fn clear(&mut self) {
        self.config_key = None;
        self.expires_at = None;
    }
}

impl Clone for PinCache {
    fn clone(&self) -> Self {
        Self {
            config_key: self
                .config_key
                .as_ref()
                .and_then(|buf| MemLockedBuffer::new(buf.as_slice()).ok()),
            expires_at: self.expires_at,
            ttl: self.ttl,
            clock: self.clock.clone(),
        }
    }
}

impl std::fmt::Debug for PinCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PinCache")
            .field("has_key", &self.config_key.is_some())
            .field("expires_at", &self.expires_at)
            .field("ttl", &self.ttl)
            .finish()
    }
}

impl Default for PinCache {
    fn default() -> Self {
        Self::new(Duration::from_secs(sw_config::DEFAULT_PIN_CACHE_TTL_SECS))
    }
}

/// Security-related state: biometrics, pin cache, keyring, notifier, clock, last activity.
#[derive(Clone, Debug)]
pub struct SecurityContext {
    pub biometrics: Arc<dyn sw_systemauth::Biometrics>,
    pub pin_cache: PinCache,
    pub keyring: Arc<tokio::sync::RwLock<sw_crypto::Keyring>>,
    pub notifier: Arc<dyn sw_notify::Notifier>,
    pub clock: Arc<dyn Clock>,
    pub last_activity: Arc<tokio::sync::RwLock<std::time::Instant>>,
}

/// Session-related state: sessions, locked flag, pin configured flag.
#[derive(Clone, Debug)]
pub struct SessionContext {
    pub sessions: SessionStore,
    pub is_locked: bool,
    pub has_pin: bool,
}

/// Daemon services: vault agent, api client, shutdown channel, config, config directory.
#[derive(Clone, Debug)]
pub struct DaemonServices {
    pub vault_agent: Arc<VaultAgentServer>,
    pub api_client: Option<Arc<sw_bitwarden_api::AuthenticatedClient>>,
    pub shutdown_sender: Option<tokio::sync::mpsc::Sender<()>>,
    pub config: ConfigFile,
    pub config_directory: Option<PathBuf>,
}

/// Central state maintained by the agent daemon.
#[derive(Clone, Debug)]
pub struct AgentState {
    pub security: SecurityContext,
    pub session: SessionContext,
    pub services: DaemonServices,
}

impl AgentState {
    pub fn new(config: ConfigFile, vault_agent: Arc<VaultAgentServer>) -> Self {
        let has_pin = !config.config_key_hash.is_empty();
        let pin_cache_ttl = Duration::from_secs(config.runtime_config.pin_cache_ttl_secs);
        Self {
            security: SecurityContext {
                biometrics: Arc::new(sw_systemauth::PolkitBiometrics::new()),
                pin_cache: PinCache::new(pin_cache_ttl),
                keyring: Arc::new(tokio::sync::RwLock::new(sw_crypto::Keyring::new())),
                notifier: Arc::new(sw_notify::DbusNotifier::new()),
                clock: Arc::new(SystemClock),
                last_activity: Arc::new(tokio::sync::RwLock::new(std::time::Instant::now())),
            },
            session: SessionContext {
                sessions: SessionStore::new(),
                is_locked: true,
                has_pin,
            },
            services: DaemonServices {
                vault_agent,
                api_client: None,
                shutdown_sender: None,
                config,
                config_directory: None,
            },
        }
    }

    /// Touches the last activity timestamp, resetting the inactivity counter.
    pub async fn touch_activity(&self) {
        let mut guard = self.security.last_activity.write().await;
        *guard = self.security.clock.now();
    }

    /// Returns the duration elapsed since the last IPC or user activity.
    pub async fn idle_duration(&self) -> Duration {
        let guard = self.security.last_activity.read().await;
        self.security.clock.now().saturating_duration_since(*guard)
    }

    /// Returns the configured idle time-to-live before automatic lock.
    pub async fn idle_ttl(&self) -> Duration {
        Duration::from_secs(self.services.config.runtime_config.idle_ttl_secs)
    }

    /// Sets an injectable desktop notifier.
    pub fn with_notifier(mut self, notifier: Arc<dyn sw_notify::Notifier>) -> Self {
        self.security.notifier = notifier;
        self
    }

    /// Sets an injectable clock for deterministic time in pin cache and timeout operations.
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.security.pin_cache = PinCache::with_clock(self.security.pin_cache.ttl(), clock.clone());
        self.security.clock = clock;
        self
    }

    /// Sets an injectable biometrics backend.
    pub fn with_biometrics(mut self, biometrics: Arc<dyn sw_systemauth::Biometrics>) -> Self {
        self.security.biometrics = biometrics;
        self
    }

    /// Sets an authenticated API client in state.
    pub fn with_api_client(mut self, client: Arc<sw_bitwarden_api::AuthenticatedClient>) -> Self {
        self.services.api_client = Some(client);
        self
    }

    /// Sets an injectable configuration directory for saving and loading config.
    pub fn with_config_directory(mut self, dir: impl Into<PathBuf>) -> Self {
        self.services.config_directory = Some(dir.into());
        self
    }

    /// Returns the target path for saving/loading configuration.
    /// In test mode (`#[cfg(test)]`), this NEVER touches `$HOME` unless `config_directory` was explicitly set.
    pub fn config_path(&self) -> Option<PathBuf> {
        if let Some(dir) = &self.services.config_directory {
            if dir.ends_with("goldwarden.json") {
                Some(dir.clone())
            } else {
                Some(dir.join("goldwarden.json"))
            }
        } else {
            #[cfg(test)]
            {
                // In test builds, NEVER write to or touch the user's real $HOME directory
                None
            }
            #[cfg(not(test))]
            {
                std::env::var("HOME")
                    .ok()
                    .map(|home| sw_config::get_new_config_path(Path::new(&home)))
            }
        }
    }

    /// Returns the resolved vault path if available.
    pub fn vault_path(&self) -> Option<PathBuf> {
        #[cfg(test)]
        {
            self.services.config_directory
                .as_ref()
                .map(|dir| dir.join("vault.json"))
        }
        #[cfg(not(test))]
        {
            if let Some(dir) = &self.services.config_directory {
                Some(dir.join("vault.json"))
            } else {
                sw_vault::VaultPaths::default_paths()
                    .ok()
                    .map(|p| p.vault_file())
            }
        }
    }

    /// Sets the `VaultAgentServer` instance in state.
    pub fn with_vault_agent(mut self, agent: Arc<VaultAgentServer>) -> Self {
        self.services.vault_agent = agent;
        self
    }

    /// Loads the configuration file with a given VaultAgentServer.
    pub fn load_or_default_with(vault_agent: Arc<VaultAgentServer>) -> Self {
        Self::load_or_default_from_with(None, vault_agent)
    }

    /// Loads the configuration file from ~/.config/goldwarden/goldwarden.json or defaults.
    pub fn load_or_default() -> Self {
        Self::load_or_default_with(Arc::new(VaultAgentServer::default()))
    }

    /// Loads the configuration from an optional directory, or defaults.
    pub fn load_or_default_from(config_dir: Option<PathBuf>) -> Self {
        Self::load_or_default_from_with(config_dir, Arc::new(VaultAgentServer::default()))
    }

    /// Loads the configuration from an optional directory and injected VaultAgentServer, or defaults.
    pub fn load_or_default_from_with(
        config_dir: Option<PathBuf>,
        vault_agent: Arc<VaultAgentServer>,
    ) -> Self {
        let mut state = Self::new(ConfigFile::default(), vault_agent);
        if let Some(dir) = config_dir {
            state.services.config_directory = Some(dir);
        }
        if let Some(path) = state.config_path() {
            if path.exists() {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if let Ok(cfg) = serde_json::from_str::<ConfigFile>(&content) {
                        state.services.config = cfg;
                        state.session.has_pin = !state.services.config.config_key_hash.is_empty();
                        return state;
                    }
                }
            }
        }
        state
    }
}

impl Default for AgentState {
    fn default() -> Self {
        Self::new(ConfigFile::default(), Arc::new(VaultAgentServer::default()))
    }
}
