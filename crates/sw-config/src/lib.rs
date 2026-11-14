pub mod defaults;
pub mod migration;
pub mod model;
pub mod paths;

#[cfg(test)]
pub(crate) use defaults::TINK_HEADER;
pub use defaults::{
    default_idle_ttl_secs, default_pin_cache_ttl_secs, derive_server_urls, RuntimeConfig,
    DEFAULT_IDLE_TTL_SECS, DEFAULT_PIN_CACHE_TTL_SECS, KDF_ITERATIONS, KDF_MEMORY_KIB,
    KDF_MEMORY_KIB_TEST, KDF_PARALLELISM,
};
pub use migration::{
    backup_config, get_new_config_path, get_old_config_path, migrate_old_path, migrate_old_path_in,
    run_migration, run_migration_in, MIGRATION_SUCCESS_MSG,
};
pub use model::{
    decrypt_string, derive_config_key, derive_config_key_with_params, deserialize_opt_or_default,
    encrypt_string, hash_config_key, verify_pin, verify_pin_with_params, ConfigError, ConfigFile,
    LoginToken,
};
pub use paths::{
    default_socket_path, default_ssh_agent_socket_path, socket_path_from_home,
    ssh_agent_socket_path_from_home, ssh_agent_socket_path_next_to,
};

#[cfg(test)]
mod tests;
