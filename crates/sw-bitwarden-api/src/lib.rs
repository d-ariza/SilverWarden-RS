pub use sw_config::LoginToken;
pub use sw_crypto::{KdfConfig, KdfType};

pub mod auth;
pub use auth::{
    decrypt_enc_key, derive_master_password_hash, login, login_api_key, login_with_api_key,
    login_with_password, prelogin, PreloginResponse,
};

pub mod ciphers;
pub use ciphers::{delete_cipher, get_cipher, post_cipher, put_cipher};

pub mod client;
pub use client::{
    ApiError, AuthenticatedClient, RequestBody, BITWARDEN_CLIENT_NAME, BITWARDEN_CLIENT_VERSION,
    BITWARDEN_DEVICE_TYPE, BITWARDEN_USER_AGENT,
};
pub type BitwardenApiClient = AuthenticatedClient;

pub mod sync;
pub use sync::{do_full_sync, sync};

pub mod twofactor;
pub use twofactor::{
    complete_email, complete_fido2, complete_totp, parse_two_factor_error,
    send_two_factor_email_login, TwoFactorProvider,
};

pub mod websocket;
pub use websocket::{
    encode_notification_message, parse_message_pack, run_websocket_daemon,
    run_websocket_daemon_with_options, NotificationMessage, WebsocketClient,
};

#[cfg(test)]
mod tests;
