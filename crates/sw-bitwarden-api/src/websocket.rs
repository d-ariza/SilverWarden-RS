pub mod connection;
pub mod dispatcher;
pub mod protocol;

pub use connection::{WebsocketClient, WsStream};
pub use dispatcher::{run_websocket_daemon, run_websocket_daemon_with_options};
pub use protocol::{
    build_hub_url, encode_notification_message, parse_message_pack, MsgPackValue,
    NotificationMessage, NOTIFICATION_AUTH_REQUEST, NOTIFICATION_AUTH_REQUEST_RESPONSE,
    NOTIFICATION_LOGOUT, NOTIFICATION_SYNC_CIPHERS, NOTIFICATION_SYNC_CIPHER_CREATE,
    NOTIFICATION_SYNC_CIPHER_DELETE, NOTIFICATION_SYNC_CIPHER_UPDATE,
    NOTIFICATION_SYNC_FOLDER_CREATE, NOTIFICATION_SYNC_FOLDER_DELETE,
    NOTIFICATION_SYNC_FOLDER_UPDATE, NOTIFICATION_SYNC_LOGIN_DELETE, NOTIFICATION_SYNC_ORG_KEYS,
    NOTIFICATION_SYNC_SEND_CREATE, NOTIFICATION_SYNC_SEND_DELETE, NOTIFICATION_SYNC_SEND_UPDATE,
    NOTIFICATION_SYNC_SETTINGS, NOTIFICATION_SYNC_VAULT,
};

#[cfg(test)]
#[path = "websocket_tests.rs"]
mod websocket_tests;
