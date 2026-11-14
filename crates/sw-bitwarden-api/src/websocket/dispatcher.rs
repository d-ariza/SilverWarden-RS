use super::connection::WebsocketClient;
use super::protocol::{
    NOTIFICATION_LOGOUT, NOTIFICATION_SYNC_CIPHERS, NOTIFICATION_SYNC_CIPHER_CREATE,
    NOTIFICATION_SYNC_CIPHER_DELETE, NOTIFICATION_SYNC_CIPHER_UPDATE,
    NOTIFICATION_SYNC_LOGIN_DELETE, NOTIFICATION_SYNC_VAULT,
};
use crate::{ApiError, AuthenticatedClient};
use std::sync::Arc;
use sw_config::{ConfigFile, LoginToken};
use sw_crypto::SymmetricKey;
use sw_vault::{VaultPaths, VaultStore};
use tokio::sync::{Mutex, RwLock};

/// Runs the WebSocket daemon loop listening for Bitwarden synchronization events.
pub async fn run_websocket_daemon(
    client: Arc<Mutex<WebsocketClient>>,
    vault_store: Arc<VaultStore>,
    config: Arc<RwLock<ConfigFile>>,
    user_symmetric_key: SymmetricKey,
    vault_paths: VaultPaths,
) -> Result<(), ApiError> {
    run_websocket_daemon_with_options(
        client,
        vault_store,
        config,
        user_symmetric_key,
        vault_paths,
        std::time::Duration::from_secs(60),
        None,
    )
    .await
}

/// Runs the WebSocket daemon with customizable reconnection backoff and stop channel.
pub async fn run_websocket_daemon_with_options(
    client: Arc<Mutex<WebsocketClient>>,
    vault_store: Arc<VaultStore>,
    config: Arc<RwLock<ConfigFile>>,
    user_symmetric_key: SymmetricKey,
    vault_paths: VaultPaths,
    backoff: std::time::Duration,
    mut stop_rx: Option<tokio::sync::watch::Receiver<bool>>,
) -> Result<(), ApiError> {
    loop {
        if let Some(rx) = &stop_rx {
            if *rx.borrow() {
                break;
            }
        }

        // 1. Connect if not connected
        let is_connected = client.lock().await.is_connected();
        if !is_connected {
            let (url, token) = {
                let guard = client.lock().await;
                let url = if !guard.url().is_empty() {
                    guard.url().to_string()
                } else {
                    config.read().await.notifications_url.clone()
                };
                let token = if !guard.token().is_empty() {
                    guard.token().to_string()
                } else {
                    String::new()
                };
                (url, token)
            };

            if url.is_empty() {
                tokio::select! {
                    _ = tokio::time::sleep(backoff) => continue,
                    _ = async {
                        if let Some(rx) = &mut stop_rx {
                            let _ = rx.changed().await;
                        } else {
                            futures_util::future::pending::<()>().await;
                        }
                    } => break,
                }
            }

            match WebsocketClient::connect(&url, &token).await {
                Ok(new_client) => {
                    let mut guard = client.lock().await;
                    let existing_api = guard.api_client.clone();
                    *guard = new_client;
                    if let Some(api) = existing_api {
                        guard.set_api_client(api);
                    }
                }
                Err(_) => {
                    tokio::select! {
                        _ = tokio::time::sleep(backoff) => continue,
                        _ = async {
                            if let Some(rx) = &mut stop_rx {
                                let _ = rx.changed().await;
                            } else {
                                futures_util::future::pending::<()>().await;
                            }
                        } => break,
                    }
                }
            }
        }

        // 2. Message read loop
        loop {
            if let Some(rx) = &stop_rx {
                if *rx.borrow() {
                    return Ok(());
                }
            }

            let next_fut = async {
                let mut guard = client.lock().await;
                guard.next_message().await
            };

            let msg_opt = if let Some(rx) = &mut stop_rx {
                tokio::select! {
                    _ = rx.changed() => return Ok(()),
                    res = next_fut => res,
                }
            } else {
                next_fut.await
            };

            let msg = match msg_opt {
                Some(m) => m,
                None => {
                    break;
                }
            };

            match msg.message_type {
                NOTIFICATION_SYNC_CIPHERS | NOTIFICATION_SYNC_VAULT => {
                    let api_client = get_or_create_api_client(&client, &config).await;
                    let _ = api_client
                        .do_full_sync(&vault_paths, &vault_store, Some(&user_symmetric_key))
                        .await;
                }
                NOTIFICATION_SYNC_CIPHER_UPDATE | NOTIFICATION_SYNC_CIPHER_CREATE => {
                    if let Some(ref id_str) = msg.cipher_id {
                        if let Ok(uuid) = uuid::Uuid::parse_str(id_str) {
                            let api_client = get_or_create_api_client(&client, &config).await;
                            if let Ok(cipher) = api_client.get_cipher(&uuid).await {
                                vault_store.insert(cipher).await;
                            }
                        }
                    }
                }
                NOTIFICATION_SYNC_CIPHER_DELETE | NOTIFICATION_SYNC_LOGIN_DELETE => {
                    if let Some(ref id_str) = msg.cipher_id {
                        if let Ok(uuid) = uuid::Uuid::parse_str(id_str) {
                            vault_store.delete(&uuid).await;
                        }
                    }
                }
                NOTIFICATION_LOGOUT => {
                    vault_store.clear().await;
                    client.lock().await.close().await;
                    return Ok(());
                }
                _ => {}
            }
        }

        // 3. Backoff delay upon disconnection
        tokio::select! {
            _ = tokio::time::sleep(backoff) => {},
            _ = async {
                if let Some(rx) = &mut stop_rx {
                    let _ = rx.changed().await;
                } else {
                    futures_util::future::pending::<()>().await;
                }
            } => break,
        }
    }

    Ok(())
}

async fn get_or_create_api_client(
    client: &Arc<Mutex<WebsocketClient>>,
    config: &Arc<RwLock<ConfigFile>>,
) -> Arc<AuthenticatedClient> {
    let existing = {
        let guard = client.lock().await;
        guard.api_client().cloned()
    };
    if let Some(c) = existing {
        return c;
    }

    let (identity_url, api_url, token_str) = {
        let cfg = config.read().await;
        let token = client.lock().await.token().to_string();
        (cfg.identity_url.clone(), cfg.api_url.clone(), token)
    };

    let auth = Arc::new(AuthenticatedClient::from_token(
        identity_url,
        api_url,
        LoginToken {
            access_token: token_str,
            ..Default::default()
        },
    ));
    client.lock().await.set_api_client(auth.clone());
    auth
}
