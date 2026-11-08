use sw_client::{AgentClient, ClientError};
use tauri::menu::{Menu, MenuItem, Submenu};
use tauri::Emitter;
use tauri::Manager;

fn get_settings_path() -> Result<std::path::PathBuf, String> {
    let home = std::env::var("HOME").map_err(|_| "No HOME directory".to_string())?;
    let dir = std::path::PathBuf::from(home)
        .join(".config")
        .join("silverwarden");
    if !dir.exists() {
        let _ = std::fs::create_dir_all(&dir);
    }
    Ok(dir.join("gui-settings.json"))
}

#[tauri::command]
fn save_settings(theme: String, mode: String) -> Result<(), String> {
    let path = get_settings_path()?;
    let payload = serde_json::json!({
        "theme": theme,
        "mode": mode
    });
    std::fs::write(&path, payload.to_string()).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
fn load_settings() -> Result<String, String> {
    let path = get_settings_path()?;
    if path.exists() {
        let content = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
        Ok(content)
    } else {
        Ok(serde_json::json!({
            "theme": "fluent",
            "mode": "light"
        })
        .to_string())
    }
}

fn build_menu<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    is_logged_in: bool,
) -> tauri::Result<Menu<R>> {
    let quit_item = MenuItem::with_id(app, "quit", "Salir", true, None::<&str>)?;
    let file_menu = Submenu::with_items(app, "Archivo", true, &[&quit_item])?;

    let about_item = MenuItem::with_id(app, "about", "Acerca de", true, None::<&str>)?;
    let help_menu = Submenu::with_items(app, "Ayuda", true, &[&about_item])?;

    if is_logged_in {
        let new_login = MenuItem::with_id(app, "new_login", "Nuevo Login", true, None::<&str>)?;
        let ssh_keys = MenuItem::with_id(app, "ssh_keys", "Claves SSH", true, None::<&str>)?;
        let lock_vault =
            MenuItem::with_id(app, "lock_vault", "Bloquear Bóveda", true, None::<&str>)?;
        let vault_menu =
            Submenu::with_items(app, "Bóveda", true, &[&new_login, &ssh_keys, &lock_vault])?;

        Menu::with_items(app, &[&vault_menu, &file_menu, &help_menu])
    } else {
        Menu::with_items(app, &[&file_menu, &help_menu])
    }
}

fn update_menu<R: tauri::Runtime>(
    window: &tauri::Window<R>,
    is_logged_in: bool,
) -> Result<(), String> {
    let app = window.app_handle();
    let menu = build_menu(app, is_logged_in).map_err(|e| e.to_string())?;
    let _ = window.set_menu(menu.clone());
    let _ = app.set_menu(menu);
    Ok(())
}

#[tauri::command]
async fn set_menu_state(window: tauri::Window, is_logged_in: bool) -> Result<(), String> {
    update_menu(&window, is_logged_in)
}

fn get_agent_client() -> Result<AgentClient, String> {
    let home = std::env::var("HOME").map_err(|_| "No se pudo determinar el directorio HOME.".to_string())?;
    let socket_path = std::path::PathBuf::from(home).join(".silverwarden.sock");
    Ok(AgentClient::new(socket_path))
}

fn map_client_error(e: ClientError) -> String {
    match e {
        ClientError::SocketNotFound(_) => "El agente no está corriendo (socket no existe).".to_string(),
        ClientError::InvalidPin => "El PIN es incorrecto, inténtalo de nuevo.".to_string(),
        ClientError::Locked => "Bóveda bloqueada. Desbloquea primero.".to_string(),
        ClientError::NotFound(msg)
        | ClientError::Unauthorized(msg)
        | ClientError::ServerError(msg)
        | ClientError::Validation(msg) => msg,
        ClientError::AgentError { message, .. } => message,
        _ => e.to_string(),
    }
}

#[tauri::command]
async fn get_agent_status() -> Result<serde_json::Value, String> {
    let client = match get_agent_client() {
        Ok(c) => c,
        Err(e) => {
            return Ok(serde_json::json!({
                "locked": true,
                "has_pin": false,
                "logged_in": false,
                "error": e,
            }));
        }
    };

    match client.call_ok(sw_client::Request::Status).await {
        Ok(payload) => {
            let locked = payload["locked"].as_bool().unwrap_or(true);
            let has_pin = payload["has_pin"].as_bool().unwrap_or(false);
            let logged_in = payload["logged_in"].as_bool().unwrap_or(false);

            let estado = if locked { "Bloqueado" } else { "Desbloqueado" };
            let pin = if has_pin { "Sí" } else { "No" };
            let session = if logged_in { "Sí" } else { "No" };

            Ok(serde_json::json!({
                "locked": locked,
                "has_pin": has_pin,
                "logged_in": logged_in,
                "text": format!("Estado: {} | PIN: {} | Sesión: {}", estado, pin, session)
            }))
        }
        Err(ClientError::SocketNotFound(_)) => Ok(serde_json::json!({
            "locked": true,
            "has_pin": false,
            "logged_in": false,
            "error": "El agente no está corriendo (socket no existe)."
        })),
        Err(ClientError::ConnectionFailed(_, err)) => Ok(serde_json::json!({
            "locked": true,
            "has_pin": false,
            "logged_in": false,
            "error": format!("Agente no disponible: {}", err)
        })),
        Err(ClientError::AgentError { message, .. }) => Ok(serde_json::json!({
            "locked": true,
            "has_pin": false,
            "logged_in": false,
            "error": format!("Agente respondió con Error: {}", message)
        })),
        Err(e) => Ok(serde_json::json!({
            "locked": true,
            "has_pin": false,
            "logged_in": false,
            "error": e.to_string()
        })),
    }
}

#[tauri::command]
async fn unlock_vault(pin: String) -> Result<String, String> {
    let client = get_agent_client()?;
    client.unlock(Some(pin)).await.map_err(map_client_error)?;
    Ok("unlocked".to_string())
}

#[tauri::command]
async fn lock_vault() -> Result<String, String> {
    let client = get_agent_client()?;
    client.lock().await.map_err(map_client_error)?;
    Ok("locked".to_string())
}

#[tauri::command]
fn copy_to_clipboard(text: String) -> Result<(), String> {
    let mut clipboard = arboard::Clipboard::new()
        .map_err(|e| format!("Error al acceder al portapapeles: {e}"))?;
    clipboard
        .set_text(&text)
        .map_err(|e| format!("Error al copiar al portapapeles: {e}"))?;

    let text_clone = text.clone();
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(25));
        if let Ok(mut cb) = arboard::Clipboard::new() {
            if let Ok(current) = cb.get_text() {
                if current == text_clone {
                    let _ = cb.clear();
                }
            } else {
                let _ = cb.clear();
            }
        }
    });

    Ok(())
}

#[tauri::command]
async fn list_logins() -> Result<serde_json::Value, String> {
    let client = get_agent_client()?;
    client.call_ok(sw_client::Request::ListLogins).await.map_err(map_client_error)
}

#[tauri::command]
async fn sync_vault() -> Result<serde_json::Value, String> {
    let client = get_agent_client()?;
    client.call_ok(sw_client::Request::Sync).await.map_err(map_client_error)
}

#[tauri::command]
async fn get_login(name: String) -> Result<serde_json::Value, String> {
    let client = get_agent_client()?;
    client.call_ok(sw_client::Request::GetLogin { name }).await.map_err(map_client_error)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            let menu = build_menu(app.handle(), false)?;
            app.set_menu(menu)?;
            Ok(())
        })
        .on_menu_event(|app, event| {
            if event.id() == "quit" {
                app.exit(0);
            } else if event.id() == "lock_vault" {
                let app_handle = app.clone();
                tauri::async_runtime::spawn(async move {
                    let _ = lock_vault().await;
                    if let Ok(m) = build_menu(&app_handle, false) {
                        let _ = app_handle.set_menu(m);
                    }
                    let _ = app_handle.emit("vault-locked", ());
                });
            }
        })
        .invoke_handler(tauri::generate_handler![
            get_agent_status,
            unlock_vault,
            lock_vault,
            list_logins,
            sync_vault,
            get_login,
            copy_to_clipboard,
            save_settings,
            load_settings,
            set_menu_state,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
