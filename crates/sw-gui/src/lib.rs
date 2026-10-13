#[tauri::command]
fn get_vault_status() -> String {
    "locked".to_string()
}

pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![get_vault_status])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
