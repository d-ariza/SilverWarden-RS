use crate::*;

pub async fn handle(
    cli: &Cli,
    action: &Option<LoginsCommands>,
    filter: &Option<String>,
) -> Result<String, CliError> {
    let socket_path = resolve_socket_path(cli.socket.clone())?;
    match action {
        None | Some(LoginsCommands::List) => {
            let val = AgentClient::new(&socket_path)
                .call_ok(Request::ListLogins)
                .await?;
            let items = val.as_array().cloned().unwrap_or_default();
            let filter_str = filter.as_deref().unwrap_or("").to_lowercase();
            let filtered: Vec<_> = items
                .into_iter()
                .filter(|item| {
                    if filter_str.is_empty() {
                        return true;
                    }
                    let name = item.get("name").and_then(|v| v.as_str()).unwrap_or("");
                    let username = item.get("username").and_then(|v| v.as_str()).unwrap_or("");
                    name.to_lowercase().contains(&filter_str)
                        || username.to_lowercase().contains(&filter_str)
                })
                .collect();

            if filtered.is_empty() {
                return Ok("No se encontraron accesos guardados.".to_string());
            }

            let mut out = format!("{:<30} | {}\n", "Nombre", "Usuario");
            out.push_str(&format!(
                "{:-<30}-+------------------------------------\n",
                ""
            ));
            for item in filtered {
                let name = item.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let username = item.get("username").and_then(|v| v.as_str()).unwrap_or("");
                out.push_str(&format!("{:<30} | {}\n", name, username));
            }
            Ok(out.trim_end().to_string())
        }
        Some(LoginsCommands::Get { name }) => {
            if name.trim().is_empty() {
                return Err(CliError::Other(
                    "El nombre no puede estar vacío.".to_string(),
                ));
            }
            let val = AgentClient::new(&socket_path)
                .call_ok(Request::GetLogin { name: name.clone() })
                .await?;
            let password = val.get("password").and_then(|v| v.as_str()).unwrap_or("");
            let totp = val.get("totp").and_then(|v| v.as_str()).unwrap_or("");
            Ok(format!("Contraseña: {password}\nTOTP: {totp}"))
        }
        Some(LoginsCommands::Create {
            name,
            username,
            password,
        }) => {
            if name.trim().is_empty() {
                return Err(CliError::Other(
                    "El nombre no puede estar vacío.".to_string(),
                ));
            }
            let val = AgentClient::new(&socket_path)
                .call_ok(Request::CreateLogin {
                    name: name.clone(),
                    username: username.clone(),
                    password: password.clone(),
                })
                .await?;

            if let Some(status) = val.get("status").and_then(|v| v.as_str()) {
                if status == "error" {
                    let err_msg = val
                        .get("error")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Error al crear el acceso");
                    return Err(CliError::AgentError(err_msg.to_string()));
                }
            }

            Ok(format!("Acceso '{name}' creado exitosamente."))
        }
        Some(LoginsCommands::Delete { name }) => {
            if name.trim().is_empty() {
                return Err(CliError::Other(
                    "El nombre no puede estar vacío.".to_string(),
                ));
            }
            AgentClient::new(&socket_path)
                .call(Request::DeleteLogin { name: name.clone() })
                .await?;
            Ok(format!("Acceso '{name}' eliminado exitosamente."))
        }
    }
}
