use crate::*;

pub async fn handle(
    cli: &Cli,
    action: &Option<LoginsCommands>,
    filter: &Option<String>,
) -> Result<String, CliError> {
    let socket_path = resolve_socket_path(cli.socket.clone())?;
    match action {
        None | Some(LoginsCommands::List) => {
            let items: Vec<sw_ipc::dto::LoginSummary> = AgentClient::new(&socket_path)
                .call_ok(Request::ListLogins)
                .await?;
            let filter_str = filter.as_deref().unwrap_or("").to_lowercase();
            let filtered: Vec<_> = items
                .into_iter()
                .filter(|item| {
                    if filter_str.is_empty() {
                        return true;
                    }
                    item.name.to_lowercase().contains(&filter_str)
                        || item.username.to_lowercase().contains(&filter_str)
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
                out.push_str(&format!("{:<30} | {}\n", item.name, item.username));
            }
            Ok(out.trim_end().to_string())
        }
        Some(LoginsCommands::Get { name }) => {
            if name.trim().is_empty() {
                return Err(CliError::Other(
                    "El nombre no puede estar vacío.".to_string(),
                ));
            }
            let detail: sw_ipc::dto::LoginDetail = AgentClient::new(&socket_path)
                .call_ok(Request::GetLogin { name: name.clone() })
                .await?;
            Ok(format!(
                "Contraseña: {}\nTOTP: {}",
                detail.password, detail.totp
            ))
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
            let val: serde_json::Value = AgentClient::new(&socket_path)
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
