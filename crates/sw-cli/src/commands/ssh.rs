use crate::*;

pub async fn handle(cli: &Cli, ssh_command: &SshCommands) -> Result<String, CliError> {
    if let SshCommands::Add { key_id } = ssh_command {
        if key_id.trim().is_empty() {
            return Err(CliError::Other(
                "El nombre de la clave SSH no puede estar vacío.".to_string(),
            ));
        }
    }

    let socket_path = resolve_socket_path(cli.socket.clone())?;
    let client = AgentClient::new(&socket_path);

    match ssh_command {
        SshCommands::List => {
            let val = client.call_ok(Request::ListSshKeys).await?;
            let keys = val.as_array().cloned().unwrap_or_default();
            if keys.is_empty() {
                return Ok("No hay claves SSH registradas.".to_string());
            }

            let mut out = String::from("Listando claves SSH registradas:\n");
            for key in keys {
                let name = key
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("(sin nombre)");
                let fingerprint = key
                    .get("fingerprint")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let id = key.get("id").and_then(|v| v.as_str()).unwrap_or("-");
                if fingerprint.is_empty() {
                    out.push_str(&format!("  - {name} ({id})\n"));
                } else {
                    out.push_str(&format!("  - {name} [{fingerprint}] ({id})\n"));
                }
            }
            Ok(out.trim_end().to_string())
        }
        SshCommands::Add { key_id } => {
            let trimmed = key_id.trim();
            if trimmed.is_empty() {
                return Err(CliError::Other(
                    "El nombre de la clave SSH no puede estar vacío.".to_string(),
                ));
            }

            let path = Path::new(trimmed);
            let request = if path.is_file() {
                let pem = std::fs::read_to_string(path).map_err(|e| {
                    CliError::Io(format!(
                        "Error al leer la clave SSH '{}': {e}",
                        path.display()
                    ))
                })?;
                let name = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .filter(|s| !s.is_empty())
                    .unwrap_or(trimmed)
                    .to_string();
                Request::ImportSshKey { name, pem }
            } else {
                Request::NewSshKey {
                    name: trimmed.to_string(),
                    key_type: "Ed25519".to_string(),
                }
            };

            let val = client.call_ok(request).await?;
            let name = val.get("name").and_then(|v| v.as_str()).unwrap_or(trimmed);
            let fingerprint = val
                .get("fingerprint")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if fingerprint.is_empty() {
                Ok(format!("Registrando clave SSH {name}: completado."))
            } else {
                Ok(format!(
                    "Registrando clave SSH {name}: completado [{fingerprint}]."
                ))
            }
        }
    }
}
