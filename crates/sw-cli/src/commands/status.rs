use crate::*;

pub async fn handle(cli: &Cli) -> Result<String, CliError> {
    let socket_path = resolve_socket_path(cli.socket.clone())?;
    let val = AgentClient::new(&socket_path)
        .call_ok(Request::Status)
        .await?;
    let locked = val.get("locked").and_then(|v| v.as_bool()).unwrap_or(true);
    let has_pin = val
        .get("has_pin")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let logged_in = val
        .get("logged_in")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let version = val
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    Ok(format!(
                "Estado del Agente SilverWarden (v{version}):\n  Bloqueado:        {}\n  PIN configurado:  {}\n  Sesión iniciada:  {}",
                if locked { "Sí" } else { "No" },
                if has_pin { "Sí" } else { "No" },
                if logged_in { "Sí" } else { "No" }
            ))
}
