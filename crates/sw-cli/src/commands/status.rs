use crate::*;

pub async fn handle(cli: &Cli) -> Result<String, CliError> {
    let socket_path = resolve_socket_path(cli.socket.clone())?;
    let status: sw_ipc::dto::AgentStatus = AgentClient::new(&socket_path)
        .call_ok(Request::Status)
        .await?;
    let version = if status.version.is_empty() {
        "unknown"
    } else {
        status.version.as_str()
    };

    Ok(format!(
                "Estado del Agente SilverWarden (v{version}):\n  Bloqueado:        {}\n  PIN configurado:  {}\n  Sesión iniciada:  {}",
                if status.locked { "Sí" } else { "No" },
                if status.has_pin { "Sí" } else { "No" },
                if status.logged_in { "Sí" } else { "No" }
            ))
}
