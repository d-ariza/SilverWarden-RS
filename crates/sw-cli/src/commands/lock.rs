use crate::*;

pub async fn handle(cli: &Cli) -> Result<String, CliError> {
    let socket_path = resolve_socket_path(cli.socket.clone())?;
    AgentClient::new(&socket_path).call(Request::Lock).await?;
    Ok("Bóveda bloqueada y sesiones en memoria eliminadas.".to_string())
}
