use crate::*;

pub async fn handle<P>(
    cli: &Cli,
    pin: &Option<String>,
    mut prompt_fn: P,
) -> Result<String, CliError>
where
    P: FnMut(&str) -> Result<String, CliError>,
{
    let socket_path = resolve_socket_path(cli.socket.clone())?;
    let pin_val = match pin {
        Some(p) => p.clone(),
        None => prompt_fn("Introduce el PIN de desbloqueo: ")?,
    };
    AgentClient::new(&socket_path)
        .call(Request::Unlock { pin: Some(pin_val) })
        .await?;
    Ok("Bóveda desbloqueada con éxito.".to_string())
}
