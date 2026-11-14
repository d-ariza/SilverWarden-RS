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
    let client = AgentClient::new(&socket_path);
    let pin_val = match pin {
        Some(p) => Some(p.clone()),
        None => {
            let status = client.call_ok(Request::Status).await?;
            let pin_cached = status
                .get("pin_cached")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if pin_cached {
                None
            } else {
                Some(prompt_fn("Introduce el PIN de desbloqueo: ")?)
            }
        }
    };
    client.call_ok(Request::Unlock { pin: pin_val }).await?;
    Ok("Bóveda desbloqueada con éxito.".to_string())
}
