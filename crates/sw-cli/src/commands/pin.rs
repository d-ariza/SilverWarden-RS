use crate::*;

pub async fn handle<P>(
    cli: &Cli,
    action: &PinCommands,
    mut prompt_fn: P,
) -> Result<String, CliError>
where
    P: FnMut(&str) -> Result<String, CliError>,
{
    let socket_path = resolve_socket_path(cli.socket.clone())?;
    match action {
        PinCommands::Set { pin } => {
            let pin_val = match pin {
                Some(p) => p.clone(),
                None => prompt_fn("Introduce el nuevo PIN: ")?,
            };
            AgentClient::new(&socket_path)
                .call(Request::PinSet { pin: pin_val })
                .await?;
            Ok("PIN configurado exitosamente.".to_string())
        }
        PinCommands::Update { old_pin, new_pin } => {
            let old_val = match old_pin {
                Some(p) => p.clone(),
                None => prompt_fn("Introduce el PIN actual: ")?,
            };
            let new_val = match new_pin {
                Some(p) => p.clone(),
                None => prompt_fn("Introduce el nuevo PIN: ")?,
            };
            AgentClient::new(&socket_path)
                .call(Request::PinUpdate {
                    old_pin: old_val,
                    new_pin: new_val,
                })
                .await?;
            Ok("PIN actualizado exitosamente.".to_string())
        }
    }
}
