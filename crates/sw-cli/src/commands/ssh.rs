use crate::*;

pub async fn handle(_cli: &Cli, ssh_command: &SshCommands) -> Result<String, CliError> {
    match ssh_command {
        SshCommands::List => Ok("Listando claves SSH registradas...".to_string()),
        SshCommands::Add { key_id } => {
            if key_id.trim().is_empty() {
                return Err(CliError::Other(
                    "El nombre de la clave SSH no puede estar vacío.".to_string(),
                ));
            }
            Ok(format!("Registrando clave SSH {key_id}"))
        }
    }
}
