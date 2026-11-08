use crate::*;

pub async fn handle(_source: &str) -> Result<String, CliError> {
    sw_config::run_migration().map_err(|e| CliError::Config(e.to_string()))
}
