use crate::AgentError;
use sw_ipc::dto::OperationAck;
use sw_vault_agent::VaultAgentServer;

fn infer_key_type(public_key: &str) -> String {
    let prefix = public_key.split_whitespace().next().unwrap_or_default();
    if prefix.contains("ed25519") {
        "Ed25519".to_string()
    } else if prefix.contains("rsa") {
        "RSA".to_string()
    } else if prefix.contains("ecdsa") {
        "ECDSA".to_string()
    } else {
        prefix.to_string()
    }
}

fn to_dto_ssh_summary(k: sw_vault_agent::SshKeySummary) -> sw_ipc::dto::SshKeySummary {
    let key_type = infer_key_type(&k.public_key);
    sw_ipc::dto::SshKeySummary {
        id: k.id.map(|u| u.to_string()),
        name: k.name,
        fingerprint: k.fingerprint,
        public_key: k.public_key,
        key_type,
    }
}

pub async fn handle_list_ssh_keys(
    agent: &VaultAgentServer,
) -> Result<Vec<sw_ipc::dto::SshKeySummary>, AgentError> {
    if agent.is_locked() {
        return Err(AgentError::Locked);
    }
    let keys = agent
        .list_ssh_keys()
        .await
        .map_err(|e| AgentError::ServerError(e.to_string()))?;
    Ok(keys.into_iter().map(to_dto_ssh_summary).collect())
}

pub async fn handle_import_ssh_key_params(
    agent: &VaultAgentServer,
    name: &str,
    pem: &str,
) -> Result<sw_ipc::dto::SshKeySummary, AgentError> {
    let sym_key = agent.get_symmetric_key().await.ok_or(AgentError::Locked)?;
    let summary = agent
        .import_ssh_key(name, pem, &sym_key)
        .await
        .map_err(|e| AgentError::ServerError(e.to_string()))?;
    Ok(to_dto_ssh_summary(summary))
}

pub async fn handle_import_ssh_key(
    agent: &VaultAgentServer,
    payload: &serde_json::Value,
) -> Result<serde_json::Value, AgentError> {
    let _ = agent.get_symmetric_key().await.ok_or(AgentError::Locked)?;

    let (name, pem) = match payload {
        serde_json::Value::Object(map) => {
            let name = map
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| AgentError::Validation("Campo 'name' requerido".to_string()))?;
            let pem = map
                .get("private_key_pem")
                .or_else(|| map.get("private_key"))
                .or_else(|| map.get("pem"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    AgentError::Validation("Campo 'private_key_pem' requerido".to_string())
                })?;
            (name.to_string(), pem.to_string())
        }
        _ => {
            return Err(AgentError::Validation(
                "Payload inválido para ImportSSHKey: se esperaba objeto".to_string(),
            ))
        }
    };

    let dto = handle_import_ssh_key_params(agent, &name, &pem).await?;
    serde_json::to_value(dto).map_err(|e| AgentError::ServerError(e.to_string()))
}

pub async fn handle_new_ssh_key_params(
    agent: &VaultAgentServer,
    name: &str,
    key_type: &str,
) -> Result<sw_ipc::dto::SshKeySummary, AgentError> {
    let sym_key = agent.get_symmetric_key().await.ok_or(AgentError::Locked)?;
    let summary = agent
        .new_ssh_key(name, key_type, &sym_key)
        .await
        .map_err(|e| AgentError::ServerError(e.to_string()))?;
    Ok(to_dto_ssh_summary(summary))
}

pub async fn handle_new_ssh_key(
    agent: &VaultAgentServer,
    payload: &serde_json::Value,
) -> Result<serde_json::Value, AgentError> {
    let _ = agent.get_symmetric_key().await.ok_or(AgentError::Locked)?;

    let (name, key_type) = match payload {
        serde_json::Value::Object(map) => {
            let name = map
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| AgentError::Validation("Campo 'name' requerido".to_string()))?;
            let kt = map
                .get("key_type")
                .or_else(|| map.get("type"))
                .and_then(|v| v.as_str())
                .unwrap_or("Ed25519");
            (name.to_string(), kt.to_string())
        }
        _ => {
            return Err(AgentError::Validation(
                "Payload inválido para NewSSHKey: se esperaba objeto".to_string(),
            ))
        }
    };

    let dto = handle_new_ssh_key_params(agent, &name, &key_type).await?;
    serde_json::to_value(dto).map_err(|e| AgentError::ServerError(e.to_string()))
}

pub async fn handle_delete_ssh_key_by_id(
    agent: &VaultAgentServer,
    id_str: &str,
) -> Result<OperationAck, AgentError> {
    if agent.is_locked() {
        return Err(AgentError::Locked);
    }
    let id = uuid::Uuid::parse_str(id_str)
        .map_err(|e| AgentError::Validation(format!("ID de clave inválido: {e}")))?;
    agent
        .delete_ssh_key(&id)
        .await
        .map_err(|e| AgentError::ServerError(e.to_string()))?;
    Ok(OperationAck::ssh_key_deleted(id.to_string()))
}

pub async fn handle_delete_ssh_key(
    agent: &VaultAgentServer,
    payload: &serde_json::Value,
) -> Result<serde_json::Value, AgentError> {
    if agent.is_locked() {
        return Err(AgentError::Locked);
    }
    #[rustfmt::skip]
    let id_str = match payload {
        serde_json::Value::Object(map) => map.get("id").and_then(|v| v.as_str()).ok_or_else(|| AgentError::Validation("Campo 'id' requerido".to_string()))?,
        serde_json::Value::String(s) => s.as_str(),
        _ => return Err(AgentError::Validation("Payload inválido para DeleteSSHKey: se esperaba objeto o id string".to_string())),
    };
    let ack = handle_delete_ssh_key_by_id(agent, id_str).await?;
    serde_json::to_value(ack).map_err(|e| AgentError::ServerError(e.to_string()))
}
