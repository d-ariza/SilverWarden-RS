use crate::{ApiError, AuthenticatedClient, RequestBody};
use sw_vault::Cipher;
use uuid::Uuid;

/// Retrieves a single cipher by UUID from the Bitwarden API (`GET /ciphers/{uuid}`).
pub async fn get_cipher(client: &AuthenticatedClient, uuid: &Uuid) -> Result<Cipher, ApiError> {
    let endpoint = format!("ciphers/{uuid}");
    let mut resp = client
        .fetch_with_auth(reqwest::Method::GET, &endpoint, RequestBody::Empty)
        .await?;

    if resp.status() == reqwest::StatusCode::NOT_FOUND && !client.api_url().ends_with("/api") {
        let alt_endpoint = format!("api/ciphers/{uuid}");
        let alt_resp = client
            .fetch_with_auth(reqwest::Method::GET, &alt_endpoint, RequestBody::Empty)
            .await?;
        if alt_resp.status().is_success() {
            resp = alt_resp;
        }
    }

    if !resp.status().is_success() {
        let status = resp.status();
        let message = resp.text().await.unwrap_or_default();
        return Err(ApiError::Status { status, message });
    }

    let cipher: Cipher = resp.json().await?;
    Ok(cipher)
}

/// Creates a new cipher in the Bitwarden vault (`POST /ciphers`).
pub async fn post_cipher(
    client: &AuthenticatedClient,
    cipher: &Cipher,
) -> Result<Cipher, ApiError> {
    let body = RequestBody::Json(serde_json::to_value(cipher)?);
    let mut resp = client
        .fetch_with_auth(reqwest::Method::POST, "ciphers", body.clone())
        .await?;

    if resp.status() == reqwest::StatusCode::NOT_FOUND && !client.api_url().ends_with("/api") {
        let alt_resp = client
            .fetch_with_auth(reqwest::Method::POST, "api/ciphers", body)
            .await?;
        if alt_resp.status().is_success() {
            resp = alt_resp;
        }
    }

    if !resp.status().is_success() {
        let status = resp.status();
        let message = resp.text().await.unwrap_or_default();
        return Err(ApiError::Status { status, message });
    }

    let created: Cipher = resp.json().await?;
    Ok(created)
}

/// Updates an existing cipher in the Bitwarden vault (`PUT /ciphers/{uuid}`).
pub async fn put_cipher(
    client: &AuthenticatedClient,
    uuid: &Uuid,
    cipher: &Cipher,
) -> Result<Cipher, ApiError> {
    let endpoint = format!("ciphers/{uuid}");
    let body = RequestBody::Json(serde_json::to_value(cipher)?);
    let mut resp = client
        .fetch_with_auth(reqwest::Method::PUT, &endpoint, body.clone())
        .await?;

    if resp.status() == reqwest::StatusCode::NOT_FOUND && !client.api_url().ends_with("/api") {
        let alt_endpoint = format!("api/ciphers/{uuid}");
        let alt_resp = client
            .fetch_with_auth(reqwest::Method::PUT, &alt_endpoint, body)
            .await?;
        if alt_resp.status().is_success() {
            resp = alt_resp;
        }
    }

    if !resp.status().is_success() {
        let status = resp.status();
        let message = resp.text().await.unwrap_or_default();
        return Err(ApiError::Status { status, message });
    }

    let updated: Cipher = resp.json().await?;
    Ok(updated)
}

/// Deletes a cipher by UUID from the Bitwarden vault (`DELETE /ciphers/{uuid}`).
pub async fn delete_cipher(client: &AuthenticatedClient, uuid: &Uuid) -> Result<(), ApiError> {
    let endpoint = format!("ciphers/{uuid}");
    let mut resp = client
        .fetch_with_auth(reqwest::Method::DELETE, &endpoint, RequestBody::Empty)
        .await?;

    if resp.status() == reqwest::StatusCode::NOT_FOUND && !client.api_url().ends_with("/api") {
        let alt_endpoint = format!("api/ciphers/{uuid}");
        let alt_resp = client
            .fetch_with_auth(reqwest::Method::DELETE, &alt_endpoint, RequestBody::Empty)
            .await?;
        if alt_resp.status().is_success() {
            resp = alt_resp;
        }
    }

    if !resp.status().is_success() {
        let status = resp.status();
        let message = resp.text().await.unwrap_or_default();
        return Err(ApiError::Status { status, message });
    }

    Ok(())
}
