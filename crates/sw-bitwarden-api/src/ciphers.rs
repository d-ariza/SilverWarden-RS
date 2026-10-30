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
    let mut cipher_to_post = cipher.clone();
    cipher_to_post.id = None;
    let body = RequestBody::Json(serde_json::to_value(&cipher_to_post)?);
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

#[cfg(test)]
mod tests {
    use serde_json::json;
    use sw_vault::{Cipher, CipherType, EncString, LoginCipher};

    #[test]
    fn test_cipher_serialization_vaultwarden_compatibility() {
        let valid_enc: EncString = "2.aXZfMTZfYnl0ZXNfbG9uZw==|Y2lwaGVydGV4dF9ieXRlcw==|bWFjXzMyX2J5dGVzX2xvbmdfaGFzaF9zdHJpbmchIQ=="
            .parse()
            .expect("valid EncString");

        let cipher = Cipher {
            id: None, // New cipher should not send an ID
            r#type: CipherType::Login,
            name: valid_enc.clone(),
            favorite: false,
            reprompt: 0,
            fields: vec![],
            login: Some(LoginCipher {
                username: Some(valid_enc.clone()),
                password: Some(valid_enc.clone()),
                uri: None,
                uris: vec![],
                totp: None,
            }),
            ..Default::default()
        };

        let val = serde_json::to_value(&cipher).expect("serialization succeeds");
        let obj = val.as_object().expect("cipher serializes as JSON object");

        // 1. Check all keys use camelCase (not PascalCase)
        for key in obj.keys() {
            assert!(
                !key.chars().next().unwrap().is_ascii_uppercase(),
                "Key '{key}' is PascalCase or starts with uppercase, Vaultwarden requires camelCase"
            );
        }

        // 2. Check mandatory fields
        assert_eq!(obj.get("type"), Some(&json!(1)), "type must be 1 for Login");
        assert_eq!(
            obj.get("name"),
            Some(&json!(valid_enc.to_string_repr().unwrap())),
            "name must be encrypted string"
        );
        assert_eq!(
            obj.get("favorite"),
            Some(&json!(false)),
            "favorite must be false"
        );
        assert_eq!(obj.get("reprompt"), Some(&json!(0)), "reprompt must be 0");

        // 3. Check format of fields: must be empty array [], never null
        assert_eq!(
            obj.get("fields"),
            Some(&json!([])),
            "fields must serialize as an array, not null"
        );

        // 4. Check login object
        let login = obj.get("login").expect("login field must be present");
        let login_obj = login.as_object().expect("login must be an object");
        for key in login_obj.keys() {
            assert!(
                !key.chars().next().unwrap().is_ascii_uppercase(),
                "Login key '{key}' must be camelCase"
            );
        }
        assert_eq!(
            login_obj.get("username"),
            Some(&json!(valid_enc.to_string_repr().unwrap()))
        );
        assert_eq!(
            login_obj.get("password"),
            Some(&json!(valid_enc.to_string_repr().unwrap()))
        );
        assert_eq!(
            login_obj.get("uris"),
            Some(&json!([])),
            "login.uris must be an empty array, not null"
        );

        // 5. id must be omitted for new cipher creations
        assert!(
            obj.get("id").is_none(),
            "id must not be present when id is None"
        );

        // 6. Compare with a real Vaultwarden / Bitwarden web vault payload
        let expected_real_payload = json!({
            "type": 1,
            "folderId": null,
            "organizationId": null,
            "name": valid_enc.to_string_repr().unwrap(),
            "notes": null,
            "favorite": false,
            "reprompt": 0,
            "login": {
                "uris": [],
                "username": valid_enc.to_string_repr().unwrap(),
                "password": valid_enc.to_string_repr().unwrap(),
                "totp": null
            },
            "fields": [],
            "secureNote": null,
            "card": null,
            "identity": null
        });

        assert_eq!(val, expected_real_payload);
    }

    #[test]
    fn test_cipher_deserializes_null_fields_and_uris_as_empty_vec() {
        let json_with_nulls = json!({
            "type": 1,
            "name": "",
            "fields": null,
            "login": {
                "uris": null
            }
        });

        let cipher: Cipher =
            serde_json::from_value(json_with_nulls).expect("deserializes null fields/uris cleanly");
        assert!(cipher.fields.is_empty());
        assert!(cipher.login.unwrap().uris.is_empty());
    }
}
