use base64::Engine;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use sw_config::LoginToken;
use zeroize::Zeroize;

use crate::client::{
    ApiError, AuthenticatedClient, BITWARDEN_CLIENT_NAME, BITWARDEN_CLIENT_VERSION,
    BITWARDEN_DEVICE_TYPE, BITWARDEN_USER_AGENT,
};
use crate::twofactor;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreloginResponse {
    pub kdf: i32,
    pub kdf_iterations: Option<u32>,
    pub kdf_memory: Option<u32>,
    pub kdf_parallelism: Option<u32>,
}

impl TryFrom<PreloginResponse> for sw_crypto::KdfConfig {
    type Error = ApiError;

    fn try_from(resp: PreloginResponse) -> Result<Self, Self::Error> {
        let kdf_type = sw_crypto::KdfType::from_i32(resp.kdf)
            .map_err(|e| ApiError::Auth(format!("Unsupported KDF type {}: {e}", resp.kdf)))?;
        let iterations = resp
            .kdf_iterations
            .unwrap_or(if kdf_type == sw_crypto::KdfType::Pbkdf2 {
                100_000
            } else {
                3
            });
        Ok(sw_crypto::KdfConfig {
            kdf_type,
            iterations,
            memory: resp.kdf_memory,
            parallelism: resp.kdf_parallelism,
        })
    }
}

impl AuthenticatedClient {
    /// Queries the prelogin endpoint to obtain the account's KDF configuration.
    pub async fn prelogin(&self, email: &str) -> Result<sw_crypto::KdfConfig, ApiError> {
        let identity_base = self.identity_url.trim_end_matches('/');
        let url = format!("{identity_base}/accounts/prelogin");
        let resp = self
            .client
            .post(&url)
            .header("User-Agent", BITWARDEN_USER_AGENT)
            .header("Device-Type", BITWARDEN_DEVICE_TYPE)
            .header("Bitwarden-Client-Name", BITWARDEN_CLIENT_NAME)
            .header("Bitwarden-Client-Version", BITWARDEN_CLIENT_VERSION)
            .json(&serde_json::json!({ "email": email }))
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(ApiError::Status {
                status,
                message: body,
            });
        }

        let prelogin_resp: PreloginResponse = resp.json().await?;
        let kdf_config: sw_crypto::KdfConfig = prelogin_resp.try_into()?;
        Ok(kdf_config)
    }

    /// Authenticates with email and derived master password hash against `/connect/token`.
    pub async fn login_with_password(
        &self,
        email: &str,
        master_password_hash: &str,
        device_uuid: &str,
    ) -> Result<LoginToken, ApiError> {
        let url = format!("{}/connect/token", self.identity_url.trim_end_matches('/'));

        let b64_email = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(email.as_bytes());

        let params = [
            ("scope", "api offline_access"),
            ("client_id", "web"),
            ("deviceType", BITWARDEN_DEVICE_TYPE),
            ("deviceIdentifier", device_uuid),
            ("deviceName", "firefox"),
            ("grant_type", "password"),
            ("username", email),
            ("password", master_password_hash),
        ];

        let resp = self
            .client
            .post(&url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Auth-Email", b64_email)
            .header("User-Agent", BITWARDEN_USER_AGENT)
            .header("Device-Type", BITWARDEN_DEVICE_TYPE)
            .header("Bitwarden-Client-Name", BITWARDEN_CLIENT_NAME)
            .header("Bitwarden-Client-Version", BITWARDEN_CLIENT_VERSION)
            .form(&params)
            .send()
            .await
            .map_err(ApiError::Reqwest)?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();

            if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
                return Err(ApiError::RateLimitExceeded);
            }

            if (status == reqwest::StatusCode::UNAUTHORIZED
                || status == reqwest::StatusCode::BAD_REQUEST)
                && (body.contains("TwoFactor") || body.contains("twoFactor"))
            {
                if let Some((providers, token)) = twofactor::parse_two_factor_error(&body) {
                    return Err(ApiError::TwoFactorRequired { providers, token });
                } else {
                    return Err(ApiError::Status {
                        status,
                        message: body,
                    });
                }
            }

            if status == reqwest::StatusCode::UNAUTHORIZED {
                return Err(ApiError::InvalidCredentials);
            }

            return Err(ApiError::Auth(format!(
                "Login with password failed with status {status}: {body}"
            )));
        }

        let token: LoginToken = resp
            .json()
            .await
            .map_err(|e| ApiError::Auth(format!("Failed to parse login token response: {e}")))?;

        // Update stored token in client
        *self.token.lock().await = token.clone();

        Ok(token)
    }

    /// Full end-to-end login orchestration:
    /// prelogin -> derive master key -> derive master password hash -> stretch key ->
    /// login_with_password -> decrypt_enc_key.
    ///
    /// Returns the active `LoginToken` and the decrypted 64-byte user symmetric key.
    pub async fn login(
        &self,
        email: &str,
        password: &str,
        device_uuid: &str,
    ) -> Result<(LoginToken, Vec<u8>), ApiError> {
        let kdf_config = self.prelogin(email).await?;
        let master_key = sw_crypto::derive_master_key(password.as_bytes(), email, &kdf_config)?;
        let master_password_hash = derive_master_password_hash(master_key.as_slice(), password);
        let stretched_sym_key = sw_crypto::stretch_key(&master_key)?;
        let stretched_bytes = stretched_sym_key.bytes();

        let token = self
            .login_with_password(email, &master_password_hash, device_uuid)
            .await?;

        if token.key.is_empty() {
            return Err(ApiError::Auth(
                "Login succeeded but server did not return an encryption key".to_string(),
            ));
        }

        let user_symmetric_key = decrypt_enc_key(&token.key, &stretched_bytes)?;
        Ok((token, user_symmetric_key))
    }

    /// Authenticates using Bitwarden API credentials (`client_id` and `client_secret`) against `/connect/token`.
    pub async fn login_with_api_key(
        &self,
        client_id: &str,
        client_secret: &str,
        device_uuid: &str,
    ) -> Result<LoginToken, ApiError> {
        let url = format!("{}/connect/token", self.identity_url.trim_end_matches('/'));

        let params = [
            ("grant_type", "client_credentials"),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("scope", "api"),
            ("deviceType", BITWARDEN_DEVICE_TYPE),
            ("deviceIdentifier", device_uuid),
        ];

        let resp = self
            .client
            .post(&url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("User-Agent", BITWARDEN_USER_AGENT)
            .header("Device-Type", BITWARDEN_DEVICE_TYPE)
            .header("Bitwarden-Client-Name", BITWARDEN_CLIENT_NAME)
            .header("Bitwarden-Client-Version", BITWARDEN_CLIENT_VERSION)
            .form(&params)
            .send()
            .await
            .map_err(ApiError::Reqwest)?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();

            if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
                return Err(ApiError::RateLimitExceeded);
            }

            if status == reqwest::StatusCode::UNAUTHORIZED
                || status == reqwest::StatusCode::BAD_REQUEST
            {
                return Err(ApiError::Auth(format!(
                    "Credenciales de API Key inválidas ({status}): {body}"
                )));
            }

            return Err(ApiError::Auth(format!(
                "Login with API key failed with status {status}: {body}"
            )));
        }

        let token: LoginToken = resp
            .json()
            .await
            .map_err(|e| ApiError::Auth(format!("Failed to parse login token response: {e}")))?;

        // Update stored token in client
        *self.token.lock().await = token.clone();

        Ok(token)
    }

    /// Full end-to-end API Key login orchestration:
    /// login_with_api_key -> prelogin -> derive master key -> stretch key -> decrypt_enc_key.
    ///
    /// Returns the active `LoginToken` and the decrypted 64-byte user symmetric key.
    pub async fn login_api_key(
        &self,
        client_id: &str,
        client_secret: &str,
        email: &str,
        password: &str,
        device_uuid: &str,
    ) -> Result<(LoginToken, Vec<u8>), ApiError> {
        let token = self
            .login_with_api_key(client_id, client_secret, device_uuid)
            .await?;

        if token.key.is_empty() {
            return Err(ApiError::Auth(
                "Login with API key succeeded but server did not return an encryption key"
                    .to_string(),
            ));
        }

        let kdf_config = self.prelogin(email).await?;
        let master_key = sw_crypto::derive_master_key(password.as_bytes(), email, &kdf_config)?;
        let stretched_sym_key = sw_crypto::stretch_key(&master_key)?;
        let user_symmetric_key = decrypt_enc_key(&token.key, &stretched_sym_key.bytes())?;

        Ok((token, user_symmetric_key))
    }

    /// Completes a 2FA challenge and decrypts the user symmetric key with the master password.
    pub async fn complete_2fa(
        &self,
        email: &str,
        password: &str,
        two_factor_token: &str,
        code: &str,
        provider: i32,
        device_uuid: &str,
    ) -> Result<(LoginToken, Vec<u8>), ApiError> {
        let kdf_config = self.prelogin(email).await?;
        let master_key = sw_crypto::derive_master_key(password.as_bytes(), email, &kdf_config)?;
        let master_password_hash = derive_master_password_hash(master_key.as_slice(), password);
        let stretched_sym_key = sw_crypto::stretch_key(&master_key)?;
        let stretched_bytes = stretched_sym_key.bytes();

        let token = match provider {
            0 => {
                self.complete_totp(
                    email,
                    &master_password_hash,
                    two_factor_token,
                    code,
                    device_uuid,
                )
                .await?
            }
            1 => {
                self.complete_email(
                    email,
                    &master_password_hash,
                    two_factor_token,
                    code,
                    device_uuid,
                )
                .await?
            }
            other => {
                return Err(ApiError::NotImplemented(format!(
                    "Proveedor 2FA no soportado: {other}"
                )));
            }
        };

        if token.key.is_empty() {
            return Err(ApiError::Auth(
                "El servidor no devolvió una clave de cifrado (Key) tras el 2FA".to_string(),
            ));
        }

        let user_symmetric_key = decrypt_enc_key(&token.key, &stretched_bytes)?;
        Ok((token, user_symmetric_key))
    }

    /// Completes 2FA login using an Authenticator/TOTP verification code.
    pub async fn complete_totp(
        &self,
        email: &str,
        master_password_hash: &str,
        two_factor_token: &str,
        totp_code: &str,
        device_uuid: &str,
    ) -> Result<LoginToken, ApiError> {
        twofactor::complete_totp(
            self,
            email,
            master_password_hash,
            two_factor_token,
            totp_code,
            device_uuid,
        )
        .await
    }

    /// Completes 2FA login using an Email verification code.
    pub async fn complete_email(
        &self,
        email: &str,
        master_password_hash: &str,
        two_factor_token: &str,
        email_code: &str,
        device_uuid: &str,
    ) -> Result<LoginToken, ApiError> {
        twofactor::complete_email(
            self,
            email,
            master_password_hash,
            two_factor_token,
            email_code,
            device_uuid,
        )
        .await
    }

    /// Sends an email with a login verification code.
    pub async fn send_two_factor_email_login(
        &self,
        email: &str,
        device_uuid: &str,
    ) -> Result<(), ApiError> {
        twofactor::send_two_factor_email_login(self, email, device_uuid).await
    }

    /// Completes 2FA login via FIDO2 (stub).
    pub async fn complete_fido2(
        &self,
        email: &str,
        master_password_hash: &str,
        two_factor_token: &str,
        device_uuid: &str,
    ) -> Result<LoginToken, ApiError> {
        twofactor::complete_fido2(
            self,
            email,
            master_password_hash,
            two_factor_token,
            device_uuid,
        )
        .await
    }
}

/// Derives the master password hash used to authenticate against Bitwarden.
///
/// Uses PBKDF2-HMAC-SHA256 with 1 iteration over the derived master key bytes
/// and the password as salt, encoded as standard Base64.
/// Parity with Goldwarden Go: `pbkdf2.Key(masterKey.GetBytes(), []byte(password), 1, 32, sha256.New)`
pub fn derive_master_password_hash(master_key: &[u8], password: &str) -> String {
    let mut hash = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(master_key, password.as_bytes(), 1, &mut hash);
    let encoded = base64::engine::general_purpose::STANDARD.encode(hash);
    hash.zeroize();
    encoded
}

/// Decrypts the user symmetric key from the wire EncString returned during login or sync.
///
/// Parses `enc_key_wire` as `sw_crypto::EncString` and decrypts using the stretched master key.
pub fn decrypt_enc_key(
    enc_key_wire: &str,
    stretched_master_key: &[u8],
) -> Result<Vec<u8>, ApiError> {
    if enc_key_wire.is_empty() {
        return Err(ApiError::Auth("enc_key is empty".to_string()));
    }

    let enc_string = sw_crypto::EncString::from_str(enc_key_wire)
        .map_err(|e| ApiError::Auth(format!("Failed to parse EncString from wire: {e}")))?;

    let sym_key = sw_crypto::SymmetricKey::from_bytes(stretched_master_key)
        .map_err(|e| ApiError::Auth(format!("Invalid stretched master key: {e}")))?;

    let decrypted = sw_crypto::decrypt_with(&enc_string, &sym_key)
        .map_err(|e| ApiError::Auth(format!("Failed to decrypt enc_key: {e}")))?;

    Ok(decrypted)
}

/// Standalone convenience wrapper for `AuthenticatedClient::prelogin`.
pub async fn prelogin(
    client: &AuthenticatedClient,
    email: &str,
) -> Result<sw_crypto::KdfConfig, ApiError> {
    client.prelogin(email).await
}

/// Standalone convenience wrapper for `AuthenticatedClient::login_with_password`.
pub async fn login_with_password(
    client: &AuthenticatedClient,
    email: &str,
    master_password_hash: &str,
    device_uuid: &str,
) -> Result<LoginToken, ApiError> {
    client
        .login_with_password(email, master_password_hash, device_uuid)
        .await
}

/// Standalone convenience wrapper for `AuthenticatedClient::login`.
pub async fn login(
    client: &AuthenticatedClient,
    email: &str,
    password: &str,
    device_uuid: &str,
) -> Result<(LoginToken, Vec<u8>), ApiError> {
    client.login(email, password, device_uuid).await
}

/// Standalone convenience wrapper for `AuthenticatedClient::login_with_api_key`.
pub async fn login_with_api_key(
    client: &AuthenticatedClient,
    client_id: &str,
    client_secret: &str,
    device_uuid: &str,
) -> Result<LoginToken, ApiError> {
    client
        .login_with_api_key(client_id, client_secret, device_uuid)
        .await
}

/// Standalone convenience wrapper for `AuthenticatedClient::login_api_key`.
pub async fn login_api_key(
    client: &AuthenticatedClient,
    client_id: &str,
    client_secret: &str,
    email: &str,
    password: &str,
    device_uuid: &str,
) -> Result<(LoginToken, Vec<u8>), ApiError> {
    client
        .login_api_key(client_id, client_secret, email, password, device_uuid)
        .await
}
