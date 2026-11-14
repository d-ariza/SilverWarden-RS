use sw_crypto::SymmetricKey;
use uuid::Uuid;

use crate::models::{Cipher, CipherType, DecryptedCipher, VaultError, VaultSshKey};
use crate::store::VaultStore;

impl VaultStore {
    /// Resolves a cipher's optional per-item symmetric key (for example, an organization key).
    pub(crate) fn resolve_cipher_key(
        cipher: &Cipher,
        user_key: &SymmetricKey,
    ) -> Option<SymmetricKey> {
        if let Some(ref enc_k) = cipher.key {
            if !enc_k.is_null() {
                match sw_crypto::decrypt_with(enc_k, user_key) {
                    Ok(kb) => SymmetricKey::from_bytes(&kb).ok(),
                    Err(_) => None,
                }
            } else {
                None
            }
        } else {
            None
        }
    }

    pub(crate) fn filter_logins(
        logins: Vec<Cipher>,
        uuid: Option<&Uuid>,
        org_id: Option<&Uuid>,
        name: Option<&str>,
        username: Option<&str>,
        key: &SymmetricKey,
    ) -> Option<Cipher> {
        for cipher in logins {
            if let Some(expected_id) = uuid {
                if cipher.id.as_ref() != Some(expected_id) {
                    continue;
                }
            }
            if let Some(expected_org) = org_id {
                if cipher.organization_id.as_ref() != Some(expected_org) {
                    continue;
                }
            }

            let cipher_key_owned = Self::resolve_cipher_key(&cipher, key);
            let cipher_key = cipher_key_owned.as_ref().unwrap_or(key);

            if let Some(expected_name) = name {
                if cipher.name.is_null() {
                    continue;
                }
                match sw_crypto::decrypt_with(&cipher.name, cipher_key) {
                    Ok(bytes) => {
                        if let Ok(dec_name) = String::from_utf8(bytes) {
                            if dec_name != expected_name {
                                continue;
                            }
                        } else {
                            continue;
                        }
                    }
                    Err(_) => continue,
                }
            }
            if let Some(expected_username) = username {
                let login_match = match &cipher.login {
                    Some(login) => match &login.username {
                        Some(enc_un) if !enc_un.is_null() => {
                            match sw_crypto::decrypt_with(enc_un, cipher_key) {
                                Ok(bytes) => match String::from_utf8(bytes) {
                                    Ok(dec_un) => dec_un == expected_username,
                                    Err(_) => false,
                                },
                                Err(_) => false,
                            }
                        }
                        _ => false,
                    },
                    None => false,
                };
                if !login_match {
                    continue;
                }
            }
            return Some(cipher);
        }
        None
    }

    pub(crate) fn filter_notes(
        notes: Vec<Cipher>,
        uuid: Option<&Uuid>,
        org_id: Option<&Uuid>,
        name: Option<&str>,
        key: &SymmetricKey,
    ) -> Option<Cipher> {
        for cipher in notes {
            if let Some(expected_id) = uuid {
                if cipher.id.as_ref() != Some(expected_id) {
                    continue;
                }
            }
            if let Some(expected_org) = org_id {
                if cipher.organization_id.as_ref() != Some(expected_org) {
                    continue;
                }
            }

            let cipher_key_owned = Self::resolve_cipher_key(&cipher, key);
            let cipher_key = cipher_key_owned.as_ref().unwrap_or(key);

            if let Some(expected_name) = name {
                if cipher.name.is_null() {
                    continue;
                }
                match sw_crypto::decrypt_with(&cipher.name, cipher_key) {
                    Ok(bytes) => {
                        if let Ok(dec_name) = String::from_utf8(bytes) {
                            if dec_name != expected_name {
                                continue;
                            }
                        } else {
                            continue;
                        }
                    }
                    Err(_) => continue,
                }
            }
            return Some(cipher);
        }
        None
    }

    /// Decrypts sensitive fields of a cipher on demand using the provided symmetric key.
    ///
    /// Synchronous method as decryption is CPU-bound.
    pub fn decrypt_cipher(
        cipher: &Cipher,
        key: &SymmetricKey,
    ) -> Result<DecryptedCipher, VaultError> {
        let cipher_key_owned = Self::resolve_cipher_key(cipher, key);
        let cipher_key = cipher_key_owned.as_ref().unwrap_or(key);

        if cipher.name.is_null() {
            return Err(VaultError::Other(
                "Cipher name is missing or empty".to_string(),
            ));
        }
        let name_bytes = sw_crypto::decrypt_with(&cipher.name, cipher_key)?;
        let name = String::from_utf8(name_bytes)?;

        let mut username = None;
        let mut password = None;
        let mut uri = None;
        let mut totp = None;

        if let Some(ref login) = cipher.login {
            if let Some(ref enc_un) = login.username {
                if !enc_un.is_null() {
                    if let Ok(bytes) = sw_crypto::decrypt_with(enc_un, cipher_key) {
                        username = String::from_utf8(bytes).ok();
                    }
                }
            }
            if let Some(ref enc_pw) = login.password {
                if !enc_pw.is_null() {
                    if let Ok(bytes) = sw_crypto::decrypt_with(enc_pw, cipher_key) {
                        password = String::from_utf8(bytes).ok();
                    }
                }
            }
            if let Some(ref enc_uri) = login.uri {
                if !enc_uri.is_null() {
                    if let Ok(bytes) = sw_crypto::decrypt_with(enc_uri, cipher_key) {
                        uri = String::from_utf8(bytes).ok();
                    } else {
                        uri = login.uris.first().and_then(|u| u.uri.clone());
                    }
                } else {
                    uri = login.uris.first().and_then(|u| u.uri.clone());
                }
            } else {
                uri = login.uris.first().and_then(|u| u.uri.clone());
            }
            if let Some(ref enc_totp) = login.totp {
                if !enc_totp.is_null() {
                    if let Ok(bytes) = sw_crypto::decrypt_with(enc_totp, cipher_key) {
                        totp = String::from_utf8(bytes).ok();
                    }
                }
            }
        }

        let mut notes = None;
        if let Some(ref enc_notes) = cipher.notes {
            if !enc_notes.is_null() {
                if let Ok(bytes) = sw_crypto::decrypt_with(enc_notes, cipher_key) {
                    notes = String::from_utf8(bytes).ok();
                }
            }
        }

        Ok(DecryptedCipher {
            id: cipher.id.unwrap_or_default(),
            name,
            cipher_type: cipher.r#type,
            username,
            password,
            uri,
            notes,
            totp,
            favorite: cipher.favorite,
        })
    }

    pub(crate) fn filter_search(
        ciphers: Vec<Cipher>,
        filter: &str,
        key: &SymmetricKey,
    ) -> Vec<DecryptedCipher> {
        let filter_lower = filter.to_lowercase();
        let mut results = Vec::new();

        for cipher in ciphers {
            if let Ok(dec) = Self::decrypt_cipher(&cipher, key) {
                let name_matches =
                    dec.name.contains(filter) || dec.name.to_lowercase().contains(&filter_lower);
                let username_matches = dec.username.as_deref().is_some_and(|u| {
                    u.contains(filter) || u.to_lowercase().contains(&filter_lower)
                });

                if name_matches || username_matches {
                    results.push(dec);
                }
            }
        }

        results
    }

    /// Extracts SSH keys from Type 5 (SshKey) ciphers.
    pub fn extract_ssh_key_ciphers(
        ciphers: &[Cipher],
        user_key: &SymmetricKey,
    ) -> Result<Vec<VaultSshKey>, VaultError> {
        let mut keys = Vec::new();
        for cipher in ciphers {
            if cipher.deleted_date.is_some() || cipher.r#type != CipherType::SshKey {
                continue;
            }

            let cipher_key_owned = Self::resolve_cipher_key(cipher, user_key);
            let cipher_key = cipher_key_owned.as_ref().unwrap_or(user_key);

            let name = if !cipher.name.is_null() {
                match sw_crypto::decrypt_with(&cipher.name, cipher_key) {
                    Ok(b) => String::from_utf8(b).unwrap_or_else(|_| "unnamed".to_string()),
                    Err(_) => "unnamed".to_string(),
                }
            } else {
                "unnamed".to_string()
            };

            if let Some(ref ssh) = cipher.ssh_key {
                let private_key = if let Some(ref pk) = ssh.private_key {
                    if !pk.is_null() {
                        sw_crypto::decrypt_with(pk, cipher_key)
                            .ok()
                            .and_then(|b| String::from_utf8(b).ok())
                    } else {
                        None
                    }
                } else {
                    None
                };

                let public_key = if let Some(ref pubk) = ssh.public_key {
                    if !pubk.is_null() {
                        sw_crypto::decrypt_with(pubk, cipher_key)
                            .ok()
                            .and_then(|b| String::from_utf8(b).ok())
                    } else {
                        None
                    }
                } else {
                    None
                };

                if let Some(pk_str) = private_key {
                    keys.push(VaultSshKey {
                        id: cipher.id,
                        name,
                        private_key: Self::normalize_pem(&pk_str),
                        public_key,
                    });
                }
            }
        }
        Ok(keys)
    }

    /// Extracts SSH keys from legacy Secure Notes (type 2 with custom-type: ssh-key).
    pub fn extract_legacy_ssh_notes(
        ciphers: &[Cipher],
        user_key: &SymmetricKey,
    ) -> Result<Vec<VaultSshKey>, VaultError> {
        let mut keys = Vec::new();
        for cipher in ciphers {
            if cipher.deleted_date.is_some() || cipher.r#type != CipherType::Note {
                continue;
            }

            let cipher_key_owned = Self::resolve_cipher_key(cipher, user_key);
            let cipher_key = cipher_key_owned.as_ref().unwrap_or(user_key);

            let name = if !cipher.name.is_null() {
                match sw_crypto::decrypt_with(&cipher.name, cipher_key) {
                    Ok(b) => String::from_utf8(b).unwrap_or_else(|_| "unnamed".to_string()),
                    Err(_) => "unnamed".to_string(),
                }
            } else {
                "unnamed".to_string()
            };

            let mut is_ssh = false;
            let mut pk_opt = None;
            let mut pubk_opt = None;

            for field in &cipher.fields {
                let fname = if let Some(ref fn_enc) = field.name {
                    if !fn_enc.is_null() {
                        sw_crypto::decrypt_with(fn_enc, cipher_key)
                            .ok()
                            .and_then(|b| String::from_utf8(b).ok())
                    } else {
                        None
                    }
                } else {
                    None
                };

                let fval = if let Some(ref fv_enc) = field.value {
                    if !fv_enc.is_null() {
                        sw_crypto::decrypt_with(fv_enc, cipher_key)
                            .ok()
                            .and_then(|b| String::from_utf8(b).ok())
                    } else {
                        None
                    }
                } else {
                    None
                };

                if let (Some(fn_str), Some(fv_str)) = (fname.as_deref(), fval.as_deref()) {
                    if fn_str == "custom-type" && fv_str == "ssh-key" || fn_str == "ssh-key" {
                        is_ssh = true;
                    }
                    if fn_str == "private-key" {
                        pk_opt = Some(fv_str.to_string());
                    }
                    if fn_str == "public-key" {
                        pubk_opt = Some(fv_str.to_string());
                    }
                }
            }

            if let Some(pk_str) = pk_opt {
                if is_ssh || !pk_str.is_empty() {
                    keys.push(VaultSshKey {
                        id: cipher.id,
                        name,
                        private_key: Self::normalize_pem(&pk_str),
                        public_key: pubk_opt,
                    });
                }
            }
        }
        Ok(keys)
    }

    pub(crate) fn normalize_pem(pem: &str) -> String {
        let trimmed = pem.trim();
        if trimmed.starts_with("-----")
            && !trimmed.contains('\n')
            && trimmed.contains("-----BEGIN ")
        {
            if let Some(begin_end) = trimmed.find("----- ") {
                let header = &trimmed[..begin_end + 5];
                let remainder = &trimmed[begin_end + 5..].trim_start();
                if let Some(last_dash) = remainder.rfind(" -----END ") {
                    let body = &remainder[..last_dash];
                    let footer = &remainder[last_dash + 1..];
                    let body_lines = body.split_whitespace().collect::<Vec<_>>().join("\n");
                    return format!("{header}\n{body_lines}\n{footer}\n");
                }
            }
        }
        trimmed.to_string()
    }
}
