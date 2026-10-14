use crate::encstring::{EncString, EncStringType};
use crate::error::CryptoError;
use crate::keyhierarchy::SymmetricKey;
use aes::cipher::block_padding::NoPadding;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use subtle::ConstantTimeEq;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type HmacSha256 = Hmac<Sha256>;

const BLOCK_SIZE: usize = 16;

/// Applies standard PKCS#7 padding to data for block_size.
pub fn pkcs7_pad(data: &[u8], block_size: usize) -> Result<Vec<u8>, CryptoError> {
    if block_size == 0 || block_size > 255 {
        return Err(CryptoError::InvalidPadding(format!(
            "invalid block size for PKCS7: {}",
            block_size
        )));
    }
    let rem = data.len() % block_size;
    let n = (block_size - rem) as u8;
    let mut padded = Vec::with_capacity(data.len() + n as usize);
    padded.extend_from_slice(data);
    padded.resize(data.len() + n as usize, n);
    Ok(padded)
}

/// Removes PKCS#7 padding from data, validating that all padding bytes match.
///
/// D20 decision: unlike Go which only checks the final byte, Rust validates that all n
/// padding bytes are equal to n and 1 <= n <= block_size.
pub fn pkcs7_unpad(data: &[u8], block_size: usize) -> Result<Vec<u8>, CryptoError> {
    if data.is_empty() || !data.len().is_multiple_of(block_size) {
        return Err(CryptoError::InvalidPadding(format!(
            "expected PKCS7 padding for block size {}, but have {} bytes",
            block_size,
            data.len()
        )));
    }
    let n = data[data.len() - 1] as usize;
    if n == 0 || n > block_size || n > data.len() {
        return Err(CryptoError::InvalidPadding(format!(
            "invalid PKCS7 padding byte: {}",
            n
        )));
    }

    // Verify all n padding bytes are equal to n
    for &b in &data[data.len() - n..] {
        if b as usize != n {
            return Err(CryptoError::InvalidPadding(
                "inconsistent PKCS7 padding bytes".into(),
            ));
        }
    }

    Ok(data[..data.len() - n].to_vec())
}

/// Checks HMAC-SHA256 over message using constant-time comparison.
pub fn is_mac_valid(message: &[u8], mac_bytes: &[u8], key: &[u8]) -> bool {
    let mut mac = match HmacSha256::new_from_slice(key) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(message);
    let expected = mac.finalize().into_bytes();
    expected.as_slice().ct_eq(mac_bytes).into()
}

/// Internal AES-256-CBC encryption with optional fixed IV.
pub fn encrypt_aes_cbc_256(
    plaintext: &[u8],
    key: &[u8],
    fixed_iv: Option<&[u8]>,
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    if key.len() != 32 {
        return Err(CryptoError::InvalidKeyLength(format!(
            "AES-256 requires 32-byte key, got {}",
            key.len()
        )));
    }

    let mut iv = [0u8; BLOCK_SIZE];
    if let Some(user_iv) = fixed_iv {
        if user_iv.len() != BLOCK_SIZE {
            return Err(CryptoError::EncryptionFailed(format!(
                "IV length does not match AES block size (16), got {}",
                user_iv.len()
            )));
        }
        iv.copy_from_slice(user_iv);
    } else {
        rand::rngs::OsRng.fill_bytes(&mut iv);
    }

    let mut padded = pkcs7_pad(plaintext, BLOCK_SIZE)?;
    let len = padded.len();
    let encryptor = Aes256CbcEnc::new(key.into(), &iv.into());
    encryptor
        .encrypt_padded_mut::<NoPadding>(&mut padded, len)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    Ok((iv.to_vec(), padded))
}

/// Internal AES-256-CBC decryption.
pub fn decrypt_aes_cbc_256(iv: &[u8], ct: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if key.len() != 32 {
        return Err(CryptoError::InvalidKeyLength(format!(
            "AES-256 requires 32-byte key, got {}",
            key.len()
        )));
    }
    if iv.len() != BLOCK_SIZE {
        return Err(CryptoError::DecryptionFailed(format!(
            "IV length does not match AES block size (16), got {}",
            iv.len()
        )));
    }
    if !ct.len().is_multiple_of(BLOCK_SIZE) || ct.is_empty() {
        return Err(CryptoError::InvalidCiphertext(format!(
            "ciphertext length ({}) is not a non-zero multiple of AES block size",
            ct.len()
        )));
    }

    let mut buffer = ct.to_vec();
    let decryptor = Aes256CbcDec::new(key.into(), iv.into());
    decryptor
        .decrypt_padded_mut::<NoPadding>(&mut buffer)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

    pkcs7_unpad(&buffer, BLOCK_SIZE)
}

/// Encrypts plaintext using AES-256-CBC with specified cipher type (Type 0 or Type 2).
pub fn encrypt_with(
    data: &[u8],
    enc_type: EncStringType,
    key: &SymmetricKey,
) -> Result<EncString, CryptoError> {
    encrypt_with_iv(data, enc_type, key, None)
}

/// Encrypts plaintext using AES-256-CBC with an optional fixed IV (for testing / deterministic vectors).
pub fn encrypt_with_iv(
    data: &[u8],
    enc_type: EncStringType,
    key: &SymmetricKey,
    fixed_iv: Option<&[u8]>,
) -> Result<EncString, CryptoError> {
    match enc_type {
        EncStringType::AesCbc256B64 | EncStringType::AesCbc256HmacSha256B64 => {}
        other => return Err(CryptoError::UnsupportedCipherType(other as i32)),
    }

    let (iv, ct) = encrypt_aes_cbc_256(data, key.enc_key(), fixed_iv)?;

    let mac = if enc_type == EncStringType::AesCbc256HmacSha256B64 {
        if key.mac_key().is_empty() {
            return Err(CryptoError::MissingEncStringComponent(
                "encrypt: cipher string type expects a MAC",
            ));
        }
        let mut msg = Vec::with_capacity(iv.len() + ct.len());
        msg.extend_from_slice(&iv);
        msg.extend_from_slice(&ct);

        let mut hmac = HmacSha256::new_from_slice(key.mac_key())
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
        hmac.update(&msg);
        hmac.finalize().into_bytes().to_vec()
    } else {
        Vec::new()
    };

    Ok(EncString::new(enc_type, iv, ct, mac))
}

/// Encrypts plaintext and returns the serialized EncString representation.
pub fn encrypt_with_to_string(
    data: &[u8],
    enc_type: EncStringType,
    key: &SymmetricKey,
) -> Result<String, CryptoError> {
    let enc = encrypt_with(data, enc_type, key)?;
    enc.to_string_repr()
}

/// Decrypts an EncString with a SymmetricKey.
///
/// Anti-padding oracle: verifies MAC before decrypting when cipher type is Type 2.
pub fn decrypt_with(enc: &EncString, key: &SymmetricKey) -> Result<Vec<u8>, CryptoError> {
    let cipher_type = enc
        .cipher_type
        .ok_or_else(|| CryptoError::InvalidEncString("Missing cipher type".into()))?;

    match cipher_type {
        EncStringType::AesCbc256B64 | EncStringType::AesCbc256HmacSha256B64 => {}
        other => return Err(CryptoError::UnsupportedCipherType(other as i32)),
    }

    if cipher_type == EncStringType::AesCbc256HmacSha256B64 {
        if enc.mac.is_empty() {
            return Err(CryptoError::MissingEncStringComponent(
                "decrypt: cipher string type expects a MAC",
            ));
        }
        if key.mac_key().is_empty() {
            return Err(CryptoError::InvalidKeyLength("MAC key is empty".into()));
        }

        let mut msg = Vec::with_capacity(enc.iv.len() + enc.ct.len());
        msg.extend_from_slice(&enc.iv);
        msg.extend_from_slice(&enc.ct);

        if !is_mac_valid(&msg, &enc.mac, key.mac_key()) {
            return Err(CryptoError::MacMismatch("MAC mismatch".into()));
        }
    } else if cipher_type == EncStringType::AesCbc256B64 {
        tracing::warn!(
            "WARNING: VAULT CONTAINS INSECURE AesCbc256_B64 CIPHER, PLEASE ROTATE YOUR VAULT KEYS IN THE WEB VAULT"
        );
    }

    decrypt_aes_cbc_256(&enc.iv, &enc.ct, key.enc_key())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[test]
    fn test_pkcs7_pad_unpad_roundtrip() {
        let cases: &[&[u8]] = &[
            b"",
            b"a",
            b"hello world",
            b"exactly 16 bytes",
            b"more than 16 bytes in this input string",
        ];

        for &case in cases {
            let padded = pkcs7_pad(case, 16).unwrap();
            assert_eq!(padded.len() % 16, 0);
            assert!(padded.len() > case.len());

            let unpadded = pkcs7_unpad(&padded, 16).unwrap();
            assert_eq!(unpadded, case);
        }
    }

    #[test]
    fn test_pkcs7_pad_exact_block_adds_full_block() {
        let input = [42u8; 16];
        let padded = pkcs7_pad(&input, 16).unwrap();
        assert_eq!(padded.len(), 32);
        assert_eq!(&padded[16..], &[16u8; 16]);
    }

    #[test]
    fn test_pkcs7_unpad_invalid_padding() {
        // Empty
        assert!(pkcs7_unpad(&[], 16).is_err());
        // Not multiple of block size
        assert!(pkcs7_unpad(&[1, 2, 3], 16).is_err());
        // Zero pad byte
        let mut zero_pad = vec![1u8; 15];
        zero_pad.push(0);
        assert!(pkcs7_unpad(&zero_pad, 16).is_err());
        // Pad byte > 16
        let mut big_pad = vec![1u8; 15];
        big_pad.push(17);
        assert!(pkcs7_unpad(&big_pad, 16).is_err());
        // Inconsistent padding bytes
        let mut inconsistent = vec![0u8; 16];
        inconsistent[14] = 1;
        inconsistent[15] = 2; // expects two 2s, but previous is 1
        assert!(pkcs7_unpad(&inconsistent, 16).is_err());
    }

    #[test]
    fn test_parity_go_cipher_type_2() {
        let enc_key = vec![0x42; 32];
        let mac_key = vec![0x43; 32];
        let key = SymmetricKey::from_parts(&enc_key, &mac_key).unwrap();

        let iv = vec![0x24; 16];
        let plaintext = b"hello world";

        // Encrypt with fixed IV and verify exact parity against Go
        let enc = encrypt_with_iv(
            plaintext,
            EncStringType::AesCbc256HmacSha256B64,
            &key,
            Some(&iv),
        )
        .unwrap();

        let expected_ct_hex = "edcfa3ee3645667d5e9b3b4fbbcce520";
        let expected_mac_hex = "56105a93e5dbd81bcdf3f030182b109ba2d7fa99108e0fda4b468c2322a30ca4";
        let expected_wire = "2.JCQkJCQkJCQkJCQkJCQkJA==|7c+j7jZFZn1emztPu8zlIA==|VhBak+Xb2BvN8/AwGCsQm6LX+pkQjg/aS0aMIyKjDKQ=";

        assert_eq!(hex_encode(&enc.ct), expected_ct_hex);
        assert_eq!(hex_encode(&enc.mac), expected_mac_hex);
        assert_eq!(enc.to_string_repr().unwrap(), expected_wire);

        // Decrypt EncString from Go wire format
        let parsed: EncString = expected_wire.parse().unwrap();
        let decrypted = decrypt_with(&parsed, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_parity_go_cipher_type_0() {
        let enc_key = vec![0x42; 32];
        let mac_key = vec![0x43; 32];
        let key = SymmetricKey::from_parts(&enc_key, &mac_key).unwrap();

        let iv = vec![0x24; 16];
        let plaintext = b"hello world";

        let enc = encrypt_with_iv(plaintext, EncStringType::AesCbc256B64, &key, Some(&iv)).unwrap();

        let expected_ct_hex = "edcfa3ee3645667d5e9b3b4fbbcce520";
        assert_eq!(hex_encode(&enc.ct), expected_ct_hex);
        assert!(enc.mac.is_empty());

        // D21: Type 0 wire string must be empty
        assert_eq!(enc.to_string_repr().unwrap(), "");

        // Decrypt Type 0
        let decrypted = decrypt_with(&enc, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_mac_mismatch_fails_before_decrypt() {
        let enc_key = vec![0x42; 32];
        let mac_key = vec![0x43; 32];
        let key = SymmetricKey::from_parts(&enc_key, &mac_key).unwrap();

        let plaintext = b"sensitive vault data";
        let mut enc = encrypt_with(plaintext, EncStringType::AesCbc256HmacSha256B64, &key).unwrap();

        // Tamper MAC
        enc.mac[0] ^= 0xff;

        let res = decrypt_with(&enc, &key);
        assert!(matches!(res, Err(CryptoError::MacMismatch(_))));
    }

    #[test]
    fn test_invalid_cipher_type_rejected() {
        let key = SymmetricKey::from_bytes(&[1u8; 64]).unwrap();
        assert!(encrypt_with(b"test", EncStringType::Rsa2048OaepSha1B64, &key).is_err());
        assert!(encrypt_with(b"test", EncStringType::AesCbc128HmacSha256B64, &key).is_err());

        let invalid_enc = EncString::new(
            EncStringType::Rsa2048OaepSha1B64,
            vec![0; 16],
            vec![0; 16],
            vec![],
        );
        assert!(decrypt_with(&invalid_enc, &key).is_err());
    }

    #[test]
    fn test_encrypt_with_to_string_roundtrip() {
        let key = SymmetricKey::from_bytes(&[9u8; 64]).unwrap();
        let plaintext = b"roundtrip test with random IV";

        let wire =
            encrypt_with_to_string(plaintext, EncStringType::AesCbc256HmacSha256B64, &key).unwrap();
        assert!(wire.starts_with("2."));

        let enc: EncString = wire.parse().unwrap();
        let decrypted = decrypt_with(&enc, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_invalid_lengths_in_decrypt() {
        let key = SymmetricKey::from_bytes(&[1u8; 64]).unwrap();

        // Invalid IV length (15 instead of 16)
        let enc_bad_iv = EncString::new(
            EncStringType::AesCbc256B64,
            vec![0u8; 15],
            vec![0u8; 16],
            vec![],
        );
        assert!(decrypt_with(&enc_bad_iv, &key).is_err());

        // Invalid CT length (15, not multiple of 16)
        let enc_bad_ct = EncString::new(
            EncStringType::AesCbc256B64,
            vec![0u8; 16],
            vec![0u8; 15],
            vec![],
        );
        assert!(decrypt_with(&enc_bad_ct, &key).is_err());
    }
}
