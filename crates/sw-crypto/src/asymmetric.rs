use crate::error::CryptoError;
use crate::mem::{LockedBuffer, MemLockedBuffer};
use base64::Engine;
use rand::rngs::OsRng;
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use sha1::Sha1;
use std::fmt;

/// RSA-2048 private key container holding PKCS#8 DER bytes in memory-locked RAM.
pub struct AsymmetricKey {
    priv_key_der: MemLockedBuffer,
}

impl AsymmetricKey {
    /// Generates a new 2048-bit RSA key pair using OS entropy and stores it in locked memory.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut rng = OsRng;
        let priv_key = RsaPrivateKey::new(&mut rng, 2048)
            .map_err(|e| CryptoError::InvalidAsymmetricKey(e.to_string()))?;
        let der = priv_key
            .to_pkcs8_der()
            .map_err(|e| CryptoError::InvalidAsymmetricKey(e.to_string()))?;
        let buf = MemLockedBuffer::new(der.as_bytes())?;
        Ok(Self { priv_key_der: buf })
    }

    /// Creates an AsymmetricKey by parsing and validating PKCS#8 private key DER bytes.
    pub fn from_pkcs8(bytes: &[u8]) -> Result<Self, CryptoError> {
        // Validate that it is a valid RSA private key in PKCS#8 format
        RsaPrivateKey::from_pkcs8_der(bytes)
            .map_err(|e| CryptoError::InvalidAsymmetricKey(e.to_string()))?;
        let buf = MemLockedBuffer::new(bytes)?;
        Ok(Self { priv_key_der: buf })
    }

    /// Returns a slice of the PKCS#8 private key DER bytes.
    pub fn private_bytes(&self) -> &[u8] {
        self.priv_key_der.as_slice()
    }

    /// Derives and serializes the RSA public key into SubjectPublicKeyInfo (PKIX/SPKI) DER format.
    pub fn public_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        let priv_key = RsaPrivateKey::from_pkcs8_der(self.private_bytes())
            .map_err(|e| CryptoError::InvalidAsymmetricKey(e.to_string()))?;
        let pub_key = priv_key.to_public_key();
        let pub_der = pub_key
            .to_public_key_der()
            .map_err(|e| CryptoError::InvalidAsymmetricKey(e.to_string()))?;
        Ok(pub_der.as_bytes().to_vec())
    }

    /// Creates an independent clone of the AsymmetricKey in a newly locked memory buffer.
    pub fn try_clone(&self) -> Result<Self, CryptoError> {
        let buf = MemLockedBuffer::new(self.private_bytes())?;
        Ok(Self { priv_key_der: buf })
    }

    /// Explicitly zeroes out the private key buffer in memory.
    pub fn wipe(&mut self) {
        self.priv_key_der.wipe();
    }
}

impl fmt::Debug for AsymmetricKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("AsymmetricKey")
            .field(&"[REDACTED ASYMMETRIC KEY]")
            .finish()
    }
}

/// Encrypts plaintext using RSAES-OAEP with SHA-1 and returns standard Bitwarden wire format (`"4." + base64`).
///
/// `public_key` must be in PKIX/SPKI DER format.
pub fn encrypt_with_asymmetric(
    plaintext: &[u8],
    public_key: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let pub_key = RsaPublicKey::from_public_key_der(public_key)
        .map_err(|e| CryptoError::InvalidAsymmetricKey(e.to_string()))?;

    let mut rng = OsRng;
    let padding = Oaep::new::<Sha1>();
    let ct = pub_key
        .encrypt(&mut rng, padding, plaintext)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    let b64 = base64::engine::general_purpose::STANDARD.encode(&ct);
    let mut out = Vec::with_capacity(2 + b64.len());
    out.extend_from_slice(b"4.");
    out.extend_from_slice(b64.as_bytes());
    Ok(out)
}

/// Decrypts RSAES-OAEP with SHA-1 ciphertext with `"4."` prefix using the private key.
pub fn decrypt_with_asymmetric(
    ciphertext_with_prefix: &[u8],
    private_key: &AsymmetricKey,
) -> Result<Vec<u8>, CryptoError> {
    if !ciphertext_with_prefix.starts_with(b"4.") {
        return Err(CryptoError::InvalidPrefix(format!(
            "ciphertext must start with '4.', got '{}'",
            String::from_utf8_lossy(&ciphertext_with_prefix[..ciphertext_with_prefix.len().min(8)])
        )));
    }

    let b64_payload = &ciphertext_with_prefix[2..];
    let raw_ct = base64::engine::general_purpose::STANDARD
        .decode(b64_payload)
        .map_err(|e| CryptoError::Base64Error(e.to_string()))?;

    let priv_key = RsaPrivateKey::from_pkcs8_der(private_key.private_bytes())
        .map_err(|e| CryptoError::InvalidAsymmetricKey(e.to_string()))?;

    let padding = Oaep::new::<Sha1>();
    let pt = priv_key
        .decrypt(padding, &raw_ct)
        .map_err(|e| CryptoError::AsymmetricDecryptionFailed(e.to_string()))?;

    Ok(pt)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GO_PKCS8_HEX: &str = "308204be020100300d06092a864886f70d0101010500048204a8308204a40201000282010100c738f48cfbeb739a641ec6c5de726514a6ab52d1a96be6c5fa20e1e59cefe292ae192a3f747e7d476ff9f42ef1ea1d68d434b77a179bd96449b1a1b44efa46d3b2c5ba98787751c9f253d7bf8f62ec7c160bcb08166d7cc206a9e9ae05748a60cd9c74ce6ef9196f0b27df1f31e3cbfa0cc14522322b7eb37c865191a5b698b2570e9cd216a7133ba370bf27a34a3e649bab7c3abe10a8228084cdc73d22271b3e8615d1c1958d2800f71b3d47b03554c0324aed200063d2f3f2b4da74994688a14acff88449ae15d0fd5d099e121719fc876e3e6179cbd7b95dfd5cbb746ea28db5e80503218677ee3901fe9f5511f74c590abc849cd76062816ad54d9f5f510203010001028201002d9266429fd7eed458e5bf6380ec9b19bbbc820fead8ff6bb739716334609d6c1f3e2b6f638711c257278ec77458310d0b49d9d4a874e2a831c15bf3a28356d353582ec474fe1a6bff2e55b280aac8dce3b023ec0031607203d3375cb2ebc341bc96f71347c85c9c8da93bbd678cabdad1b31e4ce1bc185a1778a44d1462ae0fea1f0f2090077e0e522281a3c8bfd86e9643f6a5497ff06a6b2c47ba63a0d953d4e9579cd418a4d1c1a9d9cec791afe78d8a64f14b457c76756926bc131712ebf4ba41b092562593d4ce19ed0a097dcca371acd315e01136a0cc8da980224ad41351edf04034187520c5ab109ad7d5b288b5dd3719f1913e75c6dc48d562608f02818100d49a416ef4a819546fc6173a2dbc6d6aee9e4a380675dfd2f866bd992a88f42b1f76d8b74b2ee2d45ceb470def96b49788e66a82318b318ad9626ff6e1ea73dc9da7a30e044748bc841c8f31d8f08ca7bbb39f3fe4d04068beb5a151dd304c2d3f9a44dcd097e96b1dc33ec2999d9c148ff39eb46aa7c0461228f2fd100b8ee702818100efe382dd9c35e00b50a5ebcf42f68d0bf84c2ed6b35089351cf392068d49b368a45f1f148abf7b1862dd2d40bf3dc603852eb8148582a608daeb0b61695b09a3e22146f17bdb27eac46359492ee6bfef8bf76aacb6a6a3e22d09ce6d6b565d3eec470a7dcea6f07903be664f12937f3cbad5def91d3bb06e49525cbff021f1070281802ed99755c6204d04a864f4b56362c491ede77fdf7cbcf907daa9795a895f08bf7ffd86a04db715514af0a605d22859bf92f183c310fbe57cfd8e8db1cff30479375cbbb7d9058467d68d1c99157f5cdf91a3719278efd361c1b4f0c9c37e632b0d7b0775c999d05c4480c411ca1c4b4ad4b610e11d27be5d329f477cb0ce7b3d02818100cacd4f7c64ac934d5d8ff80c4fb33a48ed5012a5061146fdf50ce1ddd222859f289f161a7ab628add41ee23c03b188aebf306105505dc45a6621218ce7d1c4139d7fbe8736cb6f32a576cc2bf78fb2a2247535e4efc16f792dd44584f1a2a0d02a5660c33d2a9acfe3df5a84ecd26f55fb2a06081ab3b493783f3e143241af8f02818100a70a7621345429476f2a3d337a3543188079ea27de1944872ab74a15cfd209ab9a4217d896c69e50a501a68b6bcdfb4e875d006711ba00c863dba73941ecbcddf40e3dfe5a3bcfc831b7bcfd941e068b276ec9d340bc10f8ebae4a35c33f5f01c4cbfa5be4b6ca33eef9d218f4c582984806ede6a804c78ec67b575204bdd888";
    const GO_PKIX_HEX: &str = "30820122300d06092a864886f70d01010105000382010f003082010a0282010100c738f48cfbeb739a641ec6c5de726514a6ab52d1a96be6c5fa20e1e59cefe292ae192a3f747e7d476ff9f42ef1ea1d68d434b77a179bd96449b1a1b44efa46d3b2c5ba98787751c9f253d7bf8f62ec7c160bcb08166d7cc206a9e9ae05748a60cd9c74ce6ef9196f0b27df1f31e3cbfa0cc14522322b7eb37c865191a5b698b2570e9cd216a7133ba370bf27a34a3e649bab7c3abe10a8228084cdc73d22271b3e8615d1c1958d2800f71b3d47b03554c0324aed200063d2f3f2b4da74994688a14acff88449ae15d0fd5d099e121719fc876e3e6179cbd7b95dfd5cbb746ea28db5e80503218677ee3901fe9f5511f74c590abc849cd76062816ad54d9f5f510203010001";
    const GO_WIRE: &str = "4.EyXlIUCwHtcE34SrfzHPFpTMGXnqWeSl/b8Zr3p4UVekQQ4YrSEkW5EC4odCU2dZZ3lniP/5avOmfv/13AlFFpaV85BVOf2PUO0brEy+KHz5F7VhjLSE4VwDwnpQEtDOD8OsdXs0T16mPoHaCDcV8eNiNAw5honLLXZfvJI7HXp7EnK4SPFtcJVQk+dbOZ+9KPLB1+faxjTz7LFKXACVBZs2g7m4xiWrybOawPQ8J3vqgOhU3QQmFwXbu9hlNvUq4MSBHA42XsMHnBVUcCPUxDrSpzDgDKDbSLR/PLaYeV+Xm7SdAkO8ZNrb4B2GJ+BL+1IFEyghkBHy4e3kFJsUNA==";
    const EXPECTED_PLAINTEXT: &[u8] =
        b"symmetric-org-key-secret-payload-64-bytes-long-padding-test-1234";

    fn hex_to_vec(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn test_generate_and_roundtrip() {
        let key = AsymmetricKey::generate().expect("key generation failed");
        let pub_bytes = key.public_bytes().expect("public key export failed");
        let plaintext = b"Hello Bitwarden legacy RSA-2048 OAEP-SHA1!";

        let encrypted = encrypt_with_asymmetric(plaintext, &pub_bytes).expect("encryption failed");
        assert!(encrypted.starts_with(b"4."));

        let decrypted = decrypt_with_asymmetric(&encrypted, &key).expect("decryption failed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_from_pkcs8_reparse_and_public_bytes() {
        let pkcs8_bytes = hex_to_vec(GO_PKCS8_HEX);
        let key = AsymmetricKey::from_pkcs8(&pkcs8_bytes).expect("parse pkcs8 failed");
        assert_eq!(key.private_bytes(), pkcs8_bytes.as_slice());

        let pub_bytes = key.public_bytes().expect("public key derive failed");
        let expected_pub = hex_to_vec(GO_PKIX_HEX);
        assert_eq!(pub_bytes, expected_pub);
    }

    #[test]
    fn test_try_clone_and_wipe() {
        let pkcs8_bytes = hex_to_vec(GO_PKCS8_HEX);
        let mut key = AsymmetricKey::from_pkcs8(&pkcs8_bytes).expect("parse pkcs8 failed");
        let clone = key.try_clone().expect("try_clone failed");

        assert_eq!(key.private_bytes(), clone.private_bytes());
        key.wipe();

        assert!(key.private_bytes().iter().all(|&b| b == 0));
        assert!(!clone.private_bytes().iter().all(|&b| b == 0));
        assert_eq!(clone.private_bytes(), pkcs8_bytes.as_slice());
    }

    #[test]
    fn test_debug_redacted() {
        let pkcs8_bytes = hex_to_vec(GO_PKCS8_HEX);
        let key = AsymmetricKey::from_pkcs8(&pkcs8_bytes).unwrap();
        let dbg = format!("{:?}", key);
        assert!(dbg.contains("[REDACTED ASYMMETRIC KEY]"));
        assert!(!dbg.contains("308204be"));
    }

    #[test]
    fn test_invalid_prefix() {
        let pkcs8_bytes = hex_to_vec(GO_PKCS8_HEX);
        let key = AsymmetricKey::from_pkcs8(&pkcs8_bytes).unwrap();
        let err = decrypt_with_asymmetric(b"2.someciphertext", &key).unwrap_err();
        match err {
            CryptoError::InvalidPrefix(msg) => {
                assert!(msg.contains("must start with '4.'"));
            }
            other => panic!("expected InvalidPrefix, got {:?}", other),
        }
    }

    #[test]
    fn test_invalid_base64() {
        let pkcs8_bytes = hex_to_vec(GO_PKCS8_HEX);
        let key = AsymmetricKey::from_pkcs8(&pkcs8_bytes).unwrap();
        let err = decrypt_with_asymmetric(b"4.not_valid_base64!!!", &key).unwrap_err();
        match err {
            CryptoError::Base64Error(_) => {}
            other => panic!("expected Base64Error, got {:?}", other),
        }
    }

    #[test]
    fn test_invalid_asymmetric_key() {
        let err = AsymmetricKey::from_pkcs8(b"not a valid pkcs8 der").unwrap_err();
        match err {
            CryptoError::InvalidAsymmetricKey(_) => {}
            other => panic!("expected InvalidAsymmetricKey, got {:?}", other),
        }

        let err2 = encrypt_with_asymmetric(b"data", b"not a valid spki der").unwrap_err();
        match err2 {
            CryptoError::InvalidAsymmetricKey(_) => {}
            other => panic!("expected InvalidAsymmetricKey, got {:?}", other),
        }
    }

    const GO_PKCS8_HEX_2: &str = "308204bd020100300d06092a864886f70d0101010500048204a7308204a30201000282010100df2aabad529940784723da6d33f31232c954b8af23fa299c83ed8ba34eac08251729c269784d06014724b6d29498bab5f4b242a1f1bdc97ecbcf272829900c12b4b244732578c49aa6f6fe127440a8fcfc825d5b4d73d116305ecea1ffb906220a18016e932f5895772d384851e7bce1363a8a65e0df3f8157b6af6e41bd20deab904ebf552c94a7924a6407e06be646b0682bde1348e76efd3c8b91e1490218380d0357071d65efdbaea443de528cd7d6d9c3f1365de8637334301cce9a86e576e259a2380cd6bb78884b43c838b229a836744751ae39283d1a6760409cc5042c77b33c903e00d41d33199699f1a670467e6fff3d34190e61cc4183e6aeed410203010001028201000f25e5d6537b7c914d7ee506319707beb3c4d0ee6e7a3e15d62cab245024443f4445bce10cdde990efa3d1d71468139063463058aec08bab54294106ac5f8f3a3bd2b7ebbaf8ea1b7746dfb31ff9fd9e828354d3ec3b76cf5344343171dabccc55b41070d183ceb7028a6abe19f529707e0e563399227e3c88d8292b4a420cb78022cf84ce6386d637b661656190e4186f82f0619dcc76a575cac74be9a99fbe1174a4842e7a3a22b236d8efd3e6a101dc2965fc5f041e1bc15fc5dd2833cee3d34aea433c896850c5536e423e08df2baabbaeb4447af686f9cfbe70e41e5626d1b9448d63893116c55e8a118321ae3bc2fc7f36bc362eda3dfd22b1b13bb14302818100f913d268a3cd1977cdb53693694a75e1011764a83e7d5ea21fc6fb43f011f42b25e7aeff3c43ffbe8750c248e3365c88c7a302fb8700d098479dc36c8ba462163d14650471bc5fcf8e1d551f8b3fbc7e5c27a5101409d841bb4d0ee9657147e83f8c9357d51b396be3707926e668f7197f78a1bb2378ca445cf14c8f9244ddcf02818100e55e7e9ae4574487fc41182d147325ae88a69dcd3a72b686b0803bd05184c71a5211a65bb4ba3b10b57263c4c7cf1bf009eef46ba0e41ef731f1e94fc7862e09c5159956574c035b1e3a4cdb0cb65d8a4537e6e642c782c5485b6a70aa9631ea11574c484877c4f6a876b9a3a05c092c8661c8aba9589c31df5ec243d5f5d7ef02818100891bec3b45cfe53119bfa3274a527ec9393c936039e5f16df5682770a27a7f9a30e7746173df4aacaaf83dbab9b876ffa4458ba2c21224c16ecadd84a6e9fa449ba2da68b3e32a2aaae462b35687e34efb93a73d4e8a8cccc23a0cf755ac22152ac64b65921dc6622975047bf161de83deb39cf3d2f6ef00ead8b9785ee021e9028180361f1df09e8099031d5a9ec1c4598742afabe10054124d4f6ac65756c865743599b7e071332bde540afc7ade2be78ac8110ff94c8c2247cc3c54c0a0ba8bc6c13767e94e9e3aa9700ea9e308acef3b132d520b81b9b02a0333179efe06c279f4a932d82516346c9d6712dcaae763d026596f2952981af8802c1cc7ea09ca80b102818013fd631ec214017e0e2667bd124eade9e8c9ea9bf3cc31ed614bc393bb2af89976499dee609c95daf0d2c185ad31ff2456eaaa8089b5e5692afe92af92605092e56a3cf9345a9a797fd4873432eaf0a979ff95fba7e0227fbf4199585494e014f48bd2e5d55eb0508e6bcbc14efdc0f3e4e2fad6fe772501146b03d2d01ff837";

    #[test]
    fn test_decryption_with_wrong_key() {
        let pkcs8_1 = hex_to_vec(GO_PKCS8_HEX);
        let key1 = AsymmetricKey::from_pkcs8(&pkcs8_1).unwrap();
        let pkcs8_2 = hex_to_vec(GO_PKCS8_HEX_2);
        let key2 = AsymmetricKey::from_pkcs8(&pkcs8_2).unwrap();
        let pub1 = key1.public_bytes().unwrap();

        let ct = encrypt_with_asymmetric(b"secret payload", &pub1).unwrap();
        let err = decrypt_with_asymmetric(&ct, &key2).unwrap_err();
        match err {
            CryptoError::AsymmetricDecryptionFailed(_) => {}
            other => panic!("expected AsymmetricDecryptionFailed, got {:?}", other),
        }
    }

    #[test]
    fn test_parity_decrypt_go_fixture() {
        let pkcs8_bytes = hex_to_vec(GO_PKCS8_HEX);
        let key = AsymmetricKey::from_pkcs8(&pkcs8_bytes).expect("parse pkcs8 failed");

        let decrypted = decrypt_with_asymmetric(GO_WIRE.as_bytes(), &key)
            .expect("decryption of Go wire ciphertext failed");
        assert_eq!(decrypted, EXPECTED_PLAINTEXT);
    }

    #[test]
    fn test_parity_encrypt_rust_decrypt_rust() {
        let pub_bytes = hex_to_vec(GO_PKIX_HEX);
        let pkcs8_bytes = hex_to_vec(GO_PKCS8_HEX);
        let key = AsymmetricKey::from_pkcs8(&pkcs8_bytes).expect("parse pkcs8 failed");

        let plaintext = b"testing rust encryption with go public key";
        let encrypted = encrypt_with_asymmetric(plaintext, &pub_bytes).expect("encrypt failed");
        assert!(encrypted.starts_with(b"4."));
        println!(
            "RustWireCiphertext: {}",
            String::from_utf8_lossy(&encrypted)
        );

        let decrypted = decrypt_with_asymmetric(&encrypted, &key).expect("decrypt failed");
        assert_eq!(decrypted, plaintext);
    }
}
