#![no_main]

use libfuzzer_sys::fuzz_target;
use sw_crypto::{decrypt_with, EncString, SymmetricKey};

fuzz_target!(|data: &[u8]| {
    let key = match SymmetricKey::from_bytes(&[0x42u8; 64]) {
        Ok(k) => k,
        Err(_) => return,
    };

    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(enc) = s.parse::<EncString>() {
            let _ = decrypt_with(&enc, &key);
        }
    }
});
