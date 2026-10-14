#![no_main]

use libfuzzer_sys::fuzz_target;
use sw_crypto::pkcs7_unpad;

fuzz_target!(|data: &[u8]| {
    let _ = pkcs7_unpad(data, 16);
});
