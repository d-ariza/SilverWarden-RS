use sw_config::{derive_config_key, hash_config_key};

const EXPECTED_KEY_HEX: &str = "46d690a92d1b2e76b901b5221dc296ebe7a9ff6ee76b8615ede85a1323aac17a";
const EXPECTED_HASH_HEX: &str = "e65f3b70990b3bb58a5fc7dc4d35bfaab58b87b81424b26f7a45dac85b2f01b3";

#[test]
#[ignore = "uses 2 GiB of RAM, run manually"]
fn test_sha3_hash_parity() {
    // Full 2 GiB Argon2i key derivation using default derive_config_key wrapper
    let key = derive_config_key("synthetic_unit_pin_123", "synthetic_device_uuid_456")
        .expect("2 GiB derivation should succeed");
    let hash = hash_config_key(&key);
    assert_eq!(hash.len(), 64);

    let key_bytes: [u8; 32] = hex::decode(EXPECTED_KEY_HEX)
        .expect("Valid hex")
        .try_into()
        .expect("32 bytes");

    let hash_hex = hash_config_key(&key_bytes);
    assert_eq!(hash_hex, EXPECTED_HASH_HEX);
}
