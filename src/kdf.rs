use ring::pbkdf2;
use std::num::NonZeroU32;

const DIGEST_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA256;

pub fn derive_key(
    password: &[u8],
    salt: &[u8],
    iterations: NonZeroU32,
    key_length: usize,
) -> Result<Vec<u8>, String> {
    let mut key = vec![0u8; key_length];
    let result = pbkdf2::derive(DIGEST_ALG, iterations, salt, password, &mut key);
    Ok(key)
}
