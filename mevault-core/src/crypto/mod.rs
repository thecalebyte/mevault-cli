use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng as AesOsRng},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{Context, Result};
use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, Params, PasswordHasher,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroize;

/// Argon2id parameters — balanced for interactive desktop use.
const ARGON2_MEM_KIB: u32 = 65_536; // 64 MiB
const ARGON2_ITERS: u32 = 3;
const ARGON2_PARA: u32 = 4;

/// Encrypted blob ready for serialization.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EncryptedBlob {
    pub salt: String,    // base64
    pub nonce: String,   // base64
    pub ciphertext: String, // base64
}

/// Encrypt plaintext with a password-derived key (Argon2id → AES-256-GCM).
pub fn encrypt(plaintext: &[u8], password: &SecretString) -> Result<EncryptedBlob> {
    // Derive key from password.
    let salt = SaltString::generate(&mut OsRng);
    let key_bytes = derive_key(password, salt.as_str())?;

    // Encrypt.
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut AesOsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("AES-GCM encrypt failed: {e}"))?;

    Ok(EncryptedBlob {
        salt: salt.to_string(),
        nonce: B64.encode(nonce),
        ciphertext: B64.encode(ciphertext),
    })
}

/// Decrypt a blob produced by `encrypt`.
pub fn decrypt(blob: &EncryptedBlob, password: &SecretString) -> Result<Vec<u8>> {
    let mut key_bytes = derive_key(password, &blob.salt)?;

    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    let nonce_bytes = B64.decode(&blob.nonce).context("decoding nonce")?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ct = B64.decode(&blob.ciphertext).context("decoding ciphertext")?;
    let plaintext = cipher
        .decrypt(nonce, ct.as_ref())
        .map_err(|_| anyhow::anyhow!("decryption failed — wrong password?"))?;

    key_bytes.zeroize();
    Ok(plaintext)
}

fn derive_key(password: &SecretString, salt_str: &str) -> Result<[u8; 32]> {
    let params = Params::new(ARGON2_MEM_KIB, ARGON2_ITERS, ARGON2_PARA, Some(32))
        .map_err(|e| anyhow::anyhow!("building argon2 params: {e}"))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let salt = argon2::password_hash::Salt::from_b64(salt_str)
        .map_err(|e| anyhow::anyhow!("invalid salt: {e}"))?;

    // Hash to 32 bytes; argon2 crate puts them in the PasswordHash output.
    let hash = argon2
        .hash_password(password.expose_secret().as_bytes(), salt)
        .map_err(|e| anyhow::anyhow!("argon2 hashing failed: {e}"))?;

    let hash_output = hash.hash.context("no hash output from argon2")?;
    let bytes = hash_output.as_bytes();
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes[..32]);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let pw = SecretString::new("correct-horse-battery-staple".to_owned().into());
        let plaintext = b"hello world, this is a secret payload";
        let blob = encrypt(plaintext, &pw).expect("encrypt");
        let recovered = decrypt(&blob, &pw).expect("decrypt");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn wrong_password_fails() {
        let pw = SecretString::new("right-password".to_owned().into());
        let bad = SecretString::new("wrong-password".to_owned().into());
        let blob = encrypt(b"data", &pw).expect("encrypt");
        assert!(decrypt(&blob, &bad).is_err(), "wrong password must fail");
    }
}
