use aes_gcm::{Aes256Gcm, Key, Nonce}; // AES-GCM
use aes_gcm::aead::{Aead, KeyInit};
use argon2::{Argon2, PasswordHasher};
use rand::Rng;
use anyhow::Result;

pub fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let argon2 = Argon2::default();
    let mut key = [0u8; 32];
    argon2.hash_password_into(password.as_bytes(), salt, &mut key)?;
    Ok(key)
}

pub fn encrypt(key: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let cipher = Aes256Gcm::new(Key::from_slice(key));
    let nonce: [u8; 12] = rand::thread_rng().gen();
    let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce), plaintext)?;
    Ok((ciphertext, key.to_vec(), nonce.to_vec()))
}

pub fn decrypt(key: &[u8], ciphertext: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::from_slice(key));
    let plaintext = cipher.decrypt(Nonce::from_slice(nonce), ciphertext)?;
    Ok(plaintext)
}
