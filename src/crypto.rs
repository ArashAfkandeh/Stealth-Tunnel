use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key,
};
use bytes::{Bytes, BytesMut};
use rand::Rng;
use rand_distr::{Distribution, Normal};
use sha2::{Digest, Sha256};

// ==========================================
// 2. CRYPTO (بخشی از "2. TCP KEEPALIVE & CRYPTO")
// ==========================================

pub fn derive_cipher(secret: &str) -> Aes256Gcm {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    let key: Key<aes_gcm::aes::Aes256> = *Key::<aes_gcm::aes::Aes256>::from_slice(&hasher.finalize());
    Aes256Gcm::new(&key)
}

pub fn encrypt_payload(cipher: &Aes256Gcm, data: &[u8]) -> Bytes {
    let normal = Normal::new(128.0, 64.0).unwrap();
    let pad_len = (normal.sample(&mut rand::thread_rng()) as i32).clamp(16, 512) as u16;

    let mut padding = vec![0u8; pad_len as usize];
    rand::thread_rng().fill(&mut padding[..]);

    let mut plaintext = Vec::with_capacity(2 + padding.len() + data.len());
    plaintext.extend_from_slice(&pad_len.to_be_bytes());
    plaintext.extend_from_slice(&padding);
    plaintext.extend_from_slice(data);

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref()).unwrap();

    let mut final_payload = BytesMut::with_capacity(12 + ciphertext.len());
    final_payload.extend_from_slice(&nonce);
    final_payload.extend_from_slice(&ciphertext);
    final_payload.freeze()
}

pub fn decrypt_payload(cipher: &Aes256Gcm, data: &[u8]) -> Result<Vec<u8>, &'static str> {
    if data.len() < 12 { return Err("Payload too short"); }
    let (nonce, ciphertext) = data.split_at(12);

    let plaintext = cipher.decrypt(nonce.into(), ciphertext).map_err(|_| "Decryption failed")?;
    if plaintext.len() < 2 { return Err("Plaintext too short"); }

    let pad_len = u16::from_be_bytes([plaintext[0], plaintext[1]]) as usize;
    if plaintext.len() < 2 + pad_len { return Err("Invalid padding"); }

    Ok(plaintext[2 + pad_len..].to_vec())
}
