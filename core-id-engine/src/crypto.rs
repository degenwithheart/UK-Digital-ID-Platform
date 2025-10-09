use std::sync::Arc;
use ring::{signature::Ed25519KeyPair, rand::SystemRandom, digest, hmac};
use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, NewAead}};
use argon2::{Argon2, PasswordHasher, password_hash::{PasswordHash, PasswordVerifier}};
use rand::{Rng, thread_rng};
use anyhow::{Result, Context};
use thiserror::Error;
use serde::{Serialize, Deserialize};
use blake3::{Hash, Hasher};
use base64::{Engine as _, engine::general_purpose};

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),
    #[error("Encryption failed: {0}")]
    Encryption(String),
    #[error("Decryption failed: {0}")]
    Decryption(String),
    #[error("Signature failed: {0}")]
    Signature(String),
    #[error("Verification failed: {0}")]
    Verification(String),
    #[error("Hash computation failed: {0}")]
    Hashing(String),
}

#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
}

#[derive(Clone)]
pub struct CryptoEngine {
    master_key: Key<Aes256Gcm>,
    signing_key: Arc<Ed25519KeyPair>,
    argon2: Argon2<'static>,
    rng: Arc<SystemRandom>,
}

impl CryptoEngine {
    pub fn new() -> Result<Self> {
        let mut key_bytes = [0u8; 32];
        thread_rng().fill(&mut key_bytes);
        let master_key = Key::<Aes256Gcm>::from_slice(&key_bytes).clone();

        let rng = SystemRandom::new();
        let signing_key_bytes = Ed25519KeyPair::generate_pkcs8(&rng)
            .context("Failed to generate signing key")?;
        let signing_key = Arc::new(
            Ed25519KeyPair::from_pkcs8(signing_key_bytes.as_ref())
                .context("Failed to parse signing key")?
        );

        Ok(Self {
            master_key,
            signing_key,
            argon2: Argon2::default(),
            rng: Arc::new(rng),
        })
    }

    pub async fn encrypt_sensitive_data(&self, data: &[u8]) -> Result<EncryptedData> {
        let cipher = Aes256Gcm::new(&self.master_key);
        
        let mut nonce_bytes = [0u8; 12];
        thread_rng().fill(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher.encrypt(nonce, data)
            .map_err(|e| CryptoError::Encryption(e.to_string()))?;

        Ok(EncryptedData {
            nonce: nonce_bytes.to_vec(),
            ciphertext,
            tag: Vec::new(), // AES-GCM includes authentication tag in ciphertext
        })
    }

    pub async fn decrypt_sensitive_data(&self, encrypted: &EncryptedData) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new(&self.master_key);
        let nonce = Nonce::from_slice(&encrypted.nonce);

        cipher.decrypt(nonce, encrypted.ciphertext.as_ref())
            .map_err(|e| CryptoError::Decryption(e.to_string()).into())
    }

    pub async fn hash_identity_data(&self, data: &[u8], salt: Option<&[u8]>) -> Result<Hash> {
        let mut hasher = Hasher::new();
        hasher.update(data);
        
        if let Some(salt) = salt {
            hasher.update(salt);
        }
        
        Ok(hasher.finalize())
    }

    pub async fn sign_verification_result(&self, data: &[u8]) -> Result<Vec<u8>> {
        let signature = self.signing_key.sign(data);
        Ok(signature.as_ref().to_vec())
    }

    pub async fn verify_signature(&self, data: &[u8], signature: &[u8]) -> Result<bool> {
        use ring::signature::{UnparsedPublicKey, ED25519};
        
        let public_key_bytes = self.signing_key.public_key().as_ref();
        let public_key = UnparsedPublicKey::new(&ED25519, public_key_bytes);
        
        match public_key.verify(data, signature) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    pub async fn derive_key(&self, password: &str, salt: &[u8]) -> Result<[u8; 32]> {
        use argon2::password_hash::{SaltString, PasswordHasher};
        
        let salt_string = SaltString::encode_b64(salt)
            .map_err(|e| CryptoError::KeyGeneration(e.to_string()))?;
        
        let hash = self.argon2.hash_password(password.as_bytes(), &salt_string)
            .map_err(|e| CryptoError::KeyGeneration(e.to_string()))?;
        
        let mut key = [0u8; 32];
        key.copy_from_slice(&hash.hash().unwrap().as_bytes()[..32]);
        Ok(key)
    }

    pub async fn secure_compare(&self, a: &[u8], b: &[u8]) -> bool {
        use ring::constant_time;
        constant_time::verify_slices_are_equal(a, b).is_ok()
    }

    pub async fn generate_secure_token(&self, length: usize) -> Result<String> {
        let mut bytes = vec![0u8; length];
        thread_rng().fill(bytes.as_mut_slice());
        Ok(general_purpose::URL_SAFE_NO_PAD.encode(&bytes))
    }

    pub async fn health_check(&self) -> Result<bool> {
        // Test basic crypto operations
        let test_data = b"health_check_test";
        let encrypted = self.encrypt_sensitive_data(test_data).await?;
        let decrypted = self.decrypt_sensitive_data(&encrypted).await?;
        
        Ok(decrypted == test_data)
    }

    pub async fn compute_hmac(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, key);
        let tag = hmac::sign(&hmac_key, data);
        Ok(tag.as_ref().to_vec())
    }

    // Zero-knowledge proof simulation (placeholder for real ZKP implementation)
    pub async fn generate_zk_proof(&self, secret: &[u8], public_commitment: &[u8]) -> Result<Vec<u8>> {
        // In production, this would use a proper ZKP library like arkworks or circom
        let mut hasher = Hasher::new();
        hasher.update(secret);
        hasher.update(public_commitment);
        hasher.update(b"zk_proof_salt");
        
        Ok(hasher.finalize().as_bytes().to_vec())
    }

    pub async fn verify_zk_proof(&self, proof: &[u8], public_commitment: &[u8]) -> Result<bool> {
        // Placeholder verification - in production would use proper ZKP verification
        Ok(proof.len() == 32 && public_commitment.len() > 0)
    }
}

#[derive(Serialize, Deserialize)]
pub struct CryptoMetrics {
    pub encryptions_performed: u64,
    pub decryptions_performed: u64,
    pub signatures_generated: u64,
    pub verifications_performed: u64,
    pub average_encryption_time_ms: f64,
    pub average_decryption_time_ms: f64,
}

impl Default for CryptoMetrics {
    fn default() -> Self {
        Self {
            encryptions_performed: 0,
            decryptions_performed: 0,
            signatures_generated: 0,
            verifications_performed: 0,
            average_encryption_time_ms: 0.0,
            average_decryption_time_ms: 0.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_encryption_decryption() {
        let crypto = CryptoEngine::new().unwrap();
        let data = b"sensitive_test_data";
        
        let encrypted = crypto.encrypt_sensitive_data(data).await.unwrap();
        let decrypted = crypto.decrypt_sensitive_data(&encrypted).await.unwrap();
        
        assert_eq!(data, decrypted.as_slice());
    }

    #[tokio::test]
    async fn test_signing_verification() {
        let crypto = CryptoEngine::new().unwrap();
        let data = b"test_data_to_sign";
        
        let signature = crypto.sign_verification_result(data).await.unwrap();
        let is_valid = crypto.verify_signature(data, &signature).await.unwrap();
        
        assert!(is_valid);
    }

    #[tokio::test]
    async fn test_hashing() {
        let crypto = CryptoEngine::new().unwrap();
        let data = b"test_data";
        let salt = b"test_salt";
        
        let hash1 = crypto.hash_identity_data(data, Some(salt)).await.unwrap();
        let hash2 = crypto.hash_identity_data(data, Some(salt)).await.unwrap();
        
        assert_eq!(hash1, hash2);
    }
}