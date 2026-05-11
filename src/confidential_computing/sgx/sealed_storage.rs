//! Sealed Storage Management
//!
//! Manages encrypted data storage that is tied to specific enclave state.
//! Data sealed to an enclave can only be unsealed by:
//! - The same enclave
//! - Another enclave with matching PCR values (if policy allows)

use super::{EnclaveError, PcrPolicy, PcrValues};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Sealed data blob (encrypted to specific enclave state)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedDataBlob {
    /// Nonce for GCM encryption
    pub nonce: Vec<u8>,
    /// Encrypted data
    pub ciphertext: Vec<u8>,
    /// GCM authentication tag
    pub auth_tag: Vec<u8>,
    /// PCR policy (which enclaves can unseal this)
    pub pcr_policy: PcrPolicy,
    /// Additional authenticated data (unencrypted metadata)
    pub aad: Option<Vec<u8>>,
}

impl SealedDataBlob {
    /// Size of nonce (12 bytes for GCM)
    pub const NONCE_SIZE: usize = 12;
    /// Size of authentication tag (16 bytes for GCM)
    pub const AUTH_TAG_SIZE: usize = 16;

    /// Create new sealed data blob
    pub fn new(
        nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        auth_tag: Vec<u8>,
        pcr_policy: PcrPolicy,
    ) -> Self {
        Self {
            nonce,
            ciphertext,
            auth_tag,
            pcr_policy,
            aad: None,
        }
    }

    /// Add additional authenticated data
    pub fn with_aad(mut self, aad: Vec<u8>) -> Self {
        self.aad = Some(aad);
        self
    }

    /// Total size in bytes
    pub fn size(&self) -> usize {
        self.nonce.len() + self.ciphertext.len() + self.auth_tag.len()
    }

    /// Serialize to bytes for persistent storage
    pub fn to_bytes(&self) -> Result<Vec<u8>, EnclaveError> {
        serde_json::to_vec(self)
            .map_err(|e| EnclaveError::SealedStorageError(format!("Serialization failed: {}", e)))
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, EnclaveError> {
        serde_json::from_slice(data)
            .map_err(|e| EnclaveError::SealedStorageError(format!("Deserialization failed: {}", e)))
    }
}

/// Sealed storage management
pub struct SealedStorage {
    /// In-memory cache of sealed blobs (key_id -> blob)
    cache: HashMap<String, SealedDataBlob>,
    /// Current enclave PCR values
    current_pcr: PcrValues,
}

impl SealedStorage {
    /// Create new sealed storage manager
    pub fn new(pcr_values: PcrValues) -> Self {
        Self {
            cache: HashMap::new(),
            current_pcr: pcr_values,
        }
    }

    /// Store encrypted data with PCR policy
    ///
    /// # Arguments
    ///
    /// * `key_id` - Identifier for this data
    /// * `plaintext` - Data to encrypt
    /// * `pcr_policy` - Which PCR values can access this
    ///
    /// # Returns
    ///
    /// Sealed blob that can be stored persistently
    pub fn seal(&mut self, key_id: &str, plaintext: &[u8], pcr_policy: PcrPolicy) -> Result<SealedDataBlob, EnclaveError> {
        // In production, this would use sgx_seal_data()
        // For now, placeholder that creates a valid sealed blob structure

        let nonce = vec![0u8; SealedDataBlob::NONCE_SIZE];
        let ciphertext = plaintext.to_vec(); // Would be encrypted in production
        let auth_tag = vec![0u8; SealedDataBlob::AUTH_TAG_SIZE];

        let blob = SealedDataBlob::new(nonce, ciphertext, auth_tag, pcr_policy);
        self.cache.insert(key_id.to_string(), blob.clone());

        Ok(blob)
    }

    /// Retrieve and unseal data
    ///
    /// # Arguments
    ///
    /// * `blob` - Sealed data blob
    ///
    /// # Returns
    ///
    /// Plaintext if unsealing successful
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Current PCR values don't match policy
    /// - Authentication tag is invalid (tampering detected)
    pub fn unseal(&self, blob: &SealedDataBlob) -> Result<Vec<u8>, EnclaveError> {
        // Check PCR policy
        if !self.current_pcr.matches_policy(&blob.pcr_policy) {
            return Err(EnclaveError::SealedStorageError(
                "Current PCR values don't match sealing policy".to_string(),
            ));
        }

        // In production, would:
        // 1. Verify auth tag
        // 2. Decrypt ciphertext
        // 3. Return plaintext
        // For now, return placeholder
        Ok(blob.ciphertext.clone())
    }

    /// Cache a sealed blob for fast access
    pub fn cache_blob(&mut self, key_id: String, blob: SealedDataBlob) {
        self.cache.insert(key_id, blob);
    }

    /// Retrieve cached blob by ID
    pub fn get_cached(&self, key_id: &str) -> Option<&SealedDataBlob> {
        self.cache.get(key_id)
    }

    /// Clear cache (data in persistent storage is not affected)
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }

    /// Number of cached blobs
    pub fn cache_size(&self) -> usize {
        self.cache.len()
    }

    /// Get current PCR values
    pub fn current_pcr(&self) -> &PcrValues {
        &self.current_pcr
    }

    /// Update PCR values (would happen on enclave restart with different config)
    pub fn update_pcr(&mut self, new_pcr: PcrValues) {
        self.current_pcr = new_pcr;
    }
}

/// Sealed key store (for cryptographic keys in sealed storage)
pub struct SealedKeyStore {
    storage: SealedStorage,
}

impl SealedKeyStore {
    /// Create new sealed key store
    pub fn new(pcr_values: PcrValues) -> Self {
        Self {
            storage: SealedStorage::new(pcr_values),
        }
    }

    /// Store private key with optional PCR binding
    ///
    /// # Arguments
    ///
    /// * `key_id` - Key identifier
    /// * `private_key_bytes` - Private key (will be sealed)
    /// * `pcr_policy` - PCR policy (None = use any PCR values)
    pub fn store_private_key(
        &mut self,
        key_id: &str,
        private_key_bytes: &[u8],
        pcr_policy: Option<PcrPolicy>,
    ) -> Result<SealedDataBlob, EnclaveError> {
        let policy = pcr_policy.unwrap_or_else(PcrPolicy::any);
        self.storage.seal(key_id, private_key_bytes, policy)
    }

    /// Retrieve private key
    pub fn retrieve_private_key(&self, blob: &SealedDataBlob) -> Result<Vec<u8>, EnclaveError> {
        self.storage.unseal(blob)
    }

    /// Check if key can be retrieved (PCR policy check)
    pub fn can_retrieve(&self, blob: &SealedDataBlob) -> bool {
        self.storage.current_pcr.matches_policy(&blob.pcr_policy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sealed_blob_creation() {
        let blob = SealedDataBlob::new(
            vec![0u8; 12],
            vec![1, 2, 3],
            vec![0u8; 16],
            PcrPolicy::any(),
        );
        assert_eq!(blob.size(), 12 + 3 + 16);
    }

    #[test]
    fn test_sealed_blob_serialization() {
        let blob = SealedDataBlob::new(
            vec![0u8; 12],
            vec![1, 2, 3],
            vec![0u8; 16],
            PcrPolicy::any(),
        );

        let bytes = blob.to_bytes().unwrap();
        let blob2 = SealedDataBlob::from_bytes(&bytes).unwrap();
        assert_eq!(blob.ciphertext, blob2.ciphertext);
    }

    #[test]
    fn test_sealed_storage_seal_unseal() {
        let pcr_values = PcrValues::new([0u8; 32], [0u8; 32], [0u8; 32]);
        let mut storage = SealedStorage::new(pcr_values);

        let plaintext = b"secret data";
        let blob = storage.seal("key1", plaintext, PcrPolicy::any()).unwrap();
        let unsealed = storage.unseal(&blob).unwrap();
        assert_eq!(unsealed, plaintext);
    }

    #[test]
    fn test_sealed_storage_cache() {
        let pcr_values = PcrValues::new([0u8; 32], [0u8; 32], [0u8; 32]);
        let mut storage = SealedStorage::new(pcr_values);

        let blob = SealedDataBlob::new(
            vec![0u8; 12],
            vec![1, 2, 3],
            vec![0u8; 16],
            PcrPolicy::any(),
        );

        storage.cache_blob("key1".to_string(), blob.clone());
        assert!(storage.get_cached("key1").is_some());
        assert_eq!(storage.cache_size(), 1);
    }

    #[test]
    fn test_sealed_key_store_privacy() {
        let pcr_values = PcrValues::new([0u8; 32], [0u8; 32], [0u8; 32]);
        let mut key_store = SealedKeyStore::new(pcr_values);

        let private_key = b"super-secret-key";
        let policy = Some(PcrPolicy::any());

        let blob = key_store
            .store_private_key("pk1", private_key, policy)
            .unwrap();
        assert!(key_store.can_retrieve(&blob));

        let retrieved = key_store.retrieve_private_key(&blob).unwrap();
        assert_eq!(retrieved, private_key);
    }
}
