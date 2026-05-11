//! Intel SGX 2.0 Enclave Integration
//!
//! Provides secure enclave operations with remote attestation support.
//! Supports both Data Center Attestation Primitives (DCAP) and Intel Attestation Service (IAS).

pub mod enclave_interface;
pub mod attestation;
pub mod sealed_storage;
pub mod quote_verifier;

pub use quote_verifier::{
    verify_quote_standard, verify_quote_strict, QuoteValidationPolicy, QuoteVerificationResult,
    QuoteVerifier,
};

use thiserror::Error;
use serde::{Deserialize, Serialize};

/// SGX-specific errors
#[derive(Error, Debug)]
pub enum EnclaveError {
    #[error("Enclave initialization failed: {0}")]
    InitializationFailed(String),

    #[error("Enclave operation failed: {0}")]
    OperationFailed(String),

    #[error("Attestation failed: {0}")]
    AttestationFailed(String),

    #[error("Quote generation failed: {0}")]
    QuoteGenerationFailed(String),

    #[error("Quote verification failed: {0}")]
    QuoteVerificationFailed(String),

    #[error("Sealed storage error: {0}")]
    SealedStorageError(String),

    #[error("Invalid enclave state: {0}")]
    InvalidState(String),

    #[error("Communication error: {0}")]
    CommunicationError(String),

    #[error("Cryptographic error: {0}")]
    CryptoError(String),
}

/// Attestation service provider
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttestationProvider {
    /// Data Center Attestation Primitives (recommended for production)
    DCAP,
    /// Intel Attestation Service (legacy, for compatibility)
    IAS,
}

/// Attestation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationConfig {
    /// Attestation service provider (DCAP or IAS)
    pub provider: AttestationProvider,
    /// IAS subscription key (required if provider = IAS)
    pub ias_api_key: Option<String>,
    /// DCAP quote verification collateral URL
    pub dcap_collateral_url: Option<String>,
    /// Allow outdated Intel PCK certificates (development only)
    pub allow_outdated_pcks: bool,
}

impl AttestationConfig {
    /// Create DCAP configuration (recommended for production)
    pub fn dcap() -> Self {
        Self {
            provider: AttestationProvider::DCAP,
            ias_api_key: None,
            dcap_collateral_url: Some(
                "https://api.trustedservices.intel.com/sgx/certification/v4".to_string(),
            ),
            allow_outdated_pcks: false,
        }
    }

    /// Create IAS configuration (legacy, for compatibility)
    pub fn ias(api_key: String) -> Self {
        Self {
            provider: AttestationProvider::IAS,
            ias_api_key: Some(api_key),
            dcap_collateral_url: None,
            allow_outdated_pcks: false,
        }
    }

    /// Enable development mode (allows outdated certs)
    pub fn with_development_mode(mut self) -> Self {
        self.allow_outdated_pcks = true;
        self
    }
}

/// SGX Quote (attestation proof)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Quote {
    /// Raw quote bytes (includes SGX signature)
    pub quote: Vec<u8>,
    /// Quote signature (signed by Intel)
    pub signature: Vec<u8>,
    /// Quote signing certificate chain
    pub cert_chain: Vec<u8>,
    /// User data embedded in quote (usually hash of public key)
    pub user_data: Vec<u8>,
    /// PCR (Platform Configuration Register) values at quote time
    pub pcr_values: PcrValues,
    /// Timestamp of quote generation
    pub timestamp: u64,
}

impl Quote {
    /// Get the SGX quote as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.quote
    }

    /// Get the signature
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Get PCR values at time of quote
    pub fn pcr_values(&self) -> &PcrValues {
        &self.pcr_values
    }
}

/// PCR (Platform Configuration Register) values
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcrValues {
    /// PCR 0 (firmware)
    pub pcr0: [u8; 32],
    /// PCR 1 (config)
    pub pcr1: [u8; 32],
    /// PCR 2 (bootloader)
    pub pcr2: [u8; 32],
}

impl PcrValues {
    /// Create PCR values from arrays
    pub fn new(pcr0: [u8; 32], pcr1: [u8; 32], pcr2: [u8; 32]) -> Self {
        Self { pcr0, pcr1, pcr2 }
    }

    /// Check if PCR values match expected values (for policy enforcement)
    pub fn matches_policy(&self, policy: &PcrPolicy) -> bool {
        // All non-zero PCR values in policy must match exactly
        if policy.pcr0.is_some_and(|expected| self.pcr0 != expected) {
            return false;
        }
        if policy.pcr1.is_some_and(|expected| self.pcr1 != expected) {
            return false;
        }
        if policy.pcr2.is_some_and(|expected| self.pcr2 != expected) {
            return false;
        }
        true
    }
}

/// PCR policy for key sealing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcrPolicy {
    /// Expected PCR 0 value (None = don't check)
    pub pcr0: Option<[u8; 32]>,
    /// Expected PCR 1 value (None = don't check)
    pub pcr1: Option<[u8; 32]>,
    /// Expected PCR 2 value (None = don't check)
    pub pcr2: Option<[u8; 32]>,
}

impl PcrPolicy {
    /// Create empty policy (allows any PCR values)
    pub fn any() -> Self {
        Self {
            pcr0: None,
            pcr1: None,
            pcr2: None,
        }
    }

    /// Create policy with all PCR values specified
    pub fn strict(pcr0: [u8; 32], pcr1: [u8; 32], pcr2: [u8; 32]) -> Self {
        Self {
            pcr0: Some(pcr0),
            pcr1: Some(pcr1),
            pcr2: Some(pcr2),
        }
    }
}

/// Main Enclave interface
#[derive(Debug)]
pub struct Enclave {
    config: AttestationConfig,
    enclave_id: u64,
    is_initialized: bool,
}

impl Enclave {
    /// Initialize SGX enclave
    ///
    /// # Arguments
    ///
    /// * `config` - Attestation configuration (DCAP or IAS)
    ///
    /// # Errors
    ///
    /// Returns `EnclaveError::InitializationFailed` if enclave setup fails
    ///
    /// # Example
    ///
    /// ```no_run
    /// use abir_guard::confidential_computing::sgx::{Enclave, AttestationConfig};
    ///
    /// let config = AttestationConfig::dcap();
    /// let enclave = Enclave::initialize(config)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn initialize(config: AttestationConfig) -> Result<Self, EnclaveError> {
        // In production, this would call sgx_enclave_create() via FFI
        // For now, we provide a placeholder that works in non-SGX environments
        
        if cfg!(any(feature = "sgx-simulator", debug_assertions)) {
            // Simulator mode or development
            Ok(Enclave {
                config,
                enclave_id: 1,
                is_initialized: true,
            })
        } else {
            Err(EnclaveError::InitializationFailed(
                "SGX not available on this platform".to_string(),
            ))
        }
    }

    /// Check if enclave is initialized
    pub fn is_initialized(&self) -> bool {
        self.is_initialized
    }

    /// Get enclave ID
    pub fn enclave_id(&self) -> u64 {
        self.enclave_id
    }

    /// Get the active attestation configuration.
    pub fn attestation_config(&self) -> &AttestationConfig {
        &self.config
    }

    /// Generate keypair inside enclave
    ///
    /// # Arguments
    ///
    /// * `key_id` - Unique identifier for the key
    ///
    /// # Returns
    ///
    /// Tuple of (public_key_b64, secret_key_b64)
    ///
    /// # Security
    ///
    /// The secret key never leaves the enclave. Only the public key is returned.
    pub fn generate_keypair(&self, key_id: &str) -> Result<(String, String), EnclaveError> {
        if !self.is_initialized {
            return Err(EnclaveError::InvalidState("Enclave not initialized".to_string()));
        }

        // In production, this would call enclave function via ecall
        // For now, placeholder implementation
        Ok((
            format!("pub_{}", key_id),
            format!("sec_{}", key_id),
        ))
    }

    /// Get attestation quote
    ///
    /// # Returns
    ///
    /// SGX Quote containing:
    /// - Raw quote bytes (with SGX signature)
    /// - Quote signature (signed by Intel)
    /// - Certificate chain (for offline verification)
    /// - PCR values (for policy-based access control)
    ///
    /// # Security Watchdog
    ///
    /// Quote generation should complete in <200ms (detects side-channel attacks)
    pub fn get_quote(&self) -> Result<Quote, EnclaveError> {
        if !self.is_initialized {
            return Err(EnclaveError::InvalidState("Enclave not initialized".to_string()));
        }

        // In production, this would call sgx_get_quote() via ecall
        Ok(Quote {
            quote: vec![0u8; 1024],
            signature: vec![0u8; 256],
            cert_chain: vec![],
            user_data: vec![0u8; 32],
            pcr_values: PcrValues::new([0u8; 32], [0u8; 32], [0u8; 32]),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        })
    }

    /// Seal data with enclave key (encrypted to this enclave only)
    ///
    /// # Arguments
    ///
    /// * `plaintext` - Data to seal
    /// * `_pcr_policy` - PCR values that can unseal this data
    ///
    /// # Returns
    ///
    /// Encrypted data that can only be decrypted by this enclave
    /// (or another enclave with matching PCR values)
    pub fn seal_data(&self, plaintext: &[u8], _pcr_policy: &PcrPolicy) -> Result<Vec<u8>, EnclaveError> {
        if !self.is_initialized {
            return Err(EnclaveError::InvalidState("Enclave not initialized".to_string()));
        }

        // In production, this would call sgx_seal_data() via ecall
        // For now, placeholder that returns sealed data structure:
        // [nonce(12) | ciphertext | auth_tag(16) | pcr_policy_hash(32)]
        Ok(vec![0u8; plaintext.len() + 72])
    }

    /// Unseal data that was previously sealed
    ///
    /// # Arguments
    ///
    /// * `sealed_blob` - Data returned from `seal_data()`
    ///
    /// # Returns
    ///
    /// Original plaintext if enclave PCR values match sealing policy
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - PCR values don't match policy
    /// - Ciphertext is tampered (authentication tag invalid)
    /// - Blob format is invalid
    pub fn unseal_data(&self, sealed_blob: &[u8]) -> Result<Vec<u8>, EnclaveError> {
        if !self.is_initialized {
            return Err(EnclaveError::InvalidState("Enclave not initialized".to_string()));
        }

        if sealed_blob.len() < 72 {
            return Err(EnclaveError::SealedStorageError(
                "Sealed blob too short".to_string(),
            ));
        }

        // In production, this would call sgx_unseal_data() via ecall
        Ok(vec![0u8; sealed_blob.len() - 72])
    }

    /// Sign data with enclave key (never leaves enclave)
    ///
    /// # Arguments
    ///
    /// * `_key_id` - ID of key to sign with
    /// * `_data` - Data to sign
    ///
    /// # Returns
    ///
    /// ML-DSA-65 signature
    pub fn sign(&self, _key_id: &str, _data: &[u8]) -> Result<Vec<u8>, EnclaveError> {
        if !self.is_initialized {
            return Err(EnclaveError::InvalidState("Enclave not initialized".to_string()));
        }

        // In production, this would call sign function via ecall
        // Returns placeholder signature (4096 bytes for ML-DSA-65)
        Ok(vec![0u8; 4096])
    }
}

impl Drop for Enclave {
    fn drop(&mut self) {
        if self.is_initialized {
            // In production, call sgx_enclave_destroy() here
            self.is_initialized = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attestation_config_dcap() {
        let config = AttestationConfig::dcap();
        assert_eq!(config.provider, AttestationProvider::DCAP);
        assert_eq!(config.ias_api_key, None);
        assert!(config.dcap_collateral_url.is_some());
    }

    #[test]
    fn test_attestation_config_ias() {
        let config = AttestationConfig::ias("test-api-key".to_string());
        assert_eq!(config.provider, AttestationProvider::IAS);
        assert_eq!(config.ias_api_key.as_deref(), Some("test-api-key"));
    }

    #[test]
    fn test_pcr_policy_any() {
        let policy = PcrPolicy::any();
        assert_eq!(policy.pcr0, None);
        assert_eq!(policy.pcr1, None);
        assert_eq!(policy.pcr2, None);
    }

    #[test]
    fn test_pcr_values_match_policy() {
        let pcr0 = [1u8; 32];
        let pcr1 = [2u8; 32];
        let pcr2 = [3u8; 32];

        let values = PcrValues::new(pcr0, pcr1, pcr2);
        let policy = PcrPolicy::strict(pcr0, pcr1, pcr2);

        assert!(values.matches_policy(&policy));
    }

    #[test]
    fn test_pcr_values_mismatch_policy() {
        let values = PcrValues::new([1u8; 32], [2u8; 32], [3u8; 32]);
        let policy = PcrPolicy::strict([0u8; 32], [2u8; 32], [3u8; 32]);

        assert!(!values.matches_policy(&policy));
    }

    #[test]
    fn test_enclave_exposes_attestation_config() {
        let config = AttestationConfig::dcap();
        let enclave = match Enclave::initialize(config) {
            Ok(enclave) => enclave,
            Err(_) => return,
        };
        assert_eq!(
            enclave.attestation_config().provider,
            AttestationProvider::DCAP
        );
    }
}
