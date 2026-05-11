//! Common TEE (Trusted Execution Environment) Abstractions
//!
//! Shared interfaces and types for different TEE platforms:
//! - Intel SGX 2.0
//! - ARM TrustZone
//! - AMD SEV (future)
//! - Intel TDX (future)

use serde::{Deserialize, Serialize};

/// TEE Platform Type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TeeType {
    /// Intel SGX 2.0 enclaves
    SGX,
    /// ARM TrustZone with OP-TEE
    TrustZone,
    /// AMD SEV-SNP (future)
    AmdSev,
    /// Intel TDX (future)
    IntelTdx,
}

/// TEE Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeeConfig {
    /// Which TEE platform to target
    pub tee_type: TeeType,
    /// Enable debug mode (reduces security)
    pub debug_mode: bool,
    /// Maximum enclave memory size
    pub max_enclave_size: u64,
}

impl TeeConfig {
    /// Create SGX configuration
    pub fn sgx() -> Self {
        Self {
            tee_type: TeeType::SGX,
            debug_mode: false,
            max_enclave_size: 0x100000, // 1MB
        }
    }

    /// Create TrustZone configuration
    pub fn trustzone() -> Self {
        Self {
            tee_type: TeeType::TrustZone,
            debug_mode: false,
            max_enclave_size: 0x200000, // 2MB
        }
    }

    /// Enable debug mode
    pub fn with_debug(mut self) -> Self {
        self.debug_mode = true;
        self
    }
}

/// Sealed data (encrypted to specific TEE state)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedData {
    /// TEE platform type
    pub tee_type: TeeType,
    /// Encrypted data
    pub ciphertext: Vec<u8>,
    /// Authentication tag
    pub auth_tag: Vec<u8>,
    /// Nonce
    pub nonce: Vec<u8>,
}

impl SealedData {
    /// Create new sealed data
    pub fn new(
        tee_type: TeeType,
        ciphertext: Vec<u8>,
        auth_tag: Vec<u8>,
        nonce: Vec<u8>,
    ) -> Self {
        Self {
            tee_type,
            ciphertext,
            auth_tag,
            nonce,
        }
    }
}

/// TEE attestation report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeeAttestationReport {
    /// TEE platform type
    pub tee_type: TeeType,
    /// Attestation data (format varies by platform)
    pub attestation_data: Vec<u8>,
    /// Timestamp
    pub timestamp: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tee_type_sgx() {
        assert_eq!(TeeType::SGX, TeeType::SGX);
    }

    #[test]
    fn test_tee_config_sgx() {
        let config = TeeConfig::sgx();
        assert_eq!(config.tee_type, TeeType::SGX);
        assert!(!config.debug_mode);
    }

    #[test]
    fn test_sealed_data_creation() {
        let sealed = SealedData::new(
            TeeType::SGX,
            vec![1, 2, 3],
            vec![0u8; 16],
            vec![0u8; 12],
        );
        assert_eq!(sealed.tee_type, TeeType::SGX);
    }
}
