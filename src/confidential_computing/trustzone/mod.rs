//! ARM TrustZone TEE Integration
//!
//! Provides a TrustZone-backed TEE interface designed for edge and mobile devices.
//! Current implementation is an abstraction layer with simulator-friendly placeholders.

pub mod attestation;
pub mod interface;

use crate::confidential_computing::tee_common::{SealedData, TeeAttestationReport, TeeConfig, TeeType};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use attestation::{
    build_simulated_report, TrustZoneAttestationPolicy, TrustZoneAttestationVerifier,
    TrustZoneVerificationResult,
};
pub use interface::{dispatch_command, TaCommand, TaRequest, TaResponse};

/// TrustZone-specific errors.
#[derive(Debug, Error)]
pub enum TrustZoneError {
    #[error("TrustZone initialization failed: {0}")]
    InitializationFailed(String),
    #[error("Trusted application operation failed: {0}")]
    OperationFailed(String),
    #[error("Attestation failed: {0}")]
    AttestationFailed(String),
    #[error("Invalid state: {0}")]
    InvalidState(String),
}

/// OP-TEE session configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustZoneConfig {
    /// Trusted application UUID.
    pub ta_uuid: String,
    /// Whether to require secure world attestation.
    pub require_attestation: bool,
}

impl TrustZoneConfig {
    /// Default secure profile for TrustZone.
    pub fn secure_default() -> Self {
        Self {
            ta_uuid: "00000000-0000-0000-0000-000000000001".to_string(),
            require_attestation: true,
        }
    }
}

/// Active TrustZone session state.
#[derive(Debug)]
pub struct TrustZoneEnclave {
    config: TrustZoneConfig,
    session_id: u64,
    initialized: bool,
}

impl TrustZoneEnclave {
    /// Create a TrustZone session.
    pub fn initialize(config: TrustZoneConfig) -> Result<Self, TrustZoneError> {
        if config.ta_uuid.is_empty() {
            return Err(TrustZoneError::InitializationFailed(
                "TA UUID cannot be empty".to_string(),
            ));
        }

        Ok(Self {
            config,
            session_id: 1,
            initialized: true,
        })
    }

    /// Check initialization status.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Return active session ID.
    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    /// Return current TrustZone configuration.
    pub fn config(&self) -> &TrustZoneConfig {
        &self.config
    }

    /// Produce a secure world attestation report.
    pub fn get_attestation(&self) -> Result<TeeAttestationReport, TrustZoneError> {
        if !self.initialized {
            return Err(TrustZoneError::InvalidState(
                "TrustZone session is not initialized".to_string(),
            ));
        }

        Ok(TeeAttestationReport {
            tee_type: TeeType::TrustZone,
            attestation_data: vec![0u8; 256],
            timestamp: 0,
        })
    }

    /// Seal bytes using TrustZone-backed key material.
    pub fn seal_data(&self, plaintext: &[u8]) -> Result<SealedData, TrustZoneError> {
        if !self.initialized {
            return Err(TrustZoneError::InvalidState(
                "TrustZone session is not initialized".to_string(),
            ));
        }

        Ok(SealedData::new(
            TeeType::TrustZone,
            plaintext.to_vec(),
            vec![0u8; 16],
            vec![0u8; 12],
        ))
    }

    /// Unseal previously sealed TrustZone data.
    pub fn unseal_data(&self, sealed: &SealedData) -> Result<Vec<u8>, TrustZoneError> {
        if !self.initialized {
            return Err(TrustZoneError::InvalidState(
                "TrustZone session is not initialized".to_string(),
            ));
        }

        if sealed.tee_type != TeeType::TrustZone {
            return Err(TrustZoneError::OperationFailed(
                "Sealed payload does not belong to TrustZone".to_string(),
            ));
        }

        Ok(sealed.ciphertext.clone())
    }

    /// Convert to common TEE config for shared logic.
    pub fn as_tee_config(&self) -> TeeConfig {
        TeeConfig::trustzone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confidential_computing::sgx::{AttestationConfig, Enclave};

    #[test]
    fn test_trustzone_init() {
        let cfg = TrustZoneConfig::secure_default();
        let tz = TrustZoneEnclave::initialize(cfg).expect("init should pass");
        assert!(tz.is_initialized());
        assert_eq!(tz.session_id(), 1);
    }

    #[test]
    fn test_trustzone_seal_unseal() {
        let cfg = TrustZoneConfig::secure_default();
        let tz = TrustZoneEnclave::initialize(cfg).expect("init should pass");
        let sealed = tz.seal_data(b"edge-secret").expect("seal should pass");
        let plain = tz.unseal_data(&sealed).expect("unseal should pass");
        assert_eq!(plain, b"edge-secret");
    }

    #[test]
    fn test_trustzone_attestation_type() {
        let cfg = TrustZoneConfig::secure_default();
        let tz = TrustZoneEnclave::initialize(cfg).expect("init should pass");
        let report = tz.get_attestation().expect("attestation should pass");
        assert_eq!(report.tee_type, TeeType::TrustZone);
    }

    #[test]
    fn test_cross_tee_attestation_contract() {
        let tz = TrustZoneEnclave::initialize(TrustZoneConfig::secure_default())
            .expect("trustzone init should pass");
        let sgx = match Enclave::initialize(AttestationConfig::dcap()) {
            Ok(enclave) => enclave,
            Err(_) => return,
        };

        let tz_report = tz.get_attestation().expect("trustzone attestation should pass");
        let sgx_report = sgx.get_quote().expect("sgx quote should pass");

        assert_eq!(tz_report.tee_type, TeeType::TrustZone);
        assert!(!sgx_report.as_bytes().is_empty());
    }

    #[test]
    fn test_cross_tee_sealing_contract() {
        let tz = TrustZoneEnclave::initialize(TrustZoneConfig::secure_default())
            .expect("trustzone init should pass");
        let sgx = match Enclave::initialize(AttestationConfig::dcap()) {
            Ok(enclave) => enclave,
            Err(_) => return,
        };

        let tz_sealed = tz.seal_data(b"contract-secret").expect("trustzone seal should pass");
        let sgx_policy = crate::confidential_computing::sgx::PcrPolicy::any();
        let sgx_sealed = sgx
            .seal_data(b"contract-secret", &sgx_policy)
            .expect("sgx seal should pass");

        assert_eq!(tz_sealed.tee_type, TeeType::TrustZone);
        assert!(!sgx_sealed.is_empty());
    }
}
