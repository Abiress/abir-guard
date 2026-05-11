//! Confidential Computing Integration for Abir-Guard
//!
//! Provides secure computation environments for AI agents:
//! - Intel SGX 2.0: Enclaves with remote attestation (DCAP/IAS)
//! - ARM TrustZone: OP-TEE integration for edge agents
//! - Multi-Party Computation: Threshold cryptography and Byzantine resilience
//! - Attestation-as-a-Service: Centralized verification for agent integrity
//!
//! # Security Properties
//!
//! - **Enclave Isolation**: CPU enforces memory protection boundaries
//! - **Remote Attestation**: Cryptographic proof of code integrity
//! - **Sealed Storage**: Encryption tied to enclave state and PCR values
//! - **Quote Verification**: Intel/ARM signed attestation reports
//!
//! # Example
//!
//! ```no_run
//! use abir_guard::confidential_computing::sgx::{Enclave, AttestationConfig};
//!
//! // Create enclave
//! let config = AttestationConfig::dcap();
//! let enclave = Enclave::initialize(config)?;
//!
//! // Generate keypair inside enclave
//! let (public_key, _) = enclave.generate_keypair("agent-1")?;
//!
//! // Get attestation quote (includes PCR values)
//! let quote = enclave.get_quote()?;
//!
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

pub mod sgx;
pub mod tee_common;
pub mod trustzone;
pub mod mpc;
pub mod attestation_service;

pub use sgx::{Enclave, AttestationConfig, Quote, EnclaveError};
pub use tee_common::{TeeConfig, TeeType, SealedData};
pub use trustzone::{TrustZoneConfig, TrustZoneEnclave, TrustZoneError};
pub use mpc::{
	AggregateMessage, CommitSubmission, MpcError, MpcPolicy, MpcSession, RevealSubmission,
	ShareSubmission,
};
pub use attestation_service::{
	AttestationService, AttestationServiceError, UnifiedAttestationResult,
};
