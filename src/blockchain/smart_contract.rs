//! Smart-contract anchor interface.
//!
//! Defines the [`SmartContractAnchor`] trait that abstracts over any blockchain
//! back-end (Ethereum EVM, Solana, Substrate, etc.) and supplies a
//! [`SimulatedContractAnchor`] that satisfies the trait in-process for testing
//! and CI without a live chain.

use crate::blockchain::key_anchor::{AnchorRegistry, KeyAnchorError};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors produced by smart-contract anchor operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ContractError {
    #[error("anchor submission failed: {reason}")]
    SubmissionFailed { reason: String },
    #[error("on-chain verification failed: {reason}")]
    VerificationFailed { reason: String },
    #[error("revocation transaction failed: {reason}")]
    RevocationFailed { reason: String },
    #[error("underlying anchor error: {0}")]
    AnchorError(#[from] KeyAnchorError),
}

/// Result of an on-chain anchor verification call.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OnChainVerificationResult {
    /// Whether the anchor is considered valid on-chain.
    pub valid: bool,
    /// Block height at which the verification was performed (0 for simulation).
    pub block_height: u64,
    /// Anchor ID that was verified.
    pub anchor_id: String,
}

/// Abstraction over a blockchain smart-contract anchor registry.
///
/// Implementors wrap a specific chain client; the blanket [`SimulatedContractAnchor`]
/// is available for unit tests.
pub trait SmartContractAnchor {
    /// Submit a new key anchor to the contract.
    ///
    /// Returns the assigned `anchor_id` string on success.
    fn submit_anchor(
        &mut self,
        public_key: &[u8],
        owner_id: &str,
        timestamp: u64,
    ) -> Result<String, ContractError>;

    /// Verify whether an anchor is currently valid on-chain.
    fn verify_on_chain(
        &self,
        anchor_id: &str,
    ) -> Result<OnChainVerificationResult, ContractError>;

    /// Revoke an existing anchor on-chain.
    fn revoke_anchor(
        &mut self,
        anchor_id: &str,
        requesting_owner: &str,
    ) -> Result<(), ContractError>;
}

/// In-process (simulated) smart-contract anchor backed by [`AnchorRegistry`].
///
/// Used in tests and CI where no real chain is available.  All operations are
/// synchronous and deterministic.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SimulatedContractAnchor {
    registry: AnchorRegistry,
    /// Simulated block height; incremented on every mutating operation.
    pub block_height: u64,
}

impl SimulatedContractAnchor {
    /// Create a fresh simulated anchor with block height 0.
    pub fn new() -> Self {
        Self::default()
    }
}

impl SmartContractAnchor for SimulatedContractAnchor {
    fn submit_anchor(
        &mut self,
        public_key: &[u8],
        owner_id: &str,
        timestamp: u64,
    ) -> Result<String, ContractError> {
        let anchor = self
            .registry
            .register(public_key, owner_id, timestamp)
            .map_err(ContractError::AnchorError)?;
        self.block_height = self.block_height.saturating_add(1);
        Ok(anchor.anchor_id)
    }

    fn verify_on_chain(
        &self,
        anchor_id: &str,
    ) -> Result<OnChainVerificationResult, ContractError> {
        match self.registry.lookup(anchor_id) {
            None => Err(ContractError::VerificationFailed {
                reason: format!("anchor {anchor_id} not found"),
            }),
            Some(anchor) => Ok(OnChainVerificationResult {
                valid: !anchor.revoked,
                block_height: self.block_height,
                anchor_id: anchor_id.to_owned(),
            }),
        }
    }

    fn revoke_anchor(
        &mut self,
        anchor_id: &str,
        requesting_owner: &str,
    ) -> Result<(), ContractError> {
        self.registry
            .revoke(anchor_id, requesting_owner)
            .map_err(ContractError::AnchorError)?;
        self.block_height = self.block_height.saturating_add(1);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(label: &str) -> Vec<u8> {
        format!("contract-pk-{label}").into_bytes()
    }

    #[test]
    fn test_submit_and_verify() {
        let mut contract = SimulatedContractAnchor::new();
        let anchor_id = contract
            .submit_anchor(&pk("alice"), "alice", 0)
            .expect("submit should pass");
        let result = contract
            .verify_on_chain(&anchor_id)
            .expect("verify should pass");
        assert!(result.valid);
        assert_eq!(result.anchor_id, anchor_id);
        assert_eq!(result.block_height, 1);
    }

    #[test]
    fn test_revoke_marks_invalid() {
        let mut contract = SimulatedContractAnchor::new();
        let anchor_id = contract
            .submit_anchor(&pk("bob"), "bob", 0)
            .expect("submit");
        contract
            .revoke_anchor(&anchor_id, "bob")
            .expect("revoke should pass");
        let result = contract
            .verify_on_chain(&anchor_id)
            .expect("verify still returns result");
        assert!(!result.valid);
        assert_eq!(result.block_height, 2);
    }

    #[test]
    fn test_verify_unknown_anchor_fails() {
        let contract = SimulatedContractAnchor::new();
        let err = contract
            .verify_on_chain("deadbeef")
            .expect_err("unknown anchor should fail");
        assert!(matches!(err, ContractError::VerificationFailed { .. }));
    }

    #[test]
    fn test_revoke_wrong_owner_fails() {
        let mut contract = SimulatedContractAnchor::new();
        let anchor_id = contract
            .submit_anchor(&pk("carol"), "carol", 0)
            .expect("submit");
        let err = contract
            .revoke_anchor(&anchor_id, "attacker")
            .expect_err("wrong owner should fail");
        assert!(matches!(err, ContractError::AnchorError(KeyAnchorError::OwnerMismatch { .. })));
    }

    #[test]
    fn test_block_height_increments() {
        let mut contract = SimulatedContractAnchor::new();
        assert_eq!(contract.block_height, 0);
        contract.submit_anchor(&pk("dan"), "dan", 0).expect("submit");
        assert_eq!(contract.block_height, 1);
        let anchor_id = contract
            .submit_anchor(&pk("eve"), "eve", 0)
            .expect("submit");
        assert_eq!(contract.block_height, 2);
        contract.revoke_anchor(&anchor_id, "eve").expect("revoke");
        assert_eq!(contract.block_height, 3);
    }
}
