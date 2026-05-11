//! On-chain key commitment model.
//!
//! `KeyAnchor` represents a tamper-evident binding of a cryptographic public key
//! to an owner identity.  `AnchorRegistry` acts as a local in-process ledger that
//! mirrors the state an on-chain registry would maintain, and can be driven by the
//! [`SmartContractAnchor`](super::SmartContractAnchor) trait for real-chain back-ends.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use thiserror::Error;

/// Errors for key-anchor operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum KeyAnchorError {
    #[error("anchor already exists for key hash")]
    AlreadyAnchored,
    #[error("anchor not found")]
    NotFound,
    #[error("anchor has been revoked")]
    Revoked,
    #[error("owner mismatch: expected {expected:?}, got {got:?}")]
    OwnerMismatch { expected: String, got: String },
    #[error("public key bytes must not be empty")]
    EmptyPublicKey,
}

/// An on-chain key commitment record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyAnchor {
    /// Unique anchor identifier (hex-encoded SHA-256 of key bytes).
    pub anchor_id: String,
    /// SHA-256 digest of the bound public key.
    pub key_hash: Vec<u8>,
    /// Owner/entity identifier.
    pub owner_id: String,
    /// Creation timestamp (Unix seconds, caller-supplied for determinism in tests).
    pub timestamp: u64,
    /// Whether this anchor has been revoked.
    pub revoked: bool,
}

impl KeyAnchor {
    /// Build a new (non-revoked) anchor.
    pub fn new(public_key: &[u8], owner_id: impl Into<String>, timestamp: u64) -> Self {
        let key_hash = Sha256::digest(public_key).to_vec();
        let anchor_id = hex_encode(&key_hash);
        Self {
            anchor_id,
            key_hash,
            owner_id: owner_id.into(),
            timestamp,
            revoked: false,
        }
    }

    /// Returns `true` when the anchor covers the given public key bytes.
    pub fn matches_key(&self, public_key: &[u8]) -> bool {
        let hash = Sha256::digest(public_key).to_vec();
        self.key_hash == hash
    }
}

/// In-process registry of [`KeyAnchor`] records.
///
/// Provides the same contract a smart-contract back-end would expose so that
/// upper-layer code can run against a simulated ledger without a live chain.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AnchorRegistry {
    /// Map of `anchor_id` → `KeyAnchor`.
    anchors: HashMap<String, KeyAnchor>,
}

impl AnchorRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new key anchor.
    ///
    /// # Errors
    /// - [`KeyAnchorError::EmptyPublicKey`] if `public_key` is empty.
    /// - [`KeyAnchorError::AlreadyAnchored`] if an anchor for the same key hash already exists.
    pub fn register(
        &mut self,
        public_key: &[u8],
        owner_id: impl Into<String>,
        timestamp: u64,
    ) -> Result<KeyAnchor, KeyAnchorError> {
        if public_key.is_empty() {
            return Err(KeyAnchorError::EmptyPublicKey);
        }
        let anchor = KeyAnchor::new(public_key, owner_id, timestamp);
        if self.anchors.contains_key(&anchor.anchor_id) {
            return Err(KeyAnchorError::AlreadyAnchored);
        }
        self.anchors
            .insert(anchor.anchor_id.clone(), anchor.clone());
        Ok(anchor)
    }

    /// Revoke an anchor by `anchor_id`.
    ///
    /// Only the original owner may request revocation.
    ///
    /// # Errors
    /// - [`KeyAnchorError::NotFound`] if no anchor matches.
    /// - [`KeyAnchorError::OwnerMismatch`] if `requesting_owner` differs from the registered owner.
    pub fn revoke(
        &mut self,
        anchor_id: &str,
        requesting_owner: &str,
    ) -> Result<(), KeyAnchorError> {
        let anchor = self
            .anchors
            .get_mut(anchor_id)
            .ok_or(KeyAnchorError::NotFound)?;

        if anchor.owner_id != requesting_owner {
            return Err(KeyAnchorError::OwnerMismatch {
                expected: anchor.owner_id.clone(),
                got: requesting_owner.to_owned(),
            });
        }
        anchor.revoked = true;
        Ok(())
    }

    /// Look up an anchor by `anchor_id`.
    pub fn lookup(&self, anchor_id: &str) -> Option<&KeyAnchor> {
        self.anchors.get(anchor_id)
    }

    /// Verify that an anchor ID refers to a valid (non-revoked) anchor.
    ///
    /// # Errors
    /// - [`KeyAnchorError::NotFound`] if no anchor matches `anchor_id`.
    /// - [`KeyAnchorError::Revoked`] if the anchor was revoked.
    pub fn verify_anchor_by_id(&self, anchor_id: &str) -> Result<&KeyAnchor, KeyAnchorError> {
        let anchor = self.anchors.get(anchor_id).ok_or(KeyAnchorError::NotFound)?;
        if anchor.revoked {
            return Err(KeyAnchorError::Revoked);
        }
        Ok(anchor)
    }

    /// Verify that a public key has a valid (non-revoked) anchor.
    ///
    /// # Errors
    /// - [`KeyAnchorError::NotFound`] if no anchor matches the key hash.
    /// - [`KeyAnchorError::Revoked`] if the matching anchor was revoked.
    pub fn verify_anchor(&self, public_key: &[u8]) -> Result<&KeyAnchor, KeyAnchorError> {
        let key_hash = Sha256::digest(public_key).to_vec();
        let anchor_id = hex_encode(&key_hash);
        let anchor = self
            .anchors
            .get(&anchor_id)
            .ok_or(KeyAnchorError::NotFound)?;
        if anchor.revoked {
            return Err(KeyAnchorError::Revoked);
        }
        Ok(anchor)
    }

    /// Return the total number of anchors (including revoked).
    pub fn len(&self) -> usize {
        self.anchors.len()
    }

    /// Returns `true` when the registry contains no anchors.
    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(label: &str) -> Vec<u8> {
        format!("public-key-{label}").into_bytes()
    }

    #[test]
    fn test_register_and_verify() {
        let mut registry = AnchorRegistry::new();
        let anchor = registry.register(&pk("alice"), "alice", 1000).expect("register should pass");
        assert!(!anchor.revoked);
        let found = registry.verify_anchor(&pk("alice")).expect("verify should pass");
        assert_eq!(found.owner_id, "alice");
    }

    #[test]
    fn test_register_duplicate_rejected() {
        let mut registry = AnchorRegistry::new();
        registry.register(&pk("bob"), "bob", 1000).expect("first register");
        let err = registry.register(&pk("bob"), "bob", 1001).expect_err("duplicate should fail");
        assert_eq!(err, KeyAnchorError::AlreadyAnchored);
    }

    #[test]
    fn test_register_empty_key_rejected() {
        let mut registry = AnchorRegistry::new();
        let err = registry.register(b"", "alice", 0).expect_err("empty key should fail");
        assert_eq!(err, KeyAnchorError::EmptyPublicKey);
    }

    #[test]
    fn test_revoke_allows_owner() {
        let mut registry = AnchorRegistry::new();
        let anchor = registry.register(&pk("carol"), "carol", 2000).expect("register");
        registry.revoke(&anchor.anchor_id, "carol").expect("revoke should pass");
        let err = registry.verify_anchor(&pk("carol")).expect_err("revoked key");
        assert_eq!(err, KeyAnchorError::Revoked);
    }

    #[test]
    fn test_revoke_rejects_wrong_owner() {
        let mut registry = AnchorRegistry::new();
        let anchor = registry.register(&pk("dan"), "dan", 3000).expect("register");
        let err = registry
            .revoke(&anchor.anchor_id, "eve")
            .expect_err("wrong owner should fail");
        assert!(matches!(err, KeyAnchorError::OwnerMismatch { .. }));
    }

    #[test]
    fn test_lookup_nonexistent_returns_none() {
        let registry = AnchorRegistry::new();
        assert!(registry.lookup("deadbeef").is_none());
    }

    #[test]
    fn test_verify_unknown_key_returns_not_found() {
        let registry = AnchorRegistry::new();
        let err = registry.verify_anchor(&pk("ghost")).expect_err("unknown key");
        assert_eq!(err, KeyAnchorError::NotFound);
    }

    #[test]
    fn test_matches_key_predicate() {
        let anchor = KeyAnchor::new(&pk("frank"), "frank", 0);
        assert!(anchor.matches_key(&pk("frank")));
        assert!(!anchor.matches_key(&pk("other")));
    }
}
