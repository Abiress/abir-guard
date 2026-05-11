//! Decentralized PKI (dPKI) facade.
//!
//! Provides a local, chain-agnostic certificate registry where each entry
//! represents a binding of an entity identity to a public key hash, anchored
//! on-chain via the [`AnchorRegistry`](super::key_anchor::AnchorRegistry).
//!
//! `DecentralizedPki` consults both its own validity window and the anchor
//! registry so that key revocation propagates immediately without re-issuing
//! certificate-like entries.

use crate::blockchain::key_anchor::{AnchorRegistry, KeyAnchorError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use thiserror::Error;

/// Errors for dPKI operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DpkiError {
    #[error("entity already has a registered key")]
    AlreadyRegistered,
    #[error("entity not found in dPKI registry")]
    NotFound,
    #[error("dPKI entry has expired (current: {current}, until: {until})")]
    Expired { current: u64, until: u64 },
    #[error("dPKI entry is not yet valid (current: {current}, from: {from})")]
    NotYetValid { current: u64, from: u64 },
    #[error("anchor verification failed: {0}")]
    AnchorError(#[from] KeyAnchorError),
    #[error("public key bytes must not be empty")]
    EmptyPublicKey,
}

/// A single dPKI binding entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DpkiEntry {
    /// Entity identifier (e.g. DID, domain, agent handle).
    pub entity_id: String,
    /// SHA-256 hash of the bound public key.
    pub key_hash: Vec<u8>,
    /// Corresponding anchor ID in the `AnchorRegistry`.
    pub anchor_id: String,
    /// Validity start (Unix seconds).
    pub valid_from: u64,
    /// Validity end (Unix seconds, `None` = no expiry).
    pub valid_until: Option<u64>,
}

impl DpkiEntry {
    /// Check whether this entry is temporally valid at `now`.
    pub fn is_valid_at(&self, now: u64) -> Result<(), DpkiError> {
        if now < self.valid_from {
            return Err(DpkiError::NotYetValid {
                current: now,
                from: self.valid_from,
            });
        }
        if let Some(until) = self.valid_until {
            if now > until {
                return Err(DpkiError::Expired {
                    current: now,
                    until,
                });
            }
        }
        Ok(())
    }
}

/// Decentralized PKI registry.
///
/// Binds entity IDs to public-key hashes and validates them against an
/// [`AnchorRegistry`].  The registry owns an `AnchorRegistry` internally;
/// callers interact only with the dPKI facade.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct DecentralizedPki {
    entries: HashMap<String, DpkiEntry>,
    anchors: AnchorRegistry,
}

impl DecentralizedPki {
    /// Create an empty dPKI registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new entity–key binding.
    ///
    /// The public key is anchored in the internal `AnchorRegistry` at the same
    /// time so that a later revocation of the anchor propagates through
    /// [`resolve`](Self::resolve).
    ///
    /// # Parameters
    /// - `entity_id`: Unique identifier for the entity.
    /// - `public_key`: Raw public key bytes (non-empty).
    /// - `valid_from`, `valid_until`: Validity window (Unix seconds).
    /// - `timestamp`: Timestamp forwarded to the `AnchorRegistry`.
    ///
    /// # Errors
    /// - [`DpkiError::EmptyPublicKey`] if `public_key` is empty.
    /// - [`DpkiError::AlreadyRegistered`] if `entity_id` already has an entry.
    /// - [`DpkiError::AnchorError`] if the anchor registration fails.
    pub fn register_key(
        &mut self,
        entity_id: impl Into<String>,
        public_key: &[u8],
        valid_from: u64,
        valid_until: Option<u64>,
        timestamp: u64,
    ) -> Result<DpkiEntry, DpkiError> {
        if public_key.is_empty() {
            return Err(DpkiError::EmptyPublicKey);
        }
        let entity_id = entity_id.into();
        if self.entries.contains_key(&entity_id) {
            return Err(DpkiError::AlreadyRegistered);
        }
        let anchor = self.anchors.register(public_key, &entity_id, timestamp)?;
        let key_hash = Sha256::digest(public_key).to_vec();
        let entry = DpkiEntry {
            entity_id: entity_id.clone(),
            key_hash,
            anchor_id: anchor.anchor_id,
            valid_from,
            valid_until,
        };
        self.entries.insert(entity_id, entry.clone());
        Ok(entry)
    }

    /// Resolve an entity's dPKI entry and validate it at `now`.
    ///
    /// Checks both the temporal validity window and the anchor status (not
    /// revoked on-chain).
    ///
    /// # Errors
    /// - [`DpkiError::NotFound`] if `entity_id` is unknown.
    /// - [`DpkiError::NotYetValid`] / [`DpkiError::Expired`] for time violations.
    /// - [`DpkiError::AnchorError`] wrapping [`KeyAnchorError::Revoked`] if the
    ///   corresponding anchor was revoked.
    pub fn resolve(&self, entity_id: &str, now: u64) -> Result<&DpkiEntry, DpkiError> {
        let entry = self.entries.get(entity_id).ok_or(DpkiError::NotFound)?;
        entry.is_valid_at(now)?;
        // Verify the on-chain anchor is still active.
        let _ = self.anchors.verify_anchor_by_id(&entry.anchor_id)?;
        Ok(entry)
    }

    /// Invalidate (revoke) an entity's key binding.
    ///
    /// Propagates the revocation to the underlying anchor registry so that
    /// any subsequent [`resolve`](Self::resolve) call returns an anchor error.
    ///
    /// # Errors
    /// - [`DpkiError::NotFound`] if `entity_id` is unknown.
    /// - [`DpkiError::AnchorError`] if the anchor revocation fails.
    pub fn invalidate(&mut self, entity_id: &str) -> Result<(), DpkiError> {
        let entry = self.entries.get(entity_id).ok_or(DpkiError::NotFound)?;
        let anchor_id = entry.anchor_id.clone();
        self.anchors.revoke(&anchor_id, entity_id)?;
        Ok(())
    }

    /// Number of registered entries (including invalidated ones).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` when no entries have been registered.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(label: &str) -> Vec<u8> {
        format!("dpki-public-key-{label}").into_bytes()
    }

    #[test]
    fn test_register_and_resolve() {
        let mut dpki = DecentralizedPki::new();
        dpki.register_key("did:alice", &pk("alice"), 0, None, 0)
            .expect("register should pass");
        let entry = dpki.resolve("did:alice", 100).expect("resolve should pass");
        assert_eq!(entry.entity_id, "did:alice");
    }

    #[test]
    fn test_duplicate_registration_rejected() {
        let mut dpki = DecentralizedPki::new();
        dpki.register_key("did:bob", &pk("bob"), 0, None, 0)
            .expect("first register");
        let err = dpki
            .register_key("did:bob", &pk("bob2"), 0, None, 1)
            .expect_err("duplicate should fail");
        assert_eq!(err, DpkiError::AlreadyRegistered);
    }

    #[test]
    fn test_resolve_expired_entry() {
        let mut dpki = DecentralizedPki::new();
        dpki.register_key("did:carol", &pk("carol"), 0, Some(500), 0)
            .expect("register");
        let err = dpki.resolve("did:carol", 501).expect_err("should be expired");
        assert!(matches!(err, DpkiError::Expired { .. }));
    }

    #[test]
    fn test_resolve_not_yet_valid() {
        let mut dpki = DecentralizedPki::new();
        dpki.register_key("did:dan", &pk("dan"), 1000, None, 0)
            .expect("register");
        let err = dpki.resolve("did:dan", 500).expect_err("should be not-yet-valid");
        assert!(matches!(err, DpkiError::NotYetValid { .. }));
    }

    #[test]
    fn test_invalidate_blocks_resolve() {
        let mut dpki = DecentralizedPki::new();
        dpki.register_key("did:eve", &pk("eve"), 0, None, 0)
            .expect("register");
        dpki.invalidate("did:eve").expect("invalidate should pass");
        let err = dpki.resolve("did:eve", 100).expect_err("should be revoked");
        assert!(matches!(err, DpkiError::AnchorError(KeyAnchorError::Revoked)));
    }

    #[test]
    fn test_resolve_unknown_entity() {
        let dpki = DecentralizedPki::new();
        let err = dpki.resolve("did:ghost", 0).expect_err("unknown entity");
        assert_eq!(err, DpkiError::NotFound);
    }

    #[test]
    fn test_empty_key_rejected() {
        let mut dpki = DecentralizedPki::new();
        let err = dpki
            .register_key("did:empty", b"", 0, None, 0)
            .expect_err("empty key should fail");
        assert_eq!(err, DpkiError::EmptyPublicKey);
    }
}
