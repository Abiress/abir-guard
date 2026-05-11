//! Multi-Party Computation (MPC) session primitives.
//!
//! This module provides a deterministic, testable MPC coordination layer that can
//! be upgraded with network transport and threshold signature backends.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Errors raised by MPC coordination.
#[derive(Debug, Error)]
pub enum MpcError {
    #[error("invalid policy: {0}")]
    InvalidPolicy(String),
    #[error("party already registered: {0}")]
    DuplicateParty(String),
    #[error("party is not registered: {0}")]
    UnknownParty(String),
    #[error("share already submitted for party: {0}")]
    DuplicateShare(String),
    #[error("commitment already submitted for party: {0}")]
    DuplicateCommitment(String),
    #[error("not enough shares to finalize")]
    InsufficientShares,
    #[error("round mismatch: expected {expected}, got {received}")]
    RoundMismatch { expected: u32, received: u32 },
    #[error("no commitment found for party: {0}")]
    UnknownCommitment(String),
    #[error("invalid commitment for party: {0}")]
    InvalidCommitment(String),
    #[error("nonce replay detected: {0}")]
    ReplayDetected(u64),
    #[error("aggregate digest does not match local digest")]
    AggregateMismatch,
}

/// MPC session policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MpcPolicy {
    /// Total parties expected in the session.
    pub total_parties: usize,
    /// Threshold needed for finalization.
    pub threshold: usize,
    /// Optional round limit for protocol orchestration.
    pub max_rounds: u32,
}

impl MpcPolicy {
    /// Create a policy with validation.
    pub fn new(total_parties: usize, threshold: usize, max_rounds: u32) -> Result<Self, MpcError> {
        if total_parties == 0 {
            return Err(MpcError::InvalidPolicy(
                "total_parties must be greater than zero".to_string(),
            ));
        }
        if threshold == 0 || threshold > total_parties {
            return Err(MpcError::InvalidPolicy(
                "threshold must be between 1 and total_parties".to_string(),
            ));
        }
        if max_rounds == 0 {
            return Err(MpcError::InvalidPolicy(
                "max_rounds must be greater than zero".to_string(),
            ));
        }

        Ok(Self {
            total_parties,
            threshold,
            max_rounds,
        })
    }
}

/// One-party share payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareSubmission {
    /// Party identifier.
    pub party_id: String,
    /// Opaque share bytes.
    pub share: Vec<u8>,
}

impl ShareSubmission {
    /// Build a submission.
    pub fn new(party_id: impl Into<String>, share: Vec<u8>) -> Self {
        Self {
            party_id: party_id.into(),
            share,
        }
    }
}

/// Round-1 commitment message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitSubmission {
    /// Party identifier.
    pub party_id: String,
    /// Hash commitment over reveal payload.
    pub commitment: Vec<u8>,
    /// Per-message nonce used to prevent replay.
    pub nonce: u64,
    /// Protocol round when the message was created.
    pub round: u32,
}

impl CommitSubmission {
    /// Build a commitment submission.
    pub fn new(party_id: impl Into<String>, commitment: Vec<u8>, nonce: u64, round: u32) -> Self {
        Self {
            party_id: party_id.into(),
            commitment,
            nonce,
            round,
        }
    }
}

/// Round-2 reveal message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevealSubmission {
    /// Party identifier.
    pub party_id: String,
    /// Revealed share bytes.
    pub share: Vec<u8>,
    /// Per-message nonce used to prevent replay.
    pub nonce: u64,
    /// Protocol round when the message was created.
    pub round: u32,
}

impl RevealSubmission {
    /// Build a reveal submission.
    pub fn new(party_id: impl Into<String>, share: Vec<u8>, nonce: u64, round: u32) -> Self {
        Self {
            party_id: party_id.into(),
            share,
            nonce,
            round,
        }
    }
}

/// Coordinator aggregate message for round closure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregateMessage {
    /// Round this aggregate belongs to.
    pub round: u32,
    /// Message nonce.
    pub nonce: u64,
    /// Deterministic digest over accepted shares.
    pub digest: Vec<u8>,
}

impl AggregateMessage {
    /// Build an aggregate message.
    pub fn new(round: u32, nonce: u64, digest: Vec<u8>) -> Self {
        Self { round, nonce, digest }
    }
}

/// Active MPC session state.
#[derive(Debug, Clone)]
pub struct MpcSession {
    policy: MpcPolicy,
    parties: HashSet<String>,
    commitments: HashMap<String, Vec<u8>>,
    shares: HashMap<String, Vec<u8>>,
    seen_nonces: HashSet<u64>,
    session_nonce: u64,
    round: u32,
}

impl MpcSession {
    /// Create a new MPC session.
    pub fn new(policy: MpcPolicy) -> Self {
        Self {
            session_nonce: ((policy.total_parties as u64) << 32)
                ^ ((policy.threshold as u64) << 16)
                ^ (policy.max_rounds as u64),
            policy,
            parties: HashSet::new(),
            commitments: HashMap::new(),
            shares: HashMap::new(),
            seen_nonces: HashSet::new(),
            round: 1,
        }
    }

    /// Stable nonce seed for this session.
    pub fn session_nonce(&self) -> u64 {
        self.session_nonce
    }

    /// Register a party in the session.
    pub fn register_party(&mut self, party_id: impl Into<String>) -> Result<(), MpcError> {
        let party_id = party_id.into();
        if self.parties.contains(&party_id) {
            return Err(MpcError::DuplicateParty(party_id));
        }
        self.parties.insert(party_id);
        Ok(())
    }

    /// Submit one share for a registered party.
    pub fn submit_share(&mut self, submission: ShareSubmission) -> Result<(), MpcError> {
        if !self.parties.contains(&submission.party_id) {
            return Err(MpcError::UnknownParty(submission.party_id));
        }

        if self.shares.contains_key(&submission.party_id) {
            return Err(MpcError::DuplicateShare(submission.party_id));
        }

        self.shares.insert(submission.party_id, submission.share);
        Ok(())
    }

    /// Submit a commitment for the current round.
    pub fn submit_commit(&mut self, submission: CommitSubmission) -> Result<(), MpcError> {
        self.ensure_round(submission.round)?;
        self.register_nonce(submission.nonce)?;

        if !self.parties.contains(&submission.party_id) {
            return Err(MpcError::UnknownParty(submission.party_id));
        }
        if self.commitments.contains_key(&submission.party_id) {
            return Err(MpcError::DuplicateCommitment(submission.party_id));
        }

        self.commitments
            .insert(submission.party_id, submission.commitment);
        Ok(())
    }

    /// Submit a reveal and validate it against prior commitment.
    pub fn submit_reveal(&mut self, submission: RevealSubmission) -> Result<(), MpcError> {
        self.ensure_round(submission.round)?;
        self.register_nonce(submission.nonce)?;

        if !self.parties.contains(&submission.party_id) {
            return Err(MpcError::UnknownParty(submission.party_id));
        }
        if self.shares.contains_key(&submission.party_id) {
            return Err(MpcError::DuplicateShare(submission.party_id));
        }

        let expected = self
            .commitments
            .get(&submission.party_id)
            .ok_or_else(|| MpcError::UnknownCommitment(submission.party_id.clone()))?;
        let received = commitment_for(&submission.share);
        if expected != &received {
            return Err(MpcError::InvalidCommitment(submission.party_id));
        }

        self.shares.insert(submission.party_id, submission.share);
        Ok(())
    }

    /// Return current protocol round.
    pub fn round(&self) -> u32 {
        self.round
    }

    /// Advance protocol round up to max_rounds.
    pub fn advance_round(&mut self) {
        if self.round < self.policy.max_rounds {
            self.round += 1;
        }
    }

    /// Validate coordinator aggregate message for this round.
    pub fn apply_aggregate(&mut self, aggregate: &AggregateMessage) -> Result<(), MpcError> {
        self.ensure_round(aggregate.round)?;
        self.register_nonce(aggregate.nonce)?;

        let local = self.finalize_digest()?;
        if local != aggregate.digest {
            return Err(MpcError::AggregateMismatch);
        }
        Ok(())
    }

    /// Number of currently submitted shares.
    pub fn submitted_shares(&self) -> usize {
        self.shares.len()
    }

    /// Whether enough shares are present for finalization.
    pub fn can_finalize(&self) -> bool {
        self.shares.len() >= self.policy.threshold
    }

    /// Deterministically finalize the session output digest from collected shares.
    pub fn finalize_digest(&self) -> Result<Vec<u8>, MpcError> {
        if !self.can_finalize() {
            return Err(MpcError::InsufficientShares);
        }

        // Hash shares in lexicographic party order for deterministic output.
        let mut parties: Vec<&str> = self
            .shares
            .keys()
            .map(String::as_str)
            .collect();
        parties.sort_unstable();

        let mut hasher = Sha256::new();
        for party in parties {
            hasher.update(party.as_bytes());
            if let Some(share) = self.shares.get(party) {
                hasher.update(share);
            }
        }

        Ok(hasher.finalize().to_vec())
    }

    fn ensure_round(&self, received: u32) -> Result<(), MpcError> {
        if received != self.round {
            return Err(MpcError::RoundMismatch {
                expected: self.round,
                received,
            });
        }
        Ok(())
    }

    fn register_nonce(&mut self, nonce: u64) -> Result<(), MpcError> {
        if self.seen_nonces.contains(&nonce) {
            return Err(MpcError::ReplayDetected(nonce));
        }
        self.seen_nonces.insert(nonce);
        Ok(())
    }
}

fn commitment_for(share: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(share);
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_validation() {
        let p = MpcPolicy::new(3, 2, 4).expect("valid policy should pass");
        assert_eq!(p.total_parties, 3);
        assert_eq!(p.threshold, 2);
        assert_eq!(p.max_rounds, 4);
    }

    #[test]
    fn test_register_and_submit() {
        let policy = MpcPolicy::new(3, 2, 3).expect("policy should pass");
        let mut session = MpcSession::new(policy);

        session.register_party("p1").expect("register p1 should pass");
        session.register_party("p2").expect("register p2 should pass");

        session
            .submit_share(ShareSubmission::new("p1", b"share1".to_vec()))
            .expect("share p1 should pass");
        session
            .submit_share(ShareSubmission::new("p2", b"share2".to_vec()))
            .expect("share p2 should pass");

        assert_eq!(session.submitted_shares(), 2);
        assert!(session.can_finalize());
    }

    #[test]
    fn test_finalize_digest_deterministic() {
        let policy = MpcPolicy::new(3, 2, 3).expect("policy should pass");
        let mut session_a = MpcSession::new(policy.clone());
        let mut session_b = MpcSession::new(policy);

        session_a.register_party("p1").expect("register p1 should pass");
        session_a.register_party("p2").expect("register p2 should pass");
        session_b.register_party("p1").expect("register p1 should pass");
        session_b.register_party("p2").expect("register p2 should pass");

        session_a
            .submit_share(ShareSubmission::new("p1", b"A".to_vec()))
            .expect("share p1 should pass");
        session_a
            .submit_share(ShareSubmission::new("p2", b"B".to_vec()))
            .expect("share p2 should pass");

        session_b
            .submit_share(ShareSubmission::new("p2", b"B".to_vec()))
            .expect("share p2 should pass");
        session_b
            .submit_share(ShareSubmission::new("p1", b"A".to_vec()))
            .expect("share p1 should pass");

        let digest_a = session_a.finalize_digest().expect("finalize should pass");
        let digest_b = session_b.finalize_digest().expect("finalize should pass");
        assert_eq!(digest_a, digest_b);
    }

    #[test]
    fn test_finalize_rejects_insufficient_shares() {
        let policy = MpcPolicy::new(3, 2, 3).expect("policy should pass");
        let mut session = MpcSession::new(policy);
        session.register_party("p1").expect("register p1 should pass");
        session
            .submit_share(ShareSubmission::new("p1", b"share1".to_vec()))
            .expect("share p1 should pass");

        let err = session.finalize_digest().expect_err("finalize should fail");
        match err {
            MpcError::InsufficientShares => {}
            _ => panic!("unexpected error variant"),
        }
    }

    #[test]
    fn test_commit_reveal_and_aggregate_flow() {
        let policy = MpcPolicy::new(3, 2, 3).expect("policy should pass");
        let mut session = MpcSession::new(policy);
        session.register_party("p1").expect("register p1 should pass");
        session.register_party("p2").expect("register p2 should pass");

        let c1 = commitment_for(b"share-a");
        let c2 = commitment_for(b"share-b");

        session
            .submit_commit(CommitSubmission::new("p1", c1, 11, 1))
            .expect("commit p1 should pass");
        session
            .submit_commit(CommitSubmission::new("p2", c2, 12, 1))
            .expect("commit p2 should pass");

        session
            .submit_reveal(RevealSubmission::new("p1", b"share-a".to_vec(), 21, 1))
            .expect("reveal p1 should pass");
        session
            .submit_reveal(RevealSubmission::new("p2", b"share-b".to_vec(), 22, 1))
            .expect("reveal p2 should pass");

        let digest = session.finalize_digest().expect("finalize should pass");
        let aggregate = AggregateMessage::new(1, 31, digest);
        session
            .apply_aggregate(&aggregate)
            .expect("aggregate should pass");
    }

    #[test]
    fn test_replay_nonce_rejected() {
        let policy = MpcPolicy::new(3, 2, 3).expect("policy should pass");
        let mut session = MpcSession::new(policy);
        session.register_party("p1").expect("register p1 should pass");

        let c1 = commitment_for(b"share-a");
        session
            .submit_commit(CommitSubmission::new("p1", c1, 99, 1))
            .expect("first commit should pass");

        let err = session
            .submit_reveal(RevealSubmission::new("p1", b"share-a".to_vec(), 99, 1))
            .expect_err("replay nonce should fail");
        match err {
            MpcError::ReplayDetected(99) => {}
            _ => panic!("unexpected error variant"),
        }
    }
}
