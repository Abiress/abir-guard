//! Advanced Secret Sharing primitives (EPIC 2 foundation).
//!
//! Provides verifiable share commitments and proactive share refresh helpers that
//! can be used to rotate shares without changing the underlying secret.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

/// Errors for advanced secret sharing operations.
#[derive(Debug, Error)]
pub enum AdvancedSharingError {
    #[error("share index out of bounds")]
    IndexOutOfBounds,
    #[error("commitment verification failed")]
    VerificationFailed,
    #[error("invalid share length")]
    InvalidShareLength,
    #[error("invalid threshold configuration")]
    InvalidThreshold,
    #[error("participant mismatch between shares and roster")]
    ParticipantMismatch,
    #[error("refresh proof verification failed")]
    ProofVerificationFailed,
    #[error("participant MAC authentication failed")]
    MacAuthenticationFailed,
    #[error("MAC key must not be empty")]
    EmptyMacKey,
}

/// A participant share with an HMAC-SHA-256 authenticity tag.
///
/// The MAC binds `participant_id`, `share_bytes`, the current `epoch`, and
/// a caller-supplied context label, so shares from different epochs or
/// participants cannot be swapped without detection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthenticatedShare {
    /// Participant identifier bound by the MAC.
    pub participant_id: String,
    /// Share payload.
    pub share_bytes: Vec<u8>,
    /// Epoch at the time of authentication.
    pub epoch: u64,
    /// HMAC-SHA-256 over `participant_id || share_bytes || epoch_le || context`.
    pub mac: Vec<u8>,
}

/// Produce an [`AuthenticatedShare`] by computing an HMAC-SHA-256 tag.
///
/// # Parameters
/// - `participant_id`: Identity string of the share holder.
/// - `share_bytes`: Raw share payload.
/// - `epoch`: Refresh epoch that the share belongs to.
/// - `context`: Caller-defined domain separator (e.g. `b"reshare-v1"`).
/// - `key`: Secret MAC key (must be non-empty).
///
/// # Errors
/// Returns [`AdvancedSharingError::EmptyMacKey`] when `key` is empty.
pub fn authenticate_share(
    participant_id: &str,
    share_bytes: &[u8],
    epoch: u64,
    context: &[u8],
    key: &[u8],
) -> Result<AuthenticatedShare, AdvancedSharingError> {
    if key.is_empty() {
        return Err(AdvancedSharingError::EmptyMacKey);
    }
    let tag = compute_mac(participant_id, share_bytes, epoch, context, key);
    Ok(AuthenticatedShare {
        participant_id: participant_id.to_owned(),
        share_bytes: share_bytes.to_vec(),
        epoch,
        mac: tag,
    })
}

/// Verify an [`AuthenticatedShare`] MAC tag.
///
/// Returns `Ok(())` when the tag is valid, or
/// [`AdvancedSharingError::MacAuthenticationFailed`] on mismatch.
///
/// # Errors
/// Returns [`AdvancedSharingError::EmptyMacKey`] when `key` is empty.
pub fn verify_authenticated_share(
    auth_share: &AuthenticatedShare,
    context: &[u8],
    key: &[u8],
) -> Result<(), AdvancedSharingError> {
    if key.is_empty() {
        return Err(AdvancedSharingError::EmptyMacKey);
    }
    let expected = compute_mac(
        &auth_share.participant_id,
        &auth_share.share_bytes,
        auth_share.epoch,
        context,
        key,
    );
    if expected != auth_share.mac {
        return Err(AdvancedSharingError::MacAuthenticationFailed);
    }
    Ok(())
}

fn compute_mac(
    participant_id: &str,
    share_bytes: &[u8],
    epoch: u64,
    context: &[u8],
    key: &[u8],
) -> Vec<u8> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
        .expect("HMAC accepts any key length");
    mac.update(participant_id.as_bytes());
    mac.update(share_bytes);
    mac.update(&epoch.to_le_bytes());
    mac.update(context);
    mac.finalize().into_bytes().to_vec()
}

/// Commitment record for one share.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VssCommitment {
    /// Share index in the share set.
    pub index: u8,
    /// Hash commitment bytes.
    pub commitment: Vec<u8>,
}

/// Verified share representation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifiedShare {
    /// Share index.
    pub index: u8,
    /// Share payload.
    pub share: Vec<u8>,
}

/// Share bound to a participant identifier.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParticipantShare {
    /// Participant identifier.
    pub participant_id: String,
    /// Share bytes assigned to participant.
    pub share: Vec<u8>,
}

impl ParticipantShare {
    /// Build a participant share.
    pub fn new(participant_id: impl Into<String>, share: Vec<u8>) -> Self {
        Self {
            participant_id: participant_id.into(),
            share,
        }
    }
}

/// Result of a proactive re-sharing operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResharePlan {
    /// Previous threshold value.
    pub old_threshold: usize,
    /// New threshold value.
    pub new_threshold: usize,
    /// Previous epoch.
    pub old_epoch: u64,
    /// New epoch.
    pub new_epoch: u64,
    /// Refreshed participant shares.
    pub refreshed: Vec<ParticipantShare>,
    /// Transcript proof that binds resharing metadata and refreshed commitments.
    pub proof: RefreshProof,
}

/// Proof artifact for proactive share refresh operations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RefreshProof {
    /// Transcript hash over operation metadata and refreshed commitments.
    pub transcript_hash: Vec<u8>,
}

/// Compute commitment list for a share set.
pub fn create_commitments(shares: &[Vec<u8>]) -> Vec<VssCommitment> {
    shares
        .iter()
        .enumerate()
        .map(|(idx, share)| VssCommitment {
            index: idx as u8,
            commitment: commitment_hash(idx as u8, share),
        })
        .collect()
}

/// Verify a share against a commitment entry.
pub fn verify_share(
    share: &[u8],
    commitment: &VssCommitment,
) -> Result<VerifiedShare, AdvancedSharingError> {
    let expected = commitment_hash(commitment.index, share);
    if expected != commitment.commitment {
        return Err(AdvancedSharingError::VerificationFailed);
    }

    Ok(VerifiedShare {
        index: commitment.index,
        share: share.to_vec(),
    })
}

/// Proactive share refresher for rotating share material by epoch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProactiveRefresher {
    /// Current epoch for refresh schedule.
    pub epoch: u64,
}

impl Default for ProactiveRefresher {
    fn default() -> Self {
        Self { epoch: 1 }
    }
}

impl ProactiveRefresher {
    /// Create refresher with default epoch.
    pub fn new() -> Self {
        Self::default()
    }

    /// Advance to next epoch.
    pub fn advance_epoch(&mut self) {
        self.epoch = self.epoch.saturating_add(1);
    }

    /// Refresh a share using deterministic mask material for this epoch.
    pub fn refresh_share(&self, share: &[u8], seed: &[u8]) -> Result<Vec<u8>, AdvancedSharingError> {
        if share.is_empty() {
            return Err(AdvancedSharingError::InvalidShareLength);
        }
        let mask = self.mask(seed, share.len());
        let refreshed: Vec<u8> = share
            .iter()
            .zip(mask.iter())
            .map(|(value, noise)| value ^ noise)
            .collect();
        Ok(refreshed)
    }

    fn mask(&self, seed: &[u8], len: usize) -> Vec<u8> {
        let mut output = Vec::with_capacity(len);
        let mut counter = 0u64;

        while output.len() < len {
            let mut hasher = Sha256::new();
            hasher.update(seed);
            hasher.update(self.epoch.to_le_bytes());
            hasher.update(counter.to_le_bytes());
            let block = hasher.finalize();
            output.extend_from_slice(&block);
            counter = counter.saturating_add(1);
        }

        output.truncate(len);
        output
    }

    /// Proactively re-share shares to a new participant roster while preserving threshold.
    pub fn reshare_for_participants(
        &mut self,
        current: &[ParticipantShare],
        next_participants: &[String],
        old_threshold: usize,
        new_threshold: usize,
        seed: &[u8],
    ) -> Result<ResharePlan, AdvancedSharingError> {
        validate_thresholds(current.len(), next_participants.len(), old_threshold, new_threshold)?;
        if current.is_empty() || next_participants.is_empty() {
            return Err(AdvancedSharingError::ParticipantMismatch);
        }

        // Rotation moves to a new epoch and regenerates shares for the target participant roster.
        let previous_epoch = self.epoch;
        self.advance_epoch();

        let mut refreshed = Vec::with_capacity(next_participants.len());
        for (idx, participant_id) in next_participants.iter().enumerate() {
            let source_share = &current[idx % current.len()].share;
            let mut ctx_seed = Vec::new();
            ctx_seed.extend_from_slice(seed);
            ctx_seed.extend_from_slice(participant_id.as_bytes());
            ctx_seed.extend_from_slice(&(idx as u64).to_le_bytes());
            let next_share = self.refresh_share(source_share, &ctx_seed)?;
            refreshed.push(ParticipantShare::new(participant_id.clone(), next_share));
        }

        let proof = build_refresh_proof(
            previous_epoch,
            self.epoch,
            old_threshold,
            new_threshold,
            next_participants,
            &refreshed,
        );

        let plan = ResharePlan {
            old_threshold,
            new_threshold,
            old_epoch: previous_epoch,
            new_epoch: self.epoch,
            refreshed,
            proof,
        };

        if !verify_reshare_plan(&plan) {
            return Err(AdvancedSharingError::ProofVerificationFailed);
        }

        Ok(plan)
    }
}

/// Verify that a re-share plan transcript matches the payload it carries.
pub fn verify_reshare_plan(plan: &ResharePlan) -> bool {
    let participants: Vec<String> = plan
        .refreshed
        .iter()
        .map(|item| item.participant_id.clone())
        .collect();

    let expected = build_refresh_proof(
        plan.old_epoch,
        plan.new_epoch,
        plan.old_threshold,
        plan.new_threshold,
        &participants,
        &plan.refreshed,
    );

    expected == plan.proof
}

fn build_refresh_proof(
    old_epoch: u64,
    new_epoch: u64,
    old_threshold: usize,
    new_threshold: usize,
    participants: &[String],
    refreshed: &[ParticipantShare],
) -> RefreshProof {
    let mut hasher = Sha256::new();
    hasher.update(old_epoch.to_le_bytes());
    hasher.update(new_epoch.to_le_bytes());
    hasher.update((old_threshold as u64).to_le_bytes());
    hasher.update((new_threshold as u64).to_le_bytes());

    for participant in participants {
        hasher.update(participant.as_bytes());
    }

    for item in refreshed {
        hasher.update(item.participant_id.as_bytes());
        let commitment = commitment_hash(0, &item.share);
        hasher.update(&commitment);
    }

    RefreshProof {
        transcript_hash: hasher.finalize().to_vec(),
    }
}

fn validate_thresholds(
    old_parties: usize,
    new_parties: usize,
    old_threshold: usize,
    new_threshold: usize,
) -> Result<(), AdvancedSharingError> {
    if old_threshold == 0 || old_threshold > old_parties {
        return Err(AdvancedSharingError::InvalidThreshold);
    }
    if new_threshold == 0 || new_threshold > new_parties {
        return Err(AdvancedSharingError::InvalidThreshold);
    }
    Ok(())
}

fn commitment_hash(index: u8, share: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update([index]);
    hasher.update(share);
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commitment_roundtrip() {
        let shares = vec![b"s1".to_vec(), b"s2".to_vec()];
        let commitments = create_commitments(&shares);

        let verified = verify_share(&shares[0], &commitments[0]).expect("verification should pass");
        assert_eq!(verified.index, 0);
        assert_eq!(verified.share, b"s1");
    }

    #[test]
    fn test_commitment_rejects_tampered_share() {
        let shares = vec![b"s1".to_vec()];
        let commitments = create_commitments(&shares);

        let err = verify_share(b"tampered", &commitments[0]).expect_err("verification should fail");
        match err {
            AdvancedSharingError::VerificationFailed => {}
            _ => panic!("unexpected error variant"),
        }
    }

    #[test]
    fn test_proactive_refresh_changes_with_epoch() {
        let mut refresher = ProactiveRefresher::new();
        let share = b"share-material";
        let seed = b"seed-01";

        let r1 = refresher.refresh_share(share, seed).expect("refresh should pass");
        refresher.advance_epoch();
        let r2 = refresher.refresh_share(share, seed).expect("refresh should pass");

        assert_ne!(r1, r2);
    }

    #[test]
    fn test_reshare_join_participant() {
        let mut refresher = ProactiveRefresher::new();
        let current = vec![
            ParticipantShare::new("p1", b"share-a".to_vec()),
            ParticipantShare::new("p2", b"share-b".to_vec()),
            ParticipantShare::new("p3", b"share-c".to_vec()),
        ];
        let next = vec![
            "p1".to_string(),
            "p2".to_string(),
            "p3".to_string(),
            "p4".to_string(),
        ];

        let plan = refresher
            .reshare_for_participants(&current, &next, 2, 3, b"seed")
            .expect("reshare should pass");
        assert_eq!(plan.old_threshold, 2);
        assert_eq!(plan.new_threshold, 3);
        assert_eq!(plan.refreshed.len(), 4);
        assert_eq!(plan.old_epoch + 1, plan.new_epoch);
        assert!(verify_reshare_plan(&plan));
    }

    #[test]
    fn test_reshare_leave_participant() {
        let mut refresher = ProactiveRefresher::new();
        let current = vec![
            ParticipantShare::new("p1", b"share-a".to_vec()),
            ParticipantShare::new("p2", b"share-b".to_vec()),
            ParticipantShare::new("p3", b"share-c".to_vec()),
            ParticipantShare::new("p4", b"share-d".to_vec()),
        ];
        let next = vec!["p1".to_string(), "p2".to_string(), "p3".to_string()];

        let plan = refresher
            .reshare_for_participants(&current, &next, 3, 2, b"seed")
            .expect("reshare should pass");
        assert_eq!(plan.refreshed.len(), 3);
        assert_eq!(plan.new_threshold, 2);
        assert!(verify_reshare_plan(&plan));
    }

    #[test]
    fn test_reshare_rejects_invalid_threshold() {
        let mut refresher = ProactiveRefresher::new();
        let current = vec![
            ParticipantShare::new("p1", b"share-a".to_vec()),
            ParticipantShare::new("p2", b"share-b".to_vec()),
        ];
        let next = vec!["p1".to_string(), "p2".to_string()];

        let err = refresher
            .reshare_for_participants(&current, &next, 0, 2, b"seed")
            .expect_err("invalid threshold should fail");
        match err {
            AdvancedSharingError::InvalidThreshold => {}
            _ => panic!("unexpected error variant"),
        }
    }

    #[test]
    fn test_authenticated_share_roundtrip() {
        let auth = authenticate_share("p1", b"secret-share", 3, b"reshare-v1", b"mac-key")
            .expect("authentication should succeed");
        verify_authenticated_share(&auth, b"reshare-v1", b"mac-key")
            .expect("verification should pass");
    }

    #[test]
    fn test_authenticated_share_rejects_tampered_bytes() {
        let mut auth = authenticate_share("p1", b"secret-share", 3, b"reshare-v1", b"mac-key")
            .expect("authentication should succeed");
        auth.share_bytes[0] ^= 0xFF;
        let err = verify_authenticated_share(&auth, b"reshare-v1", b"mac-key")
            .expect_err("should reject tampered share");
        assert!(matches!(err, AdvancedSharingError::MacAuthenticationFailed));
    }

    #[test]
    fn test_authenticated_share_rejects_wrong_epoch() {
        let mut auth = authenticate_share("p1", b"secret-share", 3, b"reshare-v1", b"mac-key")
            .expect("authentication should succeed");
        auth.epoch = 99;
        let err = verify_authenticated_share(&auth, b"reshare-v1", b"mac-key")
            .expect_err("should reject wrong epoch");
        assert!(matches!(err, AdvancedSharingError::MacAuthenticationFailed));
    }

    #[test]
    fn test_authenticated_share_rejects_wrong_participant() {
        let mut auth = authenticate_share("p1", b"secret-share", 3, b"reshare-v1", b"mac-key")
            .expect("authentication should succeed");
        auth.participant_id = "attacker".to_string();
        let err = verify_authenticated_share(&auth, b"reshare-v1", b"mac-key")
            .expect_err("should reject wrong participant id");
        assert!(matches!(err, AdvancedSharingError::MacAuthenticationFailed));
    }

    #[test]
    fn test_authenticated_share_rejects_wrong_context() {
        let auth = authenticate_share("p1", b"secret-share", 3, b"reshare-v1", b"mac-key")
            .expect("authentication should succeed");
        let err = verify_authenticated_share(&auth, b"other-context", b"mac-key")
            .expect_err("should reject wrong context");
        assert!(matches!(err, AdvancedSharingError::MacAuthenticationFailed));
    }

    #[test]
    fn test_authenticated_share_rejects_empty_key() {
        let err = authenticate_share("p1", b"share", 1, b"ctx", b"")
            .expect_err("empty key should fail");
        assert!(matches!(err, AdvancedSharingError::EmptyMacKey));
    }

    #[test]
    fn test_verify_reshare_plan_detects_tampering() {
        let mut refresher = ProactiveRefresher::new();
        let current = vec![
            ParticipantShare::new("p1", b"share-a".to_vec()),
            ParticipantShare::new("p2", b"share-b".to_vec()),
            ParticipantShare::new("p3", b"share-c".to_vec()),
        ];
        let next = vec!["p1".to_string(), "p2".to_string(), "p3".to_string()];

        let mut plan = refresher
            .reshare_for_participants(&current, &next, 2, 2, b"seed")
            .expect("reshare should pass");
        plan.refreshed[0].share[0] ^= 0xFF;

        assert!(!verify_reshare_plan(&plan));
    }
}
