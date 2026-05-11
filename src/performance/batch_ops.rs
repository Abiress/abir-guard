//! Batch cryptographic operations for ML-DSA sign and verify.
//!
//! Processing many messages individually incurs per-call overhead (key
//! deserialization, allocations).  The batch helpers here amortize that cost by
//! accepting a slice of requests and returning aggregate result types that
//! capture per-item success/failure without panicking on the first error.

use crate::ml_dsa::{sign, verify, MldsaError};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors for batch operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BatchOpsError {
    #[error("batch input must not be empty")]
    EmptyBatch,
    #[error("ML-DSA error: {0}")]
    MldsaError(String),
}

impl From<MldsaError> for BatchOpsError {
    fn from(e: MldsaError) -> Self {
        BatchOpsError::MldsaError(e.to_string())
    }
}

/// A single ML-DSA verification request.
#[derive(Debug, Clone)]
pub struct VerifyRequest {
    /// Message whose signature is to be verified.
    pub message: Vec<u8>,
    /// Detached signature bytes.
    pub signature: Vec<u8>,
    /// Verifying (public) key bytes.
    pub verifying_key: Vec<u8>,
}

/// Aggregate result of a [`batch_verify`] call.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BatchVerifyResult {
    /// Total number of requests processed.
    pub total: usize,
    /// Number of requests that passed verification.
    pub passed: usize,
    /// Number of requests that failed verification (bad sig, key error, etc.).
    pub failed: usize,
    /// Per-item outcome: `true` = valid, `false` = invalid/error.
    pub results: Vec<bool>,
}

impl BatchVerifyResult {
    /// Returns `true` when every item passed verification.
    pub fn all_passed(&self) -> bool {
        self.failed == 0
    }
}

/// A single ML-DSA signing request.
#[derive(Debug, Clone)]
pub struct SignRequest {
    /// Message to sign.
    pub message: Vec<u8>,
    /// Signing (secret) key bytes.
    pub signing_key: Vec<u8>,
}

/// Aggregate result of a [`batch_sign`] call.
#[derive(Debug, Clone)]
pub struct BatchSignResult {
    /// Total number of requests processed.
    pub total: usize,
    /// Number of successful signatures.
    pub succeeded: usize,
    /// Number of failed signing operations.
    pub failed: usize,
    /// Per-item signature bytes, or `None` on failure.
    pub signatures: Vec<Option<Vec<u8>>>,
}

impl BatchSignResult {
    /// Returns `true` when every item was signed successfully.
    pub fn all_succeeded(&self) -> bool {
        self.failed == 0
    }
}

/// Verify a batch of ML-DSA signatures.
///
/// Each request is processed independently; a single bad signature does **not**
/// abort the batch.  The [`BatchVerifyResult`] captures per-item outcomes.
///
/// # Errors
/// Returns [`BatchOpsError::EmptyBatch`] when `requests` is empty.
pub fn batch_verify(requests: &[VerifyRequest]) -> Result<BatchVerifyResult, BatchOpsError> {
    if requests.is_empty() {
        return Err(BatchOpsError::EmptyBatch);
    }

    let results: Vec<bool> = requests
        .iter()
        .map(|req| {
            verify(&req.message, &req.signature, &req.verifying_key)
                .unwrap_or(false)
        })
        .collect();

    let passed = results.iter().filter(|&&v| v).count();
    let total = results.len();
    Ok(BatchVerifyResult {
        total,
        passed,
        failed: total - passed,
        results,
    })
}

/// Sign a batch of messages with (potentially distinct) ML-DSA signing keys.
///
/// Each request is processed independently; a failure on one item is captured as
/// `None` in the output rather than aborting the batch.
///
/// # Errors
/// Returns [`BatchOpsError::EmptyBatch`] when `requests` is empty.
pub fn batch_sign(requests: &[SignRequest]) -> Result<BatchSignResult, BatchOpsError> {
    if requests.is_empty() {
        return Err(BatchOpsError::EmptyBatch);
    }

    let signatures: Vec<Option<Vec<u8>>> = requests
        .iter()
        .map(|req| sign(&req.message, &req.signing_key).ok())
        .collect();

    let succeeded = signatures.iter().filter(|s| s.is_some()).count();
    let total = signatures.len();
    Ok(BatchSignResult {
        total,
        succeeded,
        failed: total - succeeded,
        signatures,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ml_dsa::generate_keypair;

    fn make_req(message: &[u8]) -> (SignRequest, VerifyRequest) {
        let kp = generate_keypair().expect("keygen");
        let sig = sign(message, &kp.signing_key).expect("sign");
        (
            SignRequest {
                message: message.to_vec(),
                signing_key: kp.signing_key.clone(),
            },
            VerifyRequest {
                message: message.to_vec(),
                signature: sig,
                verifying_key: kp.verifying_key.clone(),
            },
        )
    }

    #[test]
    fn test_batch_verify_all_pass() {
        let (_, v1) = make_req(b"msg-1");
        let (_, v2) = make_req(b"msg-2");
        let result = batch_verify(&[v1, v2]).expect("batch verify");
        assert!(result.all_passed());
        assert_eq!(result.total, 2);
        assert_eq!(result.passed, 2);
    }

    #[test]
    fn test_batch_verify_detects_bad_signature() {
        let (_, mut v1) = make_req(b"msg-a");
        v1.signature[0] ^= 0xFF; // corrupt
        let (_, v2) = make_req(b"msg-b");
        let result = batch_verify(&[v1, v2]).expect("batch verify");
        assert!(!result.all_passed());
        assert_eq!(result.failed, 1);
        assert_eq!(result.passed, 1);
        assert!(!result.results[0]);
        assert!(result.results[1]);
    }

    #[test]
    fn test_batch_verify_bad_key_counted_as_failure() {
        let (_, mut v) = make_req(b"msg");
        v.verifying_key = b"not-a-real-key".to_vec();
        let result = batch_verify(&[v]).expect("batch verify");
        assert_eq!(result.failed, 1);
    }

    #[test]
    fn test_batch_verify_empty_rejects() {
        let err = batch_verify(&[]).expect_err("empty batch");
        assert_eq!(err, BatchOpsError::EmptyBatch);
    }

    #[test]
    fn test_batch_sign_all_succeed() {
        let (s1, _) = make_req(b"alpha");
        let (s2, _) = make_req(b"beta");
        let result = batch_sign(&[s1, s2]).expect("batch sign");
        assert!(result.all_succeeded());
        assert_eq!(result.total, 2);
        assert!(result.signatures.iter().all(|s| s.is_some()));
    }

    #[test]
    fn test_batch_sign_bad_key_captured_as_none() {
        let req = SignRequest {
            message: b"msg".to_vec(),
            signing_key: b"bad-key".to_vec(),
        };
        let result = batch_sign(&[req]).expect("batch sign");
        assert_eq!(result.failed, 1);
        assert!(result.signatures[0].is_none());
    }

    #[test]
    fn test_batch_sign_empty_rejects() {
        let err = batch_sign(&[]).expect_err("empty batch");
        assert_eq!(err, BatchOpsError::EmptyBatch);
    }

    #[test]
    fn test_batch_sign_then_verify_roundtrip() {
        let kp = generate_keypair().expect("keygen");
        let messages: Vec<Vec<u8>> = vec![b"one".to_vec(), b"two".to_vec(), b"three".to_vec()];
        let sign_requests: Vec<SignRequest> = messages
            .iter()
            .map(|m| SignRequest {
                message: m.clone(),
                signing_key: kp.signing_key.clone(),
            })
            .collect();

        let sign_result = batch_sign(&sign_requests).expect("batch sign");
        assert!(sign_result.all_succeeded());

        let verify_requests: Vec<VerifyRequest> = messages
            .iter()
            .zip(sign_result.signatures.iter())
            .map(|(msg, sig)| VerifyRequest {
                message: msg.clone(),
                signature: sig.as_ref().unwrap().clone(),
                verifying_key: kp.verifying_key.clone(),
            })
            .collect();

        let verify_result = batch_verify(&verify_requests).expect("batch verify");
        assert!(verify_result.all_passed());
    }
}
