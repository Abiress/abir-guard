//! Attestation-as-a-Service facade.
//!
//! Normalizes attestation verification outputs for different TEE providers so
//! higher-level services can enforce one policy model.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::confidential_computing::sgx::{
    verify_quote_standard, Quote, QuoteVerificationResult,
};
use crate::confidential_computing::trustzone::{
    TrustZoneAttestationPolicy, TrustZoneAttestationVerifier, TrustZoneVerificationResult,
};
use crate::confidential_computing::tee_common::{TeeAttestationReport, TeeType};

/// AaaS verification errors.
#[derive(Debug, Error)]
pub enum AttestationServiceError {
    #[error("sgx verification failed: {0}")]
    SgxVerification(String),
    #[error("trustzone verification failed: {0}")]
    TrustZoneVerification(String),
    #[error("unsupported tee type for report: {0:?}")]
    UnsupportedTee(TeeType),
    #[error("policy rejected attestation: {0}")]
    PolicyRejected(String),
}

/// Relative trust class assigned to attestation evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustLevel {
    Low,
    Medium,
    High,
}

impl TrustLevel {
    fn rank(self) -> u8 {
        match self {
            TrustLevel::Low => 1,
            TrustLevel::Medium => 2,
            TrustLevel::High => 3,
        }
    }

    fn meets_minimum(self, minimum: TrustLevel) -> bool {
        self.rank() >= minimum.rank()
    }
}

/// Policy controls for service-level routing and verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationRoutingPolicy {
    /// Which TEE providers can pass verification.
    pub allowed_tees: HashSet<TeeType>,
    /// Maximum accepted SGX evidence age in seconds.
    pub max_sgx_age_seconds: u64,
    /// Maximum accepted TrustZone evidence age in seconds.
    pub max_trustzone_age_seconds: u64,
    /// Minimum accepted trust class.
    pub minimum_trust_level: TrustLevel,
}

impl Default for AttestationRoutingPolicy {
    fn default() -> Self {
        let mut allowed_tees = HashSet::new();
        allowed_tees.insert(TeeType::SGX);
        allowed_tees.insert(TeeType::TrustZone);

        Self {
            allowed_tees,
            max_sgx_age_seconds: 3600,
            max_trustzone_age_seconds: 300,
            minimum_trust_level: TrustLevel::Low,
        }
    }
}

/// Batch verification output.
#[derive(Debug)]
pub struct BatchVerificationResult {
    /// Results in input order.
    pub items: Vec<Result<UnifiedAttestationResult, AttestationServiceError>>,
    /// Number of successful items.
    pub passed: usize,
    /// Number of failed items.
    pub failed: usize,
}

/// Unified attestation verdict used by service consumers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedAttestationResult {
    /// Which TEE generated the evidence.
    pub tee_type: TeeType,
    /// Final allow/deny status.
    pub is_valid: bool,
    /// Whether evidence freshness checks passed.
    pub is_fresh: bool,
    /// Age in seconds.
    pub evidence_age_seconds: u64,
    /// Calculated trust classification.
    pub trust_level: TrustLevel,
    /// Short human-readable summary.
    pub summary: String,
}

impl From<QuoteVerificationResult> for UnifiedAttestationResult {
    fn from(value: QuoteVerificationResult) -> Self {
        Self {
            tee_type: TeeType::SGX,
            is_valid: value.is_valid,
            is_fresh: value.is_fresh,
            evidence_age_seconds: value.quote_age_seconds,
            trust_level: if value.signature_valid && value.cert_chain_valid && value.advisories.is_empty() {
                TrustLevel::High
            } else if value.signature_valid && value.cert_chain_valid {
                TrustLevel::Medium
            } else {
                TrustLevel::Low
            },
            summary: format!(
                "sgx: signature_valid={}, cert_chain_valid={}, advisories={}",
                value.signature_valid,
                value.cert_chain_valid,
                value.advisories.len()
            ),
        }
    }
}

impl From<TrustZoneVerificationResult> for UnifiedAttestationResult {
    fn from(value: TrustZoneVerificationResult) -> Self {
        Self {
            tee_type: TeeType::TrustZone,
            is_valid: value.is_valid,
            is_fresh: value.is_fresh,
            evidence_age_seconds: value.report_age_seconds,
            trust_level: if value.is_valid {
                TrustLevel::Medium
            } else {
                TrustLevel::Low
            },
            summary: format!(
                "trustzone: expected_format={}",
                value.has_expected_format
            ),
        }
    }
}

/// Attestation service entry point.
#[derive(Debug, Clone, Default)]
pub struct AttestationService {
    tz_policy: TrustZoneAttestationPolicy,
    routing_policy: AttestationRoutingPolicy,
}

impl AttestationService {
    /// Create service with default policy set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create service with custom TrustZone policy.
    pub fn with_trustzone_policy(tz_policy: TrustZoneAttestationPolicy) -> Self {
        Self {
            tz_policy,
            routing_policy: AttestationRoutingPolicy::default(),
        }
    }

    /// Create service with explicit routing policy.
    pub fn with_routing_policy(routing_policy: AttestationRoutingPolicy) -> Self {
        Self {
            tz_policy: TrustZoneAttestationPolicy::default(),
            routing_policy,
        }
    }

    /// Verify SGX quote and return normalized result.
    pub fn verify_sgx_quote(
        &self,
        quote: &Quote,
    ) -> Result<UnifiedAttestationResult, AttestationServiceError> {
        let result = verify_quote_standard(quote)
            .map_err(|e| AttestationServiceError::SgxVerification(e.to_string()))?;
        self.enforce_policy(result.into())
    }

    /// Verify TrustZone report and return normalized result.
    pub fn verify_trustzone_report(
        &self,
        report: &TeeAttestationReport,
    ) -> Result<UnifiedAttestationResult, AttestationServiceError> {
        let verifier = TrustZoneAttestationVerifier::new(self.tz_policy.clone());
        let result = verifier
            .verify(report)
            .map_err(|e| AttestationServiceError::TrustZoneVerification(e.to_string()))?;
        self.enforce_policy(result.into())
    }

    /// Verify generic report based on declared tee type.
    pub fn verify_report(
        &self,
        report: &TeeAttestationReport,
    ) -> Result<UnifiedAttestationResult, AttestationServiceError> {
        match report.tee_type {
            TeeType::TrustZone => self.verify_trustzone_report(report),
            other => Err(AttestationServiceError::UnsupportedTee(other)),
        }
    }

    /// Verify a batch of TrustZone reports.
    pub fn verify_reports_batch(&self, reports: &[TeeAttestationReport]) -> BatchVerificationResult {
        let items: Vec<Result<UnifiedAttestationResult, AttestationServiceError>> = reports
            .iter()
            .map(|report| self.verify_report(report))
            .collect();

        let passed = items.iter().filter(|item| item.is_ok()).count();
        let failed = items.len().saturating_sub(passed);

        BatchVerificationResult {
            items,
            passed,
            failed,
        }
    }

    /// Verify a batch of SGX quotes.
    pub fn verify_sgx_quotes_batch(&self, quotes: &[Quote]) -> BatchVerificationResult {
        let items: Vec<Result<UnifiedAttestationResult, AttestationServiceError>> = quotes
            .iter()
            .map(|quote| self.verify_sgx_quote(quote))
            .collect();

        let passed = items.iter().filter(|item| item.is_ok()).count();
        let failed = items.len().saturating_sub(passed);

        BatchVerificationResult {
            items,
            passed,
            failed,
        }
    }

    fn enforce_policy(
        &self,
        mut result: UnifiedAttestationResult,
    ) -> Result<UnifiedAttestationResult, AttestationServiceError> {
        if !self.routing_policy.allowed_tees.contains(&result.tee_type) {
            return Err(AttestationServiceError::PolicyRejected(format!(
                "tee type {:?} is not allowed by routing policy",
                result.tee_type
            )));
        }

        let max_age = match result.tee_type {
            TeeType::SGX => self.routing_policy.max_sgx_age_seconds,
            TeeType::TrustZone => self.routing_policy.max_trustzone_age_seconds,
            _ => {
                return Err(AttestationServiceError::PolicyRejected(format!(
                    "tee type {:?} has no configured age SLA",
                    result.tee_type
                )))
            }
        };

        if result.evidence_age_seconds > max_age {
            return Err(AttestationServiceError::PolicyRejected(format!(
                "evidence age {}s exceeds SLA {}s for {:?}",
                result.evidence_age_seconds, max_age, result.tee_type
            )));
        }

        if !result
            .trust_level
            .meets_minimum(self.routing_policy.minimum_trust_level)
        {
            return Err(AttestationServiceError::PolicyRejected(format!(
                "trust level {:?} below minimum {:?}",
                result.trust_level, self.routing_policy.minimum_trust_level
            )));
        }

        if !result.is_valid || !result.is_fresh {
            return Err(AttestationServiceError::PolicyRejected(
                "provider verification did not return valid/fresh evidence".to_string(),
            ));
        }

        result.summary = format!("{}; policy=enforced", result.summary);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::confidential_computing::sgx::{AttestationConfig, Enclave};
    use crate::confidential_computing::trustzone::build_simulated_report;

    #[test]
    fn test_unified_from_sgx() {
        let enclave = match Enclave::initialize(AttestationConfig::dcap()) {
            Ok(enclave) => enclave,
            Err(_) => return,
        };
        let quote = enclave.get_quote().expect("quote should pass");

        let service = AttestationService::new();
        let result = service
            .verify_sgx_quote(&quote)
            .expect("sgx verification should pass");
        assert_eq!(result.tee_type, TeeType::SGX);
        assert_eq!(result.trust_level, TrustLevel::High);
    }

    #[test]
    fn test_unified_from_trustzone() {
        let service = AttestationService::new();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time should be valid")
            .as_secs();
        let report = build_simulated_report(now);

        let result = service
            .verify_trustzone_report(&report)
            .expect("trustzone verification should pass");
        assert_eq!(result.tee_type, TeeType::TrustZone);
        assert!(result.is_valid);
        assert_eq!(result.trust_level, TrustLevel::Medium);
    }

    #[test]
    fn test_verify_report_rejects_unsupported_tee() {
        let service = AttestationService::new();
        let report = TeeAttestationReport {
            tee_type: TeeType::SGX,
            attestation_data: vec![],
            timestamp: 0,
        };

        let err = service
            .verify_report(&report)
            .expect_err("unsupported report should fail");
        match err {
            AttestationServiceError::UnsupportedTee(TeeType::SGX) => {}
            _ => panic!("unexpected error variant"),
        }
    }

    #[test]
    fn test_routing_policy_blocks_disallowed_tee() {
        let mut policy = AttestationRoutingPolicy::default();
        policy.allowed_tees.clear();
        policy.allowed_tees.insert(TeeType::TrustZone);

        let service = AttestationService::with_routing_policy(policy);
        let enclave = match Enclave::initialize(AttestationConfig::dcap()) {
            Ok(enclave) => enclave,
            Err(_) => return,
        };
        let quote = enclave.get_quote().expect("quote should pass");

        let err = service
            .verify_sgx_quote(&quote)
            .expect_err("sgx should be denied by policy");
        match err {
            AttestationServiceError::PolicyRejected(msg) => {
                assert!(msg.contains("not allowed"));
            }
            _ => panic!("unexpected error variant"),
        }
    }

    #[test]
    fn test_routing_policy_enforces_age_sla() {
        let policy = AttestationRoutingPolicy {
            max_trustzone_age_seconds: 1,
            ..AttestationRoutingPolicy::default()
        };
        let service = AttestationService::with_routing_policy(policy);

        let report = build_simulated_report(0);
        let err = service
            .verify_trustzone_report(&report)
            .expect_err("stale report should be rejected");
        match err {
            AttestationServiceError::PolicyRejected(msg) => {
                assert!(msg.contains("exceeds SLA"));
            }
            _ => panic!("unexpected error variant"),
        }
    }

    #[test]
    fn test_batch_verification_mixed_reports() {
        let service = AttestationService::new();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time should be valid")
            .as_secs();

        let good = build_simulated_report(now);
        let bad = TeeAttestationReport {
            tee_type: TeeType::SGX,
            attestation_data: vec![],
            timestamp: now,
        };

        let batch = service.verify_reports_batch(&[good, bad]);
        assert_eq!(batch.passed, 1);
        assert_eq!(batch.failed, 1);
        assert_eq!(batch.items.len(), 2);
    }
}
