//! TrustZone attestation policy and verifier model.

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::confidential_computing::tee_common::{TeeAttestationReport, TeeType};

use super::TrustZoneError;

/// TrustZone attestation validation policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustZoneAttestationPolicy {
    /// Maximum accepted age in seconds.
    pub max_age_seconds: u64,
    /// Require report format marker in payload.
    pub require_format_marker: bool,
}

impl Default for TrustZoneAttestationPolicy {
    fn default() -> Self {
        Self {
            max_age_seconds: 300,
            require_format_marker: true,
        }
    }
}

/// Attestation verification output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustZoneVerificationResult {
    /// Final verdict.
    pub is_valid: bool,
    /// Whether report freshness is acceptable.
    pub is_fresh: bool,
    /// Whether payload appears to match expected format.
    pub has_expected_format: bool,
    /// Age in seconds.
    pub report_age_seconds: u64,
    /// Validation timestamp.
    pub verified_at: u64,
}

/// Verifier for TrustZone attestation reports.
pub struct TrustZoneAttestationVerifier {
    policy: TrustZoneAttestationPolicy,
}

impl TrustZoneAttestationVerifier {
    /// Create verifier with policy.
    pub fn new(policy: TrustZoneAttestationPolicy) -> Self {
        Self { policy }
    }

    /// Validate trustzone attestation report.
    pub fn verify(
        &self,
        report: &TeeAttestationReport,
    ) -> Result<TrustZoneVerificationResult, TrustZoneError> {
        if report.tee_type != TeeType::TrustZone {
            return Err(TrustZoneError::AttestationFailed(
                "report tee type is not TrustZone".to_string(),
            ));
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let age = now.saturating_sub(report.timestamp);
        let is_fresh = age <= self.policy.max_age_seconds;

        let has_expected_format = if self.policy.require_format_marker {
            report
                .attestation_data
                .starts_with(b"TZ-ATTEST")
        } else {
            true
        };

        Ok(TrustZoneVerificationResult {
            is_valid: is_fresh && has_expected_format,
            is_fresh,
            has_expected_format,
            report_age_seconds: age,
            verified_at: now,
        })
    }
}

/// Create a deterministic simulator report used in tests and local development.
pub fn build_simulated_report(timestamp: u64) -> TeeAttestationReport {
    TeeAttestationReport {
        tee_type: TeeType::TrustZone,
        attestation_data: b"TZ-ATTEST:SIMULATED:OP-TEE".to_vec(),
        timestamp,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_simulated_report() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be valid")
            .as_secs();
        let report = build_simulated_report(now);
        let verifier = TrustZoneAttestationVerifier::new(TrustZoneAttestationPolicy::default());
        let result = verifier.verify(&report).expect("verification should pass");
        assert!(result.is_valid);
        assert!(result.is_fresh);
        assert!(result.has_expected_format);
    }

    #[test]
    fn test_verify_stale_report() {
        let old = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be valid")
            .as_secs()
            .saturating_sub(10_000);
        let report = build_simulated_report(old);
        let verifier = TrustZoneAttestationVerifier::new(TrustZoneAttestationPolicy::default());
        let result = verifier.verify(&report).expect("verification should pass");
        assert!(!result.is_valid);
        assert!(!result.is_fresh);
    }

    #[test]
    fn test_verify_missing_format_marker() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be valid")
            .as_secs();
        let report = TeeAttestationReport {
            tee_type: TeeType::TrustZone,
            attestation_data: b"BAD-FORMAT".to_vec(),
            timestamp: now,
        };
        let verifier = TrustZoneAttestationVerifier::new(TrustZoneAttestationPolicy::default());
        let result = verifier.verify(&report).expect("verification should pass");
        assert!(!result.is_valid);
        assert!(!result.has_expected_format);
    }
}
