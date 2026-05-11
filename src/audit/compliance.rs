//! Compliance policy gate.
//!
//! Provides a [`ComplianceReport`] that aggregates [`AuditEntry`] events and
//! evaluates them against a configurable set of [`ComplianceRule`]s.  Each
//! rule describes a required property of the log; the report produces a list
//! of [`ComplianceViolation`]s for rules that are not satisfied.
//!
//! Built-in rules cover FIPS-140 and SOC2 concerns most relevant to a PQC key
//! management library:
//! - Maximum number of consecutive auth-failure events before an alert must
//!   be logged.
//! - Minimum required `Critical` event coverage for key revocations.
//! - No more than a configurable number of `key.revoke` events without a
//!   corresponding `key.rotation` in the same window.

use crate::audit::audit_log::{AuditEntry, AuditLog, Severity};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors for compliance report operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ComplianceError {
    #[error("audit log must not be empty")]
    EmptyLog,
}

/// Configurable compliance rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComplianceRule {
    /// Flag if `auth.failure` events appear more than `max_consecutive` times in a row.
    MaxConsecutiveAuthFailures { max_consecutive: usize },
    /// Flag if any `key.revoke` event does not have a corresponding `Critical` severity entry.
    RequireCriticalOnRevocation,
    /// Flag if the ratio of `key.revoke` to `key.rotation` events exceeds `max_ratio`.
    MaxRevocationToRotationRatio { max_ratio: f64 },
}

/// A single compliance policy violation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceViolation {
    /// Human-readable description.
    pub description: String,
    /// Relevant entry indices (empty when the rule is global).
    pub entry_indices: Vec<usize>,
}

/// Compliance report produced from an [`AuditLog`] and a set of [`ComplianceRule`]s.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub total_entries: usize,
    pub violations: Vec<ComplianceViolation>,
    pub passed: bool,
}

impl ComplianceReport {
    /// Evaluate `rules` against `log`.
    ///
    /// # Errors
    /// Returns [`ComplianceError::EmptyLog`] when the log has no entries.
    pub fn evaluate(log: &AuditLog, rules: &[ComplianceRule]) -> Result<Self, ComplianceError> {
        if log.is_empty() {
            return Err(ComplianceError::EmptyLog);
        }

        let entries = log.entries();
        let mut violations = Vec::new();

        for rule in rules {
            match rule {
                ComplianceRule::MaxConsecutiveAuthFailures { max_consecutive } => {
                    check_consecutive_auth_failures(entries, *max_consecutive, &mut violations);
                }
                ComplianceRule::RequireCriticalOnRevocation => {
                    check_revocation_criticality(entries, &mut violations);
                }
                ComplianceRule::MaxRevocationToRotationRatio { max_ratio } => {
                    check_revocation_rotation_ratio(entries, *max_ratio, &mut violations);
                }
            }
        }

        let passed = violations.is_empty();
        Ok(ComplianceReport {
            total_entries: entries.len(),
            violations,
            passed,
        })
    }
}

// ---------------------------------------------------------------------------
// Rule implementations
// ---------------------------------------------------------------------------

fn check_consecutive_auth_failures(
    entries: &[AuditEntry],
    max_consecutive: usize,
    violations: &mut Vec<ComplianceViolation>,
) {
    let mut run: Vec<usize> = Vec::new();
    for entry in entries {
        if entry.action == "auth.failure" {
            run.push(entry.index);
        } else {
            if run.len() > max_consecutive {
                violations.push(ComplianceViolation {
                    description: format!(
                        "{} consecutive auth.failure events (max allowed: {})",
                        run.len(),
                        max_consecutive
                    ),
                    entry_indices: run.clone(),
                });
            }
            run.clear();
        }
    }
    // trailing run
    if run.len() > max_consecutive {
        violations.push(ComplianceViolation {
            description: format!(
                "{} consecutive auth.failure events (max allowed: {})",
                run.len(),
                max_consecutive
            ),
            entry_indices: run,
        });
    }
}

fn check_revocation_criticality(
    entries: &[AuditEntry],
    violations: &mut Vec<ComplianceViolation>,
) {
    for entry in entries {
        if entry.action == "key.revoke" && entry.severity != Severity::Critical {
            violations.push(ComplianceViolation {
                description: format!(
                    "key.revoke at index {} is not marked Critical (got {:?})",
                    entry.index, entry.severity
                ),
                entry_indices: vec![entry.index],
            });
        }
    }
}

fn check_revocation_rotation_ratio(
    entries: &[AuditEntry],
    max_ratio: f64,
    violations: &mut Vec<ComplianceViolation>,
) {
    let revocations = entries.iter().filter(|e| e.action == "key.revoke").count();
    let rotations = entries.iter().filter(|e| e.action == "key.rotation").count();
    if rotations == 0 && revocations > 0 {
        violations.push(ComplianceViolation {
            description: format!(
                "{revocations} key.revoke events with 0 key.rotation events (ratio undefined)"
            ),
            entry_indices: vec![],
        });
        return;
    }
    if rotations > 0 {
        let ratio = revocations as f64 / rotations as f64;
        if ratio > max_ratio {
            violations.push(ComplianceViolation {
                description: format!(
                    "revoke/rotation ratio {:.2} exceeds allowed maximum {:.2}",
                    ratio, max_ratio
                ),
                entry_indices: vec![],
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::audit_log::AuditLog;

    fn make_log() -> AuditLog {
        let mut log = AuditLog::new();
        log.append(1000, "alice", "key.generate", None, Severity::Info)
            .unwrap();
        log.append(1001, "alice", "key.revoke", None, Severity::Critical)
            .unwrap();
        log.append(1002, "alice", "key.rotation", None, Severity::Info)
            .unwrap();
        log
    }

    #[test]
    fn test_empty_log_returns_error() {
        let log = AuditLog::new();
        let err = ComplianceReport::evaluate(&log, &[]).expect_err("empty log");
        assert_eq!(err, ComplianceError::EmptyLog);
    }

    #[test]
    fn test_clean_log_passes_all_rules() {
        let log = make_log();
        let rules = vec![
            ComplianceRule::MaxConsecutiveAuthFailures { max_consecutive: 3 },
            ComplianceRule::RequireCriticalOnRevocation,
            ComplianceRule::MaxRevocationToRotationRatio { max_ratio: 2.0 },
        ];
        let report = ComplianceReport::evaluate(&log, &rules).unwrap();
        assert!(report.passed);
        assert!(report.violations.is_empty());
    }

    #[test]
    fn test_consecutive_auth_failures_violation() {
        let mut log = AuditLog::new();
        for i in 0..5u64 {
            log.append(i, "anon", "auth.failure", None, Severity::Warning)
                .unwrap();
        }
        log.append(100, "sys", "session.end", None, Severity::Info)
            .unwrap();
        let rules = vec![ComplianceRule::MaxConsecutiveAuthFailures { max_consecutive: 3 }];
        let report = ComplianceReport::evaluate(&log, &rules).unwrap();
        assert!(!report.passed);
        assert_eq!(report.violations.len(), 1);
        assert_eq!(report.violations[0].entry_indices.len(), 5);
    }

    #[test]
    fn test_auth_failures_within_limit_passes() {
        let mut log = AuditLog::new();
        for i in 0..3u64 {
            log.append(i, "anon", "auth.failure", None, Severity::Warning)
                .unwrap();
        }
        log.append(100, "sys", "session.end", None, Severity::Info)
            .unwrap();
        let rules = vec![ComplianceRule::MaxConsecutiveAuthFailures { max_consecutive: 3 }];
        let report = ComplianceReport::evaluate(&log, &rules).unwrap();
        assert!(report.passed);
    }

    #[test]
    fn test_revocation_not_critical_is_violation() {
        let mut log = AuditLog::new();
        log.append(1, "sys", "key.revoke", None, Severity::Warning)
            .unwrap();
        let rules = vec![ComplianceRule::RequireCriticalOnRevocation];
        let report = ComplianceReport::evaluate(&log, &rules).unwrap();
        assert!(!report.passed);
        assert_eq!(report.violations[0].entry_indices, vec![0]);
    }

    #[test]
    fn test_revocation_with_no_rotation_is_violation() {
        let mut log = AuditLog::new();
        log.append(1, "sys", "key.revoke", None, Severity::Critical)
            .unwrap();
        log.append(2, "sys", "key.revoke", None, Severity::Critical)
            .unwrap();
        let rules = vec![ComplianceRule::MaxRevocationToRotationRatio { max_ratio: 1.0 }];
        let report = ComplianceReport::evaluate(&log, &rules).unwrap();
        assert!(!report.passed);
    }

    #[test]
    fn test_ratio_within_limit_passes() {
        let log = make_log(); // 1 revoke, 1 rotation → ratio 1.0
        let rules = vec![ComplianceRule::MaxRevocationToRotationRatio { max_ratio: 1.0 }];
        let report = ComplianceReport::evaluate(&log, &rules).unwrap();
        assert!(report.passed);
    }

    #[test]
    fn test_ratio_exceeds_limit_is_violation() {
        let mut log = AuditLog::new();
        log.append(1, "sys", "key.revoke", None, Severity::Critical)
            .unwrap();
        log.append(2, "sys", "key.revoke", None, Severity::Critical)
            .unwrap();
        log.append(3, "sys", "key.rotation", None, Severity::Info)
            .unwrap();
        let rules = vec![ComplianceRule::MaxRevocationToRotationRatio { max_ratio: 1.0 }];
        let report = ComplianceReport::evaluate(&log, &rules).unwrap();
        assert!(!report.passed); // ratio = 2.0 > 1.0
    }

    #[test]
    fn test_total_entries_is_correct() {
        let log = make_log();
        let report = ComplianceReport::evaluate(&log, &[]).unwrap();
        assert_eq!(report.total_entries, 3);
    }
}
