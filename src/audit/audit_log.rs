//! Tamper-evident append-only audit event log.
//!
//! Each [`AuditEntry`] is chained to its predecessor via a SHA-256 hash over
//! `prev_hash || timestamp || actor || action || detail`, providing tamper
//! evidence: modifying any past entry invalidates the chain from that point.
//!
//! The log is held entirely in memory.  Callers that need persistence can
//! serialise the `AuditLog` via `serde_json`.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Errors for audit log operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuditError {
    #[error("actor must not be empty")]
    EmptyActor,
    #[error("action must not be empty")]
    EmptyAction,
    #[error("chain integrity check failed at entry index {0}")]
    ChainBroken(usize),
    #[error("log is empty")]
    EmptyLog,
}

/// Severity level of an audit event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

/// A single immutable audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEntry {
    /// Sequential index (0-based).
    pub index: usize,
    /// Unix timestamp (seconds) supplied by the caller for determinism.
    pub timestamp: u64,
    /// Identity of the actor that performed the action.
    pub actor: String,
    /// Short action label (e.g. `"key.generate"`, `"vault.open"`).
    pub action: String,
    /// Optional free-form detail string.
    pub detail: Option<String>,
    /// Severity level.
    pub severity: Severity,
    /// SHA-256 hash that chains this entry to the previous one.
    pub entry_hash: Vec<u8>,
}

/// Tamper-evident append-only audit log.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    entries: Vec<AuditEntry>,
}

impl AuditLog {
    /// Create an empty log.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a new event to the log.
    ///
    /// # Parameters
    /// - `timestamp`: Caller-supplied Unix seconds (allows deterministic tests).
    /// - `actor`: Non-empty identity string.
    /// - `action`: Non-empty action label.
    /// - `detail`: Optional free-form context.
    /// - `severity`: Event severity.
    ///
    /// # Errors
    /// - [`AuditError::EmptyActor`] when `actor` is empty.
    /// - [`AuditError::EmptyAction`] when `action` is empty.
    pub fn append(
        &mut self,
        timestamp: u64,
        actor: impl Into<String>,
        action: impl Into<String>,
        detail: Option<String>,
        severity: Severity,
    ) -> Result<&AuditEntry, AuditError> {
        let actor = actor.into();
        let action = action.into();
        if actor.is_empty() {
            return Err(AuditError::EmptyActor);
        }
        if action.is_empty() {
            return Err(AuditError::EmptyAction);
        }

        let prev_hash = self
            .entries
            .last()
            .map(|e| e.entry_hash.clone())
            .unwrap_or_else(|| vec![0u8; 32]);

        let index = self.entries.len();
        let entry_hash = compute_entry_hash(
            &prev_hash,
            timestamp,
            &actor,
            &action,
            detail.as_deref().unwrap_or(""),
        );

        self.entries.push(AuditEntry {
            index,
            timestamp,
            actor,
            action,
            detail,
            severity,
            entry_hash,
        });

        Ok(self.entries.last().expect("just pushed"))
    }

    /// Verify the integrity of the entire chain.
    ///
    /// Recomputes each entry hash from scratch and checks it against the stored
    /// value.  Returns `Ok(())` when every entry is consistent.
    ///
    /// # Errors
    /// - [`AuditError::EmptyLog`] if the log has no entries.
    /// - [`AuditError::ChainBroken`] with the index of the first inconsistent entry.
    pub fn verify_chain(&self) -> Result<(), AuditError> {
        if self.entries.is_empty() {
            return Err(AuditError::EmptyLog);
        }

        let mut prev_hash = vec![0u8; 32];
        for (i, entry) in self.entries.iter().enumerate() {
            let expected = compute_entry_hash(
                &prev_hash,
                entry.timestamp,
                &entry.actor,
                &entry.action,
                entry.detail.as_deref().unwrap_or(""),
            );
            if expected != entry.entry_hash {
                return Err(AuditError::ChainBroken(i));
            }
            prev_hash = entry.entry_hash.clone();
        }
        Ok(())
    }

    /// Return all entries matching `actor`.
    pub fn entries_by_actor(&self, actor: &str) -> Vec<&AuditEntry> {
        self.entries.iter().filter(|e| e.actor == actor).collect()
    }

    /// Return all entries matching `action`.
    pub fn entries_by_action(&self, action: &str) -> Vec<&AuditEntry> {
        self.entries.iter().filter(|e| e.action == action).collect()
    }

    /// Return all entries at or above `min_severity`.
    pub fn entries_by_severity(&self, min_severity: &Severity) -> Vec<&AuditEntry> {
        let min_level = severity_level(min_severity);
        self.entries
            .iter()
            .filter(|e| severity_level(&e.severity) >= min_level)
            .collect()
    }

    /// Total number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` when the log is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Read-only slice of all entries.
    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }
}

fn severity_level(s: &Severity) -> u8 {
    match s {
        Severity::Info => 0,
        Severity::Warning => 1,
        Severity::Critical => 2,
    }
}

fn compute_entry_hash(
    prev_hash: &[u8],
    timestamp: u64,
    actor: &str,
    action: &str,
    detail: &str,
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(prev_hash);
    hasher.update(timestamp.to_le_bytes());
    hasher.update(actor.as_bytes());
    hasher.update(action.as_bytes());
    hasher.update(detail.as_bytes());
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fill_log(log: &mut AuditLog) {
        log.append(1000, "alice", "key.generate", None, Severity::Info)
            .unwrap();
        log.append(1001, "alice", "vault.open", Some("vault-id=v1".into()), Severity::Info)
            .unwrap();
        log.append(1002, "bob", "key.revoke", None, Severity::Warning)
            .unwrap();
    }

    #[test]
    fn test_append_and_length() {
        let mut log = AuditLog::new();
        fill_log(&mut log);
        assert_eq!(log.len(), 3);
    }

    #[test]
    fn test_chain_valid_after_appends() {
        let mut log = AuditLog::new();
        fill_log(&mut log);
        log.verify_chain().expect("chain should be valid");
    }

    #[test]
    fn test_chain_detects_tampered_action() {
        let mut log = AuditLog::new();
        fill_log(&mut log);
        // Tamper with the first entry's action.
        log.entries[1].action = "tampered.action".into();
        let err = log.verify_chain().expect_err("chain should be broken");
        assert!(matches!(err, AuditError::ChainBroken(1)));
    }

    #[test]
    fn test_chain_detects_tampered_hash() {
        let mut log = AuditLog::new();
        fill_log(&mut log);
        log.entries[0].entry_hash[0] ^= 0xFF;
        let err = log.verify_chain().expect_err("chain broken");
        assert!(matches!(err, AuditError::ChainBroken(0)));
    }

    #[test]
    fn test_verify_empty_log_returns_error() {
        let log = AuditLog::new();
        let err = log.verify_chain().expect_err("empty log");
        assert_eq!(err, AuditError::EmptyLog);
    }

    #[test]
    fn test_entries_by_actor() {
        let mut log = AuditLog::new();
        fill_log(&mut log);
        let alice = log.entries_by_actor("alice");
        assert_eq!(alice.len(), 2);
    }

    #[test]
    fn test_entries_by_action() {
        let mut log = AuditLog::new();
        fill_log(&mut log);
        let generates = log.entries_by_action("key.generate");
        assert_eq!(generates.len(), 1);
    }

    #[test]
    fn test_entries_by_severity_warning_and_above() {
        let mut log = AuditLog::new();
        fill_log(&mut log);
        log.append(1003, "sys", "auth.failure", None, Severity::Critical)
            .unwrap();
        let high = log.entries_by_severity(&Severity::Warning);
        assert_eq!(high.len(), 2);
    }

    #[test]
    fn test_empty_actor_rejected() {
        let mut log = AuditLog::new();
        let err = log
            .append(0, "", "action", None, Severity::Info)
            .expect_err("empty actor");
        assert_eq!(err, AuditError::EmptyActor);
    }

    #[test]
    fn test_empty_action_rejected() {
        let mut log = AuditLog::new();
        let err = log
            .append(0, "actor", "", None, Severity::Info)
            .expect_err("empty action");
        assert_eq!(err, AuditError::EmptyAction);
    }

    #[test]
    fn test_index_is_sequential() {
        let mut log = AuditLog::new();
        fill_log(&mut log);
        for (i, entry) in log.entries().iter().enumerate() {
            assert_eq!(entry.index, i);
        }
    }
}
