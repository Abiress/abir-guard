//! W3C DID Core document facade.
//!
//! Implements a minimal subset of the [W3C DID Core specification](https://www.w3.org/TR/did-core/)
//! sufficient to bind post-quantum public keys to a DID subject and express
//! verification relationships (`authentication`, `assertionMethod`,
//! `keyAgreement`).
//!
//! JWK-encoded keys (`PqcJwk`) are embedded as `verificationMethod` entries
//! using the `JsonWebKey2020` type.
//!
//! **This is a local, chain-agnostic facade.**  Resolving the DID on an
//! actual DID network requires an external resolver; this module only handles
//! construction, serialisation, and lookup.

use crate::interop::jwk::PqcJwk;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors for DID document operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DidError {
    #[error("verification method with id {0} already exists")]
    DuplicateVerificationMethod(String),
    #[error("verification method {0} not found")]
    VerificationMethodNotFound(String),
    #[error("DID must not be empty")]
    EmptyDid,
    #[error("verification method id must not be empty")]
    EmptyMethodId,
}

/// Relationship types defined by W3C DID Core §5.3.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum VerificationRelationship {
    Authentication,
    AssertionMethod,
    KeyAgreement,
    CapabilityInvocation,
    CapabilityDelegation,
}

/// A single verification method entry (JWK variant).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationMethod {
    /// Fragment identifier, e.g. `"did:example:alice#key-1"`.
    pub id: String,
    /// Verification method type — always `"JsonWebKey2020"` here.
    #[serde(rename = "type")]
    pub method_type: String,
    /// DID of the controller.
    pub controller: String,
    /// The embedded JWK.
    #[serde(rename = "publicKeyJwk")]
    pub public_key_jwk: PqcJwk,
}

impl VerificationMethod {
    /// Build a `JsonWebKey2020` verification method.
    pub fn new(id: impl Into<String>, controller: impl Into<String>, jwk: PqcJwk) -> Self {
        Self {
            id: id.into(),
            method_type: "JsonWebKey2020".to_owned(),
            controller: controller.into(),
            public_key_jwk: jwk,
        }
    }
}

/// A W3C DID Core document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidDocument {
    /// JSON-LD context.
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    /// DID subject identifier, e.g. `"did:example:alice"`.
    pub id: String,
    /// Ordered list of verification methods.
    #[serde(rename = "verificationMethod")]
    pub verification_methods: Vec<VerificationMethod>,
    /// Authentication relationship references (method fragment IDs).
    #[serde(rename = "authentication", skip_serializing_if = "Vec::is_empty")]
    pub authentication: Vec<String>,
    /// AssertionMethod relationship references.
    #[serde(rename = "assertionMethod", skip_serializing_if = "Vec::is_empty")]
    pub assertion_method: Vec<String>,
    /// KeyAgreement relationship references.
    #[serde(rename = "keyAgreement", skip_serializing_if = "Vec::is_empty")]
    pub key_agreement: Vec<String>,
}

impl DidDocument {
    /// Create a new, empty DID document for `did`.
    ///
    /// Includes the standard DID Core and JsonWebKey2020 contexts.
    ///
    /// # Errors
    /// Returns [`DidError::EmptyDid`] when `did` is empty.
    pub fn new(did: impl Into<String>) -> Result<Self, DidError> {
        let did = did.into();
        if did.is_empty() {
            return Err(DidError::EmptyDid);
        }
        Ok(Self {
            context: vec![
                "https://www.w3.org/ns/did/v1".to_owned(),
                "https://w3id.org/security/suites/jws-2020/v1".to_owned(),
            ],
            id: did,
            verification_methods: Vec::new(),
            authentication: Vec::new(),
            assertion_method: Vec::new(),
            key_agreement: Vec::new(),
        })
    }

    /// Add a verification method to the document.
    ///
    /// `relationships` lists the verification relationships this method
    /// participates in.
    ///
    /// # Errors
    /// - [`DidError::EmptyMethodId`] when `method.id` is empty.
    /// - [`DidError::DuplicateVerificationMethod`] when a method with the same
    ///   `id` already exists.
    pub fn add_verification_method(
        &mut self,
        method: VerificationMethod,
        relationships: &[VerificationRelationship],
    ) -> Result<(), DidError> {
        if method.id.is_empty() {
            return Err(DidError::EmptyMethodId);
        }
        if self.verification_methods.iter().any(|m| m.id == method.id) {
            return Err(DidError::DuplicateVerificationMethod(method.id.clone()));
        }
        let method_id = method.id.clone();
        self.verification_methods.push(method);

        for rel in relationships {
            match rel {
                VerificationRelationship::Authentication => {
                    self.authentication.push(method_id.clone());
                }
                VerificationRelationship::AssertionMethod => {
                    self.assertion_method.push(method_id.clone());
                }
                VerificationRelationship::KeyAgreement => {
                    self.key_agreement.push(method_id.clone());
                }
                VerificationRelationship::CapabilityInvocation
                | VerificationRelationship::CapabilityDelegation => {
                    // Stored inline in verification_methods; no separate ref list needed.
                }
            }
        }
        Ok(())
    }

    /// Look up a verification method by fragment ID.
    ///
    /// # Errors
    /// Returns [`DidError::VerificationMethodNotFound`] when not present.
    pub fn get_method(&self, method_id: &str) -> Result<&VerificationMethod, DidError> {
        self.verification_methods
            .iter()
            .find(|m| m.id == method_id)
            .ok_or_else(|| DidError::VerificationMethodNotFound(method_id.to_owned()))
    }

    /// Remove a verification method and all its relationship references.
    ///
    /// # Errors
    /// Returns [`DidError::VerificationMethodNotFound`] when not present.
    pub fn remove_method(&mut self, method_id: &str) -> Result<(), DidError> {
        let before = self.verification_methods.len();
        self.verification_methods.retain(|m| m.id != method_id);
        if self.verification_methods.len() == before {
            return Err(DidError::VerificationMethodNotFound(method_id.to_owned()));
        }
        self.authentication.retain(|id| id != method_id);
        self.assertion_method.retain(|id| id != method_id);
        self.key_agreement.retain(|id| id != method_id);
        Ok(())
    }

    /// Serialise to a JSON string.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("DidDocument serialisation is infallible")
    }

    /// Deserialise from a JSON string.
    ///
    /// # Errors
    /// Returns a `serde_json::Error` string wrapped in `DidError::EmptyDid` on failure.
    pub fn from_json(json: &str) -> Result<Self, DidError> {
        serde_json::from_str(json).map_err(|_| DidError::EmptyDid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interop::jwk::{PqcAlgorithm, PqcJwk};

    fn make_jwk(label: &str) -> PqcJwk {
        let key_bytes = format!("fake-public-key-{label}").into_bytes();
        PqcJwk::from_public(&PqcAlgorithm::MlDsa65, &key_bytes, Some(label.into()))
            .expect("from_public")
    }

    fn make_method(did: &str, fragment: &str) -> VerificationMethod {
        let id = format!("{did}#{fragment}");
        VerificationMethod::new(id, did, make_jwk(fragment))
    }

    #[test]
    fn test_create_did_document() {
        let doc = DidDocument::new("did:example:alice").expect("new");
        assert_eq!(doc.id, "did:example:alice");
        assert_eq!(doc.context.len(), 2);
        assert!(doc.verification_methods.is_empty());
    }

    #[test]
    fn test_add_verification_method_authentication() {
        let mut doc = DidDocument::new("did:example:alice").unwrap();
        let method = make_method("did:example:alice", "key-1");
        doc.add_verification_method(
            method,
            &[VerificationRelationship::Authentication],
        )
        .expect("add method");
        assert_eq!(doc.verification_methods.len(), 1);
        assert_eq!(doc.authentication, vec!["did:example:alice#key-1"]);
        assert!(doc.assertion_method.is_empty());
    }

    #[test]
    fn test_add_multiple_relationships() {
        let mut doc = DidDocument::new("did:example:bob").unwrap();
        let method = make_method("did:example:bob", "key-1");
        doc.add_verification_method(
            method,
            &[
                VerificationRelationship::Authentication,
                VerificationRelationship::AssertionMethod,
            ],
        )
        .expect("add method");
        assert_eq!(doc.authentication.len(), 1);
        assert_eq!(doc.assertion_method.len(), 1);
    }

    #[test]
    fn test_duplicate_method_rejected() {
        let mut doc = DidDocument::new("did:example:carol").unwrap();
        let m1 = make_method("did:example:carol", "key-1");
        let m2 = make_method("did:example:carol", "key-1");
        doc.add_verification_method(m1, &[]).expect("first");
        let err = doc
            .add_verification_method(m2, &[])
            .expect_err("duplicate");
        assert!(matches!(err, DidError::DuplicateVerificationMethod(_)));
    }

    #[test]
    fn test_get_method_found() {
        let mut doc = DidDocument::new("did:example:dan").unwrap();
        let method = make_method("did:example:dan", "key-1");
        doc.add_verification_method(method, &[]).unwrap();
        let found = doc
            .get_method("did:example:dan#key-1")
            .expect("get method");
        assert_eq!(found.method_type, "JsonWebKey2020");
    }

    #[test]
    fn test_get_method_not_found() {
        let doc = DidDocument::new("did:example:eve").unwrap();
        let err = doc.get_method("did:example:eve#missing").expect_err("not found");
        assert!(matches!(err, DidError::VerificationMethodNotFound(_)));
    }

    #[test]
    fn test_remove_method_clears_relationships() {
        let mut doc = DidDocument::new("did:example:frank").unwrap();
        let method = make_method("did:example:frank", "key-1");
        doc.add_verification_method(
            method,
            &[
                VerificationRelationship::Authentication,
                VerificationRelationship::KeyAgreement,
            ],
        )
        .unwrap();
        doc.remove_method("did:example:frank#key-1").expect("remove");
        assert!(doc.verification_methods.is_empty());
        assert!(doc.authentication.is_empty());
        assert!(doc.key_agreement.is_empty());
    }

    #[test]
    fn test_remove_nonexistent_returns_error() {
        let mut doc = DidDocument::new("did:example:grace").unwrap();
        let err = doc.remove_method("did:example:grace#ghost").expect_err("not found");
        assert!(matches!(err, DidError::VerificationMethodNotFound(_)));
    }

    #[test]
    fn test_json_roundtrip() {
        let mut doc = DidDocument::new("did:example:hank").unwrap();
        let method = make_method("did:example:hank", "key-1");
        doc.add_verification_method(method, &[VerificationRelationship::Authentication])
            .unwrap();
        let json = doc.to_json();
        assert!(json.contains("did:example:hank"));
        assert!(json.contains("JsonWebKey2020"));
    }

    #[test]
    fn test_empty_did_rejected() {
        let err = DidDocument::new("").expect_err("empty DID");
        assert_eq!(err, DidError::EmptyDid);
    }
}
