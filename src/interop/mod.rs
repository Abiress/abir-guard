//! Interoperability standards module.
//!
//! Provides two sub-systems:
//! - [`jwk`] — JWK-like serialisation for ML-DSA and ML-KEM public/private keys.
//! - [`did`] — W3C DID Core document facade with `JsonWebKey2020` verification methods.

pub mod did;
pub mod jwk;

pub use did::{DidDocument, DidError, VerificationMethod, VerificationRelationship};
pub use jwk::{JwkError, PqcAlgorithm, PqcJwk};
