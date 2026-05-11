//! JSON Web Key (JWK) serialisation for post-quantum keys.
//!
//! Standard JWK (RFC 7517) does not yet define algorithm identifiers for
//! ML-DSA or ML-KEM.  This module follows the emerging IETF draft conventions
//! (`kty = "OKP"`, algorithm-specific `alg` fields) and encodes raw key
//! material as unpadded base64url strings under the `"x"` (public) and
//! `"d"` (private) members.
//!
//! | Algorithm  | `alg`            | `crv`        |
//! |------------|------------------|--------------|
//! | ML-DSA-65  | `"ML-DSA-65"`    | `"ML-DSA-65"` |
//! | ML-KEM-1024| `"ML-KEM-1024"`  | `"ML-KEM-1024"` |
//!
//! Private (`"d"`) is omitted for public-only keys.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors for JWK operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum JwkError {
    #[error("unsupported key type: {0}")]
    UnsupportedKeyType(String),
    #[error("missing required JWK field: {0}")]
    MissingField(String),
    #[error("base64url decode failed: {0}")]
    DecodeError(String),
    #[error("key bytes must not be empty")]
    EmptyKey,
}

/// Supported post-quantum key algorithms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PqcAlgorithm {
    /// ML-DSA-65 (NIST FIPS 204, security category 3).
    MlDsa65,
    /// ML-KEM-1024 (NIST FIPS 203, security category 5).
    MlKem1024,
}

impl PqcAlgorithm {
    fn alg_str(&self) -> &'static str {
        match self {
            PqcAlgorithm::MlDsa65 => "ML-DSA-65",
            PqcAlgorithm::MlKem1024 => "ML-KEM-1024",
        }
    }

    fn from_str(s: &str) -> Result<Self, JwkError> {
        match s {
            "ML-DSA-65" => Ok(PqcAlgorithm::MlDsa65),
            "ML-KEM-1024" => Ok(PqcAlgorithm::MlKem1024),
            other => Err(JwkError::UnsupportedKeyType(other.to_owned())),
        }
    }
}

/// A JWK-encoded post-quantum key.
///
/// Maps directly to the JSON structure and can be serialised / deserialised
/// with `serde_json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PqcJwk {
    /// Key type — always `"OKP"` for PQC keys.
    pub kty: String,
    /// Algorithm identifier (e.g. `"ML-DSA-65"`).
    pub alg: String,
    /// Curve / parameter set (mirrors `alg` for PQC).
    pub crv: String,
    /// Base64url-encoded public key bytes.
    pub x: String,
    /// Base64url-encoded private key bytes; `None` for public-only keys.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,
    /// Optional key ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

impl PqcJwk {
    /// Export a **public** key as a JWK.
    ///
    /// # Errors
    /// Returns [`JwkError::EmptyKey`] when `public_key` is empty.
    pub fn from_public(
        algorithm: &PqcAlgorithm,
        public_key: &[u8],
        kid: Option<String>,
    ) -> Result<Self, JwkError> {
        if public_key.is_empty() {
            return Err(JwkError::EmptyKey);
        }
        Ok(Self {
            kty: "OKP".to_owned(),
            alg: algorithm.alg_str().to_owned(),
            crv: algorithm.alg_str().to_owned(),
            x: URL_SAFE_NO_PAD.encode(public_key),
            d: None,
            kid,
        })
    }

    /// Export a **keypair** (public + private) as a JWK.
    ///
    /// # Errors
    /// Returns [`JwkError::EmptyKey`] when either key is empty.
    pub fn from_keypair(
        algorithm: &PqcAlgorithm,
        public_key: &[u8],
        private_key: &[u8],
        kid: Option<String>,
    ) -> Result<Self, JwkError> {
        if public_key.is_empty() || private_key.is_empty() {
            return Err(JwkError::EmptyKey);
        }
        Ok(Self {
            kty: "OKP".to_owned(),
            alg: algorithm.alg_str().to_owned(),
            crv: algorithm.alg_str().to_owned(),
            x: URL_SAFE_NO_PAD.encode(public_key),
            d: Some(URL_SAFE_NO_PAD.encode(private_key)),
            kid,
        })
    }

    /// Decode the public key bytes from the JWK.
    ///
    /// # Errors
    /// Returns [`JwkError::DecodeError`] on invalid base64url.
    pub fn decode_public_key(&self) -> Result<Vec<u8>, JwkError> {
        URL_SAFE_NO_PAD
            .decode(&self.x)
            .map_err(|e| JwkError::DecodeError(e.to_string()))
    }

    /// Decode the private key bytes from the JWK (if present).
    ///
    /// Returns `None` when the JWK is public-only.
    ///
    /// # Errors
    /// Returns [`JwkError::DecodeError`] on invalid base64url.
    pub fn decode_private_key(&self) -> Result<Option<Vec<u8>>, JwkError> {
        match &self.d {
            None => Ok(None),
            Some(d) => URL_SAFE_NO_PAD
                .decode(d)
                .map(Some)
                .map_err(|e| JwkError::DecodeError(e.to_string())),
        }
    }

    /// Parse the algorithm from the `alg` field.
    ///
    /// # Errors
    /// Returns [`JwkError::UnsupportedKeyType`] for unknown values.
    pub fn algorithm(&self) -> Result<PqcAlgorithm, JwkError> {
        PqcAlgorithm::from_str(&self.alg)
    }

    /// Serialise to a JSON string.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("PqcJwk serialisation is infallible")
    }

    /// Deserialise from a JSON string.
    ///
    /// # Errors
    /// Returns [`JwkError::MissingField`] when the JSON is missing required members.
    pub fn from_json(json: &str) -> Result<Self, JwkError> {
        serde_json::from_str(json)
            .map_err(|e| JwkError::MissingField(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAKE_PK: &[u8] = b"ml-dsa-public-key-bytes-32------";
    const FAKE_SK: &[u8] = b"ml-dsa-secret-key-bytes-64------";

    #[test]
    fn test_public_jwk_roundtrip() {
        let jwk = PqcJwk::from_public(&PqcAlgorithm::MlDsa65, FAKE_PK, Some("key-1".into()))
            .expect("from_public");
        assert_eq!(jwk.kty, "OKP");
        assert_eq!(jwk.alg, "ML-DSA-65");
        assert!(jwk.d.is_none());
        let decoded = jwk.decode_public_key().expect("decode");
        assert_eq!(decoded, FAKE_PK);
    }

    #[test]
    fn test_keypair_jwk_roundtrip() {
        let jwk = PqcJwk::from_keypair(&PqcAlgorithm::MlDsa65, FAKE_PK, FAKE_SK, None)
            .expect("from_keypair");
        assert!(jwk.d.is_some());
        let decoded_pk = jwk.decode_public_key().expect("decode pk");
        let decoded_sk = jwk.decode_private_key().expect("decode sk").unwrap();
        assert_eq!(decoded_pk, FAKE_PK);
        assert_eq!(decoded_sk, FAKE_SK);
    }

    #[test]
    fn test_mlkem_public_jwk() {
        let jwk = PqcJwk::from_public(&PqcAlgorithm::MlKem1024, FAKE_PK, None)
            .expect("from_public");
        assert_eq!(jwk.alg, "ML-KEM-1024");
        assert_eq!(jwk.algorithm().expect("alg"), PqcAlgorithm::MlKem1024);
    }

    #[test]
    fn test_json_serialisation_roundtrip() {
        let jwk = PqcJwk::from_public(&PqcAlgorithm::MlDsa65, FAKE_PK, Some("k1".into()))
            .expect("from_public");
        let json = jwk.to_json();
        let restored = PqcJwk::from_json(&json).expect("from_json");
        assert_eq!(jwk, restored);
    }

    #[test]
    fn test_empty_public_key_rejected() {
        let err = PqcJwk::from_public(&PqcAlgorithm::MlDsa65, b"", None)
            .expect_err("empty key");
        assert_eq!(err, JwkError::EmptyKey);
    }

    #[test]
    fn test_empty_private_key_rejected() {
        let err = PqcJwk::from_keypair(&PqcAlgorithm::MlDsa65, FAKE_PK, b"", None)
            .expect_err("empty sk");
        assert_eq!(err, JwkError::EmptyKey);
    }

    #[test]
    fn test_public_only_decode_private_returns_none() {
        let jwk = PqcJwk::from_public(&PqcAlgorithm::MlDsa65, FAKE_PK, None).unwrap();
        let sk = jwk.decode_private_key().expect("no error");
        assert!(sk.is_none());
    }

    #[test]
    fn test_invalid_json_returns_error() {
        let err = PqcJwk::from_json("{bad json}").expect_err("invalid json");
        assert!(matches!(err, JwkError::MissingField(_)));
    }

    #[test]
    fn test_unknown_alg_returns_error() {
        let jwk = PqcJwk {
            kty: "OKP".into(),
            alg: "SomeUnknownAlg".into(),
            crv: "SomeUnknownAlg".into(),
            x: URL_SAFE_NO_PAD.encode(FAKE_PK),
            d: None,
            kid: None,
        };
        let err = jwk.algorithm().expect_err("unknown alg");
        assert!(matches!(err, JwkError::UnsupportedKeyType(_)));
    }
}
