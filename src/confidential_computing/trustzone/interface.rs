//! OP-TEE style interface and command marshalling for TrustZone.
//!
//! This module models request/response transport for trusted application calls.

use serde::{Deserialize, Serialize};

use super::{TrustZoneEnclave, TrustZoneError};

/// Command IDs used for trusted application invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u32)]
pub enum TaCommand {
    /// Retrieve attestation report from secure world.
    GetAttestation = 1,
    /// Seal input payload with TrustZone key material.
    SealData = 2,
    /// Unseal previously sealed payload.
    UnsealData = 3,
}

/// Serialized command request sent to secure world.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaRequest {
    /// Session ID bound to the enclave context.
    pub session_id: u64,
    /// Command identifier.
    pub command: TaCommand,
    /// Opaque payload bytes.
    pub payload: Vec<u8>,
}

impl TaRequest {
    /// Create a request object for a command.
    pub fn new(session_id: u64, command: TaCommand, payload: Vec<u8>) -> Self {
        Self {
            session_id,
            command,
            payload,
        }
    }

    /// Serialize request for transport.
    pub fn to_bytes(&self) -> Result<Vec<u8>, TrustZoneError> {
        serde_json::to_vec(self)
            .map_err(|e| TrustZoneError::OperationFailed(format!("request serialization failed: {e}")))
    }

    /// Deserialize request from transport bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TrustZoneError> {
        serde_json::from_slice(bytes)
            .map_err(|e| TrustZoneError::OperationFailed(format!("request deserialization failed: {e}")))
    }
}

/// Serialized command response returned from secure world.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaResponse {
    /// Whether secure world operation succeeded.
    pub success: bool,
    /// Optional message for diagnostics.
    pub message: String,
    /// Opaque output payload.
    pub payload: Vec<u8>,
}

impl TaResponse {
    /// Build a successful response.
    pub fn ok(payload: Vec<u8>) -> Self {
        Self {
            success: true,
            message: String::new(),
            payload,
        }
    }

    /// Build a failed response.
    pub fn err(message: impl Into<String>) -> Self {
        Self {
            success: false,
            message: message.into(),
            payload: Vec::new(),
        }
    }

    /// Serialize response bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, TrustZoneError> {
        serde_json::to_vec(self)
            .map_err(|e| TrustZoneError::OperationFailed(format!("response serialization failed: {e}")))
    }

    /// Deserialize response bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TrustZoneError> {
        serde_json::from_slice(bytes)
            .map_err(|e| TrustZoneError::OperationFailed(format!("response deserialization failed: {e}")))
    }
}

/// Dispatch a command through the current TrustZone enclave context.
pub fn dispatch_command(enclave: &TrustZoneEnclave, request: &TaRequest) -> Result<TaResponse, TrustZoneError> {
    if !enclave.is_initialized() {
        return Err(TrustZoneError::InvalidState(
            "cannot dispatch command on uninitialized TrustZone session".to_string(),
        ));
    }

    if request.session_id != enclave.session_id() {
        return Ok(TaResponse::err("session mismatch"));
    }

    match request.command {
        TaCommand::GetAttestation => {
            let report = enclave.get_attestation()?;
            let payload = serde_json::to_vec(&report)
                .map_err(|e| TrustZoneError::OperationFailed(format!("attestation encoding failed: {e}")))?;
            Ok(TaResponse::ok(payload))
        }
        TaCommand::SealData => {
            let sealed = enclave.seal_data(&request.payload)?;
            let payload = serde_json::to_vec(&sealed)
                .map_err(|e| TrustZoneError::OperationFailed(format!("sealed payload encoding failed: {e}")))?;
            Ok(TaResponse::ok(payload))
        }
        TaCommand::UnsealData => {
            let sealed = serde_json::from_slice(&request.payload)
                .map_err(|e| TrustZoneError::OperationFailed(format!("sealed payload decoding failed: {e}")))?;
            let plain = enclave.unseal_data(&sealed)?;
            Ok(TaResponse::ok(plain))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confidential_computing::tee_common::TeeType;

    use super::super::TrustZoneConfig;

    #[test]
    fn test_request_roundtrip() {
        let req = TaRequest::new(7, TaCommand::SealData, b"abc".to_vec());
        let bytes = req.to_bytes().expect("request serialization should work");
        let req2 = TaRequest::from_bytes(&bytes).expect("request deserialization should work");
        assert_eq!(req2.session_id, 7);
        assert_eq!(req2.command, TaCommand::SealData);
        assert_eq!(req2.payload, b"abc");
    }

    #[test]
    fn test_dispatch_attestation_command() {
        let enclave = TrustZoneEnclave::initialize(TrustZoneConfig::secure_default())
            .expect("init should pass");
        let req = TaRequest::new(enclave.session_id(), TaCommand::GetAttestation, vec![]);
        let resp = dispatch_command(&enclave, &req).expect("dispatch should pass");
        assert!(resp.success);

        let report: crate::confidential_computing::tee_common::TeeAttestationReport =
            serde_json::from_slice(&resp.payload).expect("report decode should pass");
        assert_eq!(report.tee_type, TeeType::TrustZone);
    }

    #[test]
    fn test_dispatch_session_mismatch() {
        let enclave = TrustZoneEnclave::initialize(TrustZoneConfig::secure_default())
            .expect("init should pass");
        let req = TaRequest::new(enclave.session_id() + 1, TaCommand::SealData, vec![]);
        let resp = dispatch_command(&enclave, &req).expect("dispatch should return response");
        assert!(!resp.success);
        assert_eq!(resp.message, "session mismatch");
    }
}
