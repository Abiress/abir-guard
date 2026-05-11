//! Blockchain integration module.
//!
//! Provides three layers:
//! - [`key_anchor`] — on-chain key commitment model and local registry.
//! - [`dpki`] — decentralized PKI facade backed by the anchor registry.
//! - [`smart_contract`] — trait abstraction + simulated in-process back-end.

pub mod dpki;
pub mod key_anchor;
pub mod smart_contract;

pub use dpki::{DecentralizedPki, DpkiEntry, DpkiError};
pub use key_anchor::{AnchorRegistry, KeyAnchor, KeyAnchorError};
pub use smart_contract::{
    ContractError, OnChainVerificationResult, SimulatedContractAnchor, SmartContractAnchor,
};
