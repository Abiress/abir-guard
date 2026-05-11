//! Performance optimization module.
//!
//! Provides two sub-systems:
//! - [`key_cache`] — bounded LRU-style cache for Argon2id derived keys.
//! - [`batch_ops`] — batch ML-DSA sign and verify helpers.

pub mod batch_ops;
pub mod key_cache;

pub use batch_ops::{
    batch_sign, batch_verify, BatchOpsError, BatchSignResult, BatchVerifyResult, SignRequest,
    VerifyRequest,
};
pub use key_cache::{CacheError, CacheStats, DerivedKeyCache};
