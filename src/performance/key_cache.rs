//! Bounded LRU-style cache for expensive derived key material.
//!
//! Argon2id key derivation (64 MiB, 3 iterations, 4 lanes) is intentionally
//! expensive.  When the same passphrase+salt pair is requested multiple times
//! within a session it is wasteful to re-derive.  `DerivedKeyCache` stores up
//! to `capacity` derived keys in insertion order and evicts the oldest entry
//! when the cap is exceeded.
//!
//! **Security note**: cached key material lives in heap memory.  Callers that
//! require strict zeroization on eviction should call `clear()` before dropping
//! the cache.

use crate::kdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use thiserror::Error;

/// Errors produced by the derived-key cache.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CacheError {
    #[error("output length must be between 1 and 64 bytes")]
    InvalidOutputLength,
    #[error("cache capacity must be at least 1")]
    InvalidCapacity,
    #[error("key derivation failed: {0}")]
    DerivationFailed(String),
}

/// Cache statistics snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CacheStats {
    /// Number of currently cached entries.
    pub size: usize,
    /// Configured maximum capacity.
    pub capacity: usize,
    /// Total cache hits since creation.
    pub total_hits: u64,
    /// Total cache misses (derivations performed) since creation.
    pub total_misses: u64,
}

// Internal cache key: (password_hash, salt_hash, output_len).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    password_hash: Vec<u8>,
    salt_hash: Vec<u8>,
    output_len: usize,
}

impl CacheKey {
    fn new(password: &[u8], salt: &[u8], output_len: usize) -> Self {
        Self {
            password_hash: Sha256::digest(password).to_vec(),
            salt_hash: Sha256::digest(salt).to_vec(),
            output_len,
        }
    }
}

struct CacheEntry {
    key_bytes: Vec<u8>,
    hits: u64,
}

/// Bounded derived-key cache.
pub struct DerivedKeyCache {
    capacity: usize,
    entries: HashMap<CacheKey, CacheEntry>,
    /// Insertion-ordered keys for LRU-style eviction of the oldest entry.
    order: VecDeque<CacheKey>,
    total_hits: u64,
    total_misses: u64,
}

impl DerivedKeyCache {
    /// Create a new cache with the given `capacity` (maximum number of entries).
    ///
    /// # Errors
    /// Returns [`CacheError::InvalidCapacity`] when `capacity` is 0.
    pub fn new(capacity: usize) -> Result<Self, CacheError> {
        if capacity == 0 {
            return Err(CacheError::InvalidCapacity);
        }
        Ok(Self {
            capacity,
            entries: HashMap::new(),
            order: VecDeque::new(),
            total_hits: 0,
            total_misses: 0,
        })
    }

    /// Retrieve a cached derived key or derive it on a miss.
    ///
    /// On a cache miss, Argon2id is invoked with `password` and `salt` and the
    /// result is stored.  On a hit, the cached bytes are returned directly.
    ///
    /// The returned `Vec<u8>` has exactly `output_len` bytes.
    ///
    /// # Errors
    /// - [`CacheError::InvalidOutputLength`] when `output_len` is 0 or > 64.
    /// - [`CacheError::DerivationFailed`] if Argon2id returns an error.
    pub fn get_or_derive(
        &mut self,
        password: &[u8],
        salt: &[u8],
        output_len: usize,
    ) -> Result<Vec<u8>, CacheError> {
        if output_len == 0 || output_len > 64 {
            return Err(CacheError::InvalidOutputLength);
        }

        let cache_key = CacheKey::new(password, salt, output_len);

        if let Some(entry) = self.entries.get_mut(&cache_key) {
            entry.hits = entry.hits.saturating_add(1);
            self.total_hits = self.total_hits.saturating_add(1);
            return Ok(entry.key_bytes.clone());
        }

        // Cache miss — derive with Argon2id.
        self.total_misses = self.total_misses.saturating_add(1);
        let (full_key, _) = kdf::derive_key(
            // derive_key takes &str; convert password bytes via lossy UTF-8
            &String::from_utf8_lossy(password),
            Some(salt),
        );
        let key_bytes = full_key[..output_len].to_vec();

        // Evict oldest entry if at capacity.
        if self.entries.len() >= self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            }
        }

        self.entries.insert(
            cache_key.clone(),
            CacheEntry {
                key_bytes: key_bytes.clone(),
                hits: 0,
            },
        );
        self.order.push_back(cache_key);
        Ok(key_bytes)
    }

    /// Invalidate (remove) the cache entry for the given password + salt + output_len triple.
    ///
    /// Returns `true` when an entry was present and removed, `false` otherwise.
    pub fn invalidate(&mut self, password: &[u8], salt: &[u8], output_len: usize) -> bool {
        let key = CacheKey::new(password, salt, output_len);
        if self.entries.remove(&key).is_some() {
            self.order.retain(|k| k != &key);
            true
        } else {
            false
        }
    }

    /// Remove all cached entries.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.order.clear();
    }

    /// Return current statistics without clearing them.
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            size: self.entries.len(),
            capacity: self.capacity,
            total_hits: self.total_hits,
            total_misses: self.total_misses,
        }
    }

    /// Number of entries currently in the cache.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` when the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PW: &[u8] = b"passphrase-test";
    const SALT: &[u8] = b"salt-16-bytesXXX";

    #[test]
    fn test_cache_miss_derives_key() {
        let mut cache = DerivedKeyCache::new(4).unwrap();
        let key = cache.get_or_derive(PW, SALT, 32).expect("should derive");
        assert_eq!(key.len(), 32);
        let stats = cache.stats();
        assert_eq!(stats.total_misses, 1);
        assert_eq!(stats.total_hits, 0);
    }

    #[test]
    fn test_cache_hit_returns_same_bytes() {
        let mut cache = DerivedKeyCache::new(4).unwrap();
        let k1 = cache.get_or_derive(PW, SALT, 32).expect("first");
        let k2 = cache.get_or_derive(PW, SALT, 32).expect("second");
        assert_eq!(k1, k2);
        let stats = cache.stats();
        assert_eq!(stats.total_misses, 1);
        assert_eq!(stats.total_hits, 1);
    }

    #[test]
    fn test_different_output_lengths_are_distinct_entries() {
        let mut cache = DerivedKeyCache::new(8).unwrap();
        let k16 = cache.get_or_derive(PW, SALT, 16).expect("16-byte");
        let k32 = cache.get_or_derive(PW, SALT, 32).expect("32-byte");
        assert_eq!(k16.len(), 16);
        assert_eq!(k32.len(), 32);
        // They are separate cache entries even when the first 16 bytes are identical.
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.stats().total_misses, 2);
    }

    #[test]
    fn test_capacity_evicts_oldest() {
        let mut cache = DerivedKeyCache::new(2).unwrap();
        cache.get_or_derive(b"pw1", SALT, 32).expect("pw1");
        cache.get_or_derive(b"pw2", SALT, 32).expect("pw2");
        assert_eq!(cache.len(), 2);
        // Adding pw3 should evict pw1.
        cache.get_or_derive(b"pw3", SALT, 32).expect("pw3");
        assert_eq!(cache.len(), 2);
        // pw1 should now be a miss again.
        let stats_before = cache.stats();
        cache.get_or_derive(b"pw1", SALT, 32).expect("pw1 again");
        let stats_after = cache.stats();
        assert_eq!(stats_after.total_misses, stats_before.total_misses + 1);
    }

    #[test]
    fn test_invalidate_removes_entry() {
        let mut cache = DerivedKeyCache::new(4).unwrap();
        cache.get_or_derive(PW, SALT, 32).expect("derive");
        assert_eq!(cache.len(), 1);
        let removed = cache.invalidate(PW, SALT, 32);
        assert!(removed);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_invalidate_nonexistent_returns_false() {
        let mut cache = DerivedKeyCache::new(4).unwrap();
        assert!(!cache.invalidate(b"missing", SALT, 32));
    }

    #[test]
    fn test_clear_empties_cache() {
        let mut cache = DerivedKeyCache::new(4).unwrap();
        cache.get_or_derive(PW, SALT, 32).expect("derive");
        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn test_invalid_output_length_rejected() {
        let mut cache = DerivedKeyCache::new(4).unwrap();
        assert!(cache.get_or_derive(PW, SALT, 0).is_err());
        assert!(cache.get_or_derive(PW, SALT, 65).is_err());
    }

    #[test]
    fn test_zero_capacity_rejected() {
        assert!(DerivedKeyCache::new(0).is_err());
    }
}
