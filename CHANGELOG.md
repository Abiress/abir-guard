# Changelog

All notable changes to Abir-Guard are documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [3.1.2] - 2026-05-11

### Security Fixes 🔐

- **Argon2id KDF API Correctness**: Fixed parameter order in `Argon2id` initialization (Python)
  - Parameters now correctly ordered: `salt`, `length`, `iterations`, `lanes`, `memory_cost`
  - Ensures OWASP-compliant key derivation with proper entropy mixing
  - Affected module: `abir_guard/crypto_store.py`

- **YubiKey RSA Padding**: Fixed undefined `pkcs1v15` module reference in YubiKey integration
  - Replaced with correct `padding.PSS()` from cryptography library
  - Ensures RSA-PSS signature verification works correctly with YubiKey hardware
  - Affected module: `abir_guard/yubikey_integration.py`

### Type Safety Improvements 🎯

- **Comprehensive Type Annotations**: Added full type hints across critical security modules
  - `abir_guard/revocation.py`: `Optional[bytes]`, `Dict[str, object]`, `List[Dict[str, object]]`
  - `abir_guard/rotation.py`: Return type hints (`-> None`), `Optional[float]`, `Optional[int]`
  - All core security modules now pass `mypy --strict` type checking
  - Improves IDE autocomplete and catches potential bugs at development time

### Code Quality 📐

- **Rust Formatting**: Applied `cargo fmt` across all 12 Rust modules
  - Consistent code style across `src/` directory
  - Import reorganization for readability
  - Affected modules: `lib.rs`, `main.rs`, `shamir.rs`, `persistent_vault.rs`, `quantum_kernel.rs`, `mcp_gateway.rs`, `ml_dsa.rs`, `kdf.rs`, `revocation.rs`, `entropy_inject.rs`, `differential_privacy.rs`, `zero_copy.rs`
  - **No logic changes** — formatting only

- **YubiKey Module Detection**: Improved robustness of hardware module detection
  - Now uses `importlib.util.find_spec()` for safe module availability checking
  - Graceful fallback to software crypto when hardware unavailable
  - Better error messages for missing dependencies (`fido2`, `ykman`)

### Build & Configuration ⚙️

- **Modern Python Packaging** (PEP 621):
  - Changed license format from `{text = "MIT"}` to SPDX `"MIT"`
  - Removed `setuptools-scm` from build requirements (version explicitly set in `pyproject.toml`)
  - Removed deprecated `License :: OSI Approved :: MIT License` classifier
  - Improved build reproducibility

- **Mypy Configuration**: Added `ignore_missing_imports = true` for cleaner type checking output
  - Reduces noise from untyped third-party dependencies
  - Focuses type checking on codebase quality

### Testing 🧪

- **Test Runner Fix**: Corrected JavaScript SDK path in test runner
  - Fixed path from `../src/abir_guard.js` → `../sdk/js/abir_guard.js`
  - Ensures `test_js_sdk()` properly validates JavaScript module presence
  - Test suite: **96/96 tests passing** (32 Rust + 64 Python + Go)

### Type Casting Improvements

- **GCM Encryption/Decryption**: Added explicit type casts for `AESGCM.encrypt()` and `AESGCM.decrypt()`
  - Satisfies mypy type checker while maintaining runtime safety
  - Affected module: `abir_guard/crypto_store.py`

- **YubiKey Signing**: Added explicit type cast for `piv.sign_data()` return value
  - Ensures type safety in YubiKey integration layer
  - Affected module: `abir_guard/yubikey_integration.py`

### Commits

```
0b4ce04 fix(security): correct Argon2id KDF API and YubiKey RSA padding
5ce2d16 refactor(type-safety): add comprehensive type annotations to key rotation and revocation modules
b0ee8d5 style: apply rustfmt formatting and reorganize imports across all Rust modules
1a3f8df build(config): fix pyproject.toml packaging metadata and mypy configuration
42217a0 test(fix): correct JavaScript SDK path in test runner
```

### Validation ✅

- **Rust Tests**: 32/32 passing (no warnings with `cargo clippy -D warnings`)
- **Python Tests**: 64/64 passing (mypy strict mode on core modules)
- **Go Tests**: All SDK tests passing
- **Build**: Clean build with zero warnings
- **Type Checking**: All critical security modules mypy-compliant

---

## [3.1.1] - 2026-04-15

### Added

- **ML-DSA-65 Quantum Signature Support**: Post-quantum digital signatures per NIST FIPS 204
- **Persistent Encrypted Vault**: AES-256-GCM encrypted key storage with Argon2id KDF
- **Key Lifecycle Management**: Automatic rotation (time/usage-based) and revocation with CRL
- **Shamir Secret Sharing**: Threshold cryptography (t-of-n) over GF(251)
- **Hardware Security Integration**: YubiKey PIV/FIDO2, TPM 2.0 sealing, SGX/TrustZone abstraction
- **Differential Privacy**: Laplace noise injection to defeat Spectre/Meltdown timing attacks
- **MCP Server**: JSON-RPC 2.0 gateway for remote vault access
- **Framework Integration**: LangChain, CrewAI, and custom agent support
- **Remote Attestation**: Binary integrity verification and challenge-response protocol
- **FIPS 140-3 Mode**: Approved algorithm fallbacks for compliance

### Testing

- **Test Suite**: 109+ comprehensive unit tests across Python, Rust, Go, JavaScript
  - 65+ Python tests covering crypto, HSM, revocation, rotation, differential privacy
  - 32+ Rust tests for Shamir, ML-DSA, ML-KEM, KDF, MCP gateway
  - 12+ Go SDK tests for cross-language validation

---

## [3.0.0] - 2026-03-01

### Initial Release

- **Quantum-Resistant Encryption**: ML-KEM-1024 (NIST FIPS 203) key encapsulation
- **Hybrid Cryptography**: ML-KEM + X25519 + AES-256-GCM for forward compatibility
- **Cross-Platform Support**: Python, Rust, Go, JavaScript/TypeScript SDKs
- **Zero-Copy Vault**: Memory-safe key operations with zeroization
- **Encrypted Persistence**: Disk-backed secure key storage
- **CLI Tool**: Full-featured command-line interface for vault operations

---

## Planned Features

### [3.2.0] - Phase 4: Enterprise & Confidential Computing (Q3 2026)

#### Confidential Computing Integration
- **SGX 2.0 Enclave Support**: Verified attestation and secure enclaves for MPC
- **TrustZone TEE**: ARM confidential computing for resource-constrained agents
- **Secure Multi-Party Computation**: Threshold signing across distributed agents
- **Attestation as a Service**: Remote validation of agent integrity

#### Advanced Secret Sharing
- **Verifiable Secret Sharing (VSS)**: Byzantine fault-tolerant threshold cryptography
- **Proactive Re-sharing**: Long-lived key rotation without re-initialization
- **Distributed Threshold Signatures**: Multi-party ECDSA/EdDSA schemes
- **Shamir Parameter Optimization**: Adaptive threshold selection based on agent topology

#### Blockchain Integration
- **Immutable Key Material Anchoring**: Deposit secrets on Ethereum, Solana, Polygon
- **Decentralized PKI**: Agent identity certificates via blockchain
- **Smart Contract Key Policies**: On-chain rules for key access and rotation
- **Cross-Chain Attestation**: Unified identity across multiple blockchains

#### Performance Optimization
- **GPU-Accelerated ML-KEM**: CUDA/HIP kernels for high-throughput encryption
- **AES-NI Hardware Acceleration**: Native CPU extensions for symmetric crypto
- **Batch Key Derivation**: Parallel Argon2id KDF for bulk operations
- **MPC Accelerators**: Specialized hardware support for threshold operations

#### Interoperability Standards
- **PKCS#11 HSM Interface**: Standard hardware security module compatibility
- **OpenKeychain Support**: Seamless integration with key management systems
- **Hardware Security Module Federation**: Multi-HSM orchestration
- **OpenPGP Compatibility**: Legacy key format support for migration

#### Enhanced Audit & Compliance
- **SOC 2 Type II Logging**: Compliant audit trail with tamper-evident logs
- **GDPR Key Destruction**: Cryptographically certified key deletion proofs
- **Compliance Report Generation**: Automated audit reports for regulatory bodies
- **Key Provenance Tracking**: Complete lineage and custody history

#### Quantum Key Distribution (QKD)
- **BB84 Protocol Implementation**: Quantum-secure key distribution
- **QKD Appliance Integration**: Support for commercial QKD hardware
- **Hybrid QKD + PQC**: Ultra-high-security environments combining both methods
- **Satellite QKD Support**: Space-based key distribution for global agents

---

## Version Compatibility

| Version | Python | Rust | Go | Node.js | Status |
|---------|--------|------|-----|---------|--------|
| 3.1.2 | 3.10+ | 1.70+ | 1.21+ | 18+ | ✅ Current |
| 3.1.1 | 3.10+ | 1.70+ | 1.21+ | 18+ | ✅ Stable |
| 3.0.0 | 3.10+ | 1.70+ | 1.21+ | 18+ | ⏳ Legacy |

---

## Support & Security

- **Security Reports**: Please report vulnerabilities to [SECURITY.md](SECURITY.md)
- **Issues**: GitHub Issues for bugs and feature requests
- **Discussions**: GitHub Discussions for Q&A and ideas
- **Documentation**: [README.md](README.md) and inline code comments

---

## License

Abir-Guard is released under the [MIT License](LICENSE).

---

**Last Updated**: May 11, 2026  
**Maintained By**: [Abir Maheshwari](https://github.com/Abiress)
