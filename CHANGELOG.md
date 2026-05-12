# Changelog

All notable changes to Abir-Guard are documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added

- **Phase 4 completion updates (Python):**
  - Added `abir_guard/performance_benchmark.py` with async benchmark runner (`Phase4Benchmark`) and target assertion helper (`BenchmarkResult`, `meets_target`).
  - Added YubiKey production-facing hardware helpers in `abir_guard/yubikey_integration.py`:
    - `get_fido2_info()` for CTAP2 capability/introspection
    - `list_piv_slots()` for standard PIV slot occupancy (9a/9c/9d/9e)
  - Added TPM backend routing in `abir_guard/tpm2_seal.py` with optional native TPM2-TSS binding detection and `get_backend_mode()` (`native-tss|cli|software`).
  - Added tests in `tests/test_phase4_performance.py` and extended `tests/test_phase2_hardware.py` for new Phase 4 hardware/benchmark paths.

- **Phase 5 foundations implemented (Python):**
  - Added `abir_guard/model_weight_encryption.py` with envelope-encrypted model artifact bundles and secure fine-tuning artifact pipeline helpers.
  - Added `abir_guard/prompt_injection_shield.py` with prompt risk analysis, HMAC prompt signatures, and encrypted quarantine/restore flow.
  - Added `abir_guard/compliance.py` with GDPR/CCPA/HIPAA primitives: retention windows, right-to-erasure, and audit exports (JSON/CSV).
  - Added `abir_guard/multi_agent_key_sharing.py` with threshold sharing and quorum-based key recovery for agent swarms.
  - Added `abir_guard/secure_enclave_llm.py` with Intel TDX / AMD SEV-SNP style attestation evidence model and attested inference gate.
  - Added `abir_guard/zk_compliance.py` with commitment-based zero-knowledge-style compliance proof generation and verification.
  - Added `abir_guard/ai_red_team.py` with automated AI attack scenario simulation and pass-rate scoring.
- **Phase 5 JavaScript SDK expansion:**
  - Reworked `sdk/js/abir_guard.js` to add WebCrypto AES-GCM path, ML-KEM/ML-DSA provider adapters (with deterministic simulated fallback), and browser extension messaging bridge.
  - Added `sdk/js/abir_guard_test.js` smoke tests for Phase 5 JS APIs.
- Added `tests/test_phase5.py` with Phase 5 unit coverage across all new Python modules.

### Changed

- Extended lazy exports in `abir_guard/__init__.py` to include all Phase 5 classes and helpers.
- Extended lazy exports in `abir_guard/__init__.py` to include `Phase4Benchmark` and `BenchmarkResult`.

### Validation

- `cargo clippy --all-targets --all-features -- -D warnings`: passing.
- `cargo test --all-targets`: passing (`176/176` lib + `2/2` bin tests).
- `python3 tests/run_tests.py`: passing (`5/5` suites).
- `pytest tests/test_abir_guard.py tests/test_phase2_hardware.py tests/test_phase3.py tests/test_phase5.py -v`: passing (`71/71` tests).
- `cd sdk/go && go test -v ./...`: passing.
- `node sdk/js/abir_guard_test.js`: passing (`js_phase5_ok`).

### Benchmarks

- Phase 4 vault async benchmark: `12,000` roundtrips in `0.174s` (`68,961 ops/s`), exceeding the `10,000 ops/s` roadmap target.

- Prompt shield throughput: `347,999 ops/s` over 20,000 prompt analyses.
- Model weight envelope roundtrip (1 MiB payload, mock KMS): `4.77 ms`.
- AI red-team run: score `1.00`, runtime `0.029 ms`.

## [3.2.0] - 2026-05-12

### Added

- **EPIC 1.1 (Confidential Computing - SGX 2.0)**: Completed foundational SGX module set in Rust.
  - Added `src/confidential_computing/sgx/mod.rs` with enclave lifecycle, quote model, PCR policy model, sealing and signing APIs.
  - Added `src/confidential_computing/sgx/enclave_interface.rs` with SGX FFI abstraction stubs and safety-documented interfaces.
  - Added `src/confidential_computing/sgx/attestation.rs` with DCAP/IAS attestation flow abstractions.
  - Added `src/confidential_computing/sgx/sealed_storage.rs` for sealed blob management and policy-bound retrieval.
  - Added `src/confidential_computing/sgx/quote_verifier.rs` for quote validation policy and verification result modeling.

- **EPIC 1.2 (Confidential Computing - ARM TrustZone)**: Advanced TrustZone implementation with command transport and attestation verification.
  - Added `src/confidential_computing/trustzone/mod.rs` with `TrustZoneEnclave`, session config, attestation, sealing, and unsealing interfaces.
  - Added `src/confidential_computing/trustzone/interface.rs` with OP-TEE style command IDs, request/response marshalling, and command dispatch.
  - Added `src/confidential_computing/trustzone/attestation.rs` with attestation policy and verifier for simulated TrustZone reports.
  - Added cross-TEE contract tests (SGX + TrustZone) to validate shared attestation/sealing behavior.
  - Extended `src/confidential_computing/mod.rs` exports to include TrustZone types.

- **EPIC 1.3 (Confidential Computing - Multi-Party Computation)**: Started MPC coordination primitives.
  - Added `src/confidential_computing/mpc/mod.rs` with policy validation, participant registration, share submission, round progression, and deterministic digest finalization.
  - Added MPC error model for invalid policy, duplicate participants/shares, unknown parties, and insufficient shares.
  - Added commit/reveal protocol messages with round checks and anti-replay nonce tracking.
  - Added aggregate message validation to detect digest mismatch before round closure.
  - Extended `src/confidential_computing/mod.rs` exports to include MPC policy/session types.

- **EPIC 1.4 (Confidential Computing - Attestation-as-a-Service)**: Started unified attestation verification facade.
  - Added `src/confidential_computing/attestation_service/mod.rs` with normalized result model for SGX and TrustZone evidence.
  - Added service-level error model for provider-specific verification failures and unsupported evidence types.
  - Added conversion pipeline from SGX quote verification and TrustZone report verification to one unified verdict shape.
  - Added policy-driven routing controls: allowed TEE providers, per-provider freshness SLAs, and minimum trust-level enforcement.
  - Added batch verification APIs for both generic reports and SGX quote collections.
  - Extended `src/confidential_computing/mod.rs` exports to include attestation service types.

- **EPIC 2 (Advanced Secret Sharing)**: VSS commitments, proactive share refresh, participant re-sharing with verifiable `RefreshProof` transcripts, and HMAC-SHA-256 participant MAC binding (`AuthenticatedShare`, `authenticate_share`, `verify_authenticated_share`) — tamper-evident participant identity checks on every re-sharing submission.
- **EPIC 3 (Blockchain Integration)**: Three-layer `blockchain` module — `key_anchor` (SHA-256 on-chain key commitments, owner-gated revocation, `AnchorRegistry`), `dpki` (decentralized PKI facade with validity windows and live anchor checks, `DecentralizedPki`), and `smart_contract` (`SmartContractAnchor` trait + `SimulatedContractAnchor` in-process back-end with simulated block height).
- **EPIC 5 (Interoperability Standards)**: `interop` module with two sub-systems — `jwk` (JWK-like PQC key serialisation: `PqcJwk::from_public`, `from_keypair`, `decode_public_key`, `decode_private_key`, `to_json`/`from_json` for ML-DSA-65 and ML-KEM-1024) and `did` (W3C DID Core facade: `DidDocument` with `add_verification_method`, `get_method`, `remove_method`, relationship tracking for `authentication`/`assertionMethod`/`keyAgreement`, and JSON serialisation).
- **EPIC 6 (Audit & Compliance)**: `audit` module with two sub-systems — `audit_log` (append-only SHA-256 chained `AuditLog` with tamper-evident verification via `verify_chain`) and `compliance` (`ComplianceReport::evaluate` policy checks for auth-failure streaks, revocation criticality, and revoke/rotation ratio constraints).
- **EPIC 7 (Quantum Key Distribution)**: `qkd` module with BB84-inspired simulation — pluggable `EntropySource`, deterministic `XorShift64` source, configurable `QuantumChannel` noise model, and `Bb84Simulator` session reports (`QkdSessionReport`) with QBER estimation and acceptance thresholds.
- **EPIC 4 (Performance Optimization)**: `performance` module with two sub-systems — `key_cache` (bounded LRU-style `DerivedKeyCache` that amortizes Argon2id cost across repeated passphrase+salt requests, with eviction, invalidation, and `CacheStats`) and `batch_ops` (batch ML-DSA sign/verify via `batch_sign`/`batch_verify` returning aggregate `BatchSignResult`/`BatchVerifyResult` without aborting on partial failure).
  - Added `src/advanced_secret_sharing.rs` with verifiable share commitments and share verification helpers.
  - Added `ProactiveRefresher` epoch-based share refresh model for proactive rotation workflows.
  - Added participant-aware proactive re-sharing plan for join/leave redistribution with threshold validation.
  - Added refresh transcript proof generation and plan verification (`verify_reshare_plan`) to detect resharing tamper.
  - Added re-sharing tests for participant join, participant leave, and invalid threshold rejection paths.
  - Added tamper-detection test for resharing proof verification.
  - Extended `src/lib.rs` exports to include advanced secret sharing APIs.

### Changed

- Added Cargo feature declaration for `sgx-simulator` in `Cargo.toml` to support strict linting with feature-gated SGX paths.
- Extended SGX API surface with `Enclave::attestation_config()` accessor and corresponding unit coverage.
- Hardened SGX-dependent Rust tests to gracefully handle non-SGX/non-simulator environments in release profile runs.
- Aligned Python runtime version constant in `abir_guard/__init__.py` to `3.2.0`.

### Validation

- `cargo clippy --all-targets --all-features -- -D warnings`: passing.
- `cargo test --all-targets`: passing (176/176 lib + 2/2 bin tests).
- `cargo test --lib --release`: passing (176/176 tests).
- `python3 tests/run_tests.py`: passing (5/5 suites).
- `pytest tests/test_abir_guard.py tests/test_phase2_hardware.py tests/test_phase3.py -v`: passing (64/64 tests).
- `cd sdk/go && go test -v ./...`: passing.

### Benchmarks

- `cargo bench --no-run` and `cargo bench -- --nocapture`: benchmark stage compiles/executes successfully (no dedicated Rust benchmark functions currently defined).
- Python end-to-end vault micro-benchmark: `2000` generate+encrypt+decrypt cycles in `0.15s` on the current environment.

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

## Version Compatibility

| Version | Python | Rust | Go | Node.js | Status |
|---------|--------|------|-----|---------|--------|
| 3.2.0 | 3.10+ | 1.70+ | 1.21+ | 18+ | ✅ Current |
| 3.1.2 | 3.10+ | 1.70+ | 1.21+ | 18+ | ✅ Stable |
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

**Last Updated**: May 12, 2026  
**Maintained By**: [Abir Maheshwari](https://github.com/Abiress)
