# Phase 6 Guide (Distributed & Quantum Ecosystem)

This guide describes the Phase 6 production modules added in the Python SDK.

## Modules

- `abir_guard/federated_vault.py`: CRDT-based federated vault mesh with signed deltas.
- `abir_guard/qkd_network.py`: BB84-style QKD session simulation and transport-key derivation.
- `abir_guard/pq_tls.py`: Hybrid ML-KEM + X25519 key schedule and TLS 1.3 context helpers.
- `abir_guard/wasm_edge.py`: WASM target specs for browser, Deno, and Cloudflare Workers.
- `abir_guard/native_enclave.py`: Native-path attestation metadata for Apple Secure Enclave and Intel SGX.
- `abir_guard/did_identity.py`: DID document and verifiable credential primitives.
- `abir_guard/hsm_cluster.py`: Health-aware, weighted, regional HSM routing and failover.

## Quick Start

```python
from abir_guard.federated_vault import FederatedVaultNode
from abir_guard.qkd_network import Bb84Network

# Federated CRDT sync
cluster_key = b"cluster-shared-key"
a = FederatedVaultNode("node-a", cluster_key)
b = FederatedVaultNode("node-b", cluster_key)
a.put("agent-1", "Y2lwaGVydGV4dA==")
delta = a.export_delta("agent-1")
b.apply_delta(delta)

# QKD session
qkd = Bb84Network(noise_rate=0.02)
session = qkd.run_session(rounds=512)
transport_key = qkd.derive_transport_key(session.sifted_key)
```

## Commercial Readiness Checklist

- Deterministic conflict resolution for distributed writes.
- Signed replication deltas for tamper resistance.
- TLS 1.3 minimum enforced in helper contexts.
- Hardware-aware enclave checks with attestation metadata surface.
- Health/routing failover for multi-provider HSM topology.
- DID and credential verification primitives for identity workflows.

## Deployment Notes

- For full hardware assurance, run on hosts with real YubiKey, TPM2, and SGX/SE capability.
- Use cloud KMS-backed secret storage for federation cluster keys.
- Integrate the generated WASM targets with your existing CI release pipeline.
