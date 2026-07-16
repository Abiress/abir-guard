"""Phase 6 tests: distributed + quantum + identity + hsm cluster."""

from __future__ import annotations


class TestFederatedVault:
    def test_crdt_sync_and_delete(self):
        from abir_guard.federated_vault import FederatedVaultNode

        cluster_key = b"cluster-key"
        a = FederatedVaultNode("a", cluster_key)
        b = FederatedVaultNode("b", cluster_key)

        a.put("k1", "Y2lwaGVydGV4dA==")
        delta = a.export_delta("k1")
        assert b.apply_delta(delta) is True
        assert b.get("k1") is not None

        a.delete("k1")
        delta_del = a.export_delta("k1")
        b.apply_delta(delta_del)
        assert b.get("k1") is None

    def test_delta_mac_validation(self):
        from abir_guard.federated_vault import FederatedVaultNode, FederationError

        a = FederatedVaultNode("a", b"key")
        b = FederatedVaultNode("b", b"key")
        a.put("k", "v")
        delta = a.export_delta("k")
        delta["value_b64"] = "tampered"
        try:
            b.apply_delta(delta)
            assert False
        except FederationError:
            assert True


class TestQkdNetwork:
    def test_qkd_session(self):
        from abir_guard.qkd_network import Bb84Network

        qkd = Bb84Network(noise_rate=0.01)
        s = qkd.run_session(rounds=256)
        assert len(s.sifted_key) == 32
        assert 0.0 <= s.qber <= 1.0
        assert isinstance(s.accepted, bool)


class TestPostQuantumTls:
    def test_hybrid_secret_derivation(self):
        from abir_guard.ml_kem import MLKEM1024
        from abir_guard.pq_tls import PostQuantumTls
        from cryptography.hazmat.primitives.asymmetric import x25519

        kem = MLKEM1024(require_pq=False)
        pk, _ = kem.keygen()

        x_sk = x25519.X25519PrivateKey.generate()
        x_pk = x_sk.public_key().public_bytes_raw()

        pq = PostQuantumTls()
        sec = pq.derive_hybrid_secret(pk, x_pk)
        assert len(sec.shared_secret) == 32
        assert len(sec.tls_exporter_secret) == 32


class TestWasmEdge:
    def test_specs(self):
        from abir_guard.wasm_edge import WasmEdgeBuilder

        builder = WasmEdgeBuilder()
        specs = builder.all_specs()
        assert "browser" in specs
        assert "deno" in specs
        assert "cloudflare" in specs


class TestNativeEnclave:
    def test_attestation_surface(self):
        from abir_guard.native_enclave import AppleSecureEnclaveNative, IntelSgxNative

        nonce = b"nonce"
        apple = AppleSecureEnclaveNative().attest(nonce)
        sgx = IntelSgxNative().attest(nonce)
        assert apple.platform == "apple_secure_enclave"
        assert sgx.platform == "intel_sgx"


class TestDidIdentity:
    def test_issue_and_verify_credential(self):
        from abir_guard.did_identity import DidIdentityManager, VerificationMethod

        mgr = DidIdentityManager()
        did = "did:example:issuer"
        method = VerificationMethod(
            id=f"{did}#key-1",
            type="JsonWebKey2020",
            controller=did,
            publicKeyJwk={"kty": "OKP", "crv": "Ed25519", "x": "abc"},
        )
        doc = mgr.create_document(did, method)
        assert doc.id == did

        secret = b"issuer-secret"
        vc = mgr.issue_credential(did, "did:example:holder", {"role": "agent"}, secret)
        assert mgr.verify_credential(vc, secret) is True
        assert mgr.verify_credential(vc, b"wrong") is False


class _Provider:
    def __init__(self, region: str, healthy: bool, sig: bytes):
        self.region = region
        self._healthy = healthy
        self._sig = sig

    def is_healthy(self) -> bool:
        return self._healthy

    def sign(self, key_id: str, data: bytes) -> bytes:
        return self._sig + key_id.encode() + data


class TestHsmCluster:
    def test_failover(self):
        from abir_guard.hsm_cluster import ClusterProvider, HsmCluster

        p1 = _Provider("us-east", healthy=False, sig=b"a")
        p2 = _Provider("eu-west", healthy=True, sig=b"b")

        cluster = HsmCluster(
            [
                ClusterProvider("p1", "us-east", 2, p1),
                ClusterProvider("p2", "eu-west", 1, p2),
            ]
        )
        out = cluster.sign("kid", b"data", preferred_region="us-east")
        assert out.startswith(b"b")
