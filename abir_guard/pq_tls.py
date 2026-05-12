"""Phase 6 hybrid post-quantum TLS helpers."""

from __future__ import annotations

import hashlib
import ssl
from dataclasses import dataclass

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import x25519

from .ml_kem import MLKEM1024


@dataclass
class HybridTlsSecrets:
    client_hello_kem_ct: bytes
    shared_secret: bytes
    tls_exporter_secret: bytes


class PostQuantumTls:
    """Hybrid key schedule: ML-KEM + X25519 + HKDF, with TLS 1.3 contexts."""

    def __init__(self, require_pq: bool | None = None):
        self.kem = MLKEM1024(require_pq=require_pq)

    def build_server_context(self, certfile: str, keyfile: str) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
        ctx.options |= ssl.OP_NO_COMPRESSION
        return ctx

    def build_client_context(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.options |= ssl.OP_NO_COMPRESSION
        return ctx

    def derive_hybrid_secret(self, server_kem_public_key: bytes, server_x25519_public_key: bytes) -> HybridTlsSecrets:
        kem_ct, kem_ss = self.kem.encapsulate(server_kem_public_key)

        eph_sk = x25519.X25519PrivateKey.generate()
        server_pk = x25519.X25519PublicKey.from_public_bytes(server_x25519_public_key)
        x25519_ss = eph_sk.exchange(server_pk)

        combined = hashlib.sha256(kem_ss + x25519_ss).digest()
        exporter = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"abir-guard-pq-tls-v1",
            info=b"tls13-exporter",
            backend=default_backend(),
        ).derive(combined)

        return HybridTlsSecrets(
            client_hello_kem_ct=kem_ct,
            shared_secret=combined,
            tls_exporter_secret=exporter,
        )
