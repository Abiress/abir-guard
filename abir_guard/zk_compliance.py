"""Zero-knowledge-style compliance proofs via commitment verification.

This module uses commitment proofs that avoid disclosing plaintext while allowing
an auditor to verify evidence against pre-registered digests.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass


@dataclass
class ComplianceProof:
    commitment: str
    ciphertext_digest: str
    public_salt: str


class ZkComplianceProver:
    def create_proof(self, plaintext: bytes, ciphertext: bytes, policy_id: str) -> ComplianceProof:
        plaintext_digest = hashlib.sha256(plaintext).hexdigest()
        ciphertext_digest = hashlib.sha256(ciphertext).hexdigest()
        salt = secrets.token_hex(16)
        commitment = hashlib.sha256(
            f"{plaintext_digest}:{ciphertext_digest}:{policy_id}:{salt}".encode("utf-8")
        ).hexdigest()
        return ComplianceProof(
            commitment=commitment,
            ciphertext_digest=ciphertext_digest,
            public_salt=salt,
        )


class ZkComplianceVerifier:
    def verify(
        self,
        proof: ComplianceProof,
        expected_plaintext_digest: str,
        ciphertext: bytes,
        policy_id: str,
    ) -> bool:
        ciphertext_digest = hashlib.sha256(ciphertext).hexdigest()
        if ciphertext_digest != proof.ciphertext_digest:
            return False
        check = hashlib.sha256(
            f"{expected_plaintext_digest}:{ciphertext_digest}:{policy_id}:{proof.public_salt}".encode(
                "utf-8"
            )
        ).hexdigest()
        return check == proof.commitment
