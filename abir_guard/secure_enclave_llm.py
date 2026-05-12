"""TEE-attested inference facade for Intel TDX and AMD SEV-SNP style workflows."""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import Callable, Dict


@dataclass
class AttestationEvidence:
    provider: str
    measurement: str
    nonce: str
    issued_at: float


class SecureEnclaveLLM:
    """Simulated attested inference gate usable in local and CI pipelines."""

    def __init__(self, max_age_seconds: int = 300):
        self.max_age_seconds = max_age_seconds
        self._providers: Dict[str, str] = {
            "intel-tdx": "intel-tdx-root",
            "amd-sev-snp": "amd-sev-snp-root",
        }

    def create_evidence(self, provider: str, model_hash: str, nonce: str) -> AttestationEvidence:
        if provider not in self._providers:
            raise ValueError(f"unsupported provider: {provider}")
        root = self._providers[provider].encode("utf-8")
        measurement = hashlib.sha256(root + model_hash.encode("utf-8") + nonce.encode("utf-8")).hexdigest()
        return AttestationEvidence(
            provider=provider,
            measurement=measurement,
            nonce=nonce,
            issued_at=time.time(),
        )

    def verify_evidence(self, evidence: AttestationEvidence, model_hash: str) -> bool:
        age = time.time() - evidence.issued_at
        if age > self.max_age_seconds:
            return False
        expected = self.create_evidence(evidence.provider, model_hash, evidence.nonce)
        return expected.measurement == evidence.measurement

    def run_attested_inference(
        self,
        provider: str,
        model_hash: str,
        nonce: str,
        inference_fn: Callable[[str], str],
        prompt: str,
    ) -> str:
        evidence = self.create_evidence(provider, model_hash, nonce)
        if not self.verify_evidence(evidence, model_hash):
            raise RuntimeError("attestation verification failed")
        return inference_fn(prompt)
