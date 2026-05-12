"""Model weight encryption helpers for secure at-rest storage and fine-tuning pipelines."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Optional

from .cloud_kms import CloudKmsEnvelope, EnvelopeCiphertext, KmsBackend


@dataclass
class EncryptedModelBundle:
    """Encrypted model artifact with metadata for deterministic restore."""

    artifact: EnvelopeCiphertext
    metadata: Dict[str, str]

    def to_dict(self) -> dict:
        return {
            "artifact": self.artifact.to_dict(),
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "EncryptedModelBundle":
        return cls(
            artifact=EnvelopeCiphertext.from_dict(data["artifact"]),
            metadata=dict(data.get("metadata", {})),
        )


class ModelWeightEncryptor:
    """Encrypt and decrypt model weights using envelope encryption."""

    def __init__(
        self,
        provider: str = "mock",
        key_id: str = "abir-guard:model-weights",
        backend: Optional[KmsBackend] = None,
    ):
        self._envelope = CloudKmsEnvelope(provider=provider, key_id=key_id, backend=backend)

    def encrypt_bytes(self, data: bytes, metadata: Optional[Dict[str, str]] = None) -> EncryptedModelBundle:
        artifact = self._envelope.encrypt(data)
        return EncryptedModelBundle(artifact=artifact, metadata=metadata or {})

    def decrypt_bytes(self, bundle: EncryptedModelBundle) -> bytes:
        return self._envelope.decrypt(bundle.artifact)

    def encrypt_file(
        self,
        source_path: str,
        output_path: str,
        metadata: Optional[Dict[str, str]] = None,
    ) -> EncryptedModelBundle:
        payload = Path(source_path).read_bytes()
        bundle = self.encrypt_bytes(payload, metadata=metadata)
        Path(output_path).write_text(json.dumps(bundle.to_dict(), indent=2), encoding="utf-8")
        return bundle

    def decrypt_file(self, encrypted_bundle_path: str, output_path: str) -> None:
        raw = json.loads(Path(encrypted_bundle_path).read_text(encoding="utf-8"))
        bundle = EncryptedModelBundle.from_dict(raw)
        plaintext = self.decrypt_bytes(bundle)
        Path(output_path).write_bytes(plaintext)

    def secure_fine_tuning_pipeline(
        self,
        artifacts: Iterable[bytes],
        run_id: str,
    ) -> Dict[str, EncryptedModelBundle]:
        """Encrypt intermediate artifacts generated during fine-tuning."""
        result: Dict[str, EncryptedModelBundle] = {}
        for index, artifact in enumerate(artifacts):
            label = f"{run_id}:artifact:{index}"
            result[label] = self.encrypt_bytes(
                artifact,
                metadata={"run_id": run_id, "index": str(index)},
            )
        return result
