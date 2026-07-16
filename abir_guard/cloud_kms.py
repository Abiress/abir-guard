"""Cloud KMS envelope encryption backends (AWS KMS / GCP KMS).

This module provides a unified interface for envelope encryption using
cloud-managed key encryption keys (KEKs). It supports:
- AWS KMS via boto3 (optional dependency)
- GCP Cloud KMS via google-cloud-kms (optional dependency)
- LocalMock backend for offline development and tests
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass
from typing import Optional, Protocol

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class KmsError(Exception):
    """Raised when KMS operations fail."""


class KmsBackend(Protocol):
    def wrap_key(self, plaintext_key: bytes) -> bytes:
        """Encrypt a data encryption key (DEK) using a cloud KMS KEK."""

    def unwrap_key(self, wrapped_key: bytes) -> bytes:
        """Decrypt a wrapped DEK using cloud KMS."""


@dataclass
class EnvelopeCiphertext:
    """Envelope encrypted payload.

    wrapped_key: DEK encrypted by KMS
    nonce: AES-GCM nonce used for payload encryption
    ciphertext: AES-GCM ciphertext (includes auth tag)
    provider: backend provider identifier (aws|gcp|mock)
    key_id: cloud key identifier
    """

    wrapped_key: str
    nonce: str
    ciphertext: str
    provider: str
    key_id: str

    def to_dict(self) -> dict:
        return {
            "wrapped_key": self.wrapped_key,
            "nonce": self.nonce,
            "ciphertext": self.ciphertext,
            "provider": self.provider,
            "key_id": self.key_id,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "EnvelopeCiphertext":
        return cls(
            wrapped_key=data["wrapped_key"],
            nonce=data["nonce"],
            ciphertext=data["ciphertext"],
            provider=data["provider"],
            key_id=data["key_id"],
        )


class LocalMockKmsBackend:
    """Offline mock backend for local development.

    This backend deterministically derives a wrapping key from `key_id` and is
    intended only for local testing when cloud credentials are unavailable.
    """

    def __init__(self, key_id: str):
        self.key_id = key_id
        self._wrapping_key = hashlib.sha256(key_id.encode("utf-8")).digest()

    def wrap_key(self, plaintext_key: bytes) -> bytes:
        return bytes(
            b ^ self._wrapping_key[i % len(self._wrapping_key)] for i, b in enumerate(plaintext_key)
        )

    def unwrap_key(self, wrapped_key: bytes) -> bytes:
        return self.wrap_key(wrapped_key)


class AwsKmsBackend:
    """AWS KMS backend using boto3."""

    def __init__(self, key_id: str, region: Optional[str] = None):
        self.key_id = key_id
        try:
            import boto3  # type: ignore
        except Exception as exc:
            raise KmsError("boto3 is required for AwsKmsBackend") from exc

        kwargs = {}
        if region:
            kwargs["region_name"] = region
        self._client = boto3.client("kms", **kwargs)

    def wrap_key(self, plaintext_key: bytes) -> bytes:
        try:
            resp = self._client.encrypt(KeyId=self.key_id, Plaintext=plaintext_key)
            return resp["CiphertextBlob"]
        except Exception as exc:
            raise KmsError(f"AWS KMS encrypt failed: {exc}") from exc

    def unwrap_key(self, wrapped_key: bytes) -> bytes:
        try:
            resp = self._client.decrypt(CiphertextBlob=wrapped_key)
            return resp["Plaintext"]
        except Exception as exc:
            raise KmsError(f"AWS KMS decrypt failed: {exc}") from exc


class GcpKmsBackend:
    """GCP Cloud KMS backend using google-cloud-kms."""

    def __init__(self, key_id: str):
        self.key_id = key_id
        try:
            from google.cloud import kms_v1  # type: ignore
        except Exception as exc:
            raise KmsError("google-cloud-kms is required for GcpKmsBackend") from exc

        self._client = kms_v1.KeyManagementServiceClient()

    def wrap_key(self, plaintext_key: bytes) -> bytes:
        try:
            resp = self._client.encrypt(request={"name": self.key_id, "plaintext": plaintext_key})
            return resp.ciphertext
        except Exception as exc:
            raise KmsError(f"GCP KMS encrypt failed: {exc}") from exc

    def unwrap_key(self, wrapped_key: bytes) -> bytes:
        try:
            resp = self._client.decrypt(request={"name": self.key_id, "ciphertext": wrapped_key})
            return resp.plaintext
        except Exception as exc:
            raise KmsError(f"GCP KMS decrypt failed: {exc}") from exc


class CloudKmsEnvelope:
    """Envelope encryption/decryption through a pluggable KMS backend."""

    def __init__(self, provider: str, key_id: str, backend: Optional[KmsBackend] = None):
        self.provider = provider.lower()
        self.key_id = key_id

        if backend is not None:
            self._backend = backend
            return

        if self.provider == "aws":
            self._backend = AwsKmsBackend(key_id)
        elif self.provider == "gcp":
            self._backend = GcpKmsBackend(key_id)
        elif self.provider == "mock":
            self._backend = LocalMockKmsBackend(key_id)
        else:
            raise KmsError(f"Unsupported KMS provider: {provider}")

    def encrypt(self, plaintext: bytes, aad: Optional[bytes] = None) -> EnvelopeCiphertext:
        dek = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)

        cipher = AESGCM(dek)
        ct = cipher.encrypt(nonce, plaintext, aad)
        wrapped = self._backend.wrap_key(dek)

        return EnvelopeCiphertext(
            wrapped_key=base64.b64encode(wrapped).decode("utf-8"),
            nonce=base64.b64encode(nonce).decode("utf-8"),
            ciphertext=base64.b64encode(ct).decode("utf-8"),
            provider=self.provider,
            key_id=self.key_id,
        )

    def decrypt(self, payload: EnvelopeCiphertext, aad: Optional[bytes] = None) -> bytes:
        if payload.provider != self.provider:
            raise KmsError(
                f"Provider mismatch: payload={payload.provider}, configured={self.provider}"
            )

        wrapped = base64.b64decode(payload.wrapped_key)
        nonce = base64.b64decode(payload.nonce)
        ct = base64.b64decode(payload.ciphertext)

        dek = self._backend.unwrap_key(wrapped)
        cipher = AESGCM(dek)
        return cipher.decrypt(nonce, ct, aad)
