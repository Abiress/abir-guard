"""HashiCorp Vault Transit backend integration.

This module implements a minimal Vault Transit client for enterprise secret
management workflows.
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from typing import Optional
from urllib import request


class VaultTransitError(Exception):
    """Raised when Vault Transit operations fail."""


@dataclass
class VaultTransitConfig:
    address: str
    token: str
    mount_path: str = "transit"
    timeout_seconds: int = 10


class VaultTransitClient:
    """HTTP client for Vault Transit encrypt/decrypt operations."""

    def __init__(self, config: Optional[VaultTransitConfig] = None):
        if config is None:
            address = os.environ.get("VAULT_ADDR", "").strip()
            token = os.environ.get("VAULT_TOKEN", "").strip()
            if not address or not token:
                raise VaultTransitError(
                    "VaultTransitClient requires VAULT_ADDR and VAULT_TOKEN or explicit config"
                )
            config = VaultTransitConfig(address=address, token=token)
        self.config = config

    def _post_json(self, path: str, body: dict) -> dict:
        url = f"{self.config.address.rstrip('/')}{path}"
        data = json.dumps(body).encode("utf-8")

        req = request.Request(url=url, method="POST", data=data)
        req.add_header("Content-Type", "application/json")
        req.add_header("X-Vault-Token", self.config.token)

        try:
            with request.urlopen(req, timeout=self.config.timeout_seconds) as resp:
                raw = resp.read().decode("utf-8")
                return json.loads(raw)
        except Exception as exc:
            raise VaultTransitError(f"Vault request failed: {exc}") from exc

    def encrypt(self, key_name: str, plaintext: bytes, context: Optional[bytes] = None) -> str:
        payload = {"plaintext": base64.b64encode(plaintext).decode("utf-8")}
        if context:
            payload["context"] = base64.b64encode(context).decode("utf-8")

        path = f"/v1/{self.config.mount_path}/encrypt/{key_name}"
        resp = self._post_json(path, payload)

        try:
            return resp["data"]["ciphertext"]
        except Exception as exc:
            raise VaultTransitError(f"Unexpected Vault encrypt response: {resp}") from exc

    def decrypt(self, key_name: str, ciphertext: str, context: Optional[bytes] = None) -> bytes:
        payload = {"ciphertext": ciphertext}
        if context:
            payload["context"] = base64.b64encode(context).decode("utf-8")

        path = f"/v1/{self.config.mount_path}/decrypt/{key_name}"
        resp = self._post_json(path, payload)

        try:
            encoded = resp["data"]["plaintext"]
            return base64.b64decode(encoded)
        except Exception as exc:
            raise VaultTransitError(f"Unexpected Vault decrypt response: {resp}") from exc

    def health(self) -> bool:
        path = "/v1/sys/health"
        try:
            self._post_json(path, {})
            return True
        except VaultTransitError:
            return False
