"""Prompt injection shielding with detection, signature verification, and optional quarantine."""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
from dataclasses import dataclass
from typing import Iterable, List, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


DEFAULT_PATTERNS = [
    r"ignore\s+previous\s+instructions",
    r"reveal\s+system\s+prompt",
    r"exfiltrat(e|ion)",
    r"developer\s+message",
    r"bypass\s+safety",
    r"<script",
    r"sql\s+injection",
]


@dataclass
class PromptShieldDecision:
    allowed: bool
    risk_score: float
    reason: str
    matched_rules: List[str]


@dataclass
class EncryptedPrompt:
    nonce_b64: str
    ciphertext_b64: str


class PromptInjectionShield:
    """Detect and quarantine malicious prompts before model execution."""

    def __init__(self, patterns: Optional[Iterable[str]] = None, block_threshold: float = 0.35):
        self._patterns = [re.compile(p, re.IGNORECASE) for p in (patterns or DEFAULT_PATTERNS)]
        self.block_threshold = block_threshold

    def analyze(self, prompt: str) -> PromptShieldDecision:
        matched = [p.pattern for p in self._patterns if p.search(prompt)]
        # Each matched high-risk pattern contributes strongly so a single
        # explicit injection indicator can still be blocked.
        risk = min(1.0, len(matched) * 0.4)
        allowed = risk < self.block_threshold
        reason = "allowed" if allowed else "blocked: injection patterns detected"
        return PromptShieldDecision(allowed=allowed, risk_score=risk, reason=reason, matched_rules=matched)

    def sign_prompt(self, prompt: str, signing_key: bytes) -> str:
        digest = hmac.new(signing_key, prompt.encode("utf-8"), hashlib.sha256).digest()
        return base64.b64encode(digest).decode("utf-8")

    def verify_prompt_signature(self, prompt: str, signature_b64: str, signing_key: bytes) -> bool:
        expected = self.sign_prompt(prompt, signing_key)
        return hmac.compare_digest(expected, signature_b64)

    def quarantine_prompt(self, prompt: str, quarantine_key: bytes) -> EncryptedPrompt:
        if len(quarantine_key) != 32:
            raise ValueError("quarantine_key must be exactly 32 bytes")
        nonce = hashlib.sha256(prompt.encode("utf-8")).digest()[:12]
        cipher = AESGCM(quarantine_key)
        ciphertext = cipher.encrypt(nonce, prompt.encode("utf-8"), None)
        return EncryptedPrompt(
            nonce_b64=base64.b64encode(nonce).decode("utf-8"),
            ciphertext_b64=base64.b64encode(ciphertext).decode("utf-8"),
        )

    def restore_quarantined_prompt(self, encrypted: EncryptedPrompt, quarantine_key: bytes) -> str:
        nonce = base64.b64decode(encrypted.nonce_b64)
        ciphertext = base64.b64decode(encrypted.ciphertext_b64)
        cipher = AESGCM(quarantine_key)
        plaintext = cipher.decrypt(nonce, ciphertext, None)
        return plaintext.decode("utf-8")
