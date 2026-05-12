"""Phase 6 BB84-style QKD network simulation."""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from typing import List, Tuple


class QkdNetworkError(Exception):
    """Raised when QKD session cannot be established."""


@dataclass
class QkdSession:
    sifted_key: bytes
    qber: float
    accepted: bool
    rounds: int


class Bb84Network:
    """Simple BB84 channel with configurable noise for key exchange tests."""

    def __init__(self, noise_rate: float = 0.02, acceptance_qber: float = 0.11):
        if not (0.0 <= noise_rate < 1.0):
            raise ValueError("noise_rate must be in [0,1)")
        if not (0.0 < acceptance_qber < 1.0):
            raise ValueError("acceptance_qber must be in (0,1)")
        self.noise_rate = noise_rate
        self.acceptance_qber = acceptance_qber

    def run_session(self, rounds: int = 512) -> QkdSession:
        if rounds <= 0:
            raise ValueError("rounds must be > 0")

        alice_bits = [secrets.randbelow(2) for _ in range(rounds)]
        alice_basis = [secrets.randbelow(2) for _ in range(rounds)]
        bob_basis = [secrets.randbelow(2) for _ in range(rounds)]

        bob_bits: List[int] = []
        for i in range(rounds):
            if alice_basis[i] == bob_basis[i]:
                bit = alice_bits[i]
            else:
                bit = secrets.randbelow(2)

            if secrets.randbelow(10_000) < int(self.noise_rate * 10_000):
                bit ^= 1
            bob_bits.append(bit)

        sifted_alice: List[int] = []
        sifted_bob: List[int] = []
        for i in range(rounds):
            if alice_basis[i] == bob_basis[i]:
                sifted_alice.append(alice_bits[i])
                sifted_bob.append(bob_bits[i])

        if not sifted_alice:
            raise QkdNetworkError("no sifted bits; retry with more rounds")

        mismatches = sum(1 for a, b in zip(sifted_alice, sifted_bob) if a != b)
        qber = mismatches / len(sifted_alice)

        corrected = bytes((a ^ b) & 1 for a, b in zip(sifted_alice, sifted_bob))
        key = hashlib.sha256(corrected).digest()

        return QkdSession(
            sifted_key=key,
            qber=qber,
            accepted=qber <= self.acceptance_qber,
            rounds=rounds,
        )

    @staticmethod
    def derive_transport_key(qkd_key: bytes, context: bytes = b"abir-guard-qkd-transport") -> bytes:
        if not qkd_key:
            raise ValueError("qkd_key cannot be empty")
        return hashlib.sha256(qkd_key + context).digest()
