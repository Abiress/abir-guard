"""Threshold key sharing for multi-agent swarms."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Dict, Iterable, List

# A prime larger than 2^256 to support 256-bit secret reconstruction.
PRIME = 2**521 - 1


@dataclass
class AgentShare:
    agent_id: str
    x: int
    y: int


@dataclass
class QuorumPolicy:
    threshold: int
    total_agents: int


class MultiAgentKeySharing:
    """Split and recover a symmetric key with quorum authorization."""

    def __init__(self, policy: QuorumPolicy):
        if policy.threshold < 2:
            raise ValueError("threshold must be >= 2")
        if policy.threshold > policy.total_agents:
            raise ValueError("threshold cannot exceed total_agents")
        self.policy = policy

    @staticmethod
    def _to_int(secret: bytes) -> int:
        return int.from_bytes(secret, "big")

    @staticmethod
    def _to_bytes(value: int, length: int) -> bytes:
        return value.to_bytes(length, "big")

    def split(self, secret: bytes, agent_ids: Iterable[str]) -> List[AgentShare]:
        ids = list(agent_ids)
        if len(ids) != self.policy.total_agents:
            raise ValueError("agent count mismatch")

        secret_int = self._to_int(secret)
        coeffs = [secret_int] + [
            secrets.randbelow(PRIME - 1) + 1 for _ in range(self.policy.threshold - 1)
        ]

        shares: List[AgentShare] = []
        for idx, agent_id in enumerate(ids, start=1):
            y = 0
            for power, coeff in enumerate(coeffs):
                y = (y + coeff * pow(idx, power, PRIME)) % PRIME
            shares.append(AgentShare(agent_id=agent_id, x=idx, y=y))
        return shares

    def recover(self, shares: Iterable[AgentShare], output_len: int = 32) -> bytes:
        subset = list(shares)
        if len(subset) < self.policy.threshold:
            raise ValueError("insufficient quorum")

        subset = subset[: self.policy.threshold]
        secret = 0
        for i, share_i in enumerate(subset):
            num = 1
            den = 1
            for j, share_j in enumerate(subset):
                if i == j:
                    continue
                num = (num * (-share_j.x)) % PRIME
                den = (den * (share_i.x - share_j.x)) % PRIME
            lagrange = (num * pow(den, PRIME - 2, PRIME)) % PRIME
            secret = (secret + (share_i.y * lagrange)) % PRIME
        return self._to_bytes(secret, output_len)

    def quorum_authorized(self, active_agent_ids: Iterable[str]) -> bool:
        return len(set(active_agent_ids)) >= self.policy.threshold

    def encrypt_for_swarm(self, key_material: bytes, agent_ids: Iterable[str]) -> Dict[str, object]:
        shares = self.split(key_material, agent_ids)
        return {
            "policy": {
                "threshold": self.policy.threshold,
                "total_agents": self.policy.total_agents,
            },
            "shares": [s.__dict__ for s in shares],
        }
