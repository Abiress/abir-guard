"""Phase 6 multi-HSM cluster routing with failover and region awareness."""

from __future__ import annotations

import itertools
from dataclasses import dataclass
from typing import Dict, List, Protocol


class HsmClusterError(Exception):
    """Raised when HSM cluster cannot serve requests."""


class HsmProvider(Protocol):
    region: str

    def is_healthy(self) -> bool:
        ...

    def sign(self, key_id: str, data: bytes) -> bytes:
        ...


@dataclass
class ClusterProvider:
    provider_id: str
    region: str
    weight: int
    provider: HsmProvider


class HsmCluster:
    """Weighted, health-aware provider selection with regional failover."""

    def __init__(self, providers: List[ClusterProvider]):
        if not providers:
            raise ValueError("providers cannot be empty")
        self._providers = providers
        weighted_ids: List[int] = []
        for idx, p in enumerate(providers):
            weighted_ids.extend([idx] * max(1, p.weight))
        self._cycle = itertools.cycle(weighted_ids)

    def healthy_regions(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for p in self._providers:
            if p.provider.is_healthy():
                counts[p.region] = counts.get(p.region, 0) + 1
        return counts

    def sign(self, key_id: str, data: bytes, preferred_region: str | None = None) -> bytes:
        candidates = self._providers
        if preferred_region is not None:
            regional = [p for p in candidates if p.region == preferred_region]
            if regional:
                candidates = regional

        healthy = [p for p in candidates if p.provider.is_healthy()]
        if not healthy:
            # regional failover to any healthy provider
            healthy = [p for p in self._providers if p.provider.is_healthy()]
        if not healthy:
            raise HsmClusterError("no healthy HSM providers available")

        index_map = {id(p): i for i, p in enumerate(self._providers)}
        for _ in range(len(self._providers) * 2):
            idx = next(self._cycle)
            provider = self._providers[idx]
            if provider in healthy:
                return provider.provider.sign(key_id, data)

        # deterministic fallback if weighted cycle did not pick a healthy candidate quickly
        return healthy[0].provider.sign(key_id, data)
