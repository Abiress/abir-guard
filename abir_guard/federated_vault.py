"""Phase 6 federated vault mesh with CRDT-based sync."""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Dict, Optional


class FederationError(Exception):
    """Raised when federation operations fail validation."""


@dataclass
class CrdtRecord:
    """LWW-element record replicated across nodes."""

    key_id: str
    value_b64: str
    logical_ts: int
    node_id: str
    tombstone: bool = False


class FederatedVaultNode:
    """Distributed node with deterministic CRDT conflict resolution."""

    def __init__(self, node_id: str, cluster_key: bytes):
        if not node_id:
            raise ValueError("node_id cannot be empty")
        if not cluster_key:
            raise ValueError("cluster_key cannot be empty")
        self.node_id = node_id
        self._cluster_key = cluster_key
        self._clock = 0
        self._state: Dict[str, CrdtRecord] = {}

    def _tick(self) -> int:
        self._clock = max(self._clock + 1, int(time.time_ns()))
        return self._clock

    def put(self, key_id: str, value_b64: str) -> CrdtRecord:
        ts = self._tick()
        record = CrdtRecord(key_id=key_id, value_b64=value_b64, logical_ts=ts, node_id=self.node_id)
        self._state[key_id] = record
        return record

    def delete(self, key_id: str) -> CrdtRecord:
        ts = self._tick()
        record = CrdtRecord(
            key_id=key_id,
            value_b64="",
            logical_ts=ts,
            node_id=self.node_id,
            tombstone=True,
        )
        self._state[key_id] = record
        return record

    def get(self, key_id: str) -> Optional[CrdtRecord]:
        rec = self._state.get(key_id)
        if rec is None or rec.tombstone:
            return None
        return rec

    def export_delta(self, key_id: str) -> Dict[str, str]:
        rec = self._state.get(key_id)
        if rec is None:
            raise KeyError(key_id)

        payload = {
            "key_id": rec.key_id,
            "value_b64": rec.value_b64,
            "logical_ts": str(rec.logical_ts),
            "node_id": rec.node_id,
            "tombstone": "1" if rec.tombstone else "0",
        }
        mac = hmac.new(
            self._cluster_key,
            json.dumps(payload, sort_keys=True).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        payload["mac"] = mac
        return payload

    def apply_delta(self, payload: Dict[str, str]) -> bool:
        required = {"key_id", "value_b64", "logical_ts", "node_id", "tombstone", "mac"}
        if not required.issubset(payload.keys()):
            raise FederationError("delta missing required fields")

        signed = {k: payload[k] for k in required if k != "mac"}
        expected_mac = hmac.new(
            self._cluster_key,
            json.dumps(signed, sort_keys=True).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected_mac, payload["mac"]):
            raise FederationError("delta MAC verification failed")

        incoming = CrdtRecord(
            key_id=signed["key_id"],
            value_b64=signed["value_b64"],
            logical_ts=int(signed["logical_ts"]),
            node_id=signed["node_id"],
            tombstone=signed["tombstone"] == "1",
        )

        current = self._state.get(incoming.key_id)
        if current is None or self._wins(incoming, current):
            self._state[incoming.key_id] = incoming
            self._clock = max(self._clock, incoming.logical_ts)
            return True
        return False

    @staticmethod
    def _wins(a: CrdtRecord, b: CrdtRecord) -> bool:
        if a.logical_ts != b.logical_ts:
            return a.logical_ts > b.logical_ts
        # deterministic tie-breaker for same timestamp
        return a.node_id > b.node_id

    def snapshot(self) -> Dict[str, CrdtRecord]:
        return dict(self._state)
