"""GDPR/CCPA/HIPAA-oriented compliance primitives for AI memory vault workflows."""

from __future__ import annotations

import csv
import io
import json
import time
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class ComplianceRecord:
    record_id: str
    subject_id: str
    payload: str
    purpose: str
    created_at: float
    retention_days: int
    tags: List[str]


class ComplianceManager:
    """In-memory compliance state with deterministic exports for auditing."""

    def __init__(self):
        self._records: Dict[str, ComplianceRecord] = {}
        self._audit_events: List[dict] = []

    def add_record(
        self,
        record_id: str,
        subject_id: str,
        payload: str,
        purpose: str,
        retention_days: int,
        tags: Optional[List[str]] = None,
    ) -> ComplianceRecord:
        rec = ComplianceRecord(
            record_id=record_id,
            subject_id=subject_id,
            payload=payload,
            purpose=purpose,
            created_at=time.time(),
            retention_days=retention_days,
            tags=list(tags or []),
        )
        self._records[record_id] = rec
        self._audit_events.append({"event": "add_record", "record_id": record_id, "ts": rec.created_at})
        return rec

    def right_to_erasure(self, subject_id: str) -> int:
        to_delete = [rid for rid, rec in self._records.items() if rec.subject_id == subject_id]
        for rid in to_delete:
            del self._records[rid]
            self._audit_events.append({"event": "erase_record", "record_id": rid, "subject_id": subject_id, "ts": time.time()})
        return len(to_delete)

    def purge_expired(self, now: Optional[float] = None) -> int:
        current = now if now is not None else time.time()
        expired: List[str] = []
        for rid, rec in self._records.items():
            expiry = rec.created_at + (rec.retention_days * 86400)
            if current >= expiry:
                expired.append(rid)
        for rid in expired:
            del self._records[rid]
            self._audit_events.append({"event": "retention_purge", "record_id": rid, "ts": current})
        return len(expired)

    def export_audit_json(self) -> str:
        return json.dumps(self._audit_events, indent=2)

    def export_audit_csv(self) -> str:
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=["event", "record_id", "subject_id", "ts"])
        writer.writeheader()
        for evt in self._audit_events:
            writer.writerow(
                {
                    "event": evt.get("event", ""),
                    "record_id": evt.get("record_id", ""),
                    "subject_id": evt.get("subject_id", ""),
                    "ts": evt.get("ts", ""),
                }
            )
        return buffer.getvalue()

    def compliance_summary(self) -> dict:
        return {
            "records": len(self._records),
            "audit_events": len(self._audit_events),
            "frameworks": ["GDPR", "CCPA", "HIPAA"],
        }
