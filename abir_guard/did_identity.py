"""Phase 6 DID and verifiable credential primitives (W3C-style)."""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import asdict, dataclass, field
from typing import Dict, List


class DidError(Exception):
    """Raised for DID/VC validation errors."""


@dataclass
class VerificationMethod:
    id: str
    type: str
    controller: str
    publicKeyJwk: Dict[str, str]


@dataclass
class DidDocument:
    id: str
    verificationMethod: List[VerificationMethod] = field(default_factory=list)
    authentication: List[str] = field(default_factory=list)

    def to_json(self) -> str:
        return json.dumps(
            {
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": self.id,
                "verificationMethod": [asdict(v) for v in self.verificationMethod],
                "authentication": self.authentication,
            },
            sort_keys=True,
        )


@dataclass
class VerifiableCredential:
    issuer: str
    subject: str
    claims: Dict[str, str]
    issued_at: int
    proof: str


class DidIdentityManager:
    """Manage DID documents and HMAC-signed verifiable credentials."""

    def __init__(self):
        self._docs: Dict[str, DidDocument] = {}

    def create_document(self, did: str, method: VerificationMethod) -> DidDocument:
        if not did.startswith("did:"):
            raise DidError("invalid DID")
        doc = DidDocument(id=did, verificationMethod=[method], authentication=[method.id])
        self._docs[did] = doc
        return doc

    def get_document(self, did: str) -> DidDocument:
        if did not in self._docs:
            raise DidError("DID not found")
        return self._docs[did]

    def issue_credential(
        self, issuer: str, subject: str, claims: Dict[str, str], issuer_secret: bytes
    ) -> VerifiableCredential:
        issued_at = int(time.time())
        body = json.dumps(
            {"issuer": issuer, "subject": subject, "claims": claims, "issued_at": issued_at},
            sort_keys=True,
        ).encode("utf-8")
        proof = hmac.new(issuer_secret, body, hashlib.sha256).hexdigest()
        return VerifiableCredential(
            issuer=issuer,
            subject=subject,
            claims=claims,
            issued_at=issued_at,
            proof=proof,
        )

    def verify_credential(self, vc: VerifiableCredential, issuer_secret: bytes) -> bool:
        body = json.dumps(
            {
                "issuer": vc.issuer,
                "subject": vc.subject,
                "claims": vc.claims,
                "issued_at": vc.issued_at,
            },
            sort_keys=True,
        ).encode("utf-8")
        expected = hmac.new(issuer_secret, body, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, vc.proof)
