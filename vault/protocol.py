"""Wire format shared by the client and server."""

import base64
import json

from pydantic import BaseModel, Field

SIGNING_CONTEXT = "vault-backup-v1"


class Envelope(BaseModel):
    email: str
    payload: str  # Base64-encoded UTF-8 JSON, e.g. {"type": "store", "vault": "<base64>"}
    nonce: int = Field(strict=True, ge=1, le=2**63 - 1)  # upper bound fits SQLite INTEGER
    signature: str  # Base64-encoded Ed25519 signature over signing_bytes()


class RegisterRequest(BaseModel):
    email: str
    public_key: str  # Base64-encoded raw 32-byte Ed25519 public key


class VerifyRequest(BaseModel):
    email: str
    token: str


def normalise_email(email: str) -> str:
    """Canonical form of an email. The client's KDF salt depends on this, so it must not change."""
    return email.strip().lower()


def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64decode(data: str) -> bytes:
    """Strict decode: raises ValueError on anything that isn't valid Base64."""
    return base64.b64decode(data, validate=True)


def signing_bytes(email: str, payload: str, nonce: int) -> bytes:
    """The exact bytes that get signed.

    A JSON array keeps field boundaries unambiguous, and signing the payload's Base64 string as
    received means we never have to canonicalise the inner JSON. The context string stops these
    signatures being valid for any other protocol or version.
    """
    fields = [SIGNING_CONTEXT, email, nonce, payload]
    return json.dumps(fields, separators=(",", ":"), ensure_ascii=True).encode("ascii")
