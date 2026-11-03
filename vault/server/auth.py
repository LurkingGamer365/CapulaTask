"""Authentication of signed request envelopes."""

import json
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from vault.protocol import Envelope, b64decode, normalise_email, signing_bytes
from vault.server.db import Database


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str):
        self.status = status
        self.code = code
        self.message = message


@dataclass
class AuthenticatedRequest:
    email: str
    nonce: int
    body: dict  # the decoded payload


def replayed_nonce_error() -> ApiError:
    return ApiError(409, "replayed_nonce", "Nonce must be greater than the last accepted nonce")


def _signature_is_valid(public_key: bytes, envelope: Envelope) -> bool:
    message = signing_bytes(envelope.email, envelope.payload, envelope.nonce)
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(b64decode(envelope.signature), message)
    except (InvalidSignature, ValueError):
        return False
    return True


def _decode_payload(payload: str) -> dict:
    try:
        body = json.loads(b64decode(payload).decode("utf-8"))
    except ValueError as error:
        raise ApiError(400, "malformed_payload", "Payload must be Base64 UTF-8 JSON") from error
    if not isinstance(body, dict):
        raise ApiError(400, "malformed_payload", "Payload must be a JSON object")
    return body


def authenticate(db: Database, envelope: Envelope) -> AuthenticatedRequest:
    """Check an envelope's identity and signature. The caller consumes the nonce.

    The signature comes before anything that changes state, so an attacker without the private key
    can't burn nonces. The nonce check here only rejects replays early; the check that counts is
    the atomic one in the database.
    """
    email = normalise_email(envelope.email)
    account = db.get_account(email)
    # An unknown email gets the same response as a bad signature.
    if account is None or not _signature_is_valid(account.public_key, envelope):
        raise ApiError(401, "invalid_signature", "Signature could not be verified")
    if not account.verified:
        raise ApiError(403, "email_not_verified", "Verify the email address first")
    body = _decode_payload(envelope.payload)
    if envelope.nonce <= account.last_nonce:
        raise replayed_nonce_error()
    return AuthenticatedRequest(email=email, nonce=envelope.nonce, body=body)
