"""HTTP API. Errors are returned as {"error": {"code": ..., "message": ...}}."""

import os
import secrets

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from vault.protocol import Envelope, RegisterRequest, VerifyRequest, b64decode, b64encode, normalise_email
from vault.server.auth import ApiError, authenticate, replayed_nonce_error
from vault.server.db import Database, ReplayedNonce

MAX_VAULT_BYTES = 10 * 1024 * 1024


def _error_response(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": {"code": code, "message": message}})


def _decode_public_key(public_key: str) -> bytes:
    try:
        raw = b64decode(public_key)
        Ed25519PublicKey.from_public_bytes(raw)
    except ValueError as error:
        raise ApiError(400, "invalid_public_key", "Expected a Base64 raw Ed25519 key") from error
    return raw


def _decode_vault(vault: object) -> bytes:
    if not isinstance(vault, str):
        raise ApiError(400, "malformed_payload", "Store requests need a Base64 vault")
    try:
        blob = b64decode(vault)
    except ValueError as error:
        raise ApiError(400, "malformed_payload", "Store requests need a Base64 vault") from error
    if len(blob) > MAX_VAULT_BYTES:
        raise ApiError(413, "vault_too_large", "Vault exceeds the maximum size")
    return blob


def create_app(db_path: str | None = None) -> FastAPI:
    app = FastAPI(title="Password Vault Backup API")
    db = Database(db_path or os.environ.get("VAULT_DB", "vault.db"))

    @app.exception_handler(ApiError)
    def handle_api_error(_: Request, exc: ApiError) -> JSONResponse:
        return _error_response(exc.status, exc.code, exc.message)

    @app.exception_handler(RequestValidationError)
    def handle_validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        return _error_response(400, "malformed_request", "Request body failed validation")

    @app.post("/v1/register", status_code=202)
    def register(request: RegisterRequest) -> dict:
        """Unsigned. Validate the public key, save a pending account and "send" the token.

        Mock: the token is returned in the response instead of being emailed. A verified email gets
        409 already_registered.
        """
        email = normalise_email(request.email)
        if email.count("@") != 1:
            raise ApiError(400, "invalid_email", "Expected an email address")
        public_key = _decode_public_key(request.public_key)
        token = secrets.token_urlsafe(32)
        if not db.upsert_pending_account(email, public_key, token):
            raise ApiError(409, "already_registered", "This email is already registered")
        return {"status": "pending_verification", "verification_token": token}

    @app.post("/v1/verify")
    def verify(request: VerifyRequest) -> dict:
        """Complete the mocked email verification. A wrong token gets 400 invalid_token."""
        if not db.mark_verified(normalise_email(request.email), request.token):
            raise ApiError(400, "invalid_token", "Verification token is not valid")
        return {"status": "verified"}

    @app.get("/v1/accounts/{email}/nonce")
    def get_nonce(email: str) -> dict:
        """Return {"last_nonce": n}, unauthenticated, and 0 for unknown emails.

        A new device only has the email and master password, so it needs this to pick its next nonce.
        """
        account = db.get_account(normalise_email(email))
        return {"last_nonce": account.last_nonce if account else 0}

    @app.post("/v1/vault")
    def vault_operation(envelope: Envelope) -> dict:
        """Single signed endpoint, dispatching on the signed payload's "type"."""
        request = authenticate(db, envelope)
        try:
            match request.body.get("type"):
                case "store":
                    blob = _decode_vault(request.body.get("vault"))
                    db.store_vault(request.email, request.nonce, blob)
                    return {"status": "stored"}
                case "retrieve":
                    blob = db.load_vault(request.email, request.nonce)
                    if blob is None:
                        raise ApiError(404, "vault_not_found", "No vault has been stored")
                    return {"vault": b64encode(blob)}
                case _:
                    raise ApiError(400, "unknown_type", "Unknown request type")
        except ReplayedNonce as error:
            raise replayed_nonce_error() from error

    return app
