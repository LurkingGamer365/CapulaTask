"""HTTP client for the vault API."""

import json
from urllib.parse import quote

import httpx
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from vault.client.crypto import ClientKeys
from vault.protocol import Envelope, b64decode, b64encode, normalise_email, signing_bytes

MAX_NONCE_ATTEMPTS = 3


class VaultApiError(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(f"{status} {code}: {message}")
        self.status = status
        self.code = code


def _checked(response: httpx.Response) -> dict:
    if response.is_success:
        return response.json()
    error = response.json()["error"]
    raise VaultApiError(response.status_code, error["code"], error["message"])


class VaultClient:
    def __init__(self, base_url: str, email: str, keys: ClientKeys, http: httpx.Client | None = None):
        self.http = http or httpx.Client(base_url=base_url)
        self.email = normalise_email(email)
        self.keys = keys

    def register(self) -> str:
        """POST /v1/register and return the mocked verification token."""
        public_key = self.keys.signing_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        response = self.http.post(
            "/v1/register",
            json={"email": self.email, "public_key": b64encode(public_key)},
        )
        return _checked(response)["verification_token"]

    def verify(self, token: str) -> None:
        """POST /v1/verify."""
        _checked(self.http.post("/v1/verify", json={"email": self.email, "token": token}))

    def last_nonce(self) -> int:
        response = self.http.get(f"/v1/accounts/{quote(self.email, safe='')}/nonce")
        return _checked(response)["last_nonce"]

    def sign_envelope(self, body: dict, nonce: int) -> Envelope:
        payload = b64encode(json.dumps(body).encode())
        signature = self.keys.signing_key.sign(signing_bytes(self.email, payload, nonce))
        return Envelope(email=self.email, payload=payload, nonce=nonce, signature=b64encode(signature))

    def build_envelope(self, body: dict) -> Envelope:
        """Fetch last_nonce, then Base64 the JSON body and sign signing_bytes() with nonce + 1."""
        return self.sign_envelope(body, self.last_nonce() + 1)

    def send(self, envelope: Envelope) -> httpx.Response:
        """POST an envelope as is, so the demo can also send tampered and replayed ones."""
        return self.http.post("/v1/vault", json=envelope.model_dump())

    def _signed_request(self, body: dict) -> dict:
        """Send a signed request, signing afresh if another device took our nonce first."""
        for attempt in range(MAX_NONCE_ATTEMPTS):
            try:
                return _checked(self.send(self.build_envelope(body)))
            except VaultApiError as error:
                if error.code != "replayed_nonce" or attempt == MAX_NONCE_ATTEMPTS - 1:
                    raise
        raise AssertionError("unreachable")

    def store(self, blob: bytes) -> None:
        self._signed_request({"type": "store", "vault": b64encode(blob)})

    def retrieve(self) -> bytes:
        return b64decode(self._signed_request({"type": "retrieve"})["vault"])
