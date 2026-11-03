"""End-to-end API tests, plus tests of the client crypto and the atomic nonce check."""

import json
from concurrent.futures import ThreadPoolExecutor

import pytest
from cryptography.exceptions import InvalidTag
from fastapi.testclient import TestClient

from vault.client.api import VaultApiError, VaultClient
from vault.client.crypto import decrypt_vault, derive_keys, encrypt_vault
from vault.protocol import b64decode, b64encode, signing_bytes
from vault.server import app as server_app
from vault.server.app import create_app
from vault.server.db import Database, ReplayedNonce

EMAIL = "test@example.com"
PASSWORD = "correct horse battery staple"
PLAINTEXT = b'{"example.com": "hunter2"}'


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "vault.db")


@pytest.fixture
def http(db_path):
    return TestClient(create_app(db_path))


def make_client(http, email=EMAIL, password=PASSWORD):
    return VaultClient("", email, derive_keys(email, password), http=http)


@pytest.fixture
def client(http):
    """A registered and verified client."""
    client = make_client(http)
    client.verify(client.register())
    return client


def assert_api_error(call, status, code):
    with pytest.raises(VaultApiError) as caught:
        call()
    assert (caught.value.status, caught.value.code) == (status, code)


def assert_rejected(response, status, code):
    assert response.status_code == status
    assert response.json()["error"]["code"] == code


def test_key_derivation_is_deterministic():
    first, second = derive_keys(EMAIL, PASSWORD), derive_keys(" Test@Example.com", PASSWORD)
    assert first.encryption_key == second.encryption_key
    assert first.signing_key.private_bytes_raw() == second.signing_key.private_bytes_raw()


def test_key_derivation_matches_fixed_outputs():
    """Any change to encoding, salt, Argon2id settings or HKDF labels changes every user's keys."""
    keys = derive_keys(EMAIL, PASSWORD)
    public_key = keys.signing_key.public_key().public_bytes_raw()
    assert public_key.hex() == "7a8a5d5348749d72900e5430c8ff2453096d881e8950eef7ed294a1917d889fd"
    assert keys.encryption_key.hex() == "8e4ee14c59b3a9ce8bd5ca6bbbf97a1d97d5766d55242dfeda365e1ce78c6640"


def test_password_is_not_unicode_normalised():
    composed, decomposed = "päss", "päss"  # both display as "päss"
    assert derive_keys(EMAIL, composed).encryption_key != derive_keys(EMAIL, decomposed).encryption_key


def test_signing_bytes_are_fixed():
    assert signing_bytes("a@b.c", "cGF5", 1) == b'["vault-backup-v1","a@b.c",1,"cGF5"]'


def test_keys_depend_on_password_and_email():
    keys = derive_keys(EMAIL, PASSWORD)
    assert keys.encryption_key != derive_keys(EMAIL, "other").encryption_key
    assert keys.encryption_key != derive_keys("other@example.com", PASSWORD).encryption_key


def test_signing_and_encryption_keys_are_independent():
    keys = derive_keys(EMAIL, PASSWORD)
    assert keys.encryption_key != keys.signing_key.private_bytes_raw()


def test_tampered_ciphertext_fails_to_decrypt():
    key = derive_keys(EMAIL, PASSWORD).encryption_key
    blob = bytearray(encrypt_vault(key, EMAIL, PLAINTEXT))
    blob[-1] ^= 1
    with pytest.raises(InvalidTag):
        decrypt_vault(key, EMAIL, bytes(blob))


def test_vault_for_another_email_fails_to_decrypt():
    key = derive_keys(EMAIL, PASSWORD).encryption_key
    with pytest.raises(InvalidTag):
        decrypt_vault(key, "other@example.com", encrypt_vault(key, EMAIL, PLAINTEXT))


def test_full_workflow_round_trip(client, http):
    blob = encrypt_vault(client.keys.encryption_key, EMAIL, PLAINTEXT)
    client.store(blob)

    new_device = make_client(http)
    retrieved = new_device.retrieve()
    assert retrieved == blob
    assert decrypt_vault(new_device.keys.encryption_key, EMAIL, retrieved) == PLAINTEXT


def test_server_only_stores_ciphertext(client, db_path):
    client.store(encrypt_vault(client.keys.encryption_key, EMAIL, PLAINTEXT))
    with open(db_path, "rb") as db_file:
        assert PLAINTEXT not in db_file.read()


def test_store_overwrites_previous_vault(client):
    client.store(b"first")
    client.store(b"second")
    assert client.retrieve() == b"second"


def test_retrieve_without_vault_is_not_found(client):
    assert_api_error(client.retrieve, 404, "vault_not_found")


def test_unverified_account_is_rejected(http):
    client = make_client(http)
    client.register()
    assert_api_error(lambda: client.store(b"blob"), 403, "email_not_verified")


def test_wrong_verification_token_is_rejected(http):
    client = make_client(http)
    client.register()
    assert_api_error(lambda: client.verify("wrong"), 400, "invalid_token")


def test_unknown_email_is_rejected(http):
    assert_api_error(make_client(http).retrieve, 401, "invalid_signature")


def test_wrong_password_is_rejected(client, http):
    assert_api_error(make_client(http, password="wrong").retrieve, 401, "invalid_signature")


def test_invalid_signature_is_rejected(client):
    envelope = client.build_envelope({"type": "retrieve"})
    flipped = bytearray(b64decode(envelope.signature))
    flipped[0] ^= 1
    bad = envelope.model_copy(update={"signature": b64encode(bytes(flipped))})
    assert_rejected(client.send(bad), 401, "invalid_signature")


def test_non_base64_signature_is_rejected(client):
    bad = client.build_envelope({"type": "retrieve"}).model_copy(update={"signature": "!!!"})
    assert_rejected(client.send(bad), 401, "invalid_signature")


def test_altered_payload_is_rejected(client):
    envelope = client.build_envelope({"type": "retrieve"})
    payload = b64encode(json.dumps({"type": "store", "vault": ""}).encode())
    assert_rejected(client.send(envelope.model_copy(update={"payload": payload})), 401, "invalid_signature")


def test_altered_email_or_nonce_is_rejected(client, http):
    other = make_client(http, email="other@example.com")
    other.verify(other.register())
    envelope = client.build_envelope({"type": "retrieve"})
    for update in ({"email": other.email}, {"email": "TEST@example.com"}, {"nonce": envelope.nonce + 1}):
        assert_rejected(client.send(envelope.model_copy(update=update)), 401, "invalid_signature")


def test_replayed_request_is_rejected(client):
    client.store(b"blob")
    envelope = client.build_envelope({"type": "retrieve"})
    assert client.send(envelope).status_code == 200
    assert_rejected(client.send(envelope), 409, "replayed_nonce")


def test_lower_nonce_is_rejected(client):
    client.send(client.sign_envelope({"type": "store", "vault": b64encode(b"blob")}, 5))
    assert_rejected(client.send(client.sign_envelope({"type": "retrieve"}, 4)), 409, "replayed_nonce")


def send_signed_payload(client, payload: bytes):
    """Sign raw payload bytes, bypassing the client's JSON encoding."""
    envelope = client.sign_envelope({}, client.last_nonce() + 1)
    payload_b64 = b64encode(payload)
    signature = client.keys.signing_key.sign(signing_bytes(client.email, payload_b64, envelope.nonce))
    return client.send(envelope.model_copy(update={"payload": payload_b64, "signature": b64encode(signature)}))


@pytest.mark.parametrize("payload", [b"not json", b"\xff\xfe", b'["store"]'])
def test_signed_malformed_payload_is_rejected(client, payload):
    assert_rejected(send_signed_payload(client, payload), 400, "malformed_payload")
    assert client.last_nonce() == 0


@pytest.mark.parametrize("vault", [None, "!!!", 123])
def test_signed_store_with_invalid_vault_is_rejected(client, vault):
    response = client.send(client.build_envelope({"type": "store", "vault": vault}))
    assert_rejected(response, 400, "malformed_payload")
    assert client.last_nonce() == 0


def test_empty_vault_is_rejected_and_keeps_backup(client):
    client.store(b"blob")
    assert_rejected(client.send(client.build_envelope({"type": "store", "vault": ""})), 400, "empty_vault")
    assert client.retrieve() == b"blob"


def test_oversized_vault_is_rejected(client, monkeypatch):
    monkeypatch.setattr(server_app, "MAX_VAULT_BYTES", 16)
    client.store(b"x" * 16)
    assert_api_error(lambda: client.store(b"x" * 17), 413, "vault_too_large")
    assert client.retrieve() == b"x" * 16


def test_bad_signature_does_not_consume_nonce(client):
    envelope = client.build_envelope({"type": "retrieve"})
    bad = envelope.model_copy(update={"nonce": envelope.nonce + 100})
    client.send(bad)
    assert client.last_nonce() == 0


def test_concurrent_replays_only_succeed_once(db_path):
    db = Database(db_path)
    db.upsert_pending_account(EMAIL, b"key", "token")

    def attempt(_):
        try:
            db.store_vault(EMAIL, 1, b"blob")
            return True
        except ReplayedNonce:
            return False

    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(attempt, range(8))) == 1


def test_unknown_type_is_rejected(client):
    assert_rejected(client.send(client.build_envelope({"type": "delete"})), 400, "unknown_type")


def test_string_nonce_is_rejected(client):
    envelope = client.build_envelope({"type": "retrieve"}).model_dump()
    envelope["nonce"] = str(envelope["nonce"])
    assert_rejected(client.http.post("/v1/vault", json=envelope), 400, "malformed_request")


def test_reregistering_verified_email_is_rejected(client):
    assert_api_error(client.register, 409, "already_registered")


def test_reregistering_unverified_email_replaces_key_and_token(http):
    squatter = make_client(http, password="squatter")
    squatter_token = squatter.register()
    owner = make_client(http)
    owner_token = owner.register()

    assert_api_error(lambda: squatter.verify(squatter_token), 400, "invalid_token")
    owner.verify(owner_token)
    owner.store(b"blob")
    assert owner.retrieve() == b"blob"


def test_invalid_public_key_is_rejected(http):
    response = http.post("/v1/register", json={"email": EMAIL, "public_key": b64encode(b"short")})
    assert_rejected(response, 400, "invalid_public_key")


def test_vault_survives_server_restart(client, db_path):
    client.store(b"blob")
    restarted = make_client(TestClient(create_app(db_path)))
    assert restarted.retrieve() == b"blob"
