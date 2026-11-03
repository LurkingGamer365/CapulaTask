"""Runs the full workflow against a running server: python demo.py [base_url]"""

import json
import sys
import uuid

from vault.client.api import VaultClient
from vault.client.crypto import decrypt_vault, derive_keys, encrypt_vault
from vault.protocol import b64decode, b64encode, normalise_email


def expect_rejected(client: VaultClient, name: str, envelope, status: int) -> None:
    response = client.send(envelope)
    assert response.status_code == status, f"{name}: got {response.status_code}"
    print(f"   {name}: rejected with {status} {response.json()['error']['code']}")


def main(base_url: str) -> None:
    # A fresh email each run, so the demo can be repeated against the same database.
    email = normalise_email(f"demo-{uuid.uuid4().hex[:8]}@example.com")
    master_password = "correct horse battery staple"
    sample_vault = json.dumps({"example.com": {"user": "alice", "password": "hunter2"}}).encode()

    print("1. Generate a key pair from the master password")
    keys = derive_keys(email, master_password)
    client = VaultClient(base_url, email, keys)

    print("2. Register the email and public key")
    token = client.register()

    print("3. Complete the mocked email verification")
    client.verify(token)

    print("4. Encrypt the sample vault")
    blob = encrypt_vault(keys.encryption_key, email, sample_vault)

    print("5. Store the encrypted vault")
    client.store(blob)

    print("6. Retrieve it, as a new device with only the email and password")
    new_device_keys = derive_keys(email, master_password)
    retrieved = VaultClient(base_url, email, new_device_keys).retrieve()

    print("7. Confirm the retrieved data matches")
    assert retrieved == blob
    assert decrypt_vault(new_device_keys.encryption_key, email, retrieved) == sample_vault

    print("Bad requests are rejected:")
    valid = client.build_envelope({"type": "retrieve"})

    flipped = bytearray(b64decode(valid.signature))
    flipped[0] ^= 1
    bad_signature = valid.model_copy(update={"signature": b64encode(bytes(flipped))})
    expect_rejected(client, "invalid signature", bad_signature, 401)

    other_payload = b64encode(json.dumps({"type": "store", "vault": ""}).encode())
    expect_rejected(client, "altered payload", valid.model_copy(update={"payload": other_payload}), 401)
    expect_rejected(client, "altered nonce", valid.model_copy(update={"nonce": valid.nonce + 1}), 401)

    assert client.send(valid).status_code == 200
    expect_rejected(client, "replayed request", valid, 409)

    print("OK")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000")
