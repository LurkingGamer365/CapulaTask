"""Client-side key derivation and vault encryption. Nothing here ever runs on the server.

    master password + email
            |  Argon2id (salt = SHA-256 of context + normalised email, truncated to 16 bytes)
       master key
            |  HKDF-SHA256, with separate info strings
      +-----+------+
  Ed25519 seed   AES-256-GCM key

The salt is derived rather than random because recovery only has the email and password, so there
is nowhere to keep a random salt without the server handing it to anyone who asks.
"""

import hashlib
import os
from dataclasses import dataclass

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from vault.protocol import SIGNING_CONTEXT, normalise_email

# Part of the key derivation: changing any of these locks existing users out of their vaults.
ARGON2_TIME_COST = 3
ARGON2_MEMORY_KIB = 64 * 1024
ARGON2_PARALLELISM = 1

KEY_BYTES = 32
GCM_NONCE_BYTES = 12


@dataclass
class ClientKeys:
    signing_key: Ed25519PrivateKey
    encryption_key: bytes  # 32 bytes; never leaves the client


def _expand(master_key: bytes, purpose: str) -> bytes:
    info = f"{SIGNING_CONTEXT}/{purpose}".encode()
    return HKDF(algorithm=SHA256(), length=KEY_BYTES, salt=None, info=info).derive(master_key)


def derive_keys(email: str, master_password: str) -> ClientKeys:
    """Same inputs always give the same keys. Use argon2.low_level.hash_secret_raw and HKDF."""
    salt_input = f"{SIGNING_CONTEXT}/salt/{normalise_email(email)}".encode()
    master_key = hash_secret_raw(
        secret=master_password.encode(),
        salt=hashlib.sha256(salt_input).digest()[:16],
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_KIB,
        parallelism=ARGON2_PARALLELISM,
        hash_len=KEY_BYTES,
        type=Type.ID,
    )
    return ClientKeys(
        signing_key=Ed25519PrivateKey.from_private_bytes(_expand(master_key, "signing")),
        encryption_key=_expand(master_key, "encryption"),
    )


def encrypt_vault(key: bytes, email: str, plaintext: bytes) -> bytes:
    """AES-256-GCM. Return random 12-byte nonce + ciphertext, with the email as associated data."""
    nonce = os.urandom(GCM_NONCE_BYTES)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, normalise_email(email).encode())


def decrypt_vault(key: bytes, email: str, blob: bytes) -> bytes:
    """Reverse of encrypt_vault. Raises InvalidTag if the blob was tampered with."""
    nonce, ciphertext = blob[:GCM_NONCE_BYTES], blob[GCM_NONCE_BYTES:]
    return AESGCM(key).decrypt(nonce, ciphertext, normalise_email(email).encode())
