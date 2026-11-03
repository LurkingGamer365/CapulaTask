# Password Vault Backup API

Stores a client-encrypted password vault that can be recovered with only an email and master
password. The server only ever sees ciphertext.

## Running

```sh
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

uvicorn vault.server.app:create_app --factory    # terminal 1
python demo.py                                   # terminal 2
python -m pytest                                 # tests
```

`VAULT_DB` sets the SQLite file path (default `vault.db`).

## Layout

| Path | Purpose |
| --- | --- |
| `vault/protocol.py` | Envelope models and the exact bytes that get signed |
| `vault/server/app.py` | HTTP routes |
| `vault/server/auth.py` | Envelope authentication |
| `vault/server/db.py` | SQLite persistence and atomic nonce handling |
| `vault/client/crypto.py` | Key derivation and vault encryption |
| `vault/client/api.py` | HTTP client |
| `demo.py` | The full workflow from the brief |

## API

| Method and path | Signed | Purpose |
| --- | --- | --- |
| `POST /v1/register` | No | Save an email and public key as pending; returns the mocked token |
| `POST /v1/verify` | No | Complete email verification with the token |
| `GET /v1/accounts/{email}/nonce` | No | Last accepted nonce, so a new device can continue |
| `POST /v1/vault` | Yes | `store` or `retrieve`, selected by the payload's `type` |

Errors look like `{"error": {"code": "...", "message": "..."}}`.

| Status | Codes |
| --- | --- |
| 400 | `malformed_request`, `malformed_payload`, `empty_vault`, `unknown_type`, `invalid_email`, `invalid_public_key`, `invalid_token` |
| 401 | `invalid_signature` (also used for unknown emails) |
| 403 | `email_not_verified` |
| 404 | `vault_not_found` |
| 409 | `replayed_nonce`, `already_registered` |
| 413 | `vault_too_large` |

## Design decisions

**Keys.** Argon2id turns the password into a master key, and HKDF splits that into an Ed25519 seed
and an AES-256-GCM key. The server gets only the public key, so it can't decrypt the vault.

**Salt.** The salt is derived from the normalised email. This gives each account its own salt
without extra server state or a salt lookup, so one precomputed table can't attack every user. A
random salt is the conventional alternative and would stop guesses being prepared before an account
exists. That benefit is small here, because a random salt would have to be publicly retrievable for
recovery. Deriving the salt also means a new device never relies on the server for cryptographic
inputs.

**KDF settings.** The Argon2id settings are fixed in the client: 3 passes, 64 MiB and 1 lane. That
is above OWASP's minimum, and was chosen with unlock time in mind; it should be benchmarked on real
devices. A server should never choose how weak a client's key derivation is, so any future
per-account KDF version must map to settings the client knows, and the client must reject anything
weaker.

**Password encoding.** The password is used as its exact UTF-8 bytes, with no Unicode
normalisation. Every client must do the same, or an accented password typed differently could fail
to unlock the vault. Tests pin the derived keys to fixed outputs, so any change to encoding, salt,
settings or labels shows up immediately.

**Signed data.** The signature covers `["vault-backup-v1", email, nonce, payload]` as compact JSON.
The payload is signed as the Base64 string received, so the inner JSON is never canonicalised. The
request type is inside the payload, which means it's signed too.

**Nonces.** Each account has a strictly increasing integer, and a request is accepted only if its
nonce exceeds `last_nonce`. The database enforces this with a conditional `UPDATE` in the same
transaction as the operation, so concurrent replays can't both succeed. Signatures are checked
first, so nobody can burn a nonce without the private key. Clients that race get a 409 and retry
with a new nonce.

**Repeated requests.** Replaying a signed request is always rejected, including legitimate retries,
so a client that loses a response signs a new request. Re-registering an unverified email replaces
the pending key, and a verified email gets a 409.

**Storage.** SQLite is a single file that survives restarts and provides the transactions the nonce
logic needs. Each account keeps one vault, and the last write wins. Empty vaults are rejected, so a
mistaken store can't erase a good backup.

**TLS.** Local development is plain HTTP on loopback. A deployment would terminate TLS at a reverse
proxy or use uvicorn's `--ssl-keyfile` and `--ssl-certfile`. Without TLS, the signed envelopes still
resist tampering but the ciphertext and metadata are exposed.

## Known limitations

- **Offline guessing:** this is inherent to deriving keys only from a password when an attacker has
  the encrypted data. Argon2id raises the cost of each guess but can't prevent the attack. Removing
  the password-derived public key wouldn't solve it either, because AES-GCM's authentication tag also
  shows whether a guessed key is correct.
- **Rollback:** a malicious server could return an older vault. A version counter doesn't prevent
  this by itself, because the server can roll back the counter too. Only a device that remembers the
  latest version can notice, and a new device has nothing to compare against.
- **Unsent requests:** a captured signed request that was never sent stays valid until a higher
  nonce is accepted.
- **Password changes and recovery:** keys come from the password, so changing it needs a key
  rotation operation, which isn't included. A forgotten password can't be recovered.
- **Enumeration:** registration and nonce responses can reveal which emails exist.
- **Abuse:** there is no rate limiting on any endpoint.
- **Request size:** the 10 MiB vault limit is checked after the body is read, so a deployment should
  also cap body size at the proxy.
- **Scale:** SQLite suits a single server process; several instances would need a shared database.

## Production improvements

- **Wrapped vault key:** encrypt the vault with a random key and wrap that key with the password-derived
  key, so a password change only re-wraps one key.
- **KDF versioning:** record a KDF version per account so the cost can rise over time, with the client
  enforcing its own minimum.
- **OPAQUE:** a password-authenticated protocol in which the user's keys also depend on a server-held
  secret. A stolen database alone would then not allow offline guessing, though a full server compromise
  still would.
- **Version checks on store:** store requests carry the version they replace, so a stale device can't
  overwrite newer data. Detecting a malicious rollback would also need state the client keeps itself.
- **Request expiry:** single-use challenges from the server, with an expiry, consumed atomically with
  the operation.
- **Real email verification:** send the token by email with the public-key fingerprint, require a
  deliberate confirmation, expire the token, store only its hash, and rate-limit registration.
- **Operational basics:** add rate limiting, audit logging, backups and vault version history.
