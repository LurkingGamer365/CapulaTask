"""SQLite persistence. Nonce updates and the work they authorise share one transaction."""

import hmac
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime

SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    email              TEXT PRIMARY KEY,
    public_key         BLOB NOT NULL,
    verified           INTEGER NOT NULL DEFAULT 0,
    verification_token TEXT,
    last_nonce         INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS vaults (
    email      TEXT PRIMARY KEY REFERENCES accounts(email),
    blob       BLOB NOT NULL,
    updated_at TEXT NOT NULL
);
"""


@dataclass
class Account:
    email: str
    public_key: bytes
    verified: bool
    last_nonce: int


class ReplayedNonce(Exception):
    """The nonce was not greater than the account's last accepted nonce."""


def _consume_nonce(conn: sqlite3.Connection, email: str, nonce: int) -> None:
    cursor = conn.execute(
        "UPDATE accounts SET last_nonce = ? WHERE email = ? AND last_nonce < ?",
        (nonce, email, nonce),
    )
    if cursor.rowcount == 0:
        raise ReplayedNonce


class Database:
    def __init__(self, path: str):
        self.path = path
        with self._transaction() as conn:
            conn.executescript(SCHEMA)

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        """A connection per transaction, as FastAPI runs sync routes on a thread pool."""
        conn = sqlite3.connect(self.path)
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def get_account(self, email: str) -> Account | None:
        with self._transaction() as conn:
            row = conn.execute(
                "SELECT email, public_key, verified, last_nonce FROM accounts WHERE email = ?",
                (email,),
            ).fetchone()
        if row is None:
            return None
        return Account(email=row[0], public_key=row[1], verified=bool(row[2]), last_nonce=row[3])

    def upsert_pending_account(self, email: str, public_key: bytes, token: str) -> bool:
        """Create or replace an unverified account. Return False if the email is already verified.

        Replacing is safe because only the mailbox owner receives the token, and the token is tied
        to this public key. It also stops anyone squatting on an email they don't control.
        """
        with self._transaction() as conn:
            cursor = conn.execute(
                """
                INSERT INTO accounts (email, public_key, verification_token) VALUES (?, ?, ?)
                ON CONFLICT (email) DO UPDATE SET
                    public_key = excluded.public_key,
                    verification_token = excluded.verification_token
                WHERE accounts.verified = 0
                """,
                (email, public_key, token),
            )
            return cursor.rowcount == 1

    def mark_verified(self, email: str, token: str) -> bool:
        """Compare the token in constant time, mark verified and clear the token."""
        with self._transaction() as conn:
            row = conn.execute(
                "SELECT verification_token FROM accounts WHERE email = ? AND verified = 0",
                (email,),
            ).fetchone()
            if row is None or not hmac.compare_digest(row[0].encode(), token.encode()):
                return False
            # Matching on the token means a key replaced since the SELECT can't get verified.
            cursor = conn.execute(
                """
                UPDATE accounts SET verified = 1, verification_token = NULL
                WHERE email = ? AND verification_token = ?
                """,
                (email, row[0]),
            )
            return cursor.rowcount == 1

    def store_vault(self, email: str, nonce: int, blob: bytes) -> None:
        """Atomically consume the nonce and write the vault (last write wins).

        Raises ReplayedNonce if the conditional UPDATE changes no row, so concurrent requests can't
        both succeed.
        """
        with self._transaction() as conn:
            _consume_nonce(conn, email, nonce)
            conn.execute(
                """
                INSERT INTO vaults (email, blob, updated_at) VALUES (?, ?, ?)
                ON CONFLICT (email) DO UPDATE SET
                    blob = excluded.blob,
                    updated_at = excluded.updated_at
                """,
                (email, blob, datetime.now(UTC).isoformat()),
            )

    def load_vault(self, email: str, nonce: int) -> bytes | None:
        """Atomically consume the nonce and return the vault, or None if nothing is stored."""
        with self._transaction() as conn:
            _consume_nonce(conn, email, nonce)
            row = conn.execute("SELECT blob FROM vaults WHERE email = ?", (email,)).fetchone()
        return row[0] if row else None
