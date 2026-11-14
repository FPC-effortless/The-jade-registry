"""Argon2id passwords and revocable, opaque sessions. No credentials in browser storage."""
import hashlib
import hmac
import secrets
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

_hasher = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1)
_dummy_hash = _hasher.hash(secrets.token_urlsafe(32))


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def check_password(password: str, stored: str | None) -> bool:
    if stored is None:
        stored = _dummy_hash
    if stored.startswith("$argon2id$"):
        try:
            return _hasher.verify(stored, password)
        except (VerificationError, InvalidHashError):
            return False
    # Compatibility only: upgrade v0.1 PBKDF2 digests after successful authentication.
    try:
        salt, expected = stored.split(":")
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 260000)
        return hmac.compare_digest(actual, bytes.fromhex(expected))
    except (ValueError, TypeError):
        return False


def needs_rehash(stored: str) -> bool:
    return not stored.startswith("$argon2id$") or _hasher.check_needs_rehash(stored)


def keyed_digest(secret: str, value: str) -> str:
    return hmac.new(secret.encode(), value.encode(), hashlib.sha256).hexdigest()


def csrf_for(secret: str, token: str) -> str:
    return keyed_digest(secret, "csrf:" + token)
