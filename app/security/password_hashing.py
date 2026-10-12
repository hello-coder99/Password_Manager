"""Argon2id account login password hashing and constant-time verification."""

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

# OWASP recommended Argon2id parameters for server-side authentication
_ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,  # 64 MiB
    parallelism=2,
    hash_len=32,
    salt_len=16,
    type=Type.ID,
)

# Pre-computed dummy Argon2id hash to equalize timing when email does not exist
_DUMMY_HASH = _ph.hash("dummy-timing-equalization-password-do-not-match")


def hash_login_password(password: str) -> str:
    """Hash a user's account login password using Argon2id."""
    if not isinstance(password, str) or not password:
        raise ValueError("Password must be a non-empty string.")
    return _ph.hash(password)


def verify_login_password(stored_hash: str | None, candidate_password: str) -> bool:
    """Verify a candidate login password against a stored Argon2id hash.

    If `stored_hash` is None (user does not exist), verifies against `_DUMMY_HASH`
    to mitigate timing side-channels that could reveal account existence.
    """
    target_hash = stored_hash if stored_hash else _DUMMY_HASH
    try:
        matched = _ph.verify(target_hash, candidate_password)
        return bool(matched and stored_hash is not None)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    """Return True if the stored Argon2id hash uses outdated parameters."""
    try:
        return _ph.check_needs_rehash(stored_hash)
    except InvalidHashError:
        return True
