"""Password hashing (stdlib scrypt) and policy. No third-party crypto dependency."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os

_N, _R, _P = 2**15, 8, 1
MIN_LENGTH = 12


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _derive(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(
        password.encode(), salt=salt, n=n, r=r, p=p, dklen=32, maxmem=128 * n * r * 2
    )


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    return f"scrypt${_N}${_R}${_P}${_b64(salt)}${_b64(_derive(password, salt, _N, _R, _P))}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt, digest = stored.split("$")
        if scheme != "scrypt":
            return False
        want = base64.b64decode(digest)
        got = _derive(password, base64.b64decode(salt), int(n), int(r), int(p))
    except ValueError:
        return False
    return hmac.compare_digest(got, want)


# Verified against when the username is unknown, so timing does not reveal valid usernames.
DUMMY_HASH = hash_password("not-a-real-password")


def check_policy(password: str, username: str = "") -> str | None:
    """Return a human-readable problem, or None if the password is acceptable."""
    if len(password) < MIN_LENGTH:
        return f"Password must be at least {MIN_LENGTH} characters."
    if len(password) > 256:
        return "Password must be at most 256 characters."
    if username and username.lower() in password.lower():
        return "Password must not contain the username."
    if len(set(password)) < 5:
        return "Password is too repetitive."
    return None
