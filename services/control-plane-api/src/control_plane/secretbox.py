"""Encryption at rest for connection credentials (Fernet: AES-128-CBC + HMAC-SHA256).

The key comes from ``AIOPS_SECRETS_KEY`` (generate with ``python -m control_plane.secretbox``).
Secrets are write-only through the API: they are never returned, logged or audited.
"""

from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken


class SecretBox:
    def __init__(self, key: str) -> None:
        try:
            self._f = Fernet(key.encode())
        except ValueError as e:
            raise RuntimeError(
                "AIOPS_SECRETS_KEY must be a Fernet key (32 url-safe base64 bytes)"
            ) from e

    def encrypt(self, plaintext: str) -> str:
        return self._f.encrypt(plaintext.encode()).decode()

    def decrypt(self, token: str) -> str:
        try:
            return self._f.decrypt(token.encode()).decode()
        except InvalidToken as e:
            raise ValueError("stored secret cannot be decrypted with the configured key") from e


if __name__ == "__main__":  # pragma: no cover
    print(Fernet.generate_key().decode())
