"""Signing of ledger entries.

``Signer`` is a port. In production it is backed by a cloud KMS / HSM key
(the private key never leaves the hardware); ``Ed25519Signer`` is the local
implementation used for development and tests.
"""

from __future__ import annotations

from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


class Signer(Protocol):
    key_id: str

    def sign(self, message: bytes) -> bytes: ...


class Verifier(Protocol):
    def verify(self, key_id: str, message: bytes, signature: bytes) -> bool: ...


class Ed25519Signer:
    def __init__(self, key_id: str, private_key: Ed25519PrivateKey | None = None) -> None:
        self.key_id = key_id
        self._key = private_key or Ed25519PrivateKey.generate()

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message)

    def public_key(self) -> Ed25519PublicKey:
        return self._key.public_key()


class KeyRing:
    """Maps key ids to public keys. Retired keys stay here so old entries still verify."""

    def __init__(self) -> None:
        self._keys: dict[str, Ed25519PublicKey] = {}

    def add(self, key_id: str, public_key: Ed25519PublicKey) -> None:
        if key_id in self._keys:
            raise ValueError(f"key id {key_id!r} already registered")
        self._keys[key_id] = public_key

    def verify(self, key_id: str, message: bytes, signature: bytes) -> bool:
        key = self._keys.get(key_id)
        if key is None:
            return False
        try:
            key.verify(signature, message)
        except InvalidSignature:
            return False
        return True
