"""AES-256-GCM envelope encryption.

Each object gets a fresh 256-bit data key; the data key is wrapped by the
tenant's key-encryption key held in a KMS/HSM. Only the wrapped key is stored.
``LocalKms`` is a development stand-in for AWS KMS / Azure Key Vault / GCP KMS.
"""

from __future__ import annotations

import os
from typing import Protocol

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class KeyManagementService(Protocol):
    def generate_data_key(self, key_ref: str) -> tuple[bytes, bytes]:
        """Return ``(plaintext_data_key, wrapped_data_key)``."""

    def unwrap_data_key(self, key_ref: str, wrapped: bytes) -> bytes: ...


class LocalKms:
    def __init__(self, master_keys: dict[str, bytes] | None = None) -> None:
        self._keys: dict[str, bytes] = dict(master_keys or {})
        for ref, key in self._keys.items():
            if len(key) != 32:
                raise ValueError(f"master key {ref!r} must be 32 bytes (AES-256)")

    def create_key(self, key_ref: str) -> None:
        self._keys.setdefault(key_ref, AESGCM.generate_key(bit_length=256))

    def _kek(self, key_ref: str) -> AESGCM:
        try:
            return AESGCM(self._keys[key_ref])
        except KeyError:
            raise PermissionError(f"no access to key {key_ref!r}") from None

    def generate_data_key(self, key_ref: str) -> tuple[bytes, bytes]:
        dk = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(12)
        return dk, nonce + self._kek(key_ref).encrypt(nonce, dk, key_ref.encode())

    def unwrap_data_key(self, key_ref: str, wrapped: bytes) -> bytes:
        return self._kek(key_ref).decrypt(wrapped[:12], wrapped[12:], key_ref.encode())


def seal(kms: KeyManagementService, key_ref: str, plaintext: bytes, aad: bytes) -> dict[str, bytes]:
    dk, wrapped = kms.generate_data_key(key_ref)
    nonce = os.urandom(12)
    return {"wrapped_key": wrapped, "nonce": nonce, "ciphertext": AESGCM(dk).encrypt(nonce, plaintext, aad)}


def open_sealed(kms: KeyManagementService, key_ref: str, sealed: dict[str, bytes], aad: bytes) -> bytes:
    dk = kms.unwrap_data_key(key_ref, sealed["wrapped_key"])
    return AESGCM(dk).decrypt(sealed["nonce"], sealed["ciphertext"], aad)
