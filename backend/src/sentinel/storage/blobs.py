"""Blob storage with per-tenant envelope encryption.

``BlobStore`` is the raw byte port (S3 / Azure Blob / GCS in production);
``EncryptedBlobStore`` is what the rest of the system uses. Objects are
encrypted before they leave the process and the tenant id, object key and
plaintext hash are bound in as AES-GCM associated data, so a ciphertext copied
to another tenant or key fails to decrypt.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from sentinel.crypto.envelope import KeyManagementService, open_sealed, seal
from sentinel.tenancy import TenantDirectory

_KEY_RE = re.compile(r"^[a-z0-9][a-z0-9_\-./]{0,400}$")


class BlobStore(Protocol):
    def put(self, path: str, data: bytes) -> None: ...

    def get(self, path: str) -> bytes: ...

    def exists(self, path: str) -> bool: ...


class InMemoryBlobStore:
    def __init__(self) -> None:
        self._data: dict[str, bytes] = {}
        self._lock = threading.Lock()

    def put(self, path: str, data: bytes) -> None:
        with self._lock:
            self._data[path] = bytes(data)

    def get(self, path: str) -> bytes:
        try:
            return self._data[path]
        except KeyError:
            raise FileNotFoundError(path) from None

    def exists(self, path: str) -> bool:
        return path in self._data


class FilesystemBlobStore:
    def __init__(self, root: Path) -> None:
        self._root = root.resolve()
        self._root.mkdir(parents=True, exist_ok=True)

    def _resolve(self, path: str) -> Path:
        p = (self._root / path).resolve()
        if self._root not in p.parents:
            raise ValueError("path escapes blob root")
        return p

    def put(self, path: str, data: bytes) -> None:
        p = self._resolve(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(p.suffix + ".tmp")
        tmp.write_bytes(data)
        tmp.replace(p)

    def get(self, path: str) -> bytes:
        return self._resolve(path).read_bytes()

    def exists(self, path: str) -> bool:
        return self._resolve(path).exists()


@dataclass(frozen=True)
class BlobRef:
    uri: str
    sha256: str
    size: int


class IntegrityError(RuntimeError):
    pass


class EncryptedBlobStore:
    def __init__(self, raw: BlobStore, kms: KeyManagementService, tenants: TenantDirectory) -> None:
        self._raw = raw
        self._kms = kms
        self._tenants = tenants

    @staticmethod
    def _path(tenant_id: str, key: str) -> str:
        if not _KEY_RE.match(key) or ".." in key:
            raise ValueError(f"invalid blob key {key!r}")
        return f"{tenant_id}/{key}"

    def put(self, tenant_id: str, key: str, data: bytes) -> BlobRef:
        key_ref = self._tenants.get(tenant_id).kms_key_ref
        digest = hashlib.sha256(data).hexdigest()
        aad = f"{tenant_id}|{key}|{digest}".encode()
        sealed = seal(self._kms, key_ref, data, aad)
        envelope = {
            "v": 1,
            "alg": "AES-256-GCM",
            "key_ref": key_ref,
            "sha256": digest,
            **{k: base64.b64encode(v).decode() for k, v in sealed.items()},
        }
        self._raw.put(self._path(tenant_id, key), json.dumps(envelope).encode())
        return BlobRef(uri=f"blob://{tenant_id}/{key}", sha256=digest, size=len(data))

    def get(self, tenant_id: str, key: str) -> bytes:
        env = json.loads(self._raw.get(self._path(tenant_id, key)))
        aad = f"{tenant_id}|{key}|{env['sha256']}".encode()
        sealed = {k: base64.b64decode(env[k]) for k in ("wrapped_key", "nonce", "ciphertext")}
        data = open_sealed(self._kms, env["key_ref"], sealed, aad)
        if hashlib.sha256(data).hexdigest() != env["sha256"]:
            raise IntegrityError(key)
        return data

    def exists(self, tenant_id: str, key: str) -> bool:
        return self._raw.exists(self._path(tenant_id, key))
