import base64
import os
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ENC_PREFIX = "ENC:"


class AuditLogEncryption:
    def __init__(self, key: Optional[bytes]):
        self._key = key

    @property
    def enabled(self) -> bool:
        return self._key is not None and len(self._key) == 32

    def encrypt(self, plaintext: str) -> str:
        if not self.enabled:
            return plaintext
        nonce = os.urandom(12)
        ct = AESGCM(self._key).encrypt(nonce, plaintext.encode("utf-8"), None)
        blob = base64.b64encode(nonce + ct).decode("ascii")
        return ENC_PREFIX + blob

    def decrypt(self, stored: str) -> str:
        if not stored.startswith(ENC_PREFIX):
            return stored
        if not self.enabled:
            raise ValueError("Encrypted audit entry but no decryption key")
        raw = base64.b64decode(stored[len(ENC_PREFIX) :])
        nonce, ct = raw[:12], raw[12:]
        return AESGCM(self._key).decrypt(nonce, ct, None).decode("utf-8")
