import hashlib
import hmac
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


class AuditLogSigner:
    GENESIS_HASH = "0" * 64

    def __init__(self, signing_seed: Optional[bytes] = None, hmac_key: Optional[bytes] = None):
        self._use_ed25519 = False
        self._private_key: Optional[ed25519.Ed25519PrivateKey] = None
        self._public_key_bytes: Optional[bytes] = None
        self._hmac_key: Optional[bytes] = hmac_key

        if signing_seed and len(signing_seed) >= 32:
            try:
                self._private_key = ed25519.Ed25519PrivateKey.from_private_bytes(signing_seed[:32])
                self._public_key_bytes = self._private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
                self._use_ed25519 = True
            except Exception:
                self._use_ed25519 = False

        if not self._use_ed25519 and signing_seed:
            self._hmac_key = signing_seed[:32]

    @property
    def algorithm(self) -> str:
        return "Ed25519" if self._use_ed25519 else "HMAC-SHA256"

    def get_public_key_hex(self) -> str:
        if self._public_key_bytes:
            return self._public_key_bytes.hex()
        if self._hmac_key:
            return hashlib.sha256(self._hmac_key).hexdigest()
        return ""

    def sign(self, data: bytes) -> bytes:
        if self._use_ed25519 and self._private_key:
            return self._private_key.sign(data)
        if self._hmac_key:
            return hmac.new(self._hmac_key, data, hashlib.sha256).digest()
        raise RuntimeError("Audit signing key not available")

    def verify(self, data: bytes, signature: bytes) -> bool:
        if self._use_ed25519 and self._private_key:
            try:
                self._private_key.public_key().verify(signature, data)
                return True
            except InvalidSignature:
                return False
        if self._hmac_key:
            expected = hmac.new(self._hmac_key, data, hashlib.sha256).digest()
            return hmac.compare_digest(expected, signature)
        return False

    @staticmethod
    def compute_entry_hash(entry_json: str) -> str:
        return hashlib.sha256(entry_json.encode("utf-8")).hexdigest()
