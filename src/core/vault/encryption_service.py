import json
import os
from typing import Any, Dict
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from src.core.crypto.abstract import EncryptionService, EncryptionKeyProvider
class AESGCMEncryptionService(EncryptionService):
    def encrypt(self, data: bytes, key: bytes) -> bytes:
        if len(key) != 32:
            raise ValueError("AES-256 key must be 32 bytes long")
        nonce = os.urandom(12)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        return nonce + ciphertext
    def decrypt(self, encrypted_data: bytes, key: bytes) -> bytes:
        if len(key) != 32:
            raise ValueError("AES-256 key must be 32 bytes long")
        if len(encrypted_data) < 13:
            raise ValueError("Invalid encrypted payload")
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        aesgcm = AESGCM(key)
        try:
            return aesgcm.decrypt(nonce, ciphertext, None)
        except InvalidTag as e:
            raise ValueError("Data integrity check failed") from e
    def encrypt_entry(self, entry_data: Dict[str, Any], key_provider: EncryptionKeyProvider) -> bytes:
        key = key_provider.get_encryption_key()
        if key is None:
            raise ValueError("Ключ шифрования недоступен: сначала войдите по мастер-паролю")
        payload = dict(entry_data)
        payload.setdefault("version", 1)
        plaintext = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        return self.encrypt(plaintext, key)
    def decrypt_entry(self, encrypted_blob: bytes, key_provider: EncryptionKeyProvider) -> Dict[str, Any]:
        key = key_provider.get_encryption_key()
        if key is None:
            raise ValueError("Ключ шифрования недоступен: сначала войдите по мастер-паролю")
        plaintext = self.decrypt(encrypted_blob, key)
        return json.loads(plaintext.decode("utf-8"))