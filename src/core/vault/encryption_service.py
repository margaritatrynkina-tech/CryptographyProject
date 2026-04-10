import os
import json
from datetime import datetime
from typing import Dict, Any
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from src.core.crypto.abstract import EncryptionService, EncryptionKeyProvider
class AESGCMEncryptionService(EncryptionService):
    def encrypt_entry(self, entry_data: Dict[str, Any], key_provider: EncryptionKeyProvider) -> bytes:
        payload = {
            **entry_data,
            "created_at": datetime.utcnow().isoformat(),
            "version": 1
        }
        plaintext = json.dumps(payload).encode('utf-8')
        key = key_provider.get_encryption_key()
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ciphertext
    def decrypt_entry(self, encrypted_blob: bytes, key_provider: EncryptionKeyProvider) -> Dict[str, Any]:
        key = key_provider.get_encryption_key()
        aesgcm = AESGCM(key)
        nonce = encrypted_blob[:12]
        ciphertext = encrypted_blob[12:]
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return json.loads(plaintext.decode('utf-8'))