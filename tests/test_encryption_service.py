import pytest
import json
import os
from unittest.mock import MagicMock

pytestmark = pytest.mark.crypto


class TestAESGCMEncryptionService:
    def setup_method(self):
        from src.core.vault.encryption_service import AESGCMEncryptionService
        self.crypto = AESGCMEncryptionService()
        self.key = os.urandom(32)  # 32 bytes = AES-256

    def test_encrypt_decrypt_roundtrip(self):
        data = b"Hello, World!"
        encrypted = self.crypto.encrypt(data, self.key)
        decrypted = self.crypto.decrypt(encrypted, self.key)
        assert decrypted == data

    def test_encrypt_changes_data(self):
        data = b"secret"