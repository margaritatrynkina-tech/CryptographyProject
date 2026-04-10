import pytest
from src.core.vault.encryption_service import AESGCMEncryptionService
from src.core.key_manager import KeyManager
def test_encryption_roundtrip(temp_db):
    config = ConfigManager()
    km = KeyManager(config, temp_db.connection)
    km.setup_master_password("test123!")
    crypto = AESGCMEncryptionService()
    data = {"title": "Test", "password": "secret"}
    encrypted = crypto.encrypt_entry(data, km)
    assert b'"secret"' not in encrypted
    decrypted = crypto.decrypt_entry(encrypted, km)
    assert decrypted == data