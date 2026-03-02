import pytest
import base64
from core.crypto.placeholder import AES256Placeholder
from core.key_manager import KeyManager
class TestPlaceholderCrypto:
    def test_encrypt_decrypt(self):
        crypto = AES256Placeholder()
        key = b"0123456789abcdef"  # 16 байт
        data = b"Secret message"
        encrypted = crypto.encrypt(data, key)
        assert isinstance(encrypted, bytes)
        decrypted = crypto.decrypt(encrypted, key)
        assert decrypted == data
    def test_encrypt_output_format(self):
        crypto = AES256Placeholder()
        key = b"testkey12345678"
        data = b"test"
        encrypted = crypto.encrypt(data, key)
        # Проверяем, что результат в base64
        try:
            decoded = base64.b64decode(encrypted)
            assert isinstance(decoded, bytes)
        except Exception:
            pytest.fail("Результат не в формате base64")
    def test_different_keys_different_output(self):
        crypto = AES256Placeholder()
        key1 = b"key1234567890123"
        key2 = b"key9876543210987"
        data = b"Test data"
        encrypted1 = crypto.encrypt(data, key1)
        encrypted2 = crypto.encrypt(data, key2)
        assert encrypted1 != encrypted2
    def test_same_key_same_output(self):
        crypto = AES256Placeholder()
        key = b"samekey12345678"
        data = b"Test data"
        encrypted1 = crypto.encrypt(data, key)
        encrypted2 = crypto.encrypt(data, key)
        assert encrypted1 == encrypted2
    def test_empty_data(self):
        crypto = AES256Placeholder()
        key = b"testkey12345678"
        encrypted = crypto.encrypt(b"", key)
        decrypted = crypto.decrypt(encrypted, key)
        assert decrypted == b""
    def test_long_data(self):
        crypto = AES256Placeholder()
        key = b"testkey12345678"
        data = b"x" * 10000  # 10KB данных
        encrypted = crypto.encrypt(data, key)
        decrypted = crypto.decrypt(encrypted, key)
        assert decrypted == data
class TestKeyManager:
    def test_derive_key_length(self):
        password = "test_password"
        salt = KeyManager.generate_salt()
        key = KeyManager.derive_key(password, salt)
        assert len(key) == 32  # 256 бит
    def test_derive_key_consistency(self):
        password = "consistent_password"
        salt = b"fixed_salt_16byte"
        key1 = KeyManager.derive_key(password, salt)
        key2 = KeyManager.derive_key(password, salt)
        assert key1 == key2
    def test_different_passwords_different_keys(self):
        salt = KeyManager.generate_salt()
        key1 = KeyManager.derive_key("password1", salt)
        key2 = KeyManager.derive_key("password2", salt)
        assert key1 != key2
    def test_different_salts_different_keys(self):
        password = "test_password"
        salt1 = KeyManager.generate_salt()
        salt2 = KeyManager.generate_salt()
        key1 = KeyManager.derive_key(password, salt1)
        key2 = KeyManager.derive_key(password, salt2)
        assert key1 != key2
    def test_generate_salt_length(self):
        salt = KeyManager.generate_salt()
        assert len(salt) == 16
    def test_generate_salt_uniqueness(self):
        salts = [KeyManager.generate_salt() for _ in range(100)]
        # Проверяем, что нет дубликатов
        assert len(set(salts)) == 100
    def test_empty_password(self):
        salt = KeyManager.generate_salt()
        key = KeyManager.derive_key("", salt)
        assert len(key) == 32
        assert isinstance(key, bytes)