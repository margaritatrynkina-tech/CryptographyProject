"""
TEST-1: Основные криптографические функции
Покрывает: шифрование, расшифровку, вывод ключей
Маркеры: fast, crypto
"""
import os
import pytest
import sqlite3

# ---------------------------------------------------------------------------
# AESGCMEncryptionService
# ---------------------------------------------------------------------------

@pytest.fixture
def aes_service():
    from src.core.vault.encryption_service import AESGCMEncryptionService
    return AESGCMEncryptionService()


@pytest.fixture
def aes_key():
    return os.urandom(32)


class TestAESGCMEncryptionService:
    @pytest.mark.crypto
    def test_encrypt_returns_bytes(self, aes_service, aes_key):
        ct = aes_service.encrypt(b"hello world", aes_key)
        assert isinstance(ct, bytes)

    @pytest.mark.crypto
    def test_encrypt_decrypt_roundtrip(self, aes_service, aes_key):
        plaintext = b"secret data 12345"
        ct = aes_service.encrypt(plaintext, aes_key)
        pt = aes_service.decrypt(ct, aes_key)
        assert pt == plaintext

    @pytest.mark.crypto
    def test_ciphertext_differs_from_plaintext(self, aes_service, aes_key):
        plaintext = b"hello"
        ct = aes_service.encrypt(plaintext, aes_key)
        assert ct != plaintext

    @pytest.mark.crypto
    def test_nonce_randomness(self, aes_service, aes_key):
        ct1 = aes_service.encrypt(b"same", aes_key)
        ct2 = aes_service.encrypt(b"same", aes_key)
        # Two encryptions of the same plaintext should produce different ciphertext
        assert ct1 != ct2

    @pytest.mark.crypto
    def test_wrong_key_raises(self, aes_service, aes_key):
        ct = aes_service.encrypt(b"data", aes_key)
        wrong_key = os.urandom(32)
        with pytest.raises(Exception):
            aes_service.decrypt(ct, wrong_key)

    @pytest.mark.crypto
    def test_bad_key_length_encrypt(self, aes_service):
        with pytest.raises(ValueError):
            aes_service.encrypt(b"data", b"short")

    @pytest.mark.crypto
    def test_bad_key_length_decrypt(self, aes_service):
        with pytest.raises(ValueError):
            aes_service.decrypt(b"data" * 10, b"short")

    @pytest.mark.crypto
    def test_tampered_ciphertext_raises(self, aes_service, aes_key):
        ct = bytearray(aes_service.encrypt(b"data", aes_key))
        ct[-1] ^= 0xFF  # flip last byte
        with pytest.raises(Exception):
            aes_service.decrypt(bytes(ct), aes_key)

    @pytest.mark.crypto
    def test_encrypt_entry_roundtrip(self, aes_service, aes_key):
        from unittest.mock import MagicMock
        km = MagicMock()
        km.get_encryption_key.return_value = aes_key

        data = {"title": "Test", "password": "pass123"}
        blob = aes_service.encrypt_entry(data, km)
        assert isinstance(blob, bytes)
        recovered = aes_service.decrypt_entry(blob, km)
        assert recovered["title"] == "Test"
        assert recovered["password"] == "pass123"

    @pytest.mark.crypto
    def test_encrypt_entry_no_key_raises(self, aes_service):
        from unittest.mock import MagicMock
        km = MagicMock()
        km.get_encryption_key.return_value = None
        with pytest.raises(ValueError, match="недоступен"):
            aes_service.encrypt_entry({"title": "x"}, km)

    @pytest.mark.crypto
    def test_too_short_ciphertext_raises(self, aes_service, aes_key):
        with pytest.raises(ValueError):
            aes_service.decrypt(b"\x00" * 5, aes_key)


# ---------------------------------------------------------------------------
# AES256Placeholder (legacy)
# ---------------------------------------------------------------------------

class TestAES256Placeholder:
    @pytest.mark.fast
    def test_encrypt_decrypt(self):
        from src.core.crypto.placeholder import AES256Placeholder
        svc = AES256Placeholder()
        key = b"0123456789abcdef"
        ct = svc.encrypt(b"hello", key)
        assert svc.decrypt(ct, key) == b"hello"

    @pytest.mark.fast
    def test_encrypt_returns_bytes(self):
        from src.core.crypto.placeholder import AES256Placeholder
        svc = AES256Placeholder()
        ct = svc.encrypt(b"data", b"k" * 16)
        assert isinstance(ct, bytes)


# ---------------------------------------------------------------------------
# AuditLogEncryption
# ---------------------------------------------------------------------------

class TestAuditLogEncryption:
    @pytest.mark.crypto
    def test_encrypt_decrypt_roundtrip(self):
        from src.core.audit.audit_encryption import AuditLogEncryption
        key = os.urandom(32)
        enc = AuditLogEncryption(key)
        original = "AUDIT_EVENT: user_login"
        stored = enc.encrypt(original)
        assert stored.startswith("ENC:")
        assert enc.decrypt(stored) == original

    @pytest.mark.crypto
    def test_disabled_when_no_key(self):
        from src.core.audit.audit_encryption import AuditLogEncryption
        enc = AuditLogEncryption(None)
        assert not enc.enabled
        # Encrypt returns plaintext as-is
        assert enc.encrypt("plain") == "plain"

    @pytest.mark.crypto
    def test_decrypt_plain_passthrough(self):
        from src.core.audit.audit_encryption import AuditLogEncryption
        key = os.urandom(32)
        enc = AuditLogEncryption(key)
        # Non-ENC: prefix → returned unchanged
        assert enc.decrypt("not_encrypted") == "not_encrypted"

    @pytest.mark.crypto
    def test_decrypt_without_key_raises(self):
        from src.core.audit.audit_encryption import AuditLogEncryption
        key = os.urandom(32)
        enc_with_key = AuditLogEncryption(key)
        stored = enc_with_key.encrypt("secret")
        enc_no_key = AuditLogEncryption(None)
        with pytest.raises(ValueError):
            enc_no_key.decrypt(stored)

    @pytest.mark.crypto
    def test_wrong_key_raises(self):
        from src.core.audit.audit_encryption import AuditLogEncryption
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        enc1 = AuditLogEncryption(key1)
        enc2 = AuditLogEncryption(key2)
        stored = enc1.encrypt("secret")
        with pytest.raises(Exception):
            enc2.decrypt(stored)


# ---------------------------------------------------------------------------
# KeyDerivation
# ---------------------------------------------------------------------------

class TestKeyDerivation:
    @pytest.fixture
    def kd(self):
        from src.core.crypto.key_derivation import KeyDerivation
        cfg = {
            "argon2_time": 1, "argon2_memory": 8192,
            "argon2_parallelism": 1, "pbkdf2_iterations": 1000
        }
        return KeyDerivation(cfg)

    @pytest.mark.crypto
    def test_create_auth_hash_returns_string(self, kd):
        h = kd.create_auth_hash("password123")
        assert isinstance(h, str)
        assert len(h) > 20

    @pytest.mark.crypto
    def test_verify_password_correct(self, kd):
        h = kd.create_auth_hash("mypassword")
        assert kd.verify_password("mypassword", h) is True

    @pytest.mark.crypto
    def test_verify_password_wrong(self, kd):
        h = kd.create_auth_hash("mypassword")
        assert kd.verify_password("wrongpassword", h) is False

    @pytest.mark.crypto
    def test_generate_enc_salt_length(self, kd):
        salt = kd.generate_enc_salt()
        assert len(salt) == 16

    @pytest.mark.crypto
    def test_generate_enc_salt_random(self, kd):
        salt1 = kd.generate_enc_salt()
        salt2 = kd.generate_enc_salt()
        assert salt1 != salt2

    @pytest.mark.crypto
    def test_derive_encryption_key_length(self, kd):
        salt = kd.generate_enc_salt()
        key = kd.derive_encryption_key("pass", salt)
        assert len(key) == 32

    @pytest.mark.crypto
    def test_derive_encryption_key_deterministic(self, kd):
        salt = os.urandom(16)
        k1 = kd.derive_encryption_key("same", salt)
        k2 = kd.derive_encryption_key("same", salt)
        assert k1 == k2

    @pytest.mark.crypto
    def test_derive_different_passwords_different_keys(self, kd):
        salt = os.urandom(16)
        k1 = kd.derive_encryption_key("pass1", salt)
        k2 = kd.derive_encryption_key("pass2", salt)
        assert k1 != k2

    @pytest.mark.crypto
    def test_derive_audit_signing_key_length(self, kd):
        salt = os.urandom(16)
        key = kd.derive_audit_signing_key("pass", salt)
        assert len(key) == 32

    @pytest.mark.crypto
    def test_derive_audit_encryption_key_length(self, kd):
        salt = os.urandom(16)
        key = kd.derive_audit_encryption_key("pass", salt)
        assert len(key) == 32

    @pytest.mark.crypto
    def test_audit_keys_differ_from_enc_key(self, kd):
        salt = os.urandom(16)
        enc = kd.derive_encryption_key("pass", salt)
        audit_sign = kd.derive_audit_signing_key("pass", salt)
        audit_enc = kd.derive_audit_encryption_key("pass", salt)
        assert enc != audit_sign
        assert enc != audit_enc
        assert audit_sign != audit_enc


# ---------------------------------------------------------------------------
# KeyManager (integration)
# ---------------------------------------------------------------------------

class TestKeyManager:
    @pytest.fixture
    def km_with_db(self):
        from src.core.key_manager import KeyManager
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.execute(
            "CREATE TABLE key_store "
            "(id INTEGER PRIMARY KEY AUTOINCREMENT, key_type TEXT, key_data BLOB, "
            "version INTEGER DEFAULT 1, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)"
        )
        conn.commit()
        cfg = {
            "argon2_time": 1, "argon2_memory": 8192,
            "argon2_parallelism": 1, "pbkdf2_iterations": 1000,
            "key_cache_timeout": 3600,
        }
        km = KeyManager(cfg, conn)
        return km

    @pytest.mark.crypto
    def test_setup_and_authenticate(self, km_with_db):
        km = km_with_db
        km.setup_master_password("StrongPass1!")
        assert km.authenticate("StrongPass1!") is True

    @pytest.mark.crypto
    def test_wrong_password_rejected(self, km_with_db):
        km = km_with_db
        km.setup_master_password("StrongPass1!")
        assert km.authenticate("WrongPass") is False

    @pytest.mark.crypto
    def test_get_encryption_key_after_auth(self, km_with_db):
        km = km_with_db
        km.setup_master_password("StrongPass1!")
        km.authenticate("StrongPass1!")
        key = km.get_encryption_key()
        assert key is not None
        assert len(key) == 32

    @pytest.mark.crypto
    def test_clear_keys(self, km_with_db):
        km = km_with_db
        km.setup_master_password("StrongPass1!")
        km.authenticate("StrongPass1!")
        km.clear_keys()
        assert km.get_encryption_key() is None

    @pytest.mark.crypto
    def test_get_audit_signing_seed(self, km_with_db):
        km = km_with_db
        km.setup_master_password("StrongPass1!")
        km.authenticate("StrongPass1!")
        seed = km.get_audit_signing_seed("StrongPass1!")
        assert seed is not None
        assert len(seed) == 32
