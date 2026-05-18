import tempfile
from pathlib import Path

import pytest

from src.core.audit.audit_logger import AuditLogger
from src.core.audit.audit_encryption import AuditLogEncryption, ENC_PREFIX
from src.core.audit.log_signer import AuditLogSigner
from src.core.crypto.key_derivation import KeyDerivation
from src.database.db import DatabaseManager


class DummyConfig:
    def get(self, key, default=None):
        return {"argon2_time": 1, "argon2_memory": 8192, "pbkdf2_iterations": 1000}.get(key, default)


@pytest.fixture
def enc_audit():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name
    db = DatabaseManager(path)
    db.connect()
    kd = KeyDerivation(DummyConfig())
    salt = kd.generate_enc_salt()
    sign_seed = kd.derive_audit_signing_key("pwd", salt)
    enc_key = kd.derive_audit_encryption_key("pwd", salt)
    signer = AuditLogSigner(signing_seed=sign_seed)
    logger = AuditLogger(db.connection, signer, audit_encryption_key=enc_key)
    yield {"logger": logger, "db": db, "enc_key": enc_key}
    logger.stop_periodic_verification()
    db.close()
    Path(path).unlink(missing_ok=True)


def test_audit_entry_encrypted_at_rest(enc_audit):
    logger = enc_audit["logger"]
    logger.log_event("TEST_ENC", "INFO", "t", {"x": 1})
    cur = enc_audit["db"].connection.cursor()
    cur.execute("SELECT entry_data FROM audit_log ORDER BY sequence_number DESC LIMIT 1")
    stored = cur.fetchone()[0]
    assert stored.startswith(ENC_PREFIX)


def test_audit_decrypt_and_verify(enc_audit):
    logger = enc_audit["logger"]
    for i in range(5):
        logger.log_event("E", "INFO", "t", {"i": i})
    result = logger.verify_integrity()
    assert result["verified"]


def test_audit_statistics(enc_audit):
    logger = enc_audit["logger"]
    logger.log_event("AUTH_LOGIN_FAILED", "WARN", "t", {})
    stats = logger.get_statistics(7)
    assert "by_event_type" in stats
    assert stats["total"] >= 1
