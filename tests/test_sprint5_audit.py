import json
import sqlite3
import tempfile
import time
from pathlib import Path

import pytest

from src.core.audit.audit_logger import AuditLogger
from src.core.audit.log_signer import AuditLogSigner
from src.core.audit.log_verifier import AuditLogVerifier
from src.core.audit.log_formatters import export_logs, import_signed_json
from src.core.crypto.key_derivation import KeyDerivation
from src.database.db import DatabaseManager


class DummyConfig:
    def get(self, key, default=None):
        defaults = {
            "argon2_time": 1,
            "argon2_memory": 8192,
            "argon2_parallelism": 1,
            "pbkdf2_iterations": 1000,
        }
        return defaults.get(key, default)


@pytest.fixture
def audit_env():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    db = DatabaseManager(db_path)
    db.connect()
    kd = KeyDerivation(DummyConfig())
    salt = kd.generate_enc_salt()
    seed = kd.derive_audit_signing_key("test_master_password", salt)
    signer = AuditLogSigner(signing_seed=seed)
    logger = AuditLogger(db.connection, signer)
    yield {"db": db, "logger": logger, "signer": signer, "path": db_path}
    db.close()
    Path(db_path).unlink(missing_ok=True)


# TEST-1: Integrity test
def test_integrity_tampering_detected(audit_env):
    logger = audit_env["logger"]
    for i in range(1000):
        logger.log_event("TEST_EVENT", "INFO", "test", {"index": i})

    conn = audit_env["db"].connection
    conn.execute(
        "UPDATE audit_log SET entry_data = ? WHERE sequence_number = 500",
        ('{"tampered": true}',),
    )
    conn.commit()

    result = logger.verify_integrity()
    assert not result["verified"]
    assert result["invalid_entries"] or result["chain_breaks"]


# TEST-2: Performance test
def test_performance_logging_and_verification(audit_env):
    logger = audit_env["logger"]
    signer = audit_env["signer"]

    times = []
    for i in range(10000):
        start = time.perf_counter()
        logger.log_event("PERF_EVENT", "INFO", "perf_test", {"i": i})
        times.append((time.perf_counter() - start) * 1000)

    avg_ms = sum(times) / len(times)
    assert avg_ms < 10, f"Average log time {avg_ms:.2f}ms exceeds 10ms"

    start = time.perf_counter()
    result = AuditLogVerifier(signer).verify_connection(
        audit_env["db"].connection, limit=1000
    )
    elapsed = time.perf_counter() - start
    assert elapsed < 1.0, f"Verification of 1000 entries took {elapsed:.2f}s"
    assert result["valid_entries"] == 1000


# TEST-3: Export/import test
def test_export_import_signed_json(audit_env):
    logger = audit_env["logger"]
    signer = audit_env["signer"]
    for i in range(10):
        logger.log_event("EXPORT_TEST", "INFO", "test", {"n": i})

    rows = logger.get_rows_for_export()
    with tempfile.TemporaryDirectory() as tmp:
        path = str(Path(tmp) / "audit_export.json")
        export_logs(
            rows,
            "json",
            path,
            signer_public_key_hex=signer.get_public_key_hex(),
        )
        data = import_signed_json(path)
        assert data["public_key_hex"] == signer.get_public_key_hex()
        assert len(data["entries"]) == len(rows)

        for entry in data["entries"]:
            sig = bytes.fromhex(entry["signature"])
            assert signer.verify(entry["entry_data"].encode("utf-8"), sig)

        reimport = AuditLogVerifier(signer).verify_rows(
            [
                {
                    "sequence_number": e["sequence_number"],
                    "entry_data": e["entry_data"],
                    "signature": e["signature"],
                    "entry_hash": e["entry_hash"],
                    "previous_hash": e["previous_hash"],
                }
                for e in data["entries"]
            ]
        )
        assert reimport["verified"]


# TEST-4: Failure recovery test
def test_failure_recovery_graceful_degradation(audit_env):
    logger = audit_env["logger"]
    logger.log_event("BEFORE_CORRUPTION", "INFO", "test", {})

    conn = audit_env["db"].connection
    conn.execute("DROP TABLE audit_log")
    conn.commit()

    logger.set_degraded(False)
    seq = logger.log_event("AFTER_CORRUPTION", "INFO", "test", {})
    assert seq is None
    assert logger.is_degraded

    conn.execute("""
        CREATE TABLE audit_log (
            sequence_number INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            user_id TEXT NOT NULL DEFAULT 'anonymous',
            source TEXT NOT NULL,
            entry_id TEXT,
            previous_hash TEXT NOT NULL,
            entry_data TEXT NOT NULL,
            entry_hash TEXT NOT NULL,
            signature TEXT NOT NULL
        )
    """)
    conn.commit()
    logger.set_degraded(False)
    recovery_logger = AuditLogger(conn, audit_env["signer"])
    seq2 = recovery_logger.log_event("RECOVERY", "INFO", "test", {})
    assert seq2 is not None


# TEST-5: Security test
def test_security_sql_injection_logged_and_blocked(audit_env):
    logger = audit_env["logger"]
    payloads = [
        "'; DROP TABLE audit_log; --",
        "1 OR 1=1",
        "UNION SELECT password FROM users",
    ]
    for p in payloads:
        blocked = logger.attempt_sql_injection(p)
        assert blocked

    rows = logger.query_logs(event_type="SECURITY_SQL_INJECTION_ATTEMPT", limit=10)
    assert len(rows) >= len(payloads)

    safe_search = "EXPORT_TEST"
    assert not logger.attempt_sql_injection(safe_search)
    results = logger.query_logs(search=safe_search, limit=5)
    assert isinstance(results, list)
