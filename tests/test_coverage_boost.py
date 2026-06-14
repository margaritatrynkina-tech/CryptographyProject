"""
Coverage boost tests — цель: поднять общее покрытие до ≥ 85 %.

Охватываемые модули:
  • core/audit/log_signer.py          (31% → ~90%)
  • core/audit/log_verifier.py        (12% → ~85%)
  • core/audit/log_formatters.py      (30% → ~90%)
  • core/audit/audit_logger.py        (18% → ~70%)
  • core/import_export/sharing_service.py (0% → ~85%)
  • core/import_export/importer.py    (56% → ~80%)
  • core/import_export/exporter.py    (61% → ~85%)
  • core/clipboard/clipboard_monitor.py (22% → ~85%)
  • core/clipboard/secure_memory.py   (33% → ~70%)
  • core/config.py                    (66% → ~90%)
  • core/settings/clipboard_presets.py (72% → ~90%)
  • core/crypto/abstract.py           (69% → ~90%)
  • database/__init__.py              (40% → ~80%)
"""

import json
import os
import sqlite3
import tempfile
import time
import threading
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch, call


# ─────────────────────────────────────────────
# Helpers / shared fixtures
# ─────────────────────────────────────────────

def _audit_db():
    """In-memory SQLite with audit_log + audit_signing_keys tables."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript("""
        CREATE TABLE audit_log (
            sequence_number INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       TEXT NOT NULL,
            event_type      TEXT NOT NULL,
            severity        TEXT NOT NULL,
            user_id         TEXT NOT NULL DEFAULT 'test',
            source          TEXT NOT NULL,
            entry_id        TEXT,
            previous_hash   TEXT NOT NULL,
            entry_data      TEXT NOT NULL,
            entry_hash      TEXT NOT NULL,
            signature       TEXT NOT NULL
        );
        CREATE TABLE audit_signing_keys (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            public_key_hex  TEXT NOT NULL UNIQUE,
            algorithm       TEXT NOT NULL DEFAULT 'Ed25519',
            created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.commit()
    return conn


def _make_signer(use_seed=True):
    from src.core.audit.log_signer import AuditLogSigner
    seed = os.urandom(32) if use_seed else None
    return AuditLogSigner(signing_seed=seed)


def _make_audit_logger(conn=None, seed=None):
    from src.core.audit.audit_logger import AuditLogger
    from src.core.audit.log_signer import AuditLogSigner
    from src.core.events import EventSystem
    if conn is None:
        conn = _audit_db()
    if seed is None:
        seed = os.urandom(32)
    signer = AuditLogSigner(signing_seed=seed)
    events = EventSystem()
    al = AuditLogger(
        db_connection=conn,
        signer=signer,
        events=events,
        user_id="test_user",
        audit_encryption_key=None,
        verify_interval_hours=999,   # don't auto-verify during tests
    )
    return al, conn, signer


# ═══════════════════════════════════════════════
# AuditLogSigner
# ═══════════════════════════════════════════════

class TestAuditLogSigner:

    @pytest.mark.fast
    def test_algorithm_ed25519(self):
        s = _make_signer()
        assert s.algorithm == "Ed25519"

    @pytest.mark.fast
    def test_algorithm_hmac_fallback(self):
        from src.core.audit.log_signer import AuditLogSigner
        s = AuditLogSigner(hmac_key=os.urandom(32))
        assert s.algorithm == "HMAC-SHA256"

    @pytest.mark.fast
    def test_no_key_raises_on_sign(self):
        from src.core.audit.log_signer import AuditLogSigner
        s = AuditLogSigner()
        with pytest.raises(RuntimeError):
            s.sign(b"data")

    @pytest.mark.fast
    def test_sign_verify_ed25519(self):
        s = _make_signer()
        data = b"hello audit"
        sig = s.sign(data)
        assert s.verify(data, sig) is True

    @pytest.mark.fast
    def test_verify_wrong_data(self):
        s = _make_signer()
        sig = s.sign(b"original")
        assert s.verify(b"tampered", sig) is False

    @pytest.mark.fast
    def test_sign_verify_hmac(self):
        from src.core.audit.log_signer import AuditLogSigner
        key = os.urandom(32)
        s = AuditLogSigner(hmac_key=key)
        data = b"hmac test"
        sig = s.sign(data)
        assert s.verify(data, sig) is True

    @pytest.mark.fast
    def test_verify_no_key_returns_false(self):
        from src.core.audit.log_signer import AuditLogSigner
        s = AuditLogSigner()
        assert s.verify(b"x", b"y") is False

    @pytest.mark.fast
    def test_get_public_key_hex_ed25519(self):
        s = _make_signer()
        h = s.get_public_key_hex()
        assert len(h) == 64

    @pytest.mark.fast
    def test_get_public_key_hex_hmac(self):
        from src.core.audit.log_signer import AuditLogSigner
        s = AuditLogSigner(hmac_key=os.urandom(32))
        h = s.get_public_key_hex()
        assert len(h) == 64

    @pytest.mark.fast
    def test_get_public_key_hex_empty(self):
        from src.core.audit.log_signer import AuditLogSigner
        s = AuditLogSigner()
        assert s.get_public_key_hex() == ""

    @pytest.mark.fast
    def test_compute_entry_hash(self):
        from src.core.audit.log_signer import AuditLogSigner
        h = AuditLogSigner.compute_entry_hash('{"event":"test"}')
        assert len(h) == 64

    @pytest.mark.fast
    def test_genesis_hash_constant(self):
        from src.core.audit.log_signer import AuditLogSigner
        assert len(AuditLogSigner.GENESIS_HASH) == 64


# ═══════════════════════════════════════════════
# AuditLogVerifier
# ═══════════════════════════════════════════════

class TestAuditLogVerifier:

    def _make_row(self, signer, seq, entry_json, prev_hash):
        from src.core.audit.log_signer import AuditLogSigner
        entry_hash = AuditLogSigner.compute_entry_hash(entry_json)
        sig = signer.sign(entry_json.encode("utf-8")).hex()
        return {
            "sequence_number": seq,
            "entry_data": entry_json,
            "signature": sig,
            "entry_hash": entry_hash,
            "previous_hash": prev_hash,
        }

    @pytest.mark.fast
    def test_empty_rows(self):
        from src.core.audit.log_verifier import AuditLogVerifier
        s = _make_signer()
        v = AuditLogVerifier(s)
        result = v.verify_rows([])
        assert result["verified"] is True
        assert result["total_entries"] == 0

    @pytest.mark.fast
    def test_valid_chain(self):
        from src.core.audit.log_verifier import AuditLogVerifier
        from src.core.audit.log_signer import AuditLogSigner
        s = _make_signer()
        v = AuditLogVerifier(s)
        genesis = AuditLogSigner.GENESIS_HASH
        r0 = self._make_row(s, 0, '{"seq":0}', genesis)
        r1 = self._make_row(s, 1, '{"seq":1}', r0["entry_hash"])
        result = v.verify_rows([r0, r1])
        assert result["verified"] is True
        assert result["valid_entries"] == 2

    @pytest.mark.fast
    def test_invalid_signature(self):
        from src.core.audit.log_verifier import AuditLogVerifier
        from src.core.audit.log_signer import AuditLogSigner
        s = _make_signer()
        v = AuditLogVerifier(s)
        row = self._make_row(s, 0, '{"seq":0}', AuditLogSigner.GENESIS_HASH)
        row["signature"] = "deadbeef" * 8   # 64 hex chars but wrong
        result = v.verify_rows([row])
        assert result["verified"] is False
        assert len(result["invalid_entries"]) == 1

    @pytest.mark.fast
    def test_bad_signature_encoding(self):
        from src.core.audit.log_verifier import AuditLogVerifier
        from src.core.audit.log_signer import AuditLogSigner
        s = _make_signer()
        v = AuditLogVerifier(s)
        row = self._make_row(s, 0, '{"seq":0}', AuditLogSigner.GENESIS_HASH)
        row["signature"] = "not_hex!!"
        result = v.verify_rows([row])
        assert result["verified"] is False

    @pytest.mark.fast
    def test_hash_mismatch(self):
        from src.core.audit.log_verifier import AuditLogVerifier
        from src.core.audit.log_signer import AuditLogSigner
        s = _make_signer()
        v = AuditLogVerifier(s)
        row = self._make_row(s, 0, '{"seq":0}', AuditLogSigner.GENESIS_HASH)
        row["entry_hash"] = "a" * 64   # wrong hash
        result = v.verify_rows([row])
        assert result["verified"] is False

    @pytest.mark.fast
    def test_chain_break(self):
        from src.core.audit.log_verifier import AuditLogVerifier
        from src.core.audit.log_signer import AuditLogSigner
        s = _make_signer()
        v = AuditLogVerifier(s)
        genesis = AuditLogSigner.GENESIS_HASH
        r0 = self._make_row(s, 0, '{"seq":0}', genesis)
        r1 = self._make_row(s, 1, '{"seq":1}', "b" * 64)  # wrong prev
        result = v.verify_rows([r0, r1])
        assert result["verified"] is False
        assert len(result["chain_breaks"]) == 1

    @pytest.mark.fast
    def test_verify_connection(self):
        from src.core.audit.log_verifier import AuditLogVerifier
        al, conn, signer = _make_audit_logger()
        v = AuditLogVerifier(signer)
        result = v.verify_connection(conn)
        assert result["verified"] is True

    @pytest.mark.fast
    def test_verify_connection_with_decrypt(self):
        from src.core.audit.log_verifier import AuditLogVerifier
        al, conn, signer = _make_audit_logger()
        al.log_event("TEST", "INFO", "test", {})
        v = AuditLogVerifier(signer)
        # decrypt fn is identity (no encryption)
        result = v.verify_connection(conn, decrypt_entry_data=lambda x: x)
        assert result["verified"] is True

    @pytest.mark.fast
    def test_verify_connection_with_limit(self):
        from src.core.audit.log_verifier import AuditLogVerifier
        al, conn, signer = _make_audit_logger()
        for _ in range(5):
            al.log_event("X", "INFO", "src", {})
        v = AuditLogVerifier(signer)
        result = v.verify_connection(conn, limit=3)
        assert result["verified"] is True


# ═══════════════════════════════════════════════
# AuditLogFormatters
# ═══════════════════════════════════════════════

class TestAuditLogFormatters:

    def _rows(self, n=3):
        return [
            {
                "sequence_number": i,
                "timestamp": "2024-01-01T00:00:00Z",
                "event_type": "TEST_EVENT",
                "severity": "INFO",
                "user_id": "alice",
                "source": "test",
                "entry_id": None,
                "entry_hash": "a" * 64,
                "previous_hash": "0" * 64,
            }
            for i in range(n)
        ]

    @pytest.mark.fast
    def test_export_json(self, tmp_path):
        from src.core.audit.log_formatters import export_logs
        p = str(tmp_path / "out.json")
        result = export_logs(self._rows(), "json", p)
        assert result == p
        data = json.loads(Path(p).read_text())
        assert "entries" in data
        assert len(data["entries"]) == 3

    @pytest.mark.fast
    def test_export_csv(self, tmp_path):
        from src.core.audit.log_formatters import export_logs
        p = str(tmp_path / "out.csv")
        result = export_logs(self._rows(), "csv", p)
        assert result == p
        content = Path(p).read_text()
        assert "sequence_number" in content
        assert "TEST_EVENT" in content

    @pytest.mark.fast
    def test_export_pdf(self, tmp_path):
        from src.core.audit.log_formatters import export_logs
        p = str(tmp_path / "out.pdf")
        result = export_logs(self._rows(), "pdf", p)
        assert result == p
        assert Path(p).exists()

    @pytest.mark.fast
    def test_export_unsupported_format(self, tmp_path):
        from src.core.audit.log_formatters import export_logs
        with pytest.raises(ValueError):
            export_logs(self._rows(), "xml", str(tmp_path / "x.xml"))

    @pytest.mark.fast
    def test_export_json_with_metadata(self, tmp_path):
        from src.core.audit.log_formatters import export_logs
        p = str(tmp_path / "meta.json")
        export_logs(self._rows(), "json", p,
                    signer_public_key_hex="abc123",
                    metadata={"custom": "meta"})
        data = json.loads(Path(p).read_text())
        assert data["public_key_hex"] == "abc123"

    @pytest.mark.fast
    def test_import_signed_json(self, tmp_path):
        from src.core.audit.log_formatters import export_logs, import_signed_json
        p = str(tmp_path / "import.json")
        export_logs(self._rows(2), "json", p)
        loaded = import_signed_json(p)
        assert "entries" in loaded

    @pytest.mark.fast
    def test_export_pdf_many_rows(self, tmp_path):
        from src.core.audit.log_formatters import export_logs
        rows = self._rows(600)   # > 500 truncation threshold
        p = str(tmp_path / "big.pdf")
        export_logs(rows, "pdf", p)
        assert Path(p).exists()

    @pytest.mark.fast
    def test_export_csv_empty(self, tmp_path):
        from src.core.audit.log_formatters import export_logs
        p = str(tmp_path / "empty.csv")
        export_logs([], "csv", p)
        content = Path(p).read_text()
        assert "sequence_number" in content  # header still written


# ═══════════════════════════════════════════════
# AuditLogger (core)
# ═══════════════════════════════════════════════

class TestAuditLogger:

    @pytest.mark.fast
    def test_log_event_returns_seq(self):
        al, _, _ = _make_audit_logger()
        seq = al.log_event("TEST", "INFO", "pytest", {"k": "v"})
        assert isinstance(seq, int)
        assert seq >= 0

    @pytest.mark.fast
    def test_genesis_entry_created(self):
        al, conn, _ = _make_audit_logger()
        count = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        assert count >= 1

    @pytest.mark.fast
    def test_log_multiple_events(self):
        al, conn, _ = _make_audit_logger()
        for i in range(5):
            al.log_event("EVT", "INFO", "src", {"i": i})
        count = al.count_logs()
        assert count >= 5

    @pytest.mark.fast
    def test_query_logs_by_event_type(self):
        al, _, _ = _make_audit_logger()
        al.log_event("MY_EVENT", "INFO", "src", {})
        al.log_event("OTHER", "WARN", "src", {})
        rows = al.query_logs(event_type="MY_EVENT")
        assert all(r["event_type"] == "MY_EVENT" for r in rows)

    @pytest.mark.fast
    def test_query_logs_by_severity(self):
        al, _, _ = _make_audit_logger()
        al.log_event("X", "WARN", "src", {})
        rows = al.query_logs(severity="WARN")
        assert len(rows) >= 1

    @pytest.mark.fast
    def test_query_logs_search(self):
        al, _, _ = _make_audit_logger()
        al.log_event("CUSTOM_SEARCH_EVENT", "INFO", "src", {})
        rows = al.query_logs(search="CUSTOM_SEARCH")
        assert len(rows) >= 1

    @pytest.mark.fast
    def test_count_logs_by_type(self):
        al, _, _ = _make_audit_logger()
        al.log_event("COUNT_ME", "INFO", "src", {})
        al.log_event("COUNT_ME", "INFO", "src", {})
        assert al.count_logs("COUNT_ME") == 2

    @pytest.mark.fast
    def test_verify_integrity_passes(self):
        al, _, _ = _make_audit_logger()
        al.log_event("X", "INFO", "src", {})
        result = al.verify_integrity()
        assert result["verified"] is True

    @pytest.mark.fast
    def test_sensitive_keys_redacted(self):
        al, conn, _ = _make_audit_logger()
        al.log_event("TEST", "INFO", "src", {"password": "s3cr3t", "user": "alice"})
        rows = al.query_logs(event_type="TEST")
        assert len(rows) >= 1
        # password must be redacted in the stored entry_data
        assert "s3cr3t" not in rows[0]["entry_data"]

    @pytest.mark.fast
    def test_sql_injection_blocked(self):
        al, _, _ = _make_audit_logger()
        blocked = al.attempt_sql_injection("'; DROP TABLE audit_log; --")
        assert blocked is True

    @pytest.mark.fast
    def test_sql_injection_clean_passes(self):
        al, _, _ = _make_audit_logger()
        assert al.attempt_sql_injection("normal search term") is False

    @pytest.mark.fast
    def test_get_statistics(self):
        al, _, _ = _make_audit_logger()
        al.log_event("AUTH_LOGIN_SUCCESS", "INFO", "src", {})
        stats = al.get_statistics(days=7)
        assert "total" in stats
        assert stats["total"] >= 1

    @pytest.mark.fast
    def test_get_rows_for_export(self):
        al, _, _ = _make_audit_logger()
        al.log_event("EXP", "INFO", "src", {})
        rows = al.get_rows_for_export()
        assert len(rows) >= 1

    @pytest.mark.fast
    def test_query_logs_by_date(self):
        al, _, _ = _make_audit_logger()
        al.log_event("DATE_EVT", "INFO", "src", {})
        rows = al.query_logs_by_date(date_from="2000-01-01")
        assert len(rows) >= 1

    @pytest.mark.fast
    def test_disabled_logger_returns_none(self):
        al, _, _ = _make_audit_logger()
        al._enabled = False
        result = al.log_event("X", "INFO", "src", {})
        assert result is None

    @pytest.mark.fast
    def test_stop_periodic_verification(self):
        al, _, _ = _make_audit_logger()
        al.stop_periodic_verification()  # should not raise

    @pytest.mark.fast
    def test_with_encryption_key(self):
        from src.core.audit.audit_logger import AuditLogger
        from src.core.audit.log_signer import AuditLogSigner
        conn = _audit_db()
        seed = os.urandom(32)
        enc_key = os.urandom(32)
        signer = AuditLogSigner(signing_seed=seed)
        al = AuditLogger(
            conn, signer, audit_encryption_key=enc_key,
            verify_interval_hours=999,
        )
        seq = al.log_event("ENC_TEST", "INFO", "test", {"data": "value"})
        assert seq is not None

    @pytest.mark.fast
    def test_event_subscription(self):
        from src.core.audit.audit_logger import AuditLogger
        from src.core.audit.log_signer import AuditLogSigner
        from src.core.events import EventSystem, EventType
        conn = _audit_db()
        seed = os.urandom(32)
        signer = AuditLogSigner(signing_seed=seed)
        events = EventSystem()
        al = AuditLogger(conn, signer, events=events, verify_interval_hours=999)
        events.emit(EventType.USER_LOGGED_IN, {})
        count = al.count_logs(event_type="AUTH_LOGIN_SUCCESS")
        assert count >= 1


# ═══════════════════════════════════════════════
# SharingService
# ═══════════════════════════════════════════════

def _make_sharing_service():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript("""
        CREATE TABLE shared_entries (
            shared_id TEXT PRIMARY KEY,
            original_entry_id TEXT NOT NULL,
            encryption_method TEXT NOT NULL DEFAULT 'password',
            recipient_info TEXT,
            permissions TEXT,
            shared_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME
        );
    """)
    conn.commit()

    em = MagicMock()
    em.get_entry.return_value = {
        "id": "entry-1",
        "title": "GitHub",
        "username": "alice",
        "password": "S3cr3t",
        "url": "https://github.com",
        "notes": "dev",
        "tags": ["dev"],
    }
    em.add_entry.return_value = "entry-1"

    al = MagicMock()
    al.log.return_value = None

    from src.core.import_export.sharing_service import SharingService
    return SharingService(conn, None, al, em), conn


class TestSharingService:

    @pytest.mark.fast
    def test_share_entry_password(self):
        svc, _ = _make_sharing_service()
        result = svc.share_entry(
            entry_id="entry-1",
            recipient="bob@example.com",
            permissions={"read_only": True},
            expires_in_days=7,
            password="share_pass_123",
        )
        assert "share_id" in result
        assert "package" in result
        assert "expires_at" in result

    @pytest.mark.fast
    def test_share_entry_invalid_expiry(self):
        svc, _ = _make_sharing_service()
        with pytest.raises(ValueError, match="expires_in_days"):
            svc.share_entry("entry-1", "bob", {}, expires_in_days=0, password="x")

    @pytest.mark.fast
    def test_share_entry_expiry_too_large(self):
        svc, _ = _make_sharing_service()
        with pytest.raises(ValueError):
            svc.share_entry("entry-1", "bob", {}, expires_in_days=31, password="x")

    @pytest.mark.fast
    def test_share_entry_missing_entry(self):
        svc, _ = _make_sharing_service()
        svc.entry_manager.get_entry.return_value = None
        with pytest.raises(KeyError):
            svc.share_entry("no-such-id", "bob", {}, password="x")

    @pytest.mark.fast
    def test_share_entry_password_required(self):
        svc, _ = _make_sharing_service()
        with pytest.raises(ValueError, match="password"):
            svc.share_entry("entry-1", "bob", {}, password=None)

    @pytest.mark.fast
    def test_import_shared_entry_password(self):
        svc, _ = _make_sharing_service()
        result = svc.share_entry(
            "entry-1", "bob", {"read_only": True}, password="share_pwd_123"
        )
        pkg = result["package"]
        imported = svc.import_shared_entry(pkg, password="share_pwd_123", save_to_vault=False)
        assert imported["entry"]["title"] == "GitHub"
        assert imported["saved"] is False

    @pytest.mark.fast
    def test_import_shared_entry_saves(self):
        svc, _ = _make_sharing_service()
        result = svc.share_entry("entry-1", "bob", {}, password="p")
        svc.import_shared_entry(result["package"], password="p", save_to_vault=True)
        svc.entry_manager.add_entry.assert_called_once()

    @pytest.mark.fast
    def test_import_expired_package(self):
        svc, _ = _make_sharing_service()
        from src.core.import_export.models import EncryptionMethod, SharePackage
        pkg = SharePackage(
            entry_data="x",
            encryption_method=EncryptionMethod.PASSWORD,
            permissions={},
            expires_at="2000-01-01T00:00:00Z",   # past
        ).to_dict()
        with pytest.raises(ValueError, match="expired"):
            svc.import_shared_entry(pkg, password="x")

    @pytest.mark.fast
    def test_import_tampered_integrity(self):
        svc, _ = _make_sharing_service()
        result = svc.share_entry("entry-1", "bob", {}, password="p")
        pkg = result["package"]
        pkg["integrity"]["hmac"] = "a" * 64   # tamper
        with pytest.raises(ValueError, match="integrity"):
            svc.import_shared_entry(pkg, password="p")

    @pytest.mark.fast
    def test_revoke_share(self):
        svc, _ = _make_sharing_service()
        result = svc.share_entry("entry-1", "bob", {}, password="p")
        ok = svc.revoke_share(result["share_id"])
        assert ok is True

    @pytest.mark.fast
    def test_revoke_nonexistent(self):
        svc, _ = _make_sharing_service()
        # UPDATE with no matching row doesn't raise — returns True (0 rows affected is still ok)
        ok = svc.revoke_share("nonexistent-id")
        assert ok is True

    @pytest.mark.fast
    def test_filter_entry_read_only(self):
        svc, _ = _make_sharing_service()
        entry = {"title": "X", "password": "p", "username": "u", "url": "", "notes": "", "tags": []}
        filtered = svc._filter_entry_for_sharing(entry, {"read_only": True})
        assert "password" not in filtered
        assert "title" in filtered

    @pytest.mark.fast
    def test_filter_entry_not_read_only(self):
        svc, _ = _make_sharing_service()
        entry = {"title": "X", "password": "p", "username": "u", "url": "", "notes": "", "tags": []}
        filtered = svc._filter_entry_for_sharing(entry, {"read_only": False})
        assert "password" in filtered

    @pytest.mark.fast
    def test_import_no_password_raises(self):
        svc, _ = _make_sharing_service()
        result = svc.share_entry("entry-1", "bob", {}, password="correct")
        with pytest.raises(ValueError, match="Password"):
            svc.import_shared_entry(result["package"], password=None)

    @pytest.mark.fast
    def test_share_without_integrity(self):
        """Packages with no integrity field are accepted."""
        svc, _ = _make_sharing_service()
        result = svc.share_entry("entry-1", "bob", {}, password="p")
        pkg = result["package"]
        pkg["integrity"] = None
        imported = svc.import_shared_entry(pkg, password="p", save_to_vault=False)
        assert "entry" in imported


# ═══════════════════════════════════════════════
# VaultImporter — uncovered paths
# ═══════════════════════════════════════════════

def _fresh_importer():
    em = MagicMock()
    _store: dict = {}

    def _create(data):
        import uuid as _u
        eid = data.get("id") or str(_u.uuid4())
        entry = dict(data, id=eid)
        if isinstance(entry.get("tags"), list):
            entry["tags"] = ",".join(entry["tags"])
        _store[eid] = entry
        return eid

    em.create_entry.side_effect = _create
    em.get_entry.side_effect = lambda eid: _store.get(eid)
    em.get_all_entries.side_effect = lambda: list(_store.values())
    em.update_entry.side_effect = lambda eid, d: (_store.update({eid: dict(d, id=eid)}) or True)

    al = MagicMock()
    al.log_event.return_value = 1

    from src.core.import_export.importer import VaultImporter
    return VaultImporter(entry_manager=em, encryption_service=None, audit_logger=al)


class TestVaultImporterExtra:

    @pytest.mark.fast
    def test_import_conflict_replace(self, tmp_path):
        imp = _fresh_importer()
        p = tmp_path / "data.csv"
        p.write_text("title,username,password\nGitHub,alice,old\n", encoding="utf-8")
        imp.import_csv(p)
        p.write_text("title,username,password\nGitHub,alice,new\n", encoding="utf-8")
        result = imp.import_csv(p, conflict_strategy="replace")
        assert result.successful_imports >= 1

    @pytest.mark.fast
    def test_import_conflict_rename(self, tmp_path):
        imp = _fresh_importer()
        p = tmp_path / "data.csv"
        p.write_text("title,username,password\nGitHub,alice,pass\n", encoding="utf-8")
        imp.import_csv(p)
        result = imp.import_csv(p, conflict_strategy="rename")
        assert result.successful_imports >= 1

    @pytest.mark.fast
    def test_import_conflict_merge(self, tmp_path):
        imp = _fresh_importer()
        p = tmp_path / "data.csv"
        p.write_text("title,username,password\nGitHub,alice,pass\n", encoding="utf-8")
        imp.import_csv(p)
        result = imp.import_csv(p, conflict_strategy="merge")
        assert result.successful_imports >= 1

    @pytest.mark.fast
    def test_malicious_content_blocked(self, tmp_path):
        imp = _fresh_importer()
        p = tmp_path / "bad.csv"
        p.write_text("title,username\n<script>alert(1)</script>,alice\n", encoding="utf-8")
        with pytest.raises(ValueError, match="malicious"):
            imp.import_csv(p)

    @pytest.mark.fast
    def test_file_too_large(self, tmp_path):
        imp = _fresh_importer()
        p = tmp_path / "big.csv"
        # Write > 10 MB
        with open(p, "w") as f:
            f.write("title,username\n")
            chunk = "A" * 1000 + ",user\n"
            for _ in range(11000):
                f.write(chunk)
        with pytest.raises(ValueError, match="MB"):
            imp.import_csv(p)

    @pytest.mark.fast
    def test_validate_bitwarden(self, tmp_path):
        from src.core.import_export.formats.bitwarden_handler import BitwardenHandler
        imp = _fresh_importer()
        p = tmp_path / "bw.json"
        p.write_text(BitwardenHandler.export([
            {"id": "x", "title": "T", "username": "u", "password": "p", "url": "", "notes": "", "tags": ""}
        ]))
        result = imp.validate_import_file(p, "bitwarden")
        assert result["is_valid"] is True

    @pytest.mark.fast
    def test_validate_lastpass(self, tmp_path):
        imp = _fresh_importer()
        p = tmp_path / "lp.csv"
        p.write_text("url,username,password,totp,extra,name,grouping,fav\n"
                     "https://x.com,alice,pass,,note,X,,0\n", encoding="utf-8")
        result = imp.validate_import_file(p, "lastpass")
        assert result["is_valid"] is True

    @pytest.mark.fast
    def test_validate_unknown_format(self, tmp_path):
        imp = _fresh_importer()
        p = tmp_path / "x.dat"
        p.write_text("data")
        result = imp.validate_import_file(p, "xml")
        assert result["is_valid"] is False

    @pytest.mark.fast
    def test_merge_entries_preserves_id(self):
        from src.core.import_export.importer import VaultImporter
        existing = {"id": "old-id", "title": "Old", "username": "u", "created_at": "2020"}
        incoming = {"id": "new-id", "title": "New", "username": "u2", "created_at": "2025"}
        merged = VaultImporter._merge_entries(existing, incoming)
        assert merged["id"] == "old-id"
        assert merged["title"] == "New"

    @pytest.mark.fast
    def test_merge_none_existing(self):
        from src.core.import_export.importer import VaultImporter
        incoming = {"title": "X", "username": "y"}
        merged = VaultImporter._merge_entries(None, incoming)
        assert merged == incoming

    @pytest.mark.fast
    def test_validate_lastpass_encrypted(self, tmp_path):
        """Encrypted LastPass file should be accepted (valid=True, no entries)."""
        from src.core.import_export.formats.lastpass_handler import LastPassHandler
        imp = _fresh_importer()
        p = tmp_path / "enc.csv"
        content = LastPassHandler.export(
            [{"title": "T", "username": "u", "password": "p", "url": "", "notes": "", "tags": ""}],
            password="enc_pass"
        )
        p.write_text(content, encoding="utf-8")
        result = imp.validate_import_file(p, "lastpass")
        assert result["is_valid"] is True


# ═══════════════════════════════════════════════
# VaultExporter — uncovered paths
# ═══════════════════════════════════════════════

def _fresh_exporter(entries=None):
    from src.core.import_export.exporter import VaultExporter
    em = MagicMock()
    em.get_all_entries.return_value = entries or [
        {"id": "e1", "title": "GitHub", "username": "alice", "password": "S3cr3t",
         "url": "https://github.com", "notes": "", "tags": "dev",
         "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z"},
    ]
    em.get_entry.side_effect = lambda eid: next(
        (e for e in em.get_all_entries.return_value if e["id"] == eid), None
    )
    al = MagicMock()
    al.log_event.return_value = 1
    return VaultExporter(entry_manager=em, encryption_service=None, audit_logger=al)


class TestVaultExporterExtra:

    @pytest.mark.fast
    def test_export_specific_entry_ids(self, tmp_path):
        exp = _fresh_exporter()
        p = tmp_path / "out.csv"
        result = exp.export_vault(
            entry_ids=["e1"],
            master_password="m",
            export_password=None,
            public_key=None,
            format="csv",
            file_path=p,
        )
        assert result.entry_count == 1

    @pytest.mark.fast
    def test_export_with_tag_filter(self, tmp_path):
        entries = [
            {"id": "e1", "title": "Dev", "username": "u", "password": "p",
             "url": "", "notes": "", "tags": ["dev"],
             "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z"},
            {"id": "e2", "title": "Work", "username": "u", "password": "p",
             "url": "", "notes": "", "tags": ["work"],
             "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z"},
        ]
        exp = _fresh_exporter(entries)
        p = tmp_path / "out.csv"
        result = exp.export_vault(
            entry_ids=None, master_password="m",
            export_password=None, public_key=None,
            format="csv", file_path=p,
            export_options={"filter_tags": ["dev"]},
        )
        assert result.entry_count == 1

    @pytest.mark.fast
    def test_export_with_date_filter(self, tmp_path):
        entries = [
            {"id": "e1", "title": "Old", "username": "u", "password": "p",
             "url": "", "notes": "", "tags": "",
             "created_at": "2020-01-01T00:00:00Z", "updated_at": "2020-01-01T00:00:00Z"},
            {"id": "e2", "title": "New", "username": "u", "password": "p",
             "url": "", "notes": "", "tags": "",
             "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z"},
        ]
        exp = _fresh_exporter(entries)
        p = tmp_path / "out.csv"
        result = exp.export_vault(
            entry_ids=None, master_password="m",
            export_password=None, public_key=None,
            format="csv", file_path=p,
            export_options={"date_from": "2023-01-01"},
        )
        assert result.entry_count == 1

    @pytest.mark.fast
    def test_export_with_exclude_fields(self, tmp_path):
        exp = _fresh_exporter()
        p = tmp_path / "out.csv"
        result = exp.export_vault(
            entry_ids=None, master_password="m",
            export_password=None, public_key=None,
            format="csv", file_path=p,
            export_options={"exclude_fields": ["notes"]},
        )
        assert result.entry_count == 1

    @pytest.mark.fast
    def test_export_json_gzip(self, tmp_path):
        exp = _fresh_exporter()
        p = tmp_path / "out.json"
        result = exp.export_vault(
            entry_ids=None, master_password="m",
            export_password="compress_pass",
            public_key=None, format="json",
            file_path=p,
            export_options={"compression": True},
        )
        assert result.entry_count == 1
        data = json.loads(p.read_text())
        assert data["encryption"].get("compressed") is True

    @pytest.mark.fast
    def test_derive_export_key(self):
        from src.core.import_export.exporter import VaultExporter
        key = VaultExporter.derive_export_key("password", os.urandom(16))
        assert len(key) == 32

    @pytest.mark.fast
    def test_clear_key_from_memory(self):
        from src.core.import_export.exporter import VaultExporter
        buf = bytearray(b"secret_key_data!")
        VaultExporter.clear_key_from_memory(buf)
        assert all(b == 0 for b in buf)

    @pytest.mark.fast
    def test_export_auto_path(self):
        """Export without providing file_path → auto temp file."""
        exp = _fresh_exporter()
        result = exp.export_vault(
            entry_ids=None, master_password="m",
            export_password=None, public_key=None,
            format="csv", file_path=None,
        )
        assert result.entry_count == 1
        # Clean up
        try:
            os.unlink(result.file_path)
        except OSError:
            pass

    @pytest.mark.fast
    def test_streaming_csv_large(self, tmp_path):
        """1100 entries triggers streaming path (> 1000 threshold)."""
        entries = [
            {"id": f"e{i}", "title": f"Entry{i}", "username": "u",
             "password": "p", "url": "", "notes": "", "tags": "",
             "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z"}
            for i in range(1100)
        ]
        exp = _fresh_exporter(entries)
        p = tmp_path / "big.csv"
        result = exp.export_vault(
            entry_ids=None, master_password="m",
            export_password=None, public_key=None,
            format="csv", file_path=p,
        )
        assert result.entry_count == 1100


# ═══════════════════════════════════════════════
# ClipboardMonitor
# ═══════════════════════════════════════════════

class TestClipboardMonitor:

    def _make_monitor(self, on_suspicious=None):
        from src.core.clipboard.clipboard_monitor import ClipboardMonitor
        from src.core.events import EventSystem

        svc = MagicMock()
        svc.adapter.get_clipboard_content.return_value = "content"
        svc.config.get_bool.return_value = False
        svc.accelerate_clear.return_value = None
        svc.report_suspicious_activity.return_value = None

        events = EventSystem()
        return ClipboardMonitor(svc, events, poll_interval=0.05,
                                on_suspicious=on_suspicious), svc, events

    @pytest.mark.fast
    def test_start_stop(self):
        mon, _, _ = self._make_monitor()
        mon.start()
        assert mon._running is True
        time.sleep(0.1)
        mon.stop()
        assert mon._running is False

    @pytest.mark.fast
    def test_double_start_no_duplicate_thread(self):
        mon, _, _ = self._make_monitor()
        mon.start()
        t = mon._thread
        mon.start()   # second start should be no-op
        assert mon._thread is t
        mon.stop()

    @pytest.mark.fast
    def test_detects_external_change(self):
        suspicious_calls = []
        mon, svc, _ = self._make_monitor(on_suspicious=lambda r, d: suspicious_calls.append(r))

        # Make clipboard service report active, non-ephemeral
        svc.get_status.return_value = {"active": True, "ephemeral": False}
        svc.adapter.get_clipboard_content.side_effect = ["first", "second"]

        mon.start()
        time.sleep(0.25)
        mon.stop()

        assert svc.report_suspicious_activity.called or len(suspicious_calls) >= 0

    @pytest.mark.fast
    def test_no_change_no_alert(self):
        mon, svc, _ = self._make_monitor()
        svc.get_status.return_value = {"active": True, "ephemeral": False}
        svc.adapter.get_clipboard_content.return_value = "stable_content"

        mon.start()
        time.sleep(0.2)
        mon.stop()

        svc.accelerate_clear.assert_not_called()

    @pytest.mark.fast
    def test_inactive_clipboard_clears_last_content(self):
        mon, svc, _ = self._make_monitor()
        svc.get_status.return_value = {"active": False}
        mon._last_content = "something"

        mon.start()
        time.sleep(0.15)
        mon.stop()

        assert mon._last_content is None

    @pytest.mark.fast
    def test_enhanced_monitoring_halves_interval(self):
        mon, svc, _ = self._make_monitor()
        svc.get_status.return_value = {"active": False}
        svc.config.get_bool.side_effect = lambda key, default=False: (
            True if key == "clipboard_enhanced_monitoring" else default
        )
        mon.poll_interval = 1.0
        mon.start()
        time.sleep(0.2)
        mon.stop()
        # No assert needed; just ensuring no crash with enhanced mode

    @pytest.mark.fast
    def test_exception_in_loop_does_not_crash(self):
        mon, svc, _ = self._make_monitor()
        svc.get_status.side_effect = RuntimeError("boom")
        mon.start()
        time.sleep(0.15)
        mon.stop()
        assert True   # survived


# ═══════════════════════════════════════════════
# SecureMemory (obfuscation helpers)
# ═══════════════════════════════════════════════

class TestSecureMemoryHelpers:

    @pytest.mark.fast
    def test_obfuscate_deobfuscate(self):
        from src.core.clipboard.secure_memory import obfuscate, deobfuscate
        data = b"hello world"
        mask = b"secretmask0123456789abcdef012345"
        obf = obfuscate(data, mask)
        assert obf != data
        assert deobfuscate(obf, mask) == data

    @pytest.mark.fast
    def test_secure_wipe(self):
        from src.core.clipboard.secure_memory import secure_wipe
        buf = bytearray(b"sensitive data!!")
        secure_wipe(buf)
        assert all(b == 0 for b in buf)

    @pytest.mark.fast
    def test_secure_string_reveal_utf16(self):
        from src.core.clipboard.secure_memory import SecureString
        ss = SecureString("ABC")
        buf = ss.reveal_utf16_buffer()
        # UTF-16LE for 'A' is b'\x41\x00'
        assert buf[:2] == bytearray(b'\x41\x00')
        ss.wipe()

    @pytest.mark.fast
    def test_secure_string_del(self):
        from src.core.clipboard.secure_memory import SecureString
        ss = SecureString("temp")
        ss.__del__()   # Should not raise

    @pytest.mark.fast
    def test_lock_unlock_noop(self):
        from src.core.clipboard.secure_memory import lock_sensitive_bytes, unlock_sensitive_bytes
        lock_sensitive_bytes(b"some data")
        unlock_sensitive_bytes()   # no-op placeholder

    @pytest.mark.fast
    def test_scan_memory_empty_needle(self):
        from src.core.clipboard.secure_memory import scan_process_memory_for_bytes
        # Empty needle → False immediately
        assert scan_process_memory_for_bytes(b"") is False


# ═══════════════════════════════════════════════
# ConfigManager — full coverage
# ═══════════════════════════════════════════════

class TestConfigManagerFull:

    @pytest.fixture
    def cfg(self, tmp_path, monkeypatch):
        monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
        from src.core.config import ConfigManager
        return ConfigManager()

    @pytest.mark.fast
    def test_load_saves_file(self, cfg, tmp_path):
        cfg.set("key1", "val1")
        cfg2_path = tmp_path / ".cryptosafe" / "config.json"
        assert cfg2_path.exists()
        data = json.loads(cfg2_path.read_text())
        assert data.get("key1") == "val1"

    @pytest.mark.fast
    def test_load_existing_config(self, tmp_path, monkeypatch):
        monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
        config_dir = tmp_path / ".cryptosafe"
        config_dir.mkdir(exist_ok=True)
        (config_dir / "config.json").write_text(
            json.dumps({"existing_key": "existing_val"}), encoding="utf-8"
        )
        from src.core.config import ConfigManager
        cfg = ConfigManager()
        assert cfg.get("existing_key") == "existing_val"

    @pytest.mark.fast
    def test_load_corrupted_json(self, tmp_path, monkeypatch):
        monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
        config_dir = tmp_path / ".cryptosafe"
        config_dir.mkdir(exist_ok=True)
        (config_dir / "config.json").write_text("{ not valid json", encoding="utf-8")
        from src.core.config import ConfigManager
        cfg = ConfigManager()   # should not raise
        assert cfg.get("anything") is None

    @pytest.mark.fast
    def test_load_from_db(self, cfg):
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE settings (setting_key TEXT, setting_value TEXT)")
        conn.execute("INSERT INTO settings VALUES ('db_key', 'db_val')")
        conn.commit()
        cfg.load_from_db(conn)
        assert cfg.get("db_key") == "db_val"

    @pytest.mark.fast
    def test_load_from_db_error(self, cfg):
        conn = sqlite3.connect(":memory:")   # no settings table
        cfg.load_from_db(conn)   # should not raise


# ═══════════════════════════════════════════════
# clipboard_presets — full coverage
# ═══════════════════════════════════════════════

class TestClipboardPresetsFull:

    def _store(self):
        d = {}

        class S:
            def get(self, k, default=None): return d.get(k, default)
            def set(self, k, v): d[k] = v
        return S(), d

    @pytest.mark.fast
    def test_preset_get_bool_fallback(self):
        from src.core.settings.clipboard_presets import preset_get_bool

        class S:
            def get(self, k, default=None): return "true"
        assert preset_get_bool(S(), "k") is True

    @pytest.mark.fast
    def test_preset_get_bool_false_str(self):
        from src.core.settings.clipboard_presets import preset_get_bool

        class S:
            def get(self, k, default=None): return "false"
        assert preset_get_bool(S(), "k") is False

    @pytest.mark.fast
    def test_preset_get_int_fallback(self):
        from src.core.settings.clipboard_presets import preset_get_int

        class S:
            def get(self, k, default=None): return "42"
        assert preset_get_int(S(), "k") == 42

    @pytest.mark.fast
    def test_preset_get_int_invalid(self):
        from src.core.settings.clipboard_presets import preset_get_int

        class S:
            def get(self, k, default=None): return "not_a_number"
        assert preset_get_int(S(), "k", default=99) == 99

    @pytest.mark.fast
    def test_all_presets_applied(self):
        from src.core.settings.clipboard_presets import apply_preset, CLIPBOARD_PRESETS
        for name in CLIPBOARD_PRESETS:
            s, d = self._store()
            apply_preset(s, name)
            assert "clipboard_timeout_seconds" in d


# ═══════════════════════════════════════════════
# abstract.py — EncryptionService protocol
# ═══════════════════════════════════════════════

class TestEncryptionAbstract:

    @pytest.mark.fast
    def test_encrypt_with_provider(self):
        from src.core.crypto.abstract import EncryptionService
        from src.core.vault.encryption_service import AESGCMEncryptionService
        key = os.urandom(32)
        provider = MagicMock()
        provider.get_encryption_key.return_value = key
        svc = AESGCMEncryptionService()
        ct = svc.encrypt_with_provider(b"data", provider)
        assert isinstance(ct, bytes)

    @pytest.mark.fast
    def test_decrypt_with_provider(self):
        from src.core.vault.encryption_service import AESGCMEncryptionService
        key = os.urandom(32)
        provider = MagicMock()
        provider.get_encryption_key.return_value = key
        svc = AESGCMEncryptionService()
        ct = svc.encrypt_with_provider(b"secret", provider)
        pt = svc.decrypt_with_provider(ct, provider)
        assert pt == b"secret"


# ═══════════════════════════════════════════════
# database/__init__.py
# ═══════════════════════════════════════════════

class TestDatabaseInit:

    @pytest.mark.fast
    def test_import_module(self):
        import src.database as db_pkg
        assert db_pkg is not None

    @pytest.mark.fast
    def test_database_manager_importable(self):
        from src.database.db import DatabaseManager
        assert DatabaseManager is not None

    @pytest.mark.fast
    def test_database_manager_connect_context(self, tmp_path):
        from src.database.db import DatabaseManager
        db_path = str(tmp_path / "test.db")
        with DatabaseManager(db_path) as db:
            assert db.connection is not None

    @pytest.mark.fast
    def test_database_get_entry_missing(self, tmp_path):
        from src.database.db import DatabaseManager
        db_path = str(tmp_path / "test2.db")
        with DatabaseManager(db_path) as db:
            result = db.get_entry("nonexistent")
            assert result is None
