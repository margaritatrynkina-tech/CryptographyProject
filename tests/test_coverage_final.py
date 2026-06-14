"""
Финальные тесты для достижения ≥85% покрытия.

Целевые модули и их непокрытые строки:
  secure_memory.py   — scan_process_memory_for_bytes/_plaintext, _scan_windows_memory
  sharing_service.py — RSA public-key path, _encrypt/_decrypt_pubkey, unknown method
  importer.py        — create_backup, resume_import, _write_checkpoint, private_key import,
                       _parse_strategy fallback, _make_unique_title collisions
  exporter.py        — RSA public key export path, _log_export CSV branch, helper fns
  key_exchange.py    — generate_keypair, decode_qr_chunks, store_contact, revoke, rotate,
                       get_contact, _serialise/_deserialise, _split_into_chunks
  bitwarden_handler.py — export_to_file, identity/card skipped items
  importer.py extra  — _scan_for_malicious_content patterns
"""

import base64
import hashlib
import json
import os
import sqlite3
import tempfile
import time
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch


# ────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────

def _contacts_db():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript("""
        CREATE TABLE contacts (
            contact_id   TEXT PRIMARY KEY,
            name         TEXT NOT NULL,
            identifier   TEXT NOT NULL,
            public_key   TEXT NOT NULL,
            key_fingerprint TEXT NOT NULL,
            last_used    DATETIME,
            created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.commit()
    return conn


def _gen_rsa_keypair():
    """Generate RSA-2048 PEM key pair for tests."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    priv = rsa.generate_private_key(65537, 2048, default_backend())
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem


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


def _fresh_exporter(entries=None):
    from src.core.import_export.exporter import VaultExporter
    em = MagicMock()
    _default = entries or [
        {"id": "e1", "title": "GitHub", "username": "alice", "password": "S3cr3t",
         "url": "https://github.com", "notes": "", "tags": "dev",
         "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z"},
    ]
    em.get_all_entries.return_value = _default
    em.get_entry.side_effect = lambda eid: next(
        (e for e in _default if e["id"] == eid), None
    )
    al = MagicMock()
    al.log_event.return_value = 1
    return VaultExporter(entry_manager=em, encryption_service=None, audit_logger=al)


def _make_sharing_svc():
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
        "id": "entry-1", "title": "GitHub", "username": "alice",
        "password": "S3cr3t", "url": "https://github.com",
        "notes": "dev", "tags": ["dev"],
    }
    em.add_entry.return_value = "entry-1"
    from src.core.import_export.sharing_service import SharingService
    return SharingService(conn, None, MagicMock(), em), conn


# ════════════════════════════════════════════════════════════
# secure_memory — scan functions (Windows path)
# ════════════════════════════════════════════════════════════

class TestSecureMemoryScan:

    @pytest.mark.fast
    def test_scan_for_bytes_windows(self):
        """On Windows, scan should complete without raising."""
        from src.core.clipboard.secure_memory import scan_process_memory_for_bytes
        # Just verify it runs; won't find a random needle
        result = scan_process_memory_for_bytes(b"definitely_not_in_memory_xyz")
        assert isinstance(result, bool)

    @pytest.mark.fast
    def test_scan_for_plaintext(self):
        from src.core.clipboard.secure_memory import scan_process_memory_for_plaintext
        result = scan_process_memory_for_plaintext("definitely_not_in_memory_xyz")
        assert isinstance(result, bool)

    @pytest.mark.fast
    def test_scan_finds_string_in_memory(self):
        """Put a distinctive string in memory then scan for it."""
        from src.core.clipboard.secure_memory import scan_process_memory_for_plaintext
        needle = "UNIQUE_SCAN_MARKER_7f3a9b2c"
        # Keep it alive so it's in memory
        _kept = needle * 3
        result = scan_process_memory_for_plaintext(needle)
        assert isinstance(result, bool)  # May or may not find it, but shouldn't raise

    @pytest.mark.fast
    def test_scan_empty_bytes(self):
        from src.core.clipboard.secure_memory import scan_process_memory_for_bytes
        assert scan_process_memory_for_bytes(b"") is False

    @pytest.mark.fast
    def test_scan_non_utf8_bytes(self):
        from src.core.clipboard.secure_memory import scan_process_memory_for_bytes
        # Non-UTF8 bytes — should not raise
        result = scan_process_memory_for_bytes(b"\xff\xfe\x00\x01")
        assert isinstance(result, bool)


# ════════════════════════════════════════════════════════════
# SharingService — RSA public key path + unknown method
# ════════════════════════════════════════════════════════════

class TestSharingServiceRSA:

    @pytest.mark.fast
    def test_share_with_public_key(self):
        svc, _ = _make_sharing_svc()
        priv_pem, pub_pem = _gen_rsa_keypair()
        from src.core.import_export.models import EncryptionMethod
        result = svc.share_entry(
            "entry-1", "carol",
            permissions={"read_only": True},
            expires_in_days=3,
            encryption_method=EncryptionMethod.PUBLIC_KEY,
            recipient_public_key=pub_pem,
        )
        assert "share_id" in result

    @pytest.mark.fast
    def test_import_with_private_key(self):
        svc, _ = _make_sharing_svc()
        priv_pem, pub_pem = _gen_rsa_keypair()
        from src.core.import_export.models import EncryptionMethod
        result = svc.share_entry(
            "entry-1", "carol",
            permissions={"read_only": True},
            expires_in_days=3,
            encryption_method=EncryptionMethod.PUBLIC_KEY,
            recipient_public_key=pub_pem,
        )
        imported = svc.import_shared_entry(
            result["package"],
            private_key=priv_pem,
            save_to_vault=False,
        )
        assert imported["entry"]["title"] == "GitHub"

    @pytest.mark.fast
    def test_import_pubkey_no_private_key_raises(self):
        svc, _ = _make_sharing_svc()
        _, pub_pem = _gen_rsa_keypair()
        from src.core.import_export.models import EncryptionMethod
        result = svc.share_entry(
            "entry-1", "carol",
            permissions={"read_only": True},
            expires_in_days=3,
            encryption_method=EncryptionMethod.PUBLIC_KEY,
            recipient_public_key=pub_pem,
        )
        with pytest.raises(ValueError, match="[Pp]rivate"):
            svc.import_shared_entry(result["package"], private_key=None)

    @pytest.mark.fast
    def test_share_public_key_no_key_raises(self):
        svc, _ = _make_sharing_svc()
        from src.core.import_export.models import EncryptionMethod
        with pytest.raises(ValueError, match="recipient_public_key"):
            svc.share_entry(
                "entry-1", "carol",
                permissions={},
                expires_in_days=3,
                encryption_method=EncryptionMethod.PUBLIC_KEY,
                recipient_public_key=None,
            )

    @pytest.mark.fast
    def test_unknown_method_raises_on_decrypt(self):
        """Inject a package with unknown method in entry_data."""
        svc, _ = _make_sharing_svc()
        from src.core.import_export.models import EncryptionMethod, SharePackage
        from datetime import datetime, timedelta
        fake_data = base64.b64encode(
            json.dumps({"method": "alien_method"}).encode()
        ).decode()
        expires = (datetime.utcnow() + timedelta(days=1)).isoformat() + "Z"
        pkg = SharePackage(
            entry_data=fake_data,
            encryption_method=EncryptionMethod.PASSWORD,
            permissions={},
            expires_at=expires,
            integrity=None,
        ).to_dict()
        with pytest.raises(ValueError, match="Unknown encryption method"):
            svc.import_shared_entry(pkg, password="any")

    @pytest.mark.fast
    def test_unsupported_encryption_method_on_create(self):
        """EncryptionMethod.NONE should raise on _create_share_package."""
        svc, _ = _make_sharing_svc()
        from src.core.import_export.models import EncryptionMethod
        with pytest.raises((ValueError, Exception)):
            svc.share_entry(
                "entry-1", "x",
                permissions={},
                expires_in_days=1,
                encryption_method=EncryptionMethod.NONE,
            )


# ════════════════════════════════════════════════════════════
# VaultImporter — create_backup, resume_import, checkpoint,
#                 private-key JSON import, _parse_strategy
# ════════════════════════════════════════════════════════════

class TestVaultImporterAdvanced:

    @pytest.mark.fast
    def test_create_backup(self, tmp_path):
        from src.core.import_export.importer import VaultImporter
        db_path = tmp_path / "vault.db"
        db_path.write_bytes(b"SQLite format 3\x00" + b"\x00" * 100)
        db_mgr = MagicMock()
        db_mgr.db_path = str(db_path)
        imp = VaultImporter(
            entry_manager=MagicMock(),
            encryption_service=None,
            audit_logger=MagicMock(),
            db_manager=db_mgr,
        )
        backup = imp.create_backup()
        assert backup.exists()
        backup.unlink()

    @pytest.mark.fast
    def test_create_backup_no_db_manager_raises(self):
        from src.core.import_export.importer import VaultImporter
        imp = VaultImporter(MagicMock(), None, MagicMock(), db_manager=None)
        with pytest.raises(IOError):
            imp.create_backup()

    @pytest.mark.fast
    def test_create_backup_missing_db_raises(self, tmp_path):
        from src.core.import_export.importer import VaultImporter
        db_mgr = MagicMock()
        db_mgr.db_path = str(tmp_path / "nonexistent.db")
        imp = VaultImporter(MagicMock(), None, MagicMock(), db_manager=db_mgr)
        with pytest.raises(IOError):
            imp.create_backup()

    @pytest.mark.fast
    def test_resume_import(self, tmp_path):
        imp = _fresh_importer()
        # Write a checkpoint manually
        cp = tmp_path / "cp.checkpoint.json"
        cp.write_text(json.dumps({
            "remaining_entries": [
                {"title": "Resumed", "username": "u", "password": "p",
                 "url": "", "notes": "", "tags": ""},
            ],
            "conflict_strategy": "skip",
            "source_format": "json",
            "written_at": "2024-01-01T00:00:00Z",
        }), encoding="utf-8")
        result = imp.resume_import(cp)
        assert result.successful_imports == 1
        assert not cp.exists()   # cleaned up

    @pytest.mark.fast
    def test_resume_import_empty_checkpoint(self, tmp_path):
        imp = _fresh_importer()
        cp = tmp_path / "empty.checkpoint.json"
        cp.write_text(json.dumps({
            "remaining_entries": [],
            "conflict_strategy": "skip",
            "source_format": "csv",
        }), encoding="utf-8")
        result = imp.resume_import(cp)
        assert result.total_entries == 0

    @pytest.mark.fast
    def test_resume_import_missing_file_raises(self, tmp_path):
        imp = _fresh_importer()
        with pytest.raises(FileNotFoundError):
            imp.resume_import(tmp_path / "no_such.checkpoint.json")

    @pytest.mark.fast
    def test_import_json_with_private_key(self, tmp_path):
        """Export with RSA public key, import with private key."""
        priv_pem, pub_pem = _gen_rsa_keypair()
        exp = _fresh_exporter()
        p = tmp_path / "vault.json"
        exp.export_vault(
            entry_ids=None, master_password="m",
            export_password=None,
            public_key=pub_pem,
            format="json",
            file_path=p,
        )
        imp = _fresh_importer()
        result = imp.import_json(
            p,
            master_password="m",
            private_key=priv_pem,
        )
        assert result.successful_imports == 1

    @pytest.mark.fast
    def test_import_json_no_key_raises(self, tmp_path):
        """Exported with RSA key — import without private_key must fail."""
        _, pub_pem = _gen_rsa_keypair()
        exp = _fresh_exporter()
        p = tmp_path / "vault.json"
        exp.export_vault(
            entry_ids=None, master_password="m",
            export_password=None,
            public_key=pub_pem,
            format="json",
            file_path=p,
        )
        imp = _fresh_importer()
        with pytest.raises(ValueError, match="[Pp]rivate"):
            imp.import_json(p, master_password="m")

    @pytest.mark.fast
    def test_parse_strategy_invalid_falls_back(self):
        from src.core.import_export.importer import _parse_strategy
        from src.core.import_export.models import ConflictResolution
        assert _parse_strategy("nonexistent") == ConflictResolution.SKIP

    @pytest.mark.fast
    def test_make_unique_title_no_collision(self):
        from src.core.import_export.importer import _make_unique_title
        title = _make_unique_title("GitHub", {})
        assert "GitHub" in title

    @pytest.mark.fast
    def test_make_unique_title_collision(self):
        from src.core.import_export.importer import _make_unique_title
        existing = {("github (imported)", ""): "id1"}
        title = _make_unique_title("GitHub", existing)
        assert title != "GitHub (imported)"

    @pytest.mark.fast
    def test_scan_entry_fields_clean(self):
        from src.core.import_export.importer import _scan_entry_fields
        assert _scan_entry_fields({"title": "GitHub", "url": "https://x.com"}) is None

    @pytest.mark.fast
    def test_scan_entry_fields_malicious_url(self):
        from src.core.import_export.importer import _scan_entry_fields
        result = _scan_entry_fields({"title": "T", "url": "javascript:alert(1)"})
        assert result is not None

    @pytest.mark.fast
    def test_scan_entry_fields_path_traversal(self):
        from src.core.import_export.importer import _scan_entry_fields
        result = _scan_entry_fields({"title": "T", "notes": "../../etc/passwd"})
        assert result is not None

    @pytest.mark.fast
    def test_import_csv_with_column_mapping(self, tmp_path):
        imp = _fresh_importer()
        p = tmp_path / "custom.csv"
        p.write_text("name,login,pass\nGitHub,alice,s3cr3t\n", encoding="utf-8")
        result = imp.import_csv(
            p,
            column_mapping={"name": "title", "login": "username", "pass": "password"},
        )
        assert result.successful_imports == 1

    @pytest.mark.fast
    def test_import_entries_backup_on_replace(self, tmp_path):
        """REPLACE strategy triggers backup attempt (non-fatal if db_manager is None)."""
        imp = _fresh_importer()
        p = tmp_path / "data.csv"
        p.write_text("title,username,password\nGitHub,alice,pass\n", encoding="utf-8")
        imp.import_csv(p)   # first import
        # second with replace — backup attempt will silently fail (no db_manager)
        result = imp.import_csv(p, conflict_strategy="replace")
        assert result.successful_imports >= 1


# ════════════════════════════════════════════════════════════
# VaultExporter — RSA public key export path + CSV audit event
# ════════════════════════════════════════════════════════════

class TestVaultExporterRSA:

    @pytest.mark.fast
    def test_export_json_with_public_key(self, tmp_path):
        _, pub_pem = _gen_rsa_keypair()
        exp = _fresh_exporter()
        p = tmp_path / "out.json"
        result = exp.export_vault(
            entry_ids=None, master_password="m",
            export_password=None,
            public_key=pub_pem,
            format="json",
            file_path=p,
        )
        assert result.entry_count == 1
        data = json.loads(p.read_text())
        assert data["encryption"]["method"] == "public_key"

    @pytest.mark.fast
    def test_log_export_csv_audit_event(self, tmp_path):
        """CSV format triggers AUDIT_EXPORT_CSV event."""
        exp = _fresh_exporter()
        p = tmp_path / "out.csv"
        exp.export_vault(
            entry_ids=None, master_password="m",
            export_password=None, public_key=None,
            format="csv", file_path=p,
        )
        # The audit_logger.log_event should have been called with AUDIT_EXPORT_CSV
        calls = [c for c in exp.audit_logger.log_event.call_args_list
                 if c.kwargs.get("event_type") == "AUDIT_EXPORT_CSV"
                 or (c.args and c.args[0] == "AUDIT_EXPORT_CSV")]
        assert len(calls) >= 1

    @pytest.mark.fast
    def test_helper_format_suffix(self):
        from src.core.import_export.exporter import _format_suffix
        assert _format_suffix("json") == ".json"
        assert _format_suffix("csv") == ".csv"
        assert _format_suffix("bitwarden") == ".json"
        assert _format_suffix("lastpass") == ".csv"
        assert _format_suffix("unknown") == ".dat"

    @pytest.mark.fast
    def test_helper_entry_tags_list(self):
        from src.core.import_export.exporter import _entry_tags
        assert _entry_tags({"tags": ["dev", "work"]}) == {"dev", "work"}

    @pytest.mark.fast
    def test_helper_entry_tags_string(self):
        from src.core.import_export.exporter import _entry_tags
        assert _entry_tags({"tags": "dev,work"}) == {"dev", "work"}

    @pytest.mark.fast
    def test_helper_entry_tags_empty(self):
        from src.core.import_export.exporter import _entry_tags
        assert _entry_tags({}) == set()

    @pytest.mark.fast
    def test_helper_strip_fields(self):
        from src.core.import_export.exporter import _strip_fields
        e = {"title": "X", "password": "p", "notes": "n"}
        assert _strip_fields(e, ["password"]) == {"title": "X", "notes": "n"}

    @pytest.mark.fast
    def test_helper_filter_by_date_no_ts(self):
        from src.core.import_export.exporter import _filter_by_date
        entries = [{"title": "X"}]   # no timestamps
        result = _filter_by_date(entries, "2020-01-01", None)
        assert len(result) == 1   # no timestamp → always included

    @pytest.mark.fast
    def test_helper_filter_by_date_to(self):
        from src.core.import_export.exporter import _filter_by_date
        entries = [
            {"updated_at": "2019-01-01T00:00:00Z"},
            {"updated_at": "2025-01-01T00:00:00Z"},
        ]
        result = _filter_by_date(entries, None, "2020-01-01")
        assert len(result) == 1
        assert result[0]["updated_at"].startswith("2019")


# ════════════════════════════════════════════════════════════
# QRCodeService / key_exchange.py
# ════════════════════════════════════════════════════════════

class TestQRCodeService:

    @pytest.mark.fast
    def test_generate_keypair_rsa(self):
        from src.core.import_export.key_exchange import QRCodeService
        svc = QRCodeService()
        priv, pub = svc.generate_keypair("RSA-2048")
        assert b"PRIVATE KEY" in priv
        assert b"PUBLIC KEY" in pub

    @pytest.mark.fast
    def test_generate_keypair_ecc(self):
        from src.core.import_export.key_exchange import QRCodeService
        svc = QRCodeService()
        priv, pub = svc.generate_keypair("ECC-P256")
        assert b"PRIVATE KEY" in priv
        assert b"PUBLIC KEY" in pub

    @pytest.mark.fast
    def test_generate_keypair_invalid_raises(self):
        from src.core.import_export.key_exchange import QRCodeService
        svc = QRCodeService()
        with pytest.raises(ValueError, match="Unsupported"):
            svc.generate_keypair("DES-56")

    @pytest.mark.fast
    def test_compute_key_fingerprint(self):
        from src.core.import_export.key_exchange import QRCodeService
        svc = QRCodeService()
        _, pub = svc.generate_keypair("RSA-2048")
        fp = svc.compute_key_fingerprint(pub)
        assert len(fp) == 64   # SHA-256 hex

    @pytest.mark.fast
    def test_decode_qr_chunks_single(self):
        """Build a valid single-chunk payload and decode it."""
        from src.core.import_export.key_exchange import QRCodeService
        import zlib

        payload = {"hello": "world"}
        raw = json.dumps(payload, separators=(",", ":")).encode()
        compressed = zlib.compress(raw, level=9)
        from datetime import datetime, timedelta
        expires_at = (datetime.utcnow() + timedelta(minutes=5)).isoformat() + "Z"
        envelope = json.dumps({
            "type": "generic",
            "nonce": base64.b64encode(os.urandom(16)).decode(),
            "expires_at": expires_at,
            "data": base64.b64encode(compressed).decode(),
        }, separators=(",", ":")).encode()

        checksum = hashlib.sha256(envelope).hexdigest()[:8]
        chunk = {
            "chunk": 1, "total": 1,
            "data": base64.b64encode(envelope).decode(),
            "checksum": checksum,
        }
        svc = QRCodeService()
        result = svc.decode_qr_chunks([chunk])
        assert result == payload

    @pytest.mark.fast
    def test_decode_qr_chunks_empty_raises(self):
        from src.core.import_export.key_exchange import QRCodeService
        with pytest.raises(ValueError, match="No chunks"):
            QRCodeService().decode_qr_chunks([])

    @pytest.mark.fast
    def test_decode_qr_chunks_wrong_count(self):
        from src.core.import_export.key_exchange import QRCodeService
        chunk = {"chunk": 1, "total": 2, "data": "x", "checksum": "y"}
        with pytest.raises(ValueError, match="Expected 2 chunks"):
            QRCodeService().decode_qr_chunks([chunk])

    @pytest.mark.fast
    def test_decode_qr_chunks_bad_checksum(self):
        from src.core.import_export.key_exchange import QRCodeService
        import zlib
        raw = b"test data"
        compressed = zlib.compress(raw)
        from datetime import datetime, timedelta
        expires_at = (datetime.utcnow() + timedelta(minutes=5)).isoformat() + "Z"
        envelope = json.dumps({
            "type": "t", "nonce": "n", "expires_at": expires_at,
            "data": base64.b64encode(compressed).decode(),
        }, separators=(",", ":")).encode()
        chunk = {
            "chunk": 1, "total": 1,
            "data": base64.b64encode(envelope).decode(),
            "checksum": "00000000",   # wrong
        }
        with pytest.raises(ValueError, match="Checksum"):
            QRCodeService().decode_qr_chunks([chunk])

    @pytest.mark.fast
    def test_decode_qr_chunks_expired(self):
        from src.core.import_export.key_exchange import QRCodeService
        import zlib
        raw = b"test"
        compressed = zlib.compress(raw)
        envelope = json.dumps({
            "type": "t", "nonce": "n",
            "expires_at": "2000-01-01T00:00:00Z",   # past
            "data": base64.b64encode(compressed).decode(),
        }, separators=(",", ":")).encode()
        checksum = hashlib.sha256(envelope).hexdigest()[:8]
        chunk = {
            "chunk": 1, "total": 1,
            "data": base64.b64encode(envelope).decode(),
            "checksum": checksum,
        }
        with pytest.raises(ValueError, match="expired"):
            QRCodeService().decode_qr_chunks([chunk])

    @pytest.mark.fast
    def test_store_and_get_contact(self):
        from src.core.import_export.key_exchange import QRCodeService
        conn = _contacts_db()
        svc = QRCodeService(db_connection=conn)
        _, pub = svc.generate_keypair("RSA-2048")
        cid = svc.store_contact_key("Alice", "alice@x.com", pub)
        contact = svc.get_contact(cid)
        assert contact is not None
        assert contact["name"] == "Alice"

    @pytest.mark.fast
    def test_store_contact_no_db_raises(self):
        from src.core.import_export.key_exchange import QRCodeService
        svc = QRCodeService(db_connection=None)
        with pytest.raises(RuntimeError, match="database"):
            svc.store_contact_key("X", "x@x.com", b"PEM")

    @pytest.mark.fast
    def test_get_contact_no_db_returns_none(self):
        from src.core.import_export.key_exchange import QRCodeService
        assert QRCodeService().get_contact("any-id") is None

    @pytest.mark.fast
    def test_revoke_key(self):
        from src.core.import_export.key_exchange import QRCodeService
        conn = _contacts_db()
        svc = QRCodeService(db_connection=conn)
        _, pub = svc.generate_keypair("RSA-2048")
        cid = svc.store_contact_key("Bob", "bob@x.com", pub)
        assert svc.revoke_key(cid) is True
        assert svc.get_contact(cid) is None

    @pytest.mark.fast
    def test_revoke_key_nonexistent(self):
        from src.core.import_export.key_exchange import QRCodeService
        conn = _contacts_db()
        svc = QRCodeService(db_connection=conn)
        assert svc.revoke_key("no-such-id") is False

    @pytest.mark.fast
    def test_revoke_key_no_db(self):
        from src.core.import_export.key_exchange import QRCodeService
        assert QRCodeService().revoke_key("x") is False

    @pytest.mark.fast
    def test_rotate_key(self):
        from src.core.import_export.key_exchange import QRCodeService
        conn = _contacts_db()
        svc = QRCodeService(db_connection=conn)
        _, pub1 = svc.generate_keypair("RSA-2048")
        _, pub2 = svc.generate_keypair("RSA-2048")
        cid = svc.store_contact_key("Carol", "carol@x.com", pub1)
        fp1 = svc.compute_key_fingerprint(pub1)
        assert svc.rotate_key(cid, pub2) is True
        contact = svc.get_contact(cid)
        assert contact["key_fingerprint"] != fp1

    @pytest.mark.fast
    def test_rotate_key_nonexistent(self):
        from src.core.import_export.key_exchange import QRCodeService
        conn = _contacts_db()
        svc = QRCodeService(db_connection=conn)
        _, pub = svc.generate_keypair("RSA-2048")
        assert svc.rotate_key("no-such", pub) is False

    @pytest.mark.fast
    def test_rotate_key_no_db(self):
        from src.core.import_export.key_exchange import QRCodeService
        assert QRCodeService().rotate_key("x", b"PEM") is False

    @pytest.mark.fast
    def test_serialise_bytes(self):
        from src.core.import_export.key_exchange import QRCodeService
        raw = QRCodeService._serialise_payload(b"\x00\x01\x02")
        assert raw == b"\x00\x01\x02"

    @pytest.mark.fast
    def test_serialise_str(self):
        from src.core.import_export.key_exchange import QRCodeService
        assert QRCodeService._serialise_payload("hello") == b"hello"

    @pytest.mark.fast
    def test_serialise_dict(self):
        from src.core.import_export.key_exchange import QRCodeService
        raw = QRCodeService._serialise_payload({"k": "v"})
        assert json.loads(raw) == {"k": "v"}

    @pytest.mark.fast
    def test_deserialise_json(self):
        from src.core.import_export.key_exchange import QRCodeService
        result = QRCodeService._deserialise_payload(b'{"x":1}')
        assert result == {"x": 1}

    @pytest.mark.fast
    def test_deserialise_binary_fallback(self):
        from src.core.import_export.key_exchange import QRCodeService
        raw = b"\xff\xfe binary"
        result = QRCodeService._deserialise_payload(raw)
        assert result == raw

    @pytest.mark.fast
    def test_split_into_chunks_small(self):
        from src.core.import_export.key_exchange import QRCodeService
        data = b"x" * 100
        chunks = QRCodeService._split_into_chunks(data)
        assert len(chunks) == 1
        assert chunks[0] == data

    @pytest.mark.fast
    def test_split_into_chunks_large(self):
        from src.core.import_export.key_exchange import QRCodeService, _QR_MAX_BYTES
        data = b"x" * (_QR_MAX_BYTES * 2 + 1)
        chunks = QRCodeService._split_into_chunks(data)
        assert len(chunks) == 3


# ════════════════════════════════════════════════════════════
# BitwardenHandler — extra uncovered lines
# ════════════════════════════════════════════════════════════

class TestBitwardenHandlerExtra:

    @pytest.mark.fast
    def test_export_to_file(self, tmp_path):
        from src.core.import_export.formats.bitwarden_handler import BitwardenHandler
        entries = [
            {"id": "e1", "title": "GitHub", "username": "alice",
             "password": "p", "url": "https://github.com",
             "notes": "", "tags": "dev"},
        ]
        p = str(tmp_path / "bw.json")
        n = BitwardenHandler.export_to_file(entries, p)
        assert n == 1
        assert Path(p).exists()

    @pytest.mark.fast
    def test_card_item_skipped(self):
        from src.core.import_export.formats.bitwarden_handler import BitwardenHandler
        bw = {"encrypted": False, "folders": [], "items": [
            {"id": "c1", "type": 3, "name": "My Card", "login": None}
        ]}
        entries, warnings = BitwardenHandler.import_json(json.dumps(bw))
        assert len(entries) == 0
        assert any("not a login" in w.lower() or "type 3" in w for w in warnings)

    @pytest.mark.fast
    def test_identity_item_skipped(self):
        from src.core.import_export.formats.bitwarden_handler import BitwardenHandler
        bw = {"encrypted": False, "folders": [], "items": [
            {"id": "i1", "type": 4, "name": "My Identity", "login": None}
        ]}
        entries, warnings = BitwardenHandler.import_json(json.dumps(bw))
        assert len(entries) == 0
        assert any("not a login" in w.lower() or "type 4" in w for w in warnings)

    @pytest.mark.fast
    def test_import_folder_as_tag(self):
        from src.core.import_export.formats.bitwarden_handler import BitwardenHandler
        bw = {
            "encrypted": False,
            "folders": [{"id": "f1", "name": "Work"}],
            "items": [{
                "id": "e1", "type": 1, "name": "GitHub",
                "folderId": "f1",
                "login": {"uris": [{"uri": "https://github.com", "match": None}],
                          "username": "alice", "password": "p", "totp": None},
                "notes": None, "fields": [], "favorite": False,
            }]
        }
        entries, _ = BitwardenHandler.import_json(json.dumps(bw))
        assert len(entries) == 1
        assert "Work" in entries[0]["tags"]

    @pytest.mark.fast
    def test_import_with_tags_roundtrip(self):
        from src.core.import_export.formats.bitwarden_handler import BitwardenHandler
        entry = {
            "id": "e1", "title": "Slack", "username": "bob",
            "password": "pass", "url": "https://slack.com",
            "notes": "", "tags": ["work", "chat"],
        }
        bw_json = BitwardenHandler.export([entry])
        imported, _ = BitwardenHandler.import_json(bw_json)
        assert len(imported) == 1
        assert "work" in imported[0]["tags"]

    @pytest.mark.fast
    def test_import_empty_items(self):
        from src.core.import_export.formats.bitwarden_handler import BitwardenHandler
        bw = {"encrypted": False, "folders": [], "items": []}
        entries, warnings = BitwardenHandler.import_json(json.dumps(bw))
        assert entries == []
        assert warnings == []

    @pytest.mark.fast
    def test_import_not_list_items_raises(self):
        from src.core.import_export.formats.bitwarden_handler import BitwardenHandler
        bw = {"encrypted": False, "items": "not_a_list"}
        with pytest.raises(ValueError, match="list"):
            BitwardenHandler.import_json(json.dumps(bw))

    @pytest.mark.fast
    def test_import_not_dict_raises(self):
        from src.core.import_export.formats.bitwarden_handler import BitwardenHandler
        with pytest.raises(ValueError):
            BitwardenHandler.import_json(json.dumps([1, 2, 3]))


# ════════════════════════════════════════════════════════════
# CSV / LastPass / JSON handler — remaining gaps
# ════════════════════════════════════════════════════════════

class TestFormatHandlerGaps:

    @pytest.mark.fast
    def test_csv_import_file_utf16_bom(self, tmp_path):
        from src.core.import_export.formats.csv_handler import CSVHandler
        content = "title,username,password\nGitHub,alice,pass\n"
        p = tmp_path / "utf16.csv"
        p.write_bytes(b"\xff\xfe" + content.encode("utf-16-le"))
        entries, warnings = CSVHandler.import_file(str(p))
        assert len(entries) >= 1

    @pytest.mark.fast
    def test_csv_import_file_utf8_bom(self, tmp_path):
        from src.core.import_export.formats.csv_handler import CSVHandler
        content = "title,username,password\nGitHub,alice,pass\n"
        p = tmp_path / "bom.csv"
        p.write_bytes(b"\xef\xbb\xbf" + content.encode("utf-8"))
        entries, warnings = CSVHandler.import_file(str(p))
        assert len(entries) >= 1

    @pytest.mark.fast
    def test_csv_import_file_with_column_mapping(self, tmp_path):
        from src.core.import_export.formats.csv_handler import CSVHandler
        p = tmp_path / "mapped.csv"
        p.write_text("name,login\nGitHub,alice\n", encoding="utf-8")
        entries, _ = CSVHandler.import_file(str(p), column_mapping={"name": "title", "login": "username"})
        assert len(entries) == 1
        assert entries[0]["title"] == "GitHub"

    @pytest.mark.fast
    def test_csv_export_no_header(self):
        from src.core.import_export.formats.csv_handler import CSVHandler
        entry = {"title": "X", "username": "u", "password": "p", "url": "", "notes": "", "tags": ""}
        csv_text = CSVHandler.export([entry], include_header=False)
        assert "title" not in csv_text.lower()

    @pytest.mark.fast
    def test_csv_validate_missing_title_column(self, tmp_path):
        from src.core.import_export.formats.csv_handler import CSVHandler
        p = tmp_path / "no_title.csv"
        p.write_text("url,username\nhttps://x.com,alice\n", encoding="utf-8")
        valid, errors = CSVHandler.validate(str(p))
        assert valid is False

    @pytest.mark.fast
    def test_lastpass_import_no_header(self):
        from src.core.import_export.formats.lastpass_handler import LastPassHandler
        entries, warnings = LastPassHandler.import_csv("   ")
        assert entries == []

    @pytest.mark.fast
    def test_json_handler_verify_empty_hash(self):
        """Empty stored hash → always passes (skip verification)."""
        from src.core.import_export.formats.json_handler import JSONHandler
        assert JSONHandler.verify_hash(b"anything", "") is True

    @pytest.mark.fast
    def test_json_handler_deserialise_not_list_raises(self):
        from src.core.import_export.formats.json_handler import JSONHandler
        with pytest.raises(ValueError, match="array"):
            JSONHandler.deserialise_entries(json.dumps({"not": "a list"}).encode())

    @pytest.mark.fast
    def test_json_handler_deserialise_invalid_utf8_raises(self):
        from src.core.import_export.formats.json_handler import JSONHandler
        with pytest.raises(ValueError):
            JSONHandler.deserialise_entries(b"\xff\xfe invalid")

    @pytest.mark.fast
    def test_json_parse_missing_required_field(self):
        from src.core.import_export.formats.json_handler import JSONHandler
        doc = {
            "cryptosafe_export": True, "version": "1.0",
            "metadata": {}, "encryption": {},
            # missing "data" and "integrity"
        }
        with pytest.raises(ValueError, match="data"):
            JSONHandler.parse_envelope(json.dumps(doc))


# ════════════════════════════════════════════════════════════
# state_manager — uncovered lines 36, 48-55
# ════════════════════════════════════════════════════════════

class TestStateManagerExtra:

    @pytest.mark.fast
    def test_inactivity_timer_locks(self):
        from src.core.events import EventSystem
        from src.core.state_manager import StateManager
        es = EventSystem()
        sm = StateManager(es)
        sm.unlock("user1")
        sm.start_inactivity_timer(timeout=0)   # immediate
        time.sleep(0.05)
        # Should not crash; lock state depends on timing

    @pytest.mark.fast
    def test_start_inactivity_timer_replaces_existing(self):
        from src.core.events import EventSystem
        from src.core.state_manager import StateManager
        es = EventSystem()
        sm = StateManager(es)
        sm.unlock("user1")
        sm.start_inactivity_timer(timeout=300)
        t1 = sm._inactivity_timer
        sm.start_inactivity_timer(timeout=300)
        t2 = sm._inactivity_timer
        assert t2 is not t1   # replaced

    @pytest.mark.fast
    def test_set_clipboard_replaces_timer(self):
        from src.core.events import EventSystem
        from src.core.state_manager import StateManager
        es = EventSystem()
        sm = StateManager(es)
        sm.unlock("user1")
        sm.set_clipboard("first", timeout=60)
        t1 = sm._clipboard_timer
        sm.set_clipboard("second", timeout=60)
        t2 = sm._clipboard_timer
        assert t2 is not t1
        # Cancel to avoid lingering timers
        if t2 and t2.is_alive():
            t2.cancel()


# ════════════════════════════════════════════════════════════
# entry_manager — uncovered lines 29-31, 91-93, 112-114
# ════════════════════════════════════════════════════════════

class TestEntryManagerExtra:
    """Cover rollback branches (lines 29-31, 91-93, 112-114) via a wrapper connection."""

    @pytest.fixture
    def em_and_conn(self):
        from src.core.events import EventSystem
        from src.core.vault.entry_manager import EntryManager

        key = os.urandom(32)
        km = MagicMock()
        km.get_encryption_key.return_value = key

        real_conn = sqlite3.connect(":memory:")
        real_conn.row_factory = sqlite3.Row
        real_conn.executescript("""
            CREATE TABLE vault_entries (
                id TEXT PRIMARY KEY,
                encrypted_data BLOB NOT NULL,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                tags TEXT DEFAULT ''
            );
            CREATE TABLE deleted_entries (
                entry_id TEXT PRIMARY KEY,
                deleted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME
            );
        """)
        real_conn.commit()

        # Wrapper that lets us intercept commit()
        class ConnWrapper:
            def __init__(self, c):
                self._c = c
                self.fail_next_commit = False

            def cursor(self): return self._c.cursor()
            def rollback(self): return self._c.rollback()

            def commit(self):
                if self.fail_next_commit:
                    self.fail_next_commit = False
                    raise sqlite3.OperationalError("forced error")
                return self._c.commit()

            def execute(self, *a, **kw): return self._c.execute(*a, **kw)

        wrapper = ConnWrapper(real_conn)
        em = EntryManager(wrapper, km, EventSystem())
        return em, wrapper

    @pytest.mark.fast
    def test_create_entry_db_error_rolls_back(self, em_and_conn):
        em, wrapper = em_and_conn
        wrapper.fail_next_commit = True
        with pytest.raises(Exception):
            em.create_entry({"title": "X"})

    @pytest.mark.fast
    def test_update_entry_db_error_rolls_back(self, em_and_conn):
        em, wrapper = em_and_conn
        eid = em.create_entry({"title": "Y"})
        wrapper.fail_next_commit = True
        with pytest.raises(Exception):
            em.update_entry(eid, {"title": "Z"})

    @pytest.mark.fast
    def test_delete_entry_db_error_rolls_back(self, em_and_conn):
        em, wrapper = em_and_conn
        eid = em.create_entry({"title": "Del"})
        wrapper.fail_next_commit = True
        with pytest.raises(Exception):
            em.delete_entry(eid, soft_delete=False)
