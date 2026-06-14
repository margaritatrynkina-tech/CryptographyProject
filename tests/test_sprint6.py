from __future__ import annotations

import base64
import json
import os
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

pytestmark = pytest.mark.crypto

# Make sure the project root is on sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))


def _make_entry(title: str = "Test", username: str = "user@example.com",
                password: str = "S3cr3t!", url: str = "https://example.com",
                notes: str = "some notes", tags: list = None) -> Dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "title": title,
        "username": username,
        "password": password,
        "url": url,
        "notes": notes,
        "tags": tags or ["work"],
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-01-02T00:00:00Z",
    }


def _make_entries(n: int) -> List[Dict[str, Any]]:
    return [
        _make_entry(
            title=f"Entry {i}",
            username=f"user{i}@example.com",
            password=f"Pass{i}!Abc",
            url=f"https://site{i}.example.com",
            notes=f"Notes for entry {i}",
            tags=["perf", f"batch{i // 100}"],
        )
        for i in range(n)
    ]

class _InMemoryEntryManager:

    def __init__(self, entries: List[Dict[str, Any]] = None):
        self._store: Dict[str, Dict[str, Any]] = {}
        for e in (entries or []):
            self._store[e["id"]] = e

    def get_all_entries(self) -> List[Dict[str, Any]]:
        return list(self._store.values())

    def get_entry(self, entry_id: str) -> Dict[str, Any]:
        return self._store.get(entry_id)

    def create_entry(self, data: Dict[str, Any]) -> str:
        eid = data.get("id") or str(uuid.uuid4())
        data["id"] = eid
        self._store[eid] = data
        return eid

    def update_entry(self, entry_id: str, data: Dict[str, Any]) -> bool:
        if entry_id not in self._store:
            return False
        self._store[entry_id] = data
        return True

    def add_entry(self, data: Dict[str, Any]) -> str:
        return self.create_entry(data)


def _make_audit_logger():
    logger = MagicMock()
    logger.log_event.return_value = 1
    return logger


def _qrcode_available() -> bool:
    try:
        import qrcode  # noqa: F401
        from PIL import Image  # noqa: F401
        from pyzbar import pyzbar  # noqa: F401
        return True
    except ImportError:
        return False


def _hypothesis_available() -> bool:
    try:
        import hypothesis  # noqa: F401
        return True
    except ImportError:
        return False


class TestRoundTrip:

    def test_json_roundtrip_all_fields(self, tmp_path):
        from src.core.import_export.exporter import VaultExporter
        from src.core.import_export.importer import VaultImporter

        original_entries = [
            _make_entry("GitHub", "dev@example.com", "GhP@ss1!", "https://github.com", "dev account"),
            _make_entry("Gmail", "me@gmail.com", "Gm@il99!", "https://gmail.com", "personal"),
        ]

        src_manager = _InMemoryEntryManager(original_entries)
        exporter = VaultExporter(
            entry_manager=src_manager,
            encryption_service=None,
            audit_logger=_make_audit_logger(),
        )

        export_file = tmp_path / "vault_export.json"
        password = "TestExportPass123!"
        result = exporter.export_vault(
            entry_ids=None,
            password=password,
            public_key=None,
            format="json",
            file_path=export_file,
        )

        assert export_file.exists(), "Export file was not created"
        assert result.entry_count == 2
        assert result.checksum  # non-empty SHA-256

        # Import into a fresh manager
        dst_manager = _InMemoryEntryManager()
        importer = VaultImporter(
            entry_manager=dst_manager,
            encryption_service=None,
            audit_logger=_make_audit_logger(),
        )
        import_result = importer.import_json(export_file, password=password)

        assert import_result.successful_imports == 2
        assert import_result.failed_imports == 0

        imported = {e["title"]: e for e in dst_manager.get_all_entries()}
        for orig in original_entries:
            title = orig["title"]
            assert title in imported, f"Entry '{title}' missing after import"
            imp = imported[title]
            assert imp["username"] == orig["username"]
            assert imp["password"] == orig["password"]
            assert imp["url"] == orig["url"]
            assert imp["notes"] == orig["notes"]

    def test_csv_passwords_never_exported(self, tmp_path):
        from src.core.import_export.formats.csv_handler import CSVHandler

        entries = [_make_entry(password="SuperSecret123!")]
        csv_text = CSVHandler.export(entries)

        assert "SuperSecret123!" not in csv_text
        assert "[ENCRYPTED]" in csv_text

    def test_csv_roundtrip_metadata(self, tmp_path):
        from src.core.import_export.formats.csv_handler import CSVHandler

        entries = [
            _make_entry("Site A", "alice", "pw1", "https://a.com", "note a"),
            _make_entry("Site B", "bob", "pw2", "https://b.com", "note b"),
        ]
        csv_text = CSVHandler.export(entries)
        parsed, _ = CSVHandler.import_csv(csv_text)
        csv_text2 = CSVHandler.export(parsed)
        re_parsed, _ = CSVHandler.import_csv(csv_text2)

        assert len(parsed) == len(re_parsed)
        for a, b in zip(parsed, re_parsed):
            for field in ("title", "username", "url", "notes"):
                assert a.get(field, "").strip() == b.get(field, "").strip()


class TestInteroperability:
    """TEST-2: import real Bitwarden / LastPass fixture files."""

    _BITWARDEN_FIXTURE = {
        "encrypted": False,
        "folders": [{"id": "folder-1", "name": "Work"}],
        "items": [
            {
                "id": "bw-item-1",
                "type": 1,
                "name": "GitHub",
                "notes": "dev account",
                "folderId": "folder-1",
                "login": {
                    "username": "dev@example.com",
                    "password": "GhP@ss1!",
                    "uris": [{"uri": "https://github.com", "match": None}],
                    "totp": None,
                },
                "creationDate": "2024-01-01T00:00:00.000Z",
                "revisionDate": "2024-01-02T00:00:00.000Z",
                "deletedDate": None,
                "fields": [],
                "collectionIds": None,
                "favorite": False,
                "reprompt": 0,
                "organizationId": None,
            },
            {
                "id": "bw-item-2",
                "type": 1,
                "name": "Gmail",
                "notes": None,
                "folderId": None,
                "login": {
                    "username": "me@gmail.com",
                    "password": "Gm@il99!",
                    "uris": [{"uri": "https://mail.google.com", "match": None}],
                    "totp": None,
                },
                "creationDate": "2024-01-03T00:00:00.000Z",
                "revisionDate": "2024-01-04T00:00:00.000Z",
                "deletedDate": None,
                "fields": [],
                "collectionIds": None,
                "favorite": False,
                "reprompt": 0,
                "organizationId": None,
            },
        ],
    }

    _LASTPASS_CSV = (
        "url,username,password,totp,extra,name,grouping,fav\n"
        "https://github.com,dev@example.com,GhP@ss1!,,dev account,GitHub,Work,0\n"
        "https://mail.google.com,me@gmail.com,Gm@il99!,,personal,Gmail,,0\n"
    )

    def test_bitwarden_import(self, tmp_path):
        from src.core.import_export.formats.bitwarden_handler import BitwardenHandler

        bw_file = tmp_path / "bitwarden_export.json"
        bw_file.write_text(json.dumps(self._BITWARDEN_FIXTURE), encoding="utf-8")

        entries, warnings = BitwardenHandler.import_file(str(bw_file))

        assert len(entries) == 2, f"Expected 2 entries, got {len(entries)}"

        by_title = {e["title"]: e for e in entries}
        assert "GitHub" in by_title
        assert "Gmail" in by_title

        gh = by_title["GitHub"]
        assert gh["username"] == "dev@example.com"
        assert gh["password"] == "GhP@ss1!"
        assert gh["url"] == "https://github.com"
        assert gh["notes"] == "dev account"
        # Folder name should become a tag
        assert "Work" in gh["tags"]

    def test_bitwarden_export_then_import(self, tmp_path):
        from src.core.import_export.formats.bitwarden_handler import BitwardenHandler

        original = [
            _make_entry("Site1", "u1", "p1", "https://s1.com"),
            _make_entry("Site2", "u2", "p2", "https://s2.com"),
        ]
        bw_json = BitwardenHandler.export(original)
        imported, _ = BitwardenHandler.import_json(bw_json)

        assert len(imported) == 2
        by_title = {e["title"]: e for e in imported}
        for orig in original:
            imp = by_title[orig["title"]]
            assert imp["username"] == orig["username"]
            assert imp["password"] == orig["password"]
            assert imp["url"] == orig["url"]

    def test_lastpass_import(self, tmp_path):
        from src.core.import_export.formats.lastpass_handler import LastPassHandler

        lp_file = tmp_path / "lastpass_export.csv"
        lp_file.write_text(self._LASTPASS_CSV, encoding="utf-8")

        entries, warnings = LastPassHandler.import_file(str(lp_file))

        assert len(entries) == 2
        by_title = {e["title"]: e for e in entries}
        assert "GitHub" in by_title
        assert "Gmail" in by_title

        gh = by_title["GitHub"]
        assert gh["username"] == "dev@example.com"
        assert gh["password"] == "GhP@ss1!"
        assert gh["url"] == "https://github.com"
        assert gh["notes"] == "dev account"
        assert "Work" in gh["tags"]

    def test_bitwarden_encrypted_export_rejected(self, tmp_path):
        from src.core.import_export.formats.bitwarden_handler import BitwardenHandler

        enc_file = tmp_path / "bw_enc.json"
        enc_file.write_text(json.dumps({"encrypted": True, "items": []}), encoding="utf-8")

        with pytest.raises(ValueError, match="encrypted"):
            BitwardenHandler.import_file(str(enc_file))



class TestSharingSecurity:
    """TEST-3: tamper with share package bytes → HMAC rejection."""

    def _make_sharing_service(self):
        from src.core.import_export.sharing_service import SharingService

        entry = _make_entry("BankAccount", "alice", "BankP@ss1!")
        entry_manager = _InMemoryEntryManager([entry])

        db = MagicMock()
        db.execute.return_value = MagicMock()

        svc = SharingService(
            db_connection=db,
            encryption_service=None,
            audit_logger=_make_audit_logger(),
            entry_manager=entry_manager,
        )
        return svc, entry["id"]

    def test_share_and_receive_correct_password(self):
        """Correct password decrypts successfully."""
        from src.core.import_export.models import EncryptionMethod

        svc, entry_id = self._make_sharing_service()
        result = svc.share_entry(
            entry_id=entry_id,
            recipient="bob@example.com",
            permissions={"read_only": False},
            expires_in_days=7,
            encryption_method=EncryptionMethod.PASSWORD,
            password="SharedSecret123!",
        )

        assert "share_id" in result
        assert "package" in result

        # Receive with correct password — should not raise
        recv = svc.import_shared_entry(
            package_dict=result["package"],
            password="SharedSecret123!",
            save_to_vault=False,
        )
        assert recv["entry"]["title"] == "BankAccount"
        assert recv["entry"]["username"] == "alice"

    def test_wrong_password_raises(self):
        from src.core.import_export.models import EncryptionMethod

        svc, entry_id = self._make_sharing_service()
        result = svc.share_entry(
            entry_id=entry_id,
            recipient="bob@example.com",
            permissions={"read_only": True},
            expires_in_days=7,
            encryption_method=EncryptionMethod.PASSWORD,
            password="CorrectPassword1!",
        )

        with pytest.raises(Exception):
            svc.import_shared_entry(
                package_dict=result["package"],
                password="WrongPassword999!",
                save_to_vault=False,
            )

    def test_tampered_entry_data_rejected(self):
        from src.core.import_export.models import EncryptionMethod, SharePackage

        svc, entry_id = self._make_sharing_service()
        result = svc.share_entry(
            entry_id=entry_id,
            recipient="eve@example.com",
            permissions={"read_only": True},
            expires_in_days=7,
            encryption_method=EncryptionMethod.PASSWORD,
            password="LegitPassword1!",
        )

        package_dict = result["package"]

        # Tamper: flip the last character of entry_data
        original_data = package_dict["entry_data"]
        tampered_data = original_data[:-1] + ("A" if original_data[-1] != "A" else "B")
        package_dict["entry_data"] = tampered_data

        with pytest.raises(ValueError, match="[Ii]ntegrity|[Tt]amper"):
            svc.import_shared_entry(
                package_dict=package_dict,
                password="LegitPassword1!",
                save_to_vault=False,
            )

    def test_expired_package_rejected(self):
        from src.core.import_export.models import EncryptionMethod

        svc, entry_id = self._make_sharing_service()
        result = svc.share_entry(
            entry_id=entry_id,
            recipient="carol@example.com",
            permissions={"read_only": True},
            expires_in_days=1,
            encryption_method=EncryptionMethod.PASSWORD,
            password="AnyPass1!",
        )

        # Manually set expiry to the past
        package_dict = result["package"]
        package_dict["expires_at"] = "2000-01-01T00:00:00Z"

        with pytest.raises(ValueError, match="[Ee]xpir"):
            svc.import_shared_entry(
                package_dict=package_dict,
                password="AnyPass1!",
                save_to_vault=False,
            )

    def test_read_only_excludes_password(self):
        from src.core.import_export.models import EncryptionMethod

        svc, entry_id = self._make_sharing_service()
        result = svc.share_entry(
            entry_id=entry_id,
            recipient="dave@example.com",
            permissions={"read_only": True},
            expires_in_days=7,
            encryption_method=EncryptionMethod.PASSWORD,
            password="ReadOnlyPass1!",
        )

        recv = svc.import_shared_entry(
            package_dict=result["package"],
            password="ReadOnlyPass1!",
            save_to_vault=False,
        )
        assert "password" not in recv["entry"], (
            "read_only share must not expose the password field"
        )


class TestQRCode:
    """TEST-4: generate QR with 1 KB payload, decode, verify integrity."""

    @pytest.mark.skipif(
        not _qrcode_available(),
        reason="qrcode[pil] not installed — skipping QR tests",
    )
    def test_qr_roundtrip_small_payload(self, tmp_path):
        from src.core.import_export.key_exchange import QRCodeService

        svc = QRCodeService(db_connection=None, ttl_seconds=300)
        payload = {"message": "hello", "value": 42, "nested": {"a": 1}}

        images = svc.generate_qr_code(payload, payload_type="test")
        assert len(images) >= 1

        # Save first chunk to PNG and decode it
        png_path = tmp_path / "qr_chunk_1.png"
        images[0].save(str(png_path))

        chunk = svc.decode_qr_image(str(png_path))
        assert chunk["chunk"] == 1
        assert chunk["total"] == len(images)

        # Reassemble all chunks (save remaining if multi-chunk)
        all_chunks = [chunk]
        for i, img in enumerate(images[1:], start=2):
            p = tmp_path / f"qr_chunk_{i}.png"
            img.save(str(p))
            all_chunks.append(svc.decode_qr_image(str(p)))

        recovered = svc.decode_qr_chunks(all_chunks)
        assert recovered == payload

    @pytest.mark.skipif(
        not _qrcode_available(),
        reason="qrcode[pil] not installed — skipping QR tests",
    )
    def test_qr_roundtrip_1kb_payload(self, tmp_path):
        from src.core.import_export.key_exchange import QRCodeService

        svc = QRCodeService(db_connection=None, ttl_seconds=300)
        # Build ~1 KB of data
        payload = {"data": "x" * 900, "id": str(uuid.uuid4())}

        images = svc.generate_qr_code(payload, payload_type="large_test")
        assert len(images) >= 1

        all_chunks = []
        for i, img in enumerate(images, start=1):
            p = tmp_path / f"qr_{i}.png"
            img.save(str(p))
            all_chunks.append(svc.decode_qr_image(str(p)))

        recovered = svc.decode_qr_chunks(all_chunks)
        assert recovered == payload

    @pytest.mark.skipif(
        not _qrcode_available(),
        reason="qrcode[pil] not installed — skipping QR tests",
    )
    def test_qr_checksum_mismatch_rejected(self, tmp_path):
        from src.core.import_export.key_exchange import QRCodeService

        svc = QRCodeService(db_connection=None, ttl_seconds=300)
        images = svc.generate_qr_code({"k": "v"}, payload_type="test")

        png_path = tmp_path / "qr.png"
        images[0].save(str(png_path))
        chunk = svc.decode_qr_image(str(png_path))

        # Corrupt the checksum
        chunk["checksum"] = "deadbeef"

        with pytest.raises(ValueError, match="[Cc]hecksum"):
            svc.decode_qr_chunks([chunk])

    @pytest.mark.skipif(
        not _qrcode_available(),
        reason="qrcode[pil] not installed — skipping QR tests",
    )
    def test_qr_keypair_fingerprint(self):
        from src.core.import_export.key_exchange import QRCodeService

        svc = QRCodeService()
        _, pub_pem = svc.generate_keypair("RSA-2048")
        fp1 = svc.compute_key_fingerprint(pub_pem)
        fp2 = svc.compute_key_fingerprint(pub_pem)
        assert fp1 == fp2
        assert len(fp1) == 64  # SHA-256 hex

    @pytest.mark.skipif(
        not _qrcode_available(),
        reason="qrcode[pil] not installed — skipping QR tests",
    )
    def test_qr_generation_speed(self):
        from src.core.import_export.key_exchange import QRCodeService

        svc = QRCodeService(db_connection=None, ttl_seconds=300)
        payload = {"data": "x" * 900}

        start = time.monotonic()
        svc.generate_qr_code(payload, payload_type="perf_test")
        elapsed_ms = (time.monotonic() - start) * 1000

        assert elapsed_ms < 100, (
            f"QR generation took {elapsed_ms:.1f} ms, expected <100 ms"
        )

class TestPerformance:
    """TEST-5: export 1000 entries <5 s, import 1000 entries <10 s."""

    @pytest.mark.slow
    @pytest.mark.perf
    def test_export_1000_entries_under_5s(self, tmp_path):
        from src.core.import_export.exporter import VaultExporter

        entries = _make_entries(1000)
        manager = _InMemoryEntryManager(entries)
        exporter = VaultExporter(
            entry_manager=manager,
            encryption_service=None,
            audit_logger=_make_audit_logger(),
        )

        export_file = tmp_path / "perf_export.json"
        start = time.monotonic()
        result = exporter.export_vault(
            entry_ids=None,
            password="PerfTestPass1!",
            public_key=None,
            format="json",
            file_path=export_file,
        )
        elapsed = time.monotonic() - start

        assert result.entry_count == 1000
        assert elapsed < 5.0, (
            f"Export of 1000 entries took {elapsed:.2f}s, expected <5s"
        )

    @pytest.mark.slow
    @pytest.mark.perf
    def test_import_1000_entries_under_10s(self, tmp_path):
        from src.core.import_export.exporter import VaultExporter
        from src.core.import_export.importer import VaultImporter

        entries = _make_entries(1000)
        src_manager = _InMemoryEntryManager(entries)
        exporter = VaultExporter(
            entry_manager=src_manager,
            encryption_service=None,
            audit_logger=_make_audit_logger(),
        )
        export_file = tmp_path / "perf_import_src.json"
        exporter.export_vault(
            entry_ids=None,
            password="PerfImportPass1!",
            public_key=None,
            format="json",
            file_path=export_file,
        )

        dst_manager = _InMemoryEntryManager()
        importer = VaultImporter(
            entry_manager=dst_manager,
            encryption_service=None,
            audit_logger=_make_audit_logger(),
        )

        start = time.monotonic()
        result = importer.import_json(export_file, password="PerfImportPass1!")
        elapsed = time.monotonic() - start

        assert result.successful_imports == 1000
        assert elapsed < 10.0, (
            f"Import of 1000 entries took {elapsed:.2f}s, expected <10s"
        )

    @pytest.mark.slow
    @pytest.mark.perf
    def test_csv_export_1000_entries(self, tmp_path):
        from src.core.import_export.exporter import VaultExporter

        entries = _make_entries(1000)
        manager = _InMemoryEntryManager(entries)
        exporter = VaultExporter(
            entry_manager=manager,
            encryption_service=None,
            audit_logger=_make_audit_logger(),
        )

        csv_file = tmp_path / "perf_export.csv"
        start = time.monotonic()
        result = exporter.export_vault(
            entry_ids=None,
            password="",
            public_key=None,
            format="csv",
            file_path=csv_file,
        )
        elapsed = time.monotonic() - start

        assert result.entry_count == 1000
        assert elapsed < 5.0, f"CSV export took {elapsed:.2f}s"

    @pytest.mark.slow
    @pytest.mark.perf
    def test_bitwarden_export_1000_entries(self, tmp_path):
        from src.core.import_export.exporter import VaultExporter

        entries = _make_entries(1000)
        manager = _InMemoryEntryManager(entries)
        exporter = VaultExporter(
            entry_manager=manager,
            encryption_service=None,
            audit_logger=_make_audit_logger(),
        )

        bw_file = tmp_path / "perf_bw.json"
        start = time.monotonic()
        result = exporter.export_vault(
            entry_ids=None,
            password="",
            public_key=None,
            format="bitwarden",
            file_path=bw_file,
        )
        elapsed = time.monotonic() - start

        assert result.entry_count == 1000
        assert elapsed < 5.0, f"Bitwarden export took {elapsed:.2f}s"


def _hypothesis_available() -> bool:
    try:
        import hypothesis  # noqa: F401
        return True
    except ImportError:
        return False


@pytest.mark.skipif(not _hypothesis_available(), reason="hypothesis not installed")
@pytest.mark.property
class TestPropertyBased:

    def test_p2_csv_never_contains_password(self):
        from hypothesis import given, settings
        from hypothesis import strategies as st
        from src.core.import_export.formats.csv_handler import CSVHandler

        @given(
            title=st.text(min_size=1, max_size=50),
            username=st.text(max_size=50),
            password=st.text(min_size=1, max_size=50),
        )
        @settings(max_examples=10)
        def inner(title, username, password):
            entry = _make_entry(title=title, username=username, password=password)
            csv_text = CSVHandler.export([entry])
            assert password not in csv_text or password == "[ENCRYPTED]"

        inner()

    def test_p3_no_duplicates_after_conflict_resolution(self):
        from src.core.import_export.importer import VaultImporter

        strategies = ["skip", "replace", "rename", "merge"]
        for strategy in strategies:
            existing = [_make_entry("Site", "user")]
            incoming = [_make_entry("Site", "user", password="NewPass1!")]

            manager = _InMemoryEntryManager(existing)
            importer = VaultImporter(
                entry_manager=manager,
                encryption_service=None,
                audit_logger=_make_audit_logger(),
            )
            importer._import_entries(incoming, strategy)

            all_entries = manager.get_all_entries()
            seen = set()
            for e in all_entries:
                key = (e.get("title", "").lower(), e.get("username", "").lower())
                assert key not in seen, (
                    f"Duplicate entry {key} found after strategy '{strategy}'"
                )
                seen.add(key)


class TestExportImportAdditional:
    """Дополнительные тесты для экспорта/импорта"""
    
    def test_exporter_creates_file(self, tmp_path):
        """TEST: проверка создания файла при экспорте"""
        from src.core.import_export.exporter import VaultExporter
        
        # Создаем тестовые данные
        entries = [
            _make_entry("TestSite1", "user1", "pass1", "https://site1.com"),
            _make_entry("TestSite2", "user2", "pass2", "https://site2.com"),
        ]
        
        manager = _InMemoryEntryManager(entries)
        exporter = VaultExporter(
            entry_manager=manager,
            encryption_service=None,
            audit_logger=_make_audit_logger(),
        )
        
        # Пробуем разные форматы экспорта
        test_cases = [
            ("json", "test_export.json"),
            ("csv", "test_export.csv"),
            ("bitwarden", "test_export_bitwarden.json"),
        ]
        
        for format_name, filename in test_cases:
            export_file = tmp_path / filename
            
            # Для CSV и Bitwarden не нужен пароль
            master_password = "TestMasterPass123!"  # Нужен мастер-пароль
            export_password = "" if format_name in ["csv", "bitwarden"] else "TestExportPass123!"
            
            result = exporter.export_vault(
                entry_ids=None,
                master_password=master_password,
                export_password=export_password,
                public_key=None,
                format=format_name,
                file_path=export_file,
            )
            
            # Проверяем, что файл создан
            assert export_file.exists(), f"Файл {filename} не создан при экспорте в формате {format_name}"
            assert export_file.stat().st_size > 0, f"Файл {filename} пустой"
            
            # Проверяем результат экспорта
            assert result.entry_count == 2, f"Неверное количество экспортированных записей для {format_name}"
            assert result.file_path == str(export_file), f"Неверный путь в результате для {format_name}"
    
    def test_importer_duplicate_handling(self):
        """TEST: проверка обработки дубликатов при импорте"""
        from src.core.import_export.importer import VaultImporter
        
        # Создаем существующие записи
        existing_entries = [
            _make_entry("Site1", "user1", "old_pass", "https://site1.com", "Old notes"),
            _make_entry("Site2", "user2", "pass2", "https://site2.com"),
        ]
        
        # Создаем импортируемые записи (включая дубликат)
        import_entries = [
            _make_entry("Site1", "user1", "new_pass", "https://site1.com", "New notes"),  # Дубликат
            _make_entry("Site3", "user3", "pass3", "https://site3.com"),  # Новая
            _make_entry("Site4", "user4", "pass4", "https://site4.com"),  # Новая
        ]
        
        manager = _InMemoryEntryManager(existing_entries)
        importer = VaultImporter(
            entry_manager=manager,
            encryption_service=None,
            audit_logger=_make_audit_logger(),
        )
        
        # Тестируем разные стратегии обработки дубликатов
        test_strategies = ["skip", "replace", "rename", "merge"]
        
        for strategy in test_strategies:
            # Копируем менеджер для каждого теста
            test_manager = _InMemoryEntryManager(existing_entries.copy())
            importer.entry_manager = test_manager
            
            # Импортируем с текущей стратегией
            result = importer._import_entries(import_entries.copy(), strategy)
            
            # Проверяем результаты в зависимости от стратегии
            all_entries = test_manager.get_all_entries()
            
            if strategy == "skip":
                # Дубликат пропущен, добавлены только новые
                assert len(all_entries) == 4  # 2 существующих + 2 новых
                # Проверяем, что пароль Site1 остался старым
                site1_entry = next((e for e in all_entries if e["title"] == "Site1"), None)
                assert site1_entry is not None
                assert site1_entry["password"] == "old_pass"
                assert site1_entry["notes"] == "Old notes"
                
            elif strategy == "replace":
                # Дубликат заменен, добавлены новые
                assert len(all_entries) == 4  # 1 заменен + 1 существующий + 2 новых
                # Проверяем, что пароль Site1 обновлен
                site1_entry = next((e for e in all_entries if e["title"] == "Site1"), None)
                assert site1_entry is not None
                assert site1_entry["password"] == "new_pass"
                assert site1_entry["notes"] == "New notes"
                
            elif strategy == "rename":
                # Дубликат переименован, добавлены новые
                assert len(all_entries) == 5  # 2 существующих + 1 переименованный + 2 новых
                # Проверяем, что есть оригинал и переименованный
                original_site1 = next((e for e in all_entries if e["title"] == "Site1" and e["password"] == "old_pass"), None)
                renamed_site1 = next((e for e in all_entries if "Site1" in e["title"] and e["title"] != "Site1" and e["password"] == "new_pass"), None)
                assert original_site1 is not None
                assert renamed_site1 is not None
                # Проверяем, что переименованный содержит суффикс
                assert renamed_site1["title"].startswith("Site1")
                assert renamed_site1["title"] != "Site1"
                
            elif strategy == "merge":
                # Дубликат объединен, добавлены новые
                # В зависимости от реализации merge может создавать новую запись или обновлять существующую
                # Проверяем, что у нас есть запись Site1
                site1_entries = [e for e in all_entries if e["title"] == "Site1"]
                assert len(site1_entries) >= 1, "Should have at least one Site1 entry"
                
                # Проверяем username в одной из записей Site1
                site1_entry = site1_entries[0]
                assert "username" in site1_entry
                assert site1_entry["username"] == "user1"
            # Проверяем результат импорта
            assert result.successful_imports >= 2  # Минимум 2 новых записи добавлены
            assert result.failed_imports == 0
            assert result.total_entries == len(import_entries)

            print(f"Strategy '{strategy}' passed: {result.successful_imports} successful imports")

    print("All duplicate handling strategies tested successfully!")

# Добавляем закрывающие скобки для класса
# Завершаем файл
if __name__ == "__main__":
    pytest.main([__file__, "-v"])