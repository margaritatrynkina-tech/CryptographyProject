"""
TEST-1: Процедуры импорта/экспорта
Покрывает: JSON, CSV, Bitwarden, LastPass экспорт и импорт
Маркеры: fast
"""
import os
import json
import tempfile
import pytest
from pathlib import Path
from unittest.mock import MagicMock


# ---------------------------------------------------------------------------
# Helper builders
# ---------------------------------------------------------------------------

def make_entry(title="GitHub", username="alice", password="S3cr3t!",
               url="https://github.com", notes="", tags=""):
    return {
        "id": "test-uuid-1234",
        "title": title,
        "username": username,
        "password": password,
        "url": url,
        "notes": notes,
        "tags": tags,
    }


def make_exporter(entries=None):
    """Create a VaultExporter with a mock entry_manager and a stub audit_logger."""
    from src.core.import_export.exporter import VaultExporter
    em = MagicMock()
    em.get_all_entries.return_value = entries or [make_entry()]
    em.get_entry.side_effect = lambda eid: next(
        (e for e in (entries or [make_entry()]) if e["id"] == eid), None
    )
    al = MagicMock()
    al.log_event.return_value = 1
    return VaultExporter(entry_manager=em, encryption_service=None, audit_logger=al)


def make_importer(db_conn=None):
    """Create a VaultImporter with a mock entry_manager for isolation."""
    from src.core.import_export.importer import VaultImporter

    # Track stored entries
    _store: dict = {}

    em = MagicMock()

    def _create(data):
        import uuid as _uuid
        eid = data.get("id") or str(_uuid.uuid4())
        entry = dict(data, id=eid)
        if isinstance(entry.get("tags"), list):
            entry["tags"] = ",".join(entry["tags"])
        _store[eid] = entry
        return eid

    def _get(eid):
        return _store.get(eid)

    def _get_all():
        return list(_store.values())

    def _update(eid, data):
        if eid not in _store:
            return False
        entry = dict(data, id=eid)
        if isinstance(entry.get("tags"), list):
            entry["tags"] = ",".join(entry["tags"])
        _store[eid] = entry
        return True

    em.create_entry.side_effect = _create
    em.get_entry.side_effect = _get
    em.get_all_entries.side_effect = _get_all
    em.update_entry.side_effect = _update

    al = MagicMock()
    al.log_event.return_value = 1

    return VaultImporter(entry_manager=em, encryption_service=None, audit_logger=al)


# ---------------------------------------------------------------------------
# JSONHandler (envelope schema)
# ---------------------------------------------------------------------------

class TestJSONHandler:
    @pytest.mark.fast
    def test_build_and_parse_envelope(self):
        from src.core.import_export.formats.json_handler import JSONHandler
        data_b64 = "dGVzdA=="  # base64("test")
        meta = {"export_id": "x", "timestamp": "2024-01-01T00:00:00Z",
                "format": "json", "entry_count": 1, "app_version": "1.0"}
        enc = {"method": "none"}
        envelope_str = JSONHandler.build_envelope(data_b64, meta, enc)
        parsed = JSONHandler.parse_envelope(envelope_str)
        assert parsed["cryptosafe_export"] is True
        assert parsed["data"] == data_b64

    @pytest.mark.fast
    def test_parse_invalid_json_raises(self):
        from src.core.import_export.formats.json_handler import JSONHandler
        with pytest.raises(ValueError):
            JSONHandler.parse_envelope("{not valid json}")

    @pytest.mark.fast
    def test_parse_missing_flag_raises(self):
        from src.core.import_export.formats.json_handler import JSONHandler
        with pytest.raises(ValueError, match="cryptosafe_export"):
            JSONHandler.parse_envelope(json.dumps({"version": "1.0"}))

    @pytest.mark.fast
    def test_parse_wrong_version_raises(self):
        from src.core.import_export.formats.json_handler import JSONHandler
        doc = {"cryptosafe_export": True, "version": "99.0",
               "metadata": {}, "encryption": {}, "data": "", "integrity": {}}
        with pytest.raises(ValueError, match="version"):
            JSONHandler.parse_envelope(json.dumps(doc))

    @pytest.mark.fast
    def test_compute_hash(self):
        from src.core.import_export.formats.json_handler import JSONHandler
        h = JSONHandler.compute_hash(b"hello")
        assert len(h) == 64  # SHA-256 hex

    @pytest.mark.fast
    def test_verify_hash_correct(self):
        from src.core.import_export.formats.json_handler import JSONHandler
        data = b"important data"
        h = JSONHandler.compute_hash(data)
        assert JSONHandler.verify_hash(data, h) is True

    @pytest.mark.fast
    def test_verify_hash_wrong(self):
        from src.core.import_export.formats.json_handler import JSONHandler
        assert JSONHandler.verify_hash(b"data", "a" * 64) is False

    @pytest.mark.fast
    def test_serialise_deserialise_entries(self):
        from src.core.import_export.formats.json_handler import JSONHandler
        entries = [make_entry(), make_entry("Twitter", "bob")]
        raw = JSONHandler.serialise_entries(entries)
        back = JSONHandler.deserialise_entries(raw)
        assert len(back) == 2
        assert back[0]["title"] == "GitHub"

    @pytest.mark.fast
    def test_is_cryptosafe_export_positive(self):
        from src.core.import_export.formats.json_handler import JSONHandler
        doc = json.dumps({"cryptosafe_export": True})
        assert JSONHandler.is_cryptosafe_export(doc) is True

    @pytest.mark.fast
    def test_is_cryptosafe_export_negative(self):
        from src.core.import_export.formats.json_handler import JSONHandler
        assert JSONHandler.is_cryptosafe_export("{}") is False


# ---------------------------------------------------------------------------
# CSVHandler
# ---------------------------------------------------------------------------

class TestCSVHandler:
    @pytest.mark.fast
    def test_export_has_header(self):
        from src.core.import_export.formats.csv_handler import CSVHandler
        csv_text = CSVHandler.export([make_entry()])
        assert "title" in csv_text.lower()

    @pytest.mark.fast
    def test_export_masks_password(self):
        from src.core.import_export.formats.csv_handler import CSVHandler
        entry = make_entry(password="SuperSecret123")
        csv_text = CSVHandler.export([entry])
        assert "SuperSecret123" not in csv_text
        assert "[ENCRYPTED]" in csv_text

    @pytest.mark.fast
    def test_export_import_roundtrip_title(self):
        from src.core.import_export.formats.csv_handler import CSVHandler
        entries = [make_entry("Notion"), make_entry("Slack", "bob")]
        csv_text = CSVHandler.export(entries)
        imported, warnings = CSVHandler.import_csv(csv_text)
        titles = [e["title"] for e in imported]
        assert "Notion" in titles
        assert "Slack" in titles

    @pytest.mark.fast
    def test_import_empty_csv(self):
        from src.core.import_export.formats.csv_handler import CSVHandler
        entries, warnings = CSVHandler.import_csv("")
        assert entries == []

    @pytest.mark.fast
    def test_import_skips_empty_rows(self):
        from src.core.import_export.formats.csv_handler import CSVHandler
        csv_text = "title,username\n,\n,\nGitHub,alice\n"
        entries, warnings = CSVHandler.import_csv(csv_text)
        assert len(entries) == 1

    @pytest.mark.fast
    def test_validate_valid_file(self, tmp_path):
        from src.core.import_export.formats.csv_handler import CSVHandler
        p = tmp_path / "test.csv"
        p.write_text("title,username,password\nGitHub,alice,pass\n", encoding="utf-8")
        valid, errors = CSVHandler.validate(str(p))
        assert valid is True

    @pytest.mark.fast
    def test_export_to_file(self, tmp_path):
        from src.core.import_export.formats.csv_handler import CSVHandler
        p = tmp_path / "out.csv"
        n = CSVHandler.export_to_file([make_entry()], str(p))
        assert n == 1
        assert p.exists()

    @pytest.mark.fast
    def test_tags_list_serialised(self):
        from src.core.import_export.formats.csv_handler import CSVHandler
        entry = make_entry()
        entry["tags"] = ["dev", "personal"]
        csv_text = CSVHandler.export([entry])
        assert "dev" in csv_text


# ---------------------------------------------------------------------------
# BitwardenHandler
# ---------------------------------------------------------------------------

class TestBitwardenHandler:
    @pytest.mark.fast
    def test_export_produces_valid_json(self):
        from src.core.import_export.formats.bitwarden_handler import BitwardenHandler
        out = BitwardenHandler.export([make_entry()])
        data = json.loads(out)
        assert "items" in data
        assert len(data["items"]) == 1

    @pytest.mark.fast
    def test_export_import_roundtrip(self):
        from src.core.import_export.formats.bitwarden_handler import BitwardenHandler
        entries = [make_entry("Google", "carol", "P@ssw0rd")]
        bw_json = BitwardenHandler.export(entries)
        imported, warnings = BitwardenHandler.import_json(bw_json)
        assert len(imported) == 1
        assert imported[0]["title"] == "Google"
        assert imported[0]["username"] == "carol"

    @pytest.mark.fast
    def test_import_preserves_url(self):
        from src.core.import_export.formats.bitwarden_handler import BitwardenHandler
        entry = make_entry(url="https://google.com")
        bw_json = BitwardenHandler.export([entry])
        imported, _ = BitwardenHandler.import_json(bw_json)
        assert imported[0]["url"] == "https://google.com"

    @pytest.mark.fast
    def test_import_encrypted_raises(self):
        from src.core.import_export.formats.bitwarden_handler import BitwardenHandler
        with pytest.raises(ValueError, match="encrypted"):
            BitwardenHandler.import_json(json.dumps({"encrypted": True, "items": []}))

    @pytest.mark.fast
    def test_validate_valid(self, tmp_path):
        from src.core.import_export.formats.bitwarden_handler import BitwardenHandler
        p = tmp_path / "bw.json"
        p.write_text(BitwardenHandler.export([make_entry()]))
        valid, errors = BitwardenHandler.validate(str(p))
        assert valid is True

    @pytest.mark.fast
    def test_validate_missing_items(self, tmp_path):
        from src.core.import_export.formats.bitwarden_handler import BitwardenHandler
        p = tmp_path / "bw_bad.json"
        p.write_text(json.dumps({"encrypted": False}))
        valid, errors = BitwardenHandler.validate(str(p))
        assert valid is False

    @pytest.mark.fast
    def test_secure_note_imported_with_warning(self):
        from src.core.import_export.formats.bitwarden_handler import BitwardenHandler
        bw = {"encrypted": False, "folders": [], "items": [{
            "id": "x", "type": 2, "name": "My Note",
            "notes": "some text", "login": None
        }]}
        entries, warnings = BitwardenHandler.import_json(json.dumps(bw))
        assert len(entries) == 1
        assert any("note" in w.lower() or "secure" in w.lower() for w in warnings)


# ---------------------------------------------------------------------------
# LastPassHandler
# ---------------------------------------------------------------------------

class TestLastPassHandler:
    @pytest.mark.fast
    def test_export_produces_csv(self):
        from src.core.import_export.formats.lastpass_handler import LastPassHandler
        csv_text = LastPassHandler.export([make_entry()])
        assert "url" in csv_text.lower()
        assert "username" in csv_text.lower()

    @pytest.mark.fast
    def test_export_import_roundtrip(self):
        from src.core.import_export.formats.lastpass_handler import LastPassHandler
        entries = [make_entry("Amazon", "dave")]
        csv_text = LastPassHandler.export(entries)
        imported, warnings = LastPassHandler.import_csv(csv_text)
        assert len(imported) == 1
        assert imported[0]["title"] == "Amazon"

    @pytest.mark.fast
    def test_export_encrypted_roundtrip(self):
        from src.core.import_export.formats.lastpass_handler import LastPassHandler
        entries = [make_entry()]
        encrypted = LastPassHandler.export(entries, password="test_password_123")
        assert encrypted.startswith("ENCRYPTED:")
        decrypted = LastPassHandler._decrypt_content(encrypted, "test_password_123")
        back, _ = LastPassHandler.import_csv(decrypted)
        assert len(back) == 1

    @pytest.mark.fast
    def test_decrypt_wrong_password_raises(self):
        from src.core.import_export.formats.lastpass_handler import LastPassHandler
        encrypted = LastPassHandler.export([make_entry()], password="right_pass")
        with pytest.raises(ValueError):
            LastPassHandler._decrypt_content(encrypted, "wrong_pass")

    @pytest.mark.fast
    def test_import_csv_empty(self):
        from src.core.import_export.formats.lastpass_handler import LastPassHandler
        entries, warnings = LastPassHandler.import_csv("")
        assert entries == []

    @pytest.mark.fast
    def test_validate_valid_file(self, tmp_path):
        from src.core.import_export.formats.lastpass_handler import LastPassHandler
        p = tmp_path / "lp.csv"
        p.write_text("url,username,password,totp,extra,name,grouping,fav\n"
                     "https://x.com,alice,pass,,note,X,,0\n", encoding="utf-8")
        valid, errors = LastPassHandler.validate(str(p))
        assert valid is True

    @pytest.mark.fast
    def test_import_file_to_file(self, tmp_path):
        from src.core.import_export.formats.lastpass_handler import LastPassHandler
        p = tmp_path / "lp.csv"
        n = LastPassHandler.export_to_file([make_entry()], str(p))
        assert n == 1
        assert p.exists()
        entries, _ = LastPassHandler.import_file(str(p))
        assert len(entries) == 1

    @pytest.mark.fast
    def test_tags_as_list(self):
        from src.core.import_export.formats.lastpass_handler import LastPassHandler
        entry = make_entry()
        entry["tags"] = ["work", "personal"]
        csv_text = LastPassHandler.export([entry])
        assert "work" in csv_text


# ---------------------------------------------------------------------------
# VaultExporter (integration)
# ---------------------------------------------------------------------------

class TestVaultExporter:
    @pytest.mark.fast
    def test_export_csv(self, tmp_path):
        exporter = make_exporter()
        p = tmp_path / "out.csv"
        result = exporter.export_vault(
            entry_ids=None,
            master_password="master",
            export_password=None,
            public_key=None,
            format="csv",
            file_path=p,
        )
        assert result.entry_count == 1
        assert p.exists()

    @pytest.mark.fast
    def test_export_bitwarden(self, tmp_path):
        exporter = make_exporter()
        p = tmp_path / "out.json"
        result = exporter.export_vault(
            entry_ids=None,
            master_password="master",
            export_password=None,
            public_key=None,
            format="bitwarden",
            file_path=p,
        )
        assert result.entry_count == 1
        data = json.loads(p.read_text())
        assert "items" in data

    @pytest.mark.fast
    def test_export_json_with_password(self, tmp_path):
        exporter = make_exporter()
        p = tmp_path / "out.json"
        result = exporter.export_vault(
            entry_ids=None,
            master_password="master",
            export_password="export_pwd_123",
            public_key=None,
            format="json",
            file_path=p,
        )
        assert result.entry_count == 1
        data = json.loads(p.read_text())
        assert data["cryptosafe_export"] is True

    @pytest.mark.fast
    def test_export_checksum_length(self, tmp_path):
        exporter = make_exporter()
        p = tmp_path / "out.csv"
        result = exporter.export_vault(
            entry_ids=None, master_password="m",
            export_password=None, public_key=None,
            format="csv", file_path=p,
        )
        assert len(result.checksum) == 64  # SHA-256 hex

    @pytest.mark.fast
    def test_export_unsupported_format_raises(self, tmp_path):
        exporter = make_exporter()
        p = tmp_path / "out.dat"
        with pytest.raises(ValueError, match="Unsupported"):
            exporter.export_vault(
                entry_ids=None, master_password="m",
                export_password=None, public_key=None,
                format="xml", file_path=p,
            )

    @pytest.mark.fast
    def test_export_lastpass(self, tmp_path):
        exporter = make_exporter()
        p = tmp_path / "out.csv"
        result = exporter.export_vault(
            entry_ids=None,
            master_password="master",
            export_password=None,
            public_key=None,
            format="lastpass",
            file_path=p,
        )
        assert result.entry_count == 1


# ---------------------------------------------------------------------------
# VaultImporter (integration)
# ---------------------------------------------------------------------------

class TestVaultImporter:
    @pytest.mark.fast
    def test_import_csv(self, tmp_path):
        importer = make_importer()
        p = tmp_path / "data.csv"
        p.write_text(
            "title,username,password,url\nGitHub,alice,pass,https://github.com\n",
            encoding="utf-8"
        )
        result = importer.import_csv(p)
        assert result.successful_imports == 1
        assert result.total_entries == 1

    @pytest.mark.fast
    def test_import_bitwarden(self, tmp_path):
        from src.core.import_export.formats.bitwarden_handler import BitwardenHandler
        importer = make_importer()
        p = tmp_path / "bw.json"
        p.write_text(BitwardenHandler.export([make_entry()]))
        result = importer.import_bitwarden(p)
        assert result.successful_imports == 1

    @pytest.mark.fast
    def test_import_lastpass(self, tmp_path):
        from src.core.import_export.formats.lastpass_handler import LastPassHandler
        importer = make_importer()
        p = tmp_path / "lp.csv"
        LastPassHandler.export_to_file([make_entry()], str(p))
        result = importer.import_lastpass(p, master_password="master")
        assert result.successful_imports == 1

    @pytest.mark.fast
    def test_import_json_with_password(self, tmp_path):
        exporter = make_exporter()
        p = tmp_path / "vault.json"
        exporter.export_vault(
            entry_ids=None, master_password="master",
            export_password="export_pwd", public_key=None,
            format="json", file_path=p,
        )
        importer = make_importer()
        result = importer.import_json(p, master_password="master",
                                      file_password="export_pwd")
        assert result.successful_imports == 1

    @pytest.mark.fast
    def test_import_json_wrong_password_raises(self, tmp_path):
        exporter = make_exporter()
        p = tmp_path / "vault.json"
        exporter.export_vault(
            entry_ids=None, master_password="master",
            export_password="correct_pass", public_key=None,
            format="json", file_path=p,
        )
        importer = make_importer()
        with pytest.raises(ValueError):
            importer.import_json(p, master_password="master",
                                 file_password="wrong_pass")

    @pytest.mark.fast
    def test_import_missing_file_raises(self, tmp_path):
        importer = make_importer()
        with pytest.raises(FileNotFoundError):
            importer.import_csv(tmp_path / "nonexistent.csv")

    @pytest.mark.fast
    def test_import_conflict_skip(self, tmp_path):
        importer = make_importer()
        p = tmp_path / "data.csv"
        csv_content = "title,username,password\nGitHub,alice,pass\n"
        p.write_text(csv_content, encoding="utf-8")
        r1 = importer.import_csv(p, conflict_strategy="skip")
        assert r1.successful_imports == 1
        # Second import: same title+username → conflict, skipped
        r2 = importer.import_csv(p, conflict_strategy="skip")
        assert r2.conflict_count == 1
        assert r2.successful_imports == 0

    @pytest.mark.fast
    def test_validate_csv_file(self, tmp_path):
        importer = make_importer()
        p = tmp_path / "data.csv"
        p.write_text("title,username\nGitHub,alice\n", encoding="utf-8")
        result = importer.validate_import_file(p, "csv")
        assert result["is_valid"] is True

    @pytest.mark.fast
    def test_validate_nonexistent_file(self, tmp_path):
        importer = make_importer()
        result = importer.validate_import_file(tmp_path / "no.csv", "csv")
        assert result["is_valid"] is False

    @pytest.mark.fast
    def test_import_entry_without_title_skipped(self, tmp_path):
        importer = make_importer()
        p = tmp_path / "bad.csv"
        p.write_text("title,username\n,alice\nGitHub,bob\n", encoding="utf-8")
        result = importer.import_csv(p)
        # "GitHub" imported successfully; the empty-title row generates a warning
        assert result.successful_imports == 1
        assert len(result.validation_errors) >= 1
