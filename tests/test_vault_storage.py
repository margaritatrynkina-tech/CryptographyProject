"""
TEST-1: Операции хранилища
Покрывает: добавление, редактирование, удаление, поиск записей
Маркеры: fast
"""
import os
import sqlite3
import pytest
from unittest.mock import MagicMock

from src.core.events import EventSystem, EventType
from src.core.vault.entry_manager import EntryManager
from src.core.vault.encryption_service import AESGCMEncryptionService


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def enc_key():
    return os.urandom(32)


@pytest.fixture
def mock_key_manager(enc_key):
    km = MagicMock()
    km.get_encryption_key.return_value = enc_key
    return km


@pytest.fixture
def db_conn():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE vault_entries (
            id TEXT PRIMARY KEY,
            encrypted_data BLOB NOT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            tags TEXT DEFAULT ''
        )
    """)
    conn.execute("""
        CREATE TABLE deleted_entries (
            entry_id TEXT PRIMARY KEY,
            deleted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME
        )
    """)
    conn.commit()
    return conn


@pytest.fixture
def entry_mgr(db_conn, mock_key_manager):
    events = EventSystem()
    return EntryManager(db_conn, mock_key_manager, events)


@pytest.fixture
def sample_entry():
    return {
        "title": "GitHub",
        "username": "alice",
        "password": "S3cr3t!Pass",
        "url": "https://github.com",
        "notes": "personal account",
        "tags": "dev,work",
    }


# ---------------------------------------------------------------------------
# Create (add)
# ---------------------------------------------------------------------------

class TestEntryCreate:
    @pytest.mark.fast
    def test_create_returns_uuid(self, entry_mgr, sample_entry):
        eid = entry_mgr.create_entry(sample_entry)
        assert isinstance(eid, str)
        assert len(eid) == 36  # UUID4

    @pytest.mark.fast
    def test_create_then_retrieve(self, entry_mgr, sample_entry):
        eid = entry_mgr.create_entry(sample_entry)
        e = entry_mgr.get_entry(eid)
        assert e is not None
        assert e["title"] == "GitHub"
        assert e["username"] == "alice"

    @pytest.mark.fast
    def test_create_password_not_stored_plaintext(self, db_conn, entry_mgr, sample_entry):
        eid = entry_mgr.create_entry(sample_entry)
        row = db_conn.execute(
            "SELECT encrypted_data FROM vault_entries WHERE id = ?", (eid,)
        ).fetchone()
        raw = bytes(row["encrypted_data"])
        assert b"S3cr3t!Pass" not in raw

    @pytest.mark.fast
    def test_create_multiple_distinct_ids(self, entry_mgr, sample_entry):
        e1 = entry_mgr.create_entry(sample_entry)
        e2 = entry_mgr.create_entry({**sample_entry, "title": "Other"})
        assert e1 != e2

    @pytest.mark.fast
    def test_create_emits_event(self, entry_mgr, sample_entry):
        received = []
        entry_mgr.events.subscribe(EventType.ENTRY_ADDED, lambda d: received.append(d))
        eid = entry_mgr.create_entry(sample_entry)
        assert len(received) == 1
        assert received[0]["entry_id"] == eid

    @pytest.mark.fast
    def test_create_without_optional_fields(self, entry_mgr):
        eid = entry_mgr.create_entry({"title": "Minimal"})
        e = entry_mgr.get_entry(eid)
        assert e["title"] == "Minimal"


# ---------------------------------------------------------------------------
# Read (get / get_all)
# ---------------------------------------------------------------------------

class TestEntryRead:
    @pytest.mark.fast
    def test_get_nonexistent_returns_none(self, entry_mgr):
        assert entry_mgr.get_entry("00000000-0000-0000-0000-000000000000") is None

    @pytest.mark.fast
    def test_get_all_empty(self, entry_mgr):
        assert entry_mgr.get_all_entries() == []

    @pytest.mark.fast
    def test_get_all_returns_all(self, entry_mgr, sample_entry):
        entry_mgr.create_entry(sample_entry)
        entry_mgr.create_entry({**sample_entry, "title": "GitLab"})
        all_e = entry_mgr.get_all_entries()
        assert len(all_e) == 2

    @pytest.mark.fast
    def test_get_entry_contains_metadata(self, entry_mgr, sample_entry):
        eid = entry_mgr.create_entry(sample_entry)
        e = entry_mgr.get_entry(eid)
        assert "id" in e
        assert "created_at" in e
        assert "updated_at" in e


# ---------------------------------------------------------------------------
# Update (edit)
# ---------------------------------------------------------------------------

class TestEntryUpdate:
    @pytest.mark.fast
    def test_update_title(self, entry_mgr, sample_entry):
        eid = entry_mgr.create_entry(sample_entry)
        ok = entry_mgr.update_entry(eid, {**sample_entry, "title": "GitLab"})
        assert ok is True
        assert entry_mgr.get_entry(eid)["title"] == "GitLab"

    @pytest.mark.fast
    def test_update_password(self, entry_mgr, sample_entry):
        eid = entry_mgr.create_entry(sample_entry)
        entry_mgr.update_entry(eid, {**sample_entry, "password": "NewPass456!"})
        assert entry_mgr.get_entry(eid)["password"] == "NewPass456!"

    @pytest.mark.fast
    def test_update_nonexistent_returns_false(self, entry_mgr):
        ok = entry_mgr.update_entry(
            "00000000-0000-0000-0000-000000000000", {"title": "X"}
        )
        assert ok is False

    @pytest.mark.fast
    def test_update_emits_event(self, entry_mgr, sample_entry):
        eid = entry_mgr.create_entry(sample_entry)
        received = []
        entry_mgr.events.subscribe(EventType.ENTRY_UPDATED, lambda d: received.append(d))
        entry_mgr.update_entry(eid, {**sample_entry, "title": "New"})
        assert len(received) == 1

    @pytest.mark.fast
    def test_update_password_stays_encrypted(self, db_conn, entry_mgr, sample_entry):
        eid = entry_mgr.create_entry(sample_entry)
        entry_mgr.update_entry(eid, {**sample_entry, "password": "NewS3cr3t!"})
        row = db_conn.execute(
            "SELECT encrypted_data FROM vault_entries WHERE id = ?", (eid,)
        ).fetchone()
        raw = bytes(row["encrypted_data"])
        assert b"NewS3cr3t!" not in raw


# ---------------------------------------------------------------------------
# Delete
# ---------------------------------------------------------------------------

class TestEntryDelete:
    @pytest.mark.fast
    def test_hard_delete(self, entry_mgr, sample_entry):
        eid = entry_mgr.create_entry(sample_entry)
        ok = entry_mgr.delete_entry(eid, soft_delete=False)
        assert ok is True
        assert entry_mgr.get_entry(eid) is None

    @pytest.mark.fast
    def test_soft_delete_removes_from_vault(self, entry_mgr, sample_entry):
        eid = entry_mgr.create_entry(sample_entry)
        ok = entry_mgr.delete_entry(eid, soft_delete=True)
        assert ok is True
        assert entry_mgr.get_entry(eid) is None

    @pytest.mark.fast
    def test_delete_nonexistent_returns_false(self, entry_mgr):
        ok = entry_mgr.delete_entry("00000000-0000-0000-0000-000000000000", soft_delete=False)
        assert ok is False

    @pytest.mark.fast
    def test_delete_emits_event(self, entry_mgr, sample_entry):
        eid = entry_mgr.create_entry(sample_entry)
        received = []
        entry_mgr.events.subscribe(EventType.ENTRY_DELETED, lambda d: received.append(d))
        entry_mgr.delete_entry(eid, soft_delete=False)
        assert len(received) == 1


# ---------------------------------------------------------------------------
# Search (via get_all + filter in test)
# ---------------------------------------------------------------------------

class TestEntrySearch:
    @pytest.mark.fast
    def test_get_all_and_filter_by_title(self, entry_mgr, sample_entry):
        entry_mgr.create_entry(sample_entry)
        entry_mgr.create_entry({**sample_entry, "title": "Bitbucket", "username": "bob"})
        all_e = entry_mgr.get_all_entries()
        results = [e for e in all_e if "git" in e["title"].lower()]
        assert any(e["title"] == "GitHub" for e in results)

    @pytest.mark.fast
    def test_search_by_username(self, entry_mgr, sample_entry):
        entry_mgr.create_entry(sample_entry)
        entry_mgr.create_entry({**sample_entry, "title": "Other", "username": "bob"})
        all_e = entry_mgr.get_all_entries()
        alice_entries = [e for e in all_e if e.get("username") == "alice"]
        assert len(alice_entries) == 1

    @pytest.mark.fast
    def test_get_all_decrypts_all_fields(self, entry_mgr, sample_entry):
        entry_mgr.create_entry(sample_entry)
        all_e = entry_mgr.get_all_entries()
        e = all_e[0]
        assert e["password"] == sample_entry["password"]
        assert e["url"] == sample_entry["url"]
