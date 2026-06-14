import pytest
import tempfile
import sqlite3
from unittest.mock import MagicMock


@pytest.fixture
def db_and_key():
    """Создает временную БД с таблицей vault_entries"""
    conn = sqlite3.connect(':memory:')
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE vault_entries (
            id TEXT PRIMARY KEY,
            encrypted_data BLOB NOT NULL,
            created_at TIMESTAMP,
            updated_at TIMESTAMP,
            tags TEXT
        )
    """)

    mock_key_manager = MagicMock()
    mock_key_manager.get_encryption_key.return_value = os.urandom(32)

    yield conn, mock_key_manager
    conn.close()


import os


class TestEntryManager:
    def test_create_entry(self, db_and_key):
        from src.core.vault.entry_manager import EntryManager
        from src.core.events import EventSystem

        conn, key_manager = db_and_key
        events = EventSystem()
        manager = EntryManager(conn, key_manager, events)

        entry_id = manager.create_entry({
            "title": "Test Entry",
            "username": "user@test.com",
            "password": "secret123"
        })

        assert entry_id is not None
        assert len(entry_id) > 0

    def test_get_entry(self, db_and_key):
        from src.core.vault.entry_manager import EntryManager
        from src.core.events import EventSystem

        conn, key_manager = db_and_key
        events = EventSystem()
        manager = EntryManager(conn, key_manager, events)

        original = {"title": "Test", "username": "user", "password": "pass"}
        entry_id = manager.create_entry(original)

        retrieved = manager.get_entry(entry_id)

        assert retrieved is not None
        assert retrieved["title"] == "Test"
        assert retrieved["username"] == "user"
        assert retrieved["password"] == "pass"

    def test_get_entry_not_found(self, db_and_key):
        from src.core.vault.entry_manager import EntryManager
        from src.core.events import EventSystem

        conn, key_manager = db_and_key
        events = EventSystem()
        manager = EntryManager(conn, key_manager, events)

        result = manager.get_entry("non-existent-id")
        assert result is None

    def test_get_all_entries(self, db_and_key):
        from src.core.vault.entry_manager import EntryManager
        from src.core.events import EventSystem

        conn, key_manager = db_and_key
        events = EventSystem()
        manager = EntryManager(conn, key_manager, events)

        for i in range(5):
            manager.create_entry({"title": f"Entry {i}", "password": f"pass{i}"})

        entries = manager.get_all_entries()
        assert len(entries) == 5

    def test_update_entry(self, db_and_key):
        from src.core.vault.entry_manager import EntryManager
        from src.core.events import EventSystem

        conn, key_manager = db_and_key
        events = EventSystem()
        manager = EntryManager(conn, key_manager, events)

        entry_id = manager.create_entry({"title": "Old", "password": "old"})
        result = manager.update_entry(entry_id, {"title": "New", "password": "new"})

        assert result is True

        updated = manager.get_entry(entry_id)
        assert updated["title"] == "New"
        assert updated["password"] == "new"

    def test_update_entry_not_found(self, db_and_key):
        from src.core.vault.entry_manager import EntryManager
        from src.core.events import EventSystem

        conn, key_manager = db_and_key
        events = EventSystem()
        manager = EntryManager(conn, key_manager, events)

        result = manager.update_entry("non-existent", {"title": "Test"})
        assert result is False

    def test_delete_entry(self, db_and_key):
        from src.core.vault.entry_manager import EntryManager
        from src.core.events import EventSystem

        conn, key_manager = db_and_key
        events = EventSystem()
        manager = EntryManager(conn, key_manager, events)

        entry_id = manager.create_entry({"title": "To Delete", "password": "secret"})
        result = manager.delete_entry(entry_id, soft_delete=False)

        assert result is True
        assert manager.get_entry(entry_id) is None