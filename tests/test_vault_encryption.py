from src.core.config import ConfigManager
from src.core.key_manager import KeyManager
from src.core.events import EventSystem
from src.core.vault.entry_manager import EntryManager
from src.database.db import DatabaseManager
from src.core.vault.password_generator import PasswordGenerator
def test_entry_manager_create_and_get(temp_db_path):
    config = ConfigManager()
    db = DatabaseManager(temp_db_path)
    db.connect()
    try:
        km = KeyManager(config, db.connection)
        km.setup_master_password("Test123!")
        events = EventSystem()
        manager = EntryManager(db.connection, km, events)
        data = {
            "title": "Test",
            "username": "user@example.com",
            "password": "secret",
            "url": "https://example.com",
            "notes": "note",
            "tags": "work"
        }
        entry_id = manager.create_entry(data)
        entry = manager.get_entry(entry_id)
        assert entry is not None
        assert entry["title"] == "Test"
        assert entry["username"] == "user@example.com"
        assert entry["password"] == "secret"
        assert entry["url"] == "https://example.com"
        assert entry["notes"] == "note"
    finally:
        db.close()
def test_entry_manager_get_all_entries(temp_db_path):
    config = ConfigManager()
    db = DatabaseManager(temp_db_path)
    db.connect()
    try:
        km = KeyManager(config, db.connection)
        km.setup_master_password("Test123!")
        events = EventSystem()
        manager = EntryManager(db.connection, km, events)

        for i in range(3):
            manager.create_entry({
                "title": f"Test {i}",
                "username": f"user{i}@example.com",
                "password": f"secret{i}",
                "url": "https://example.com",
                "notes": "",
                "tags": "test"
            })
        entries = manager.get_all_entries()
        assert len(entries) == 3
        assert entries[0]["title"].startswith("Test")
    finally:
        db.close()
def test_entry_manager_update_entry(temp_db_path):
    config = ConfigManager()
    db = DatabaseManager(temp_db_path)
    db.connect()
    try:
        km = KeyManager(config, db.connection)
        km.setup_master_password("Test123!")
        events = EventSystem()
        manager = EntryManager(db.connection, km, events)
        entry_id = manager.create_entry({
            "title": "Old title",
            "username": "old@example.com",
            "password": "oldpass",
            "url": "https://old.com",
            "notes": "",
            "tags": "old"
        })
        updated = manager.update_entry(entry_id, {
            "title": "New title",
            "username": "new@example.com",
            "password": "newpass",
            "url": "https://new.com",
            "notes": "updated",
            "tags": "new"
        })
        entry = manager.get_entry(entry_id)
        assert updated is True
        assert entry["title"] == "New title"
        assert entry["username"] == "new@example.com"
        assert entry["password"] == "newpass"
        assert entry["tags"] == "new"
    finally:
        db.close()
def test_entry_manager_delete_entry(temp_db_path):
    config = ConfigManager()
    db = DatabaseManager(temp_db_path)
    db.connect()
    try:
        km = KeyManager(config, db.connection)
        km.setup_master_password("Test123!")
        events = EventSystem()
        manager = EntryManager(db.connection, km, events)
        entry_id = manager.create_entry({
            "title": "To delete",
            "username": "delete@example.com",
            "password": "secret",
            "url": "https://example.com",
            "notes": "",
            "tags": "temp"
        })
        deleted = manager.delete_entry(entry_id, soft_delete=False)
        entry = manager.get_entry(entry_id)
        assert deleted is True
        assert entry is None
    finally:
        db.close()
def test_password_generator_length():
    gen = PasswordGenerator()
    password = gen.generate(length=16)
    assert len(password) == 16
def test_password_generator_contains_required_sets():
    gen = PasswordGenerator()
    password = gen.generate(length=16, uppercase=True, lowercase=True, digits=True, symbols=True)
    assert any(c.isupper() for c in password)
    assert any(c.islower() for c in password)
    assert any(c.isdigit() for c in password)
    assert any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
def test_password_generator_avoids_ambiguous_chars():
    gen = PasswordGenerator()
    password = gen.generate(length=64)
    for ch in "lI10O":
        assert ch not in password