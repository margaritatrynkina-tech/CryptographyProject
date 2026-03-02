import sys
import os
import pytest
import sqlite3
# путь к src
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from database.db import DatabaseManager
class TestDatabaseConnection:
    def test_connect_creates_file(self, temp_db_path)
        assert not os.path.exists(temp_db_path)
        db = DatabaseManager(temp_db_path)
        db.connect()
        assert os.path.exists(temp_db_path)
        db.close()
    def test_connect_creates_tables(self, db_manager):
        cursor = db_manager._conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]

        expected_tables = ['vault_entries', 'audit_log', 'settings', 'key_store']
        for table in expected_tables:
            assert table in tables
    def test_context_manager(self, temp_db_path):
        with DatabaseManager(temp_db_path) as db:
            db.set_master_password("test")
            db.add_entry(title="Context Test")
            assert db._conn is not None
        # После выхода соединение должно быть закрыто
        assert db._conn is None

    def test_reconnect_after_close(self, db_manager):
        db_manager.close()
        assert db_manager._conn is None
        db_manager.connect()
        assert db_manager._conn is not None
class TestVaultEntries:
    def test_add_entry(self, db_manager, sample_entry_data):
        entry_id = db_manager.add_entry(**sample_entry_data)
        assert entry_id > 0
        entries = db_manager.get_all_entries()
        assert len(entries) == 1
        assert entries[0]['title'] == sample_entry_data['title']
        assert entries[0]['username'] == sample_entry_data['username']
    def test_add_entry_minimal(self, db_manager):
        entry_id = db_manager.add_entry(title="Minimal Test")
        assert entry_id > 0
        entries = db_manager.get_all_entries()
        assert len(entries) == 1
        assert entries[0]['title'] == "Minimal Test"
        assert entries[0]['username'] == ""
    def test_get_entry_with_password(self, db_manager, sample_entry_data):
        entry_id = db_manager.add_entry(**sample_entry_data)
        entry = db_manager.get_entry(entry_id)
        assert entry is not None
        assert entry['password'] == sample_entry_data['password']
        assert entry['title'] == sample_entry_data['title']
    def test_get_nonexistent_entry(self, db_manager):
        entry = db_manager.get_entry(999)
        assert entry is None
    def test_multiple_entries(self, db_manager):
        for i in range(5):
            db_manager.add_entry(title=f"Test {i}", username=f"user{i}")
        entries = db_manager.get_all_entries()
        assert len(entries) == 5
class TestSettings:
        def test_set_setting(self, db_manager):
        """Тест: установка настройки"""
        db_manager.set_setting("theme", "dark")
        value = db_manager.get_setting("theme")
        assert value == "dark"
    def test_set_multiple_settings(self, db_manager):
        settings = {
            "theme": "dark",
            "language": "ru",
            "timeout": 300,
            "auto_lock": True
        }
        for key, value in settings.items():
            db_manager.set_setting(key, value)
        for key, value in settings.items():
            assert db_manager.get_setting(key) == str(value)
    def test_get_default_value(self, db_manager):
        value = db_manager.get_setting("nonexistent", "default")
        assert value == "default"
    def test_update_setting(self, db_manager):
       db_manager.set_setting("theme", "dark")
        db_manager.set_setting("theme", "light")
        assert db_manager.get_setting("theme") == "light"
class TestErrorHandling:
        def test_encrypt_without_master_key(self, empty_db_manager):
        with pytest.raises(ValueError, match="Мастер-пароль не установлен"):
            empty_db_manager.encrypt_field("test")
    def test_decrypt_without_master_key(self, empty_db_manager):
        with pytest.raises(ValueError, match="Мастер-пароль не установлен"):
            empty_db_manager.decrypt_field(b"test")
    def test_operation_after_close(self, db_manager):
        db_manager.close()
        # Должно быть исключение, но мы его перехватываем в тесте
        with pytest.raises(Exception):
            db_manager.get_all_entries()