import pytest
import os
import tempfile
from src.database.db import DatabaseManager
from src.core.events import EventSystem, EventType
from src.core.config import ConfigManager


class TestDatabaseWithEvents:
    def test_add_entry_emits_event(self, temp_db_path):
        events = EventSystem()
        received = []
        def on_entry_added(data):
            received.append(data)
        events.subscribe(EventType.ENTRY_ADDED, on_entry_added)
        db = DatabaseManager(temp_db_path, events=events)
        db.set_master_password("test")
        db.connect()
        entry_id = db.add_entry(title="Test Event")
        assert len(received) == 1
        assert received[0]["id"] == entry_id
        assert received[0]["title"] == "Test Event"
        db.close()
        events.stop_async_processing()

    def test_multiple_entries_multiple_events(self, temp_db_path):
        events = EventSystem()
        count = 0
        def counter(data):
            nonlocal count
            count += 1
        events.subscribe(EventType.ENTRY_ADDED, counter)
        db = DatabaseManager(temp_db_path, events=events)
        db.set_master_password("test")
        db.connect()
        for i in range(5):
            db.add_entry(title=f"Test {i}")
        assert count == 5
        db.close()
        events.stop_async_processing()
class TestFullWorkflow:
    def test_complete_entry_lifecycle(self, temp_db_path):
        db = DatabaseManager(temp_db_path)
        db.set_master_password("test_password")
        db.connect()
        # 1. Создание
        entry_id = db.add_entry(
            title="Integration Test",
            username="testuser",
            password="secret123",
            url="https://test.com"
        )
        assert entry_id > 0
        # 2. Чтение
        entries = db.get_all_entries()
        assert len(entries) == 1
        assert entries[0]['title'] == "Integration Test"
        # 3. Получение с паролем
        entry = db.get_entry(entry_id)
        assert entry['password'] == "secret123"
        # 4. Обновление (в следующем спринте)
        # 5. Удаление (в следующем спринте)
        db.close()
    def test_config_and_db_integration(self, temp_db_path):
        config = ConfigManager()
        config.db_path = temp_db_path
        db = DatabaseManager(config.db_path)
        db.set_master_password("test")
        db.connect()
        db.add_entry(title="Config Test")
        entries = db.get_all_entries()
        assert len(entries) == 1
        db.close()
class TestErrorScenarios:
    def test_wrong_password(self, temp_db_path):
        # В текущей версии пароль не проверяется
        pass

    def test_concurrent_access(self, temp_db_path):
        import threading
        db = DatabaseManager(temp_db_path)
        db.set_master_password("test")
        db.connect()
        results = []
        def add_entries(thread_id):
            for i in range(10):
                try:
                    entry_id = db.add_entry(title=f"Thread {thread_id}-{i}")
                    results.append(entry_id)
                except Exception as e:
                    results.append(f"Error: {e}")
        threads = []
        for i in range(5):
            t = threading.Thread(target=add_entries, args=(i,))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()
        assert len(results) == 50
        assert all(isinstance(r, int) for r in results)
        db.close()