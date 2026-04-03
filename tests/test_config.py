import pytest
import json
import os
from src.core.config import ConfigManager
class TestConfigManager:
    def test_set_get(self, config_manager):
        config_manager.set("test_key", "test_value")
        assert config_manager.get("test_key") == "test_value"
        config_manager.set("number", 42)
        assert config_manager.get("number") == 42
        config_manager.set("boolean", True)
        assert config_manager.get("boolean") is True

    def test_default_values(self, config_manager):
        assert config_manager.get("nonexistent") is None
        assert config_manager.get("nonexistent", "default") == "default"

    def test_db_path_property(self, config_manager):
        assert config_manager.db_path is None
        test_path = "C:/test/database.db"
        config_manager.db_path = test_path
        assert config_manager.db_path == test_path
        assert config_manager.get("db_path") == test_path

    def test_save_load(self, config_manager):
        config_manager.set("key1", "value1")
        config_manager.set("key2", 123)
        config_manager.save()

        new_config = ConfigManager()
        new_config.config_dir = config_manager.config_dir
        new_config.config_file = config_manager.config_file
        new_config.load()
        assert new_config.get("key1") == "value1"
        assert new_config.get("key2") == 123

    def test_config_file_creation(self, config_manager):
        config_manager.set("test", "value")
        config_manager.save()
        assert os.path.exists(config_manager.config_file)
        with open(config_manager.config_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            assert data["test"] == "value"
    def test_load_nonexistent_file(self, config_manager):
        if config_manager.config_file.exists():
            os.unlink(config_manager.config_file)
        config_manager.load()
        assert config_manager._data == {}
    def test_corrupted_config(self, config_manager):
        with open(config_manager.config_file, 'w') as f:
            f.write("{this is not json")
        config_manager.load()
        assert config_manager._data == {}
    def test_multiple_updates(self, config_manager):
        for i in range(100):
            config_manager.set(f"key{i}", f"value{i}")
        for i in range(100):
            assert config_manager.get(f"key{i}") == f"value{i}"