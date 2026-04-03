import sys
import os
import pytest
import tempfile
import shutil
from pathlib import Path
#путь к src в sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from src.database.db import DatabaseManager
from src.core.config import ConfigManager
from src.core.events import EventSystem
@pytest.fixture
def temp_db_path():
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        db_path = f.name
    yield db_path
    # Очистка после теста
    if os.path.exists(db_path):
        os.unlink(db_path)
@pytest.fixture
def db_manager(temp_db_path):
    manager = DatabaseManager(temp_db_path)
    manager.set_master_password("test_password_123")
    manager.connect()
    yield manager
    manager.close()
@pytest.fixture
def empty_db_manager(temp_db_path):
    manager = DatabaseManager(temp_db_path)
    manager.connect()
    yield manager
    manager.close()
@pytest.fixture
def config_manager():
    # Создаем временную папку для тестов
    test_config_dir = Path(tempfile.gettempdir()) / "cryptosafe_test_config"
    test_config_dir.mkdir(exist_ok=True)
    # Создаем тестовую конфигурацию
    config = ConfigManager()
    config.config_dir = test_config_dir
    config.config_file = test_config_dir / "config.json"
    yield config
    # Очистка
    if test_config_dir.exists():
        shutil.rmtree(test_config_dir)
@pytest.fixture
def event_system():
    es = EventSystem()
    es.start_async_processing()
    yield es
    es.stop_async_processing()
@pytest.fixture
def sample_entry_data():
    return {
        "title": "Test Account",
        "username": "testuser",
        "password": "SecurePass123!",
        "url": "https://example.com",
        "notes": "This is a test entry",
        "tags": "test,important"
    }