import pytest
import tempfile
from pathlib import Path
from unittest.mock import MagicMock


@pytest.fixture
def mock_entry_manager():
    manager = MagicMock()
    manager.get_all_entries.return_value = []
    manager.create_entry.return_value = "new_id"
    return manager


def test_import_csv_success(mock_entry_manager):
    from src.core.import_export.importer import VaultImporter

    importer = VaultImporter(mock_entry_manager, None, None)

    # Создаём тестовый CSV файл
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as tmp:
        tmp.write('title,username,password,url,notes\n')
        tmp.write('Test,user,pass,https://test.com,\n')
        tmp_path = Path(tmp.name)

    result = importer.import_csv(tmp_path, conflict_strategy="skip")

    assert result.total_entries == 1
    assert result.successful_imports == 1


def test_import_duplicate_skip(mock_entry_manager):
    from src.core.import_export.importer import VaultImporter

    # Настраиваем существующую запись
    mock_entry_manager.get_all_entries.return_value = [
        {"id": "1", "title": "Test", "username": "user"}
    ]

    importer = VaultImporter(mock_entry_manager, None, None)

    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as tmp:
        tmp.write('title,username,password,url,notes\n')
        tmp.write('Test,user,newpass,https://test.com,\n')
        tmp_path = Path(tmp.name)

    result = importer.import_csv(tmp_path, conflict_strategy="skip")

    assert result.conflict_count > 0