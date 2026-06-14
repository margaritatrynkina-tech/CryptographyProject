import pytest
import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch


@pytest.fixture
def mock_entry_manager():
    manager = MagicMock()
    manager.get_all_entries.return_value = [
        {"id": "1", "title": "Test", "username": "user", "password": "pass", "url": "https://test.com", "notes": ""}
    ]
    return manager


@pytest.fixture
def mock_audit_logger():
    return MagicMock()


def test_export_to_csv(mock_entry_manager, mock_audit_logger):
    from src.core.import_export.exporter import VaultExporter

    exporter = VaultExporter(mock_entry_manager, None, mock_audit_logger)

    with tempfile.NamedTemporaryFile(suffix='.csv', delete=False) as tmp:
        result = exporter.export_vault(
            entry_ids=None,
            master_password="test_master_pass",
            export_password="",
            public_key=None,
            format="csv",
            file_path=Path(tmp.name)
        )

    assert result.entry_count == 1
    assert Path(result.file_path).exists()


def test_export_to_json_with_master_password(mock_entry_manager, mock_audit_logger):
    from src.core.import_export.exporter import VaultExporter

    exporter = VaultExporter(mock_entry_manager, None, mock_audit_logger)

    with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as tmp:
        result = exporter.export_vault(
            entry_ids=None,
            master_password="test_master_pass",
            export_password="export_password123",
            public_key=None,
            format="json",
            file_path=Path(tmp.name)
        )

    assert result.entry_count == 1
    # Проверяем, что файл создан и содержит данные
    with open(result.file_path) as f:
        data = json.load(f)
        assert "encryption" in data