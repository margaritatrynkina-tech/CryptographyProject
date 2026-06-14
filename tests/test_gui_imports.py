"""
Тесты для импорта GUI модулей.
Эти тесты проверяют, что все GUI модули могут быть импортированы корректно.
"""

import pytest
import sys


def test_import_main_window():
    """Тест импорта MainWindow."""
    try:
        from src.gui.main_window import MainWindow
        assert MainWindow is not None
    except ImportError as e:
        pytest.fail(f"Не удалось импортировать MainWindow: {e}")


def test_import_export_dialog():
    """Тест импорта ExportDialog."""
    try:
        from src.gui.dialogs.export_dialog import ExportDialog
        assert ExportDialog is not None
    except ImportError as e:
        pytest.fail(f"Не удалось импортировать ExportDialog: {e}")


def test_import_import_dialog():
    """Тест импорта ImportDialog."""
    try:
        from src.gui.dialogs.import_dialog import ImportDialog
        assert ImportDialog is not None
    except ImportError as e:
        pytest.fail(f"Не удалось импортировать ImportDialog: {e}")


def test_import_sharing_dialog():
    """Тест импорта SharingDialog."""
    try:
        from src.gui.dialogs.sharing_dialog import SharingDialog
        assert SharingDialog is not None
    except ImportError as e:
        pytest.fail(f"Не удалось импортировать SharingDialog: {e}")


def test_import_audit_viewer_window():
    """Тест импорта AuditViewerWindow."""
    try:
        from src.gui.widgets.audit_viewer import AuditViewerWindow
        assert AuditViewerWindow is not None
    except ImportError as e:
        pytest.fail(f"Не удалось импортировать AuditViewerWindow: {e}")


def test_import_clipboard_preview_panel():
    """Тест импорта ClipboardPreviewPanel."""
    try:
        from src.gui.widgets.clipboard_preview import ClipboardPreviewPanel
        assert ClipboardPreviewPanel is not None
    except ImportError as e:
        pytest.fail(f"Не удалось импортировать ClipboardPreviewPanel: {e}")


def test_import_password_entry():
    """Тест импорта PasswordEntry."""
    try:
        from src.gui.widgets.password_entry import PasswordEntry
        assert PasswordEntry is not None
    except ImportError as e:
        pytest.fail(f"Не удалось импортировать PasswordEntry: {e}")


def test_import_toast_manager():
    """Тест импорта ToastManager."""
    try:
        from src.gui.widgets.toast import ToastManager
        assert ToastManager is not None
    except ImportError as e:
        pytest.fail(f"Не удалось импортировать ToastManager: {e}")


def test_import_system_tray():
    """Тест импорта SystemTray."""
    try:
        from src.gui.system_tray import SystemTray
        assert SystemTray is not None
    except ImportError as e:
        pytest.fail(f"Не удалось импортировать SystemTray: {e}")


def test_all_gui_modules_importable():
    """Комплексный тест импорта всех GUI модулей."""
    modules_to_test = [
        ('src.gui.main_window', 'MainWindow'),
        ('src.gui.dialogs.export_dialog', 'ExportDialog'),
        ('src.gui.dialogs.import_dialog', 'ImportDialog'),
        ('src.gui.dialogs.sharing_dialog', 'SharingDialog'),
        ('src.gui.widgets.audit_viewer', 'AuditViewerWindow'),
        ('src.gui.widgets.clipboard_preview', 'ClipboardPreviewPanel'),
        ('src.gui.widgets.password_entry', 'PasswordEntry'),
        ('src.gui.widgets.toast', 'ToastManager'),
        ('src.gui.system_tray', 'SystemTray'),
    ]
    
    failed_imports = []
    
    for module_path, class_name in modules_to_test:
        try:
            exec(f"from {module_path} import {class_name}")
        except ImportError as e:
            failed_imports.append(f"{class_name}: {e}")
    
    if failed_imports:
        pytest.fail(f"Не удалось импортировать следующие модули:\n" + "\n".join(failed_imports))


if __name__ == "__main__":
    # Запуск тестов напрямую для отладки
    import unittest
    
    class TestGUI(unittest.TestCase):
        def test_imports(self):
            test_import_main_window()
            test_import_export_dialog()
            test_import_import_dialog()
            test_import_sharing_dialog()
            test_import_audit_viewer_window()
            test_import_clipboard_preview_panel()
            test_import_password_entry()
            test_import_toast_manager()
            test_import_system_tray()
    
    unittest.main()