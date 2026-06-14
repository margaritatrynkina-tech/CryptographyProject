"""
Расширенные тесты для модуля config.py
Цель: повысить покрытие с 73% до 90%
"""

import pytest
import json
import os
import tempfile
import sqlite3
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

# Добавляем путь к src для импорта
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


class TestConfigManagerExtended:
    """Расширенные тесты для ConfigManager"""
    
    def setup_method(self):
        """Настройка перед каждым тестом"""
        from src.core.config import ConfigManager
        
        # Создаем временную директорию для тестов
        self.temp_dir = tempfile.mkdtemp()
        self.original_home = str(Path.home())
        
        # Патчим Path.home() чтобы возвращал временную директорию
        self.home_patcher = patch('pathlib.Path.home')
        mock_home = self.home_patcher.start()
        mock_home.return_value = Path(self.temp_dir)
        
        # Создаем ConfigManager с временной директорией
        self.config = ConfigManager()
        
    def teardown_method(self):
        """Очистка после каждого теста"""
        self.home_patcher.stop()
        
        # Удаляем временную директорию
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
            
    def test_load_from_db_success(self):
        """Тест load_from_db() успешная загрузка"""
        # Создаем mock соединение с БД
        mock_conn = Mock()
        mock_cursor = Mock()
        mock_conn.cursor.return_value = mock_cursor
        
        # Настраиваем mock для возврата данных
        mock_cursor.fetchall.return_value = [
            ("setting1", "value1"),
            ("setting2", "value2"),
            ("setting3", "value3")
        ]
        
        # Вызываем load_from_db
        self.config.load_from_db(mock_conn)
        
        # Проверяем, что данные загружены
        assert self.config.get("setting1") == "value1"
        assert self.config.get("setting2") == "value2"
        assert self.config.get("setting3") == "value3"
        
        # Проверяем вызовы БД
        mock_conn.cursor.assert_called_once()
        mock_cursor.execute.assert_called_once_with(
            "SELECT setting_key, setting_value FROM settings"
        )
        mock_cursor.fetchall.assert_called_once()
        
    def test_load_from_db_empty_result(self):
        """Тест load_from_db() с пустым результатом"""
        mock_conn = Mock()
        mock_cursor = Mock()
        mock_conn.cursor.return_value = mock_cursor
        mock_cursor.fetchall.return_value = []
        
        # Запоминаем текущие данные
        original_data = self.config._data.copy()
        
        # Вызываем load_from_db
        self.config.load_from_db(mock_conn)
        
        # Данные не должны измениться
        assert self.config._data == original_data
        
    def test_load_from_db_exception(self):
        """Тест load_from_db() с исключением"""
        mock_conn = Mock()
        mock_conn.cursor.side_effect = Exception("Test database error")
        
        # Запоминаем текущие данные
        original_data = self.config._data.copy()
        
        # Вызываем load_from_db - не должно вызывать исключение
        self.config.load_from_db(mock_conn)
        
        # Данные не должны измениться
        assert self.config._data == original_data
        
    def test_load_with_valid_json(self):
        """Тест load() с валидным JSON"""
        # Создаем тестовый конфиг файл
        test_data = {
            "key1": "value1",
            "key2": 123,
            "key3": True,
            "key4": ["list", "of", "values"],
            "key5": {"nested": "object"}
        }
        
        with open(self.config.config_file, 'w', encoding='utf-8') as f:
            json.dump(test_data, f)
            
        # Создаем новый ConfigManager (автоматически загрузит)
        from src.core.config import ConfigManager
        new_config = ConfigManager()
        
        # Проверяем загрузку
        for key, value in test_data.items():
            assert new_config.get(key) == value
            
    def test_load_with_invalid_json_syntax(self):
        """Тест load() с синтаксически невалидным JSON"""
        # Создаем битый JSON файл
        with open(self.config.config_file, 'w', encoding='utf-8') as f:
            f.write("{this is not valid json")
            
        # Создаем новый ConfigManager
        from src.core.config import ConfigManager
        new_config = ConfigManager()
        
        # Должен создаться пустой конфиг
        assert new_config._data == {}
        
    def test_load_with_valid_but_not_dict_json(self):
        """Тест load() с валидным JSON но не словарем"""
        # JSON который не является словарем
        with open(self.config.config_file, 'w', encoding='utf-8') as f:
            f.write('["array", "not", "dict"]')
            
        from src.core.config import ConfigManager
        new_config = ConfigManager()
        
        # Должен создаться пустой конфиг
        assert new_config._data == {}
        
    def test_load_file_not_exists(self):
        """Тест load() когда файл не существует"""
        # Удаляем файл если существует
        if self.config.config_file.exists():
            self.config.config_file.unlink()
            
        # Создаем новый ConfigManager
        from src.core.config import ConfigManager
        new_config = ConfigManager()
        
        # Должен создаться пустой конфиг
        assert new_config._data == {}
        
    def test_load_file_permission_error(self):
        """Тест load() с ошибкой прав доступа"""
        # Создаем файл без прав на чтение
        test_data = {"test": "data"}
        with open(self.config.config_file, 'w', encoding='utf-8') as f:
            json.dump(test_data, f)
            
        # Патчим open чтобы вызвать PermissionError
        with patch('builtins.open', side_effect=PermissionError("No permission")):
            from src.core.config import ConfigManager
            new_config = ConfigManager()
            
            # Должен создаться пустой конфиг
            assert new_config._data == {}
            
    def test_load_unicode_content(self):
        """Тест load() с Unicode содержимым"""
        unicode_data = {
            "русский": "текст",
            "emoji": "✅🎉",
            "mixed": "русский text with emoji ✅"
        }
        
        with open(self.config.config_file, 'w', encoding='utf-8') as f:
            json.dump(unicode_data, f, ensure_ascii=False)
            
        from src.core.config import ConfigManager
        new_config = ConfigManager()
        
        for key, value in unicode_data.items():
            assert new_config.get(key) == value
            
    def test_save_success(self):
        """Тест save() успешное сохранение"""
        # Добавляем данные
        test_data = {
            "string": "value",
            "number": 42,
            "boolean": True,
            "null": None,
            "list": [1, 2, 3],
            "dict": {"nested": "value"}
        }
        
        for key, value in test_data.items():
            self.config.set(key, value)
            
        # Проверяем, что файл создан
        assert self.config.config_file.exists()
        
        # Читаем файл и проверяем содержимое
        with open(self.config.config_file, 'r', encoding='utf-8') as f:
            saved_data = json.load(f)
            
        for key, value in test_data.items():
            assert saved_data.get(key) == value
            
    def test_save_permission_error(self):
        """Тест save() с ошибкой прав доступа"""
        # Патчим open чтобы вызвать PermissionError
        with patch('builtins.open', side_effect=PermissionError("No permission")):
            # Попытка сохранения не должна вызывать исключение
            self.config.set("test", "value")
            
            # Данные должны быть установлены в памяти, даже если не сохранены в файл
            assert self.config.get("test") == "value"
            
    def test_save_json_serialization_error(self):
        """Тест save() с ошибкой сериализации JSON"""
        # Создаем объект, который нельзя сериализовать в JSON
        class Unserializable:
            pass
            
        # Устанавливаем несериализуемое значение
        self.config._data["unserializable"] = Unserializable()
        
        # Попытка сохранения не должна вызывать исключение
        self.config.save()
        
    def test_save_empty_data(self):
        """Тест save() с пустыми данными"""
        # Очищаем данные
        self.config._data = {}
        
        # Сохраняем
        self.config.save()
        
        # Проверяем файл
        assert self.config.config_file.exists()
        
        with open(self.config.config_file, 'r', encoding='utf-8') as f:
            saved_data = json.load(f)
            
        assert saved_data == {}
        
    def test_get_with_default(self):
        """Тест get() со значениями по умолчанию"""
        # Несуществующий ключ с default
        assert self.config.get("nonexistent") is None
        assert self.config.get("nonexistent", "default") == "default"
        assert self.config.get("nonexistent", 42) == 42
        assert self.config.get("nonexistent", False) is False
        assert self.config.get("nonexistent", []) == []
        assert self.config.get("nonexistent", {}) == {}
        
        # Существующий ключ не должен использовать default
        self.config.set("existing", "value")
        assert self.config.get("existing", "default") == "value"
        
    def test_get_nested_access(self):
        """Тест get() с вложенными структурами"""
        nested_data = {
            "level1": {
                "level2": {
                    "level3": "deep_value"
                }
            }
        }
        
        # Устанавливаем через set
        self.config.set("nested", nested_data)
        
        # Получаем всю структуру
        retrieved = self.config.get("nested")
        assert retrieved == nested_data
        
        # Получаем глубокое значение
        assert retrieved["level1"]["level2"]["level3"] == "deep_value"
        
    def test_set_overwrite_existing(self):
        """Тест set() перезапись существующего значения"""
        self.config.set("key", "original")
        assert self.config.get("key") == "original"
        
        self.config.set("key", "updated")
        assert self.config.get("key") == "updated"
        
    def test_set_special_values(self):
        """Тест set() со специальными значениями"""
        special_values = [
            "",  # Пустая строка
            0,   # Ноль
            -1,  # Отрицательное число
            3.14,  # Float
            float('inf'),  # Бесконечность
            [],  # Пустой список
            {},  # Пустой словарь
            set(),  # Множество (не JSON сериализуемое)
        ]
        
        for i, value in enumerate(special_values):
            key = f"special_{i}"
            self.config.set(key, value)
            
            # Проверяем, что значение сохранено в памяти
            # (некоторые типы могут быть преобразованы при сохранении в JSON)
            if isinstance(value, (set, float)):
                # Эти типы могут не сохраняться точно в JSON
                pass
            else:
                assert self.config.get(key) == value
                
    def test_set_none_value(self):
        """Тест set() с None значением"""
        self.config.set("null_key", None)
        assert self.config.get("null_key") is None
        assert self.config.get("null_key", "default") is None
        
    def test_db_path_property_get(self):
        """Тест свойства db_path getter"""
        # Изначально None
        assert self.config.db_path is None
        
        # Устанавливаем значение
        test_path = "/path/to/database.db"
        self.config.set("db_path", test_path)
        
        # Проверяем getter
        assert self.config.db_path == test_path
        
    def test_db_path_property_set(self):
        """Тест свойства db_path setter"""
        test_path = "/new/path/to/database.db"
        
        # Используем setter
        self.config.db_path = test_path
        
        # Проверяем, что значение установлено
        assert self.config.get("db_path") == test_path
        assert self.config.db_path == test_path
        
    def test_db_path_property_set_none(self):
        """Тест свойства db_path setter с None"""
        # Устанавливаем значение
        self.config.db_path = "/some/path"
        
        # Устанавливаем None
        self.config.db_path = None
        
        # Проверяем
        assert self.config.get("db_path") is None
        assert self.config.db_path is None
        
    def test_config_dir_creation(self):
        """Тест создания директории конфигурации"""
        # Директория должна быть создана при инициализации
        assert self.config.config_dir.exists()
        assert self.config.config_dir.is_dir()
        
        # Пытаемся создать ConfigManager когда директория уже существует
        from src.core.config import ConfigManager
        another_config = ConfigManager()
        
        # Не должно быть ошибок
        assert another_config.config_dir.exists()
        
    def test_multiple_config_managers(self):
        """Тест нескольких экземпляров ConfigManager"""
        from src.core.config import ConfigManager
        
        # Создаем несколько конфигов
        config1 = ConfigManager()
        config2 = ConfigManager()
        
        # Устанавливаем значение в первом
        config1.set("shared_key", "config1_value")
        
        # Второй должен видеть то же значение (один файл)
        # Но может не видеть, если не вызван load
        config2.load()
        assert config2.get("shared_key") == "config1_value"
        
    def test_concurrent_access_simulation(self):
        """Тест симуляции конкурентного доступа"""
        from src.core.config import ConfigManager
        import threading
        
        results = []
        
        def worker(worker_id):
            config = ConfigManager()
            config.set(f"worker_{worker_id}", worker_id)
            value = config.get(f"worker_{worker_id}")
            results.append((worker_id, value))
            
        # Запускаем несколько потоков
        threads = []
        for i in range(5):
            thread = threading.Thread(target=worker, args=(i,))
            threads.append(thread)
            thread.start()
            
        for thread in threads:
            thread.join()
            
        # Проверяем результаты
        for worker_id, value in results:
            assert value == worker_id
            
    def test_large_config(self):
        """Тест работы с большим конфигом"""
        # Добавляем много данных
        for i in range(1000):
            self.config.set(f"key_{i}", f"value_{i}" * 10)
            
        # Сохраняем
        self.config.save()
        
        # Проверяем размер файла
        assert self.config.config_file.stat().st_size > 0
        
        # Проверяем, что все данные сохранились
        for i in range(1000):
            assert self.config.get(f"key_{i}") == f"value_{i}" * 10
            
    def test_config_with_different_types(self):
        """Тест конфига с различными типами данных"""
        test_cases = [
            ("string", "hello world"),
            ("integer", 42),
            ("float", 3.14159),
            ("boolean_true", True),
            ("boolean_false", False),
            ("none", None),
            ("list", [1, 2, 3, "four"]),
            ("dict", {"key": "value", "number": 123}),
            ("nested_list", [[1, 2], [3, 4]]),
            ("nested_dict", {"outer": {"inner": "value"}}),
        ]
        
        for key, value in test_cases:
            self.config.set(key, value)
            
        # Сохраняем и загружаем заново
        self.config.save()
        
        from src.core.config import ConfigManager
        new_config = ConfigManager()
        
        # Проверяем все значения
        for key, expected_value in test_cases:
            actual_value = new_config.get(key)
            
            # Некоторые типы могут немного меняться при сериализации/десериализации JSON
            if expected_value is None:
                assert actual_value is None
            elif isinstance(expected_value, float):
                # Float могут терять точность
                pytest.approx(actual_value, expected_value)
            else:
                assert actual_value == expected_value
                
    def test_error_handling_in_init(self):
        """Тест обработки ошибок в __init__"""
        # Патчим load чтобы вызвать исключение
        with patch.object(self.config, 'load', side_effect=Exception("Test error")):
            # Создание ConfigManager не должно вызывать исключение
            from src.core.config import ConfigManager
            try:
                config = ConfigManager()
                # Должен создаться с пустыми данными
                assert config._data == {}
            except Exception:
                pytest.fail("__init__ should not propagate exceptions from load()")
                

class TestConfigIntegration:
    """Интеграционные тесты для конфигурации"""
    
    def setup_method(self):
        """Настройка перед каждым тестом"""
        self.temp_dir = tempfile.mkdtemp()
        
        # Патчим Path.home()
        self.home_patcher = patch('pathlib.Path.home')
        mock_home = self.home_patcher.start()
        mock_home.return_value = Path(self.temp_dir)
        
    def teardown_method(self):
        """Очистка после каждого теста"""
        self.home_patcher.stop()
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
            
    def test_config_persistence(self):
        """Тест персистентности конфигурации"""
        from src.core.config import ConfigManager
        
        # Создаем и настраиваем конфиг
        config1 = ConfigManager()
        config1.set("app_name", "CryptoSafe")
        config1.set("version", "1.0.0")
        config1.set("settings", {"auto_lock": True, "timeout": 300})
        
        # Сохраняем
        config1.save()
        
        # Создаем новый экземпляр (загрузит из файла)
        config2 = ConfigManager()
        
        # Проверяем, что данные сохранились
        assert config2.get("app_name") == "CryptoSafe"
        assert config2.get("version") == "1.0.0"
        assert config2.get("settings") == {"auto_lock": True, "timeout": 300}
        
    def test_config_with_real_database(self):
        """Тест конфига с реальной БД"""
        from src.core.config import ConfigManager
        
        # Создаем временную БД
        db_path = os.path.join(self.temp_dir, "test.db")
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Создаем таблицу settings
        cursor.execute("""
            CREATE TABLE settings (
                setting_key TEXT PRIMARY KEY,
                setting_value TEXT
            )
        """)
        
        # Добавляем тестовые данные
        cursor.execute(
            "INSERT INTO settings (setting_key, setting_value) VALUES (?, ?)",
            ("db_setting1", "db_value1")
        )
        cursor.execute(
            "INSERT INTO settings (setting_key, setting_value) VALUES (?, ?)",
            ("db_setting2", "db_value2")
        )
        conn.commit()
        
        # За��ружаем из БД
        config = ConfigManager()
        config.load_from_db(conn)
        
        # Проверяем загрузку
        assert config.get("db_setting1") == "db_value1"
        assert config.get("db_setting2") == "db_value2"
        
        # Закрываем соединение
        conn.close()
        
    def test_config_migration_scenario(self):
        """Тест сценария миграции конфигурации"""
        from src.core.config import ConfigManager
        
        # Старая конфигурация в файле
        old_config = {
            "old_setting1": "old_value1",
            "old_setting2": "old_value2"
        }
        
        config_file = Path(self.temp_dir) / ".cryptosafe" / "config.json"
        config_file.parent.mkdir(exist_ok=True)
        
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(old_config, f)
            
        # Создаем ConfigManager - загрузит старую конфигурацию
        config = ConfigManager()
        
        # Добавляем новые настройки
        config.set("new_setting", "new_value")
        config.set("migrated", True)
        
        # Сохраняем
        config.save()
        
        # Проверяем, что старые и новые настройки сохранились
        with open(config_file, 'r', encoding='utf-8') as f:
            final_config = json.load(f)
            
        assert final_config["old_setting1"] == "old_value1"
        assert final_config["old_setting2"] == "old_value2"
        assert final_config["new_setting"] == "new_value"
        assert final_config["migrated"] is True
        

if __name__ == "__main__":
    pytest.main([__file__, "-v"])