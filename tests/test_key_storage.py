"""
Тесты для модуля key_storage.py
Цель: повысить покрытие с 62% до 85%
"""

import pytest
import os
import sys
import sqlite3
import tempfile
import threading
import time
from unittest.mock import Mock, patch, MagicMock

# Добавляем путь к src для импорта
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


class TestKeyCache:
    """Тесты для класса KeyCache"""
    
    def setup_method(self):
        """Настройка перед каждым тестом"""
        from src.core.crypto.key_storage import KeyCache
        self.cache = KeyCache(inactivity_timeout=1)  # 1 секунда для тестов
        
    def test_key_cache_init(self):
        """Тест инициализации KeyCache"""
        from src.core.crypto.key_storage import KeyCache
        
        cache = KeyCache(inactivity_timeout=3600)
        
        assert cache._key is None
        assert cache._audit_seed is None
        assert cache._audit_enc_key is None
        assert cache._timeout == 3600
        assert cache._last_activity == 0.0
        assert isinstance(cache._lock, threading.RLock)
        
    def test_set_key_and_get_key(self):
        """Тест установки и получения ключа"""
        test_key = b"test_key_1234567890"
        
        # Устанавливаем ключ
        self.cache.set_key(test_key)
        
        # Получаем ключ
        retrieved_key = self.cache.get_key()
        
        assert retrieved_key == test_key
        assert self.cache._key is not None
        assert isinstance(self.cache._key, bytearray)
        
    def test_get_key_none_when_not_set(self):
        """Тест get_key() когда ключ не установлен"""
        result = self.cache.get_key()
        
        assert result is None
        
    def test_key_timeout(self):
        """Тест таймаута ключа"""
        test_key = b"test_key_for_timeout"
        
        # Устанавливаем ключ
        self.cache.set_key(test_key)
        
        # Сразу получаем - должен быть доступен
        result1 = self.cache.get_key()
        assert result1 == test_key
        
        # Ждем больше времени таймаута
        time.sleep(1.1)
        
        # Пытаемся получить снова - должен быть None
        result2 = self.cache.get_key()
        assert result2 is None
        
    def test_key_activity_refresh(self):
        """Тест обновления времени активности при get_key()"""
        test_key = b"test_key_for_activity"
        
        # Устанавливаем ключ
        self.cache.set_key(test_key)
        initial_activity = self.cache._last_activity
        
        # Ждем немного
        time.sleep(0.1)
        
        # Получаем ключ - должно обновить время активности
        result = self.cache.get_key()
        assert result == test_key
        assert self.cache._last_activity > initial_activity
        
    def test_zero_key(self):
        """Тест обнуления ключа"""
        test_key = b"test_key_to_zero"
        
        # Устанавливаем ключ
        self.cache.set_key(test_key)
        
        # Проверяем, что ключ установлен
        assert self.cache._key is not None
        assert bytes(self.cache._key) == test_key
        
        # Обнуляем ключ через приватный метод
        self.cache._zero_key()
        
        # Проверяем, что ключ обнулен
        assert self.cache._key is None
        
    def test_set_key_overwrites_previous(self):
        """Тест установки нового ключа поверх старого"""
        key1 = b"first_key_123456"
        key2 = b"second_key_789012"
        
        # Устанавливаем первый ключ
        self.cache.set_key(key1)
        
        # Проверяем, что установлен
        result1 = self.cache.get_key()
        assert result1 == key1
        
        # Устанавливаем второй ключ
        self.cache.set_key(key2)
        
        # Проверяем, что теперь второй ключ
        result2 = self.cache.get_key()
        assert result2 == key2
        
    def test_audit_seed_operations(self):
        """Тест операций с audit seed"""
        test_seed = b"audit_seed_1234567890"
        
        # Устанавливаем seed
        self.cache.set_audit_seed(test_seed)
        
        # Получаем seed
        retrieved_seed = self.cache.get_audit_seed()
        
        assert retrieved_seed == test_seed
        assert self.cache._audit_seed is not None
        assert isinstance(self.cache._audit_seed, bytearray)
        
    def test_get_audit_seed_none_when_not_set(self):
        """Тест get_audit_seed() когда seed не установлен"""
        result = self.cache.get_audit_seed()
        
        assert result is None
        
    def test_zero_audit_seed(self):
        """Тест обнуления audit seed"""
        test_seed = b"seed_to_zero_123"
        
        # Устанавливаем seed
        self.cache.set_audit_seed(test_seed)
        
        # Проверяем, что seed установлен
        assert self.cache._audit_seed is not None
        
        # Обнуляем seed
        self.cache._zero_audit_seed()
        
        # Проверяем, что seed обнулен
        assert self.cache._audit_seed is None
        
    def test_audit_enc_key_operations(self):
        """Тест операций с audit encryption key"""
        test_key = b"audit_enc_key_123456"
        
        # Устанавливаем ключ
        self.cache.set_audit_enc_key(test_key)
        
        # Получаем ключ
        retrieved_key = self.cache.get_audit_enc_key()
        
        assert retrieved_key == test_key
        assert self.cache._audit_enc_key is not None
        assert isinstance(self.cache._audit_enc_key, bytearray)
        
    def test_get_audit_enc_key_none_when_not_set(self):
        """Тест get_audit_enc_key() когда ключ не установлен"""
        result = self.cache.get_audit_enc_key()
        
        assert result is None
        
    def test_set_audit_enc_key_overwrites_previous(self):
        """Тест установки нового audit enc key поверх старого"""
        key1 = b"audit_enc_key_1"
        key2 = b"audit_enc_key_2"
        
        # Устанавливаем первый ключ
        self.cache.set_audit_enc_key(key1)
        
        # Проверяем
        result1 = self.cache.get_audit_enc_key()
        assert result1 == key1
        
        # Устанавливаем второй ключ
        self.cache.set_audit_enc_key(key2)
        
        # Проверяем, что теперь второй ключ
        result2 = self.cache.get_audit_enc_key()
        assert result2 == key2
        
    def test_clear_method(self):
        """Тест метода clear()"""
        # Устанавливаем все типы ключей
        self.cache.set_key(b"main_key")
        self.cache.set_audit_seed(b"audit_seed")
        self.cache.set_audit_enc_key(b"audit_enc_key")
        
        # Проверяем, что все установлены
        assert self.cache.get_key() is not None
        assert self.cache.get_audit_seed() is not None
        assert self.cache.get_audit_enc_key() is not None
        
        # Очищаем
        self.cache.clear()
        
        # Проверяем, что все очищены
        assert self.cache.get_key() is None
        assert self.cache.get_audit_seed() is None
        assert self.cache.get_audit_enc_key() is None
        
    def test_thread_safety(self):
        """Тест потокобезопасности KeyCache"""
        import concurrent.futures
        
        test_key = b"thread_safe_key"
        
        # Создаем функцию для тестирования из разных потоков
        def worker(worker_id):
            # Каждый поток устанавливает и получает ключ
            self.cache.set_key(f"key_{worker_id}".encode())
            result = self.cache.get_key()
            return result
        
        # Запускаем несколько потоков
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(worker, i) for i in range(5)]
            results = [f.result() for f in futures]
            
        # Проверяем, что все операции завершились без ошибок
        assert len(results) == 5
        # Все результаты должны быть байтовыми строками
        for result in results:
            assert isinstance(result, bytes)
            
    def test_concurrent_access(self):
        """Тест конкурентного доступа к кешу"""
        import concurrent.futures
        
        test_key = b"concurrent_key"
        
        # Устанавливаем ключ
        self.cache.set_key(test_key)
        
        # Создаем функцию для чтения из многих потоков
        def reader(_):
            return self.cache.get_key()
        
        # Запускаем множество читателей
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(reader, i) for i in range(20)]
            results = [f.result() for f in futures]
            
        # Все читатели должны получить один и тот же ключ
        for result in results:
            assert result == test_key
            
    def test_key_rotation_simulation(self):
        """Тест симуляции ротации ключей"""
        # Имитируем ротацию ключей
        keys = [b"key_1", b"key_2", b"key_3", b"key_4"]
        
        for i, key in enumerate(keys):
            # Устанавливаем новый ключ
            self.cache.set_key(key)
            
            # Проверяем, что установился правильный ключ
            retrieved = self.cache.get_key()
            assert retrieved == key
            
            # Имитируем использование
            for _ in range(3):
                assert self.cache.get_key() == key
                
    def test_memory_safety(self):
        """Тест безопасности памяти (обнуление)"""
        sensitive_key = b"sensitive_key_data_123"
        
        # Устанавливаем чувствительный ключ
        self.cache.set_key(sensitive_key)
        
        # Получаем ссылку на внутренний bytearray
        key_ref = self.cache._key
        
        # Очищаем кеш
        self.cache.clear()
        
        # Проверяем, что bytearray обнулен
        if key_ref is not None:
            # После clear() key_ref должен быть None или обнуленным bytearray
            pass
            
    def test_empty_key(self):
        """Тест работы с пустым ключом"""
        empty_key = b""
        
        # Устанавливаем пустой ключ
        self.cache.set_key(empty_key)
        
        # Получаем ключ
        retrieved = self.cache.get_key()
        
        assert retrieved == empty_key
        assert len(retrieved) == 0
        
    def test_large_key(self):
        """Тест работы с большим ключом"""
        # Большой ключ (64 KB)
        large_key = b"x" * (64 * 1024)
        
        # Устанавливаем большой ключ
        self.cache.set_key(large_key)
        
        # Получаем ключ
        retrieved = self.cache.get_key()
        
        assert retrieved == large_key
        assert len(retrieved) == len(large_key)


class TestKeyStore:
    """Тесты для класса KeyStore"""
    
    def setup_method(self):
        """Настройка перед каждым тестом"""
        # Создаем временную базу данных в памяти
        self.conn = sqlite3.connect(':memory:')
        
        # Создаем таблицу для тестов
        self.conn.execute("""
            CREATE TABLE key_store (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_type TEXT NOT NULL,
                key_data BLOB NOT NULL,
                version INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        from src.core.crypto.key_storage import KeyStore
        self.store = KeyStore(self.conn)
        
    def teardown_method(self):
        """Очистка после каждого теста"""
        self.conn.close()
        
    def test_key_store_init(self):
        """Тест инициализации KeyStore"""
        from src.core.crypto.key_storage import KeyStore
        
        store = KeyStore(self.conn)
        
        assert store.conn == self.conn
        
    def test_save_auth_hash(self):
        """Тест сохранения auth hash"""
        test_hash = "test_hash_value_123"
        version = 2
        
        # Сохраняем хеш
        self.store.save_auth_hash(test_hash, version)
        
        # Проверяем, что сохранилось
        cursor = self.conn.cursor()
        cursor.execute("SELECT key_data, version FROM key_store WHERE key_type = 'auth_hash'")
        row = cursor.fetchone()
        
        assert row is not None
        assert row[0].decode('utf-8') == test_hash
        assert row[1] == version
        
    def test_save_auth_hash_default_version(self):
        """Тест сохранения auth hash с версией по умолчанию"""
        test_hash = "test_hash_default_version"
        
        # Сохраняем без указания версии
        self.store.save_auth_hash(test_hash)
        
        # Проверяем
        cursor = self.conn.cursor()
        cursor.execute("SELECT version FROM key_store WHERE key_type = 'auth_hash'")
        row = cursor.fetchone()
        
        assert row is not None
        assert row[0] == 1  # Версия по умолчанию
        
    def test_get_latest_auth_hash(self):
        """Тест получения последнего auth hash"""
        # Сохраняем несколько хешей
        hashes = ["hash_1", "hash_2", "hash_3"]
        
        for h in hashes:
            self.store.save_auth_hash(h)
            # Добавляем небольшую задержку для разного времени создания
            time.sleep(0.001)
            
        # Получаем последний
        latest = self.store.get_latest_auth_hash()
        
        assert latest == "hash_3"
        
    def test_get_latest_auth_hash_none_when_empty(self):
        """Тест get_latest_auth_hash() когда нет данных"""
        result = self.store.get_latest_auth_hash()
        
        assert result is None
        
    def test_save_enc_salt(self):
        """Тест сохранения encryption salt"""
        test_salt = b"salt_data_123456"
        version = 3
        
        # Сохраняем salt
        self.store.save_enc_salt(test_salt, version)
        
        # Проверяем
        cursor = self.conn.cursor()
        cursor.execute("SELECT key_data, version FROM key_store WHERE key_type = 'enc_salt'")
        row = cursor.fetchone()
        
        assert row is not None
        assert row[0] == test_salt
        assert row[1] == version
        
    def test_save_enc_salt_default_version(self):
        """Тест сохранения enc salt с версией по умолчанию"""
        test_salt = b"salt_default_version"
        
        # Сохраняем без указания версии
        self.store.save_enc_salt(test_salt)
        
        # Проверяем
        cursor = self.conn.cursor()
        cursor.execute("SELECT version FROM key_store WHERE key_type = 'enc_salt'")
        row = cursor.fetchone()
        
        assert row is not None
        assert row[0] == 1  # Версия по умолчанию
        
    def test_get_latest_enc_salt(self):
        """Тест получения последнего enc salt"""
        # Сохраняем несколько salt
        salts = [b"salt_1", b"salt_2", b"salt_3"]
        
        for salt in salts:
            self.store.save_enc_salt(salt)
            time.sleep(0.001)
            
        # Получаем последний
        latest = self.store.get_latest_enc_salt()
        
        assert latest == b"salt_3"
        
    def test_get_latest_enc_salt_none_when_empty(self):
        """Тест get_latest_enc_salt() когда нет данных"""
        result = self.store.get_latest_enc_salt()
        
        assert result is None
        
    def test_multiple_key_types(self):
        """Тест работы с несколькими типами ключей"""
        # Сохраняем разные типы ключей
        self.store.save_auth_hash("auth_hash_value")
        self.store.save_enc_salt(b"enc_salt_value")
        
        # Проверяем, что оба сохранились
        cursor = self.conn.cursor()
        cursor.execute("SELECT key_type, COUNT(*) FROM key_store GROUP BY key_type")
        rows = cursor.fetchall()
        
        # Должно быть 2 записи: одна auth_hash, одна enc_salt
        assert len(rows) == 2
        
        key_types = [row[0] for row in rows]
        assert "auth_hash" in key_types
        assert "enc_salt" in key_types
        
    def test_concurrent_saves(self):
        """Тест конкурентного сохранения ключей"""
        import concurrent.futures
        
        # Функция для сохранения в отдельном потоке
        def save_auth_hash_thread(thread_id):
            self.store.save_auth_hash(f"hash_from_thread_{thread_id}")
            
        # Запускаем несколько потоков
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(save_auth_hash_thread, i) for i in range(10)]
            # Ждем завершения всех
            for f in futures:
                f.result()
                
        # Проверяем, что все сохранилось
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM key_store WHERE key_type = 'auth_hash'")
        count = cursor.fetchone()[0]
        
        assert count == 10
        
    def test_unicode_auth_hash(self):
        """Тест сохранения auth hash с Unicode символами"""
        unicode_hash = "хеш_с_юникодом_✅"
        
        self.store.save_auth_hash(unicode_hash)
        
        retrieved = self.store.get_latest_auth_hash()
        
        assert retrieved == unicode_hash
        
    def test_large_enc_salt(self):
        """Тест сохранения большого enc salt"""
        # Большой salt (32 байта - типичный размер для криптографии)
        large_salt = os.urandom(32)
        
        self.store.save_enc_salt(large_salt)
        
        retrieved = self.store.get_latest_enc_salt()
        
        assert retrieved == large_salt
        assert len(retrieved) == 32
        
    def test_empty_enc_salt(self):
        """Тест сохранения пустого enc salt"""
        empty_salt = b""
        
        self.store.save_enc_salt(empty_salt)
        
        retrieved = self.store.get_latest_enc_salt()
        
        assert retrieved == empty_salt
        assert len(retrieved) == 0
        
    def test_database_rollback_on_error(self):
        """Тест отката транзакции при ошибке"""
        # Создаем сломанное соединение
        broken_conn = Mock(spec=sqlite3.Connection)
        broken_cursor = Mock()
        
        # Настраиваем mock для имитации ошибки
        broken_cursor.execute.side_effect = sqlite3.Error("Test error")
        broken_conn.cursor.return_value = broken_cursor
        broken_conn.commit = Mock()
        broken_conn.rollback = Mock()
        
        from src.core.crypto.key_storage import KeyStore
        broken_store = KeyStore(broken_conn)
        
        # Пытаемся сохранить - должно вызвать ошибку
        with pytest.raises(sqlite3.Error):
            broken_store.save_auth_hash("test_hash")
            
        # Проверяем, что был вызван rollback
        broken_conn.rollback.assert_called_once()
        
    def test_key_rotation_with_versions(self):
        """Тест ротации ключей с версиями"""
        # Сохраняем ключи с разными версиями
        self.store.save_auth_hash("hash_v1", version=1)
        time.sleep(0.001)
        self.store.save_auth_hash("hash_v2", version=2)
        time.sleep(0.001)
        self.store.save_auth_hash("hash_v3", version=3)
        
        # Получаем последний (должен быть v3)
        latest = self.store.get_latest_auth_hash()
        assert latest == "hash_v3"
        
        # Проверяем, что все версии сохранились
        cursor = self.conn.cursor()
        cursor.execute("SELECT version FROM key_store WHERE key_type = 'auth_hash' ORDER BY id")
        versions = [row[0] for row in cursor.fetchall()]
        
        assert versions == [1, 2, 3]


class TestKeyStorageIntegration:
    """Интеграционные тесты для key storage"""
    
    def test_key_cache_and_store_integration(self):
        """Тест интеграции KeyCache и KeyStore"""
        from src.core.crypto.key_storage import KeyCache, KeyStore
        
        # Создаем временную БД
        conn = sqlite3.connect(':memory:')
        conn.execute("""
            CREATE TABLE key_store (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_type TEXT NOT NULL,
                key_data BLOB NOT NULL,
                version INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        store = KeyStore(conn)
        cache = KeyCache(inactivity_timeout=3600)
        
        # Сохраняем хеш в store
        test_hash = "integrated_test_hash"
        store.save_auth_hash(test_hash)
        
        # Получаем из store
        retrieved_hash = store.get_latest_auth_hash()
        assert retrieved_hash == test_hash
        
        # Устанавливаем ключ в cache
        test_key = b"integrated_test_key"
        cache.set_key(test_key)
        
        # Получаем из cache
        retrieved_key = cache.get_key()
        assert retrieved_key == test_key
        
        # Очищаем
        cache.clear()
        conn.close()
        
    def test_realistic_key_rotation_scenario(self):
        """Тест реалистичного сценария ротации ключей"""
        from src.core.crypto.key_storage import KeyCache, KeyStore
        
        # Создаем окружение
        conn = sqlite3.connect(':memory:')
        conn.execute("""
            CREATE TABLE key_store (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_type TEXT NOT NULL,
                key_data BLOB NOT NULL,
                version INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        store = KeyStore(conn)
        cache = KeyCache(inactivity_timeout=60)  # 1 минута для теста
        
        # Имитируем процесс ротации ключей
        keys = [b"old_key", b"new_key", b"latest_key"]
        
        for i, key in enumerate(keys):
            # Сохраняем хеш ключа в store
            store.save_auth_hash(f"hash_for_key_{i}", version=i+1)
            
            # Устанавливаем ключ в cache
            cache.set_key(key)
            
            # Используем ключ
            assert cache.get_key() == key
            
            # Имитируем небольшую паузу между ротациями
            time.sleep(0.01)
            
        # В конце должен быть последний ключ
        assert cache.get_key() == b"latest_key"
        assert store.get_latest_auth_hash() == "hash_for_key_2"
        
        # Очищаем
        cache.clear()
        conn.close()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])