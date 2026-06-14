"""
Тесты для модуля key_manager.py
Цель: повысить покрытие с 25% до 70%
"""

import pytest
import os
import sys
import tempfile
import sqlite3
from unittest.mock import Mock, patch, MagicMock, call

# Добавляем путь к src для импорта
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


class TestKeyManager:
    """Тесты для класса KeyManager"""
    
    def setup_method(self):
        """Настройка перед каждым тестом"""
        from src.core.key_manager import KeyManager
        
        # Создаем mock объекты
        self.mock_config = Mock()
        self.mock_db_connection = Mock()
        self.mock_config.get.return_value = 3600  # key_cache_timeout
        
        # Создаем KeyManager
        self.key_manager = KeyManager(self.mock_config, self.mock_db_connection)
        
    def test_key_manager_init(self):
        """Тест инициализации KeyManager"""
        from src.core.key_manager import KeyManager
        from src.core.crypto.key_derivation import KeyDerivation
        from src.core.crypto.key_storage import KeyCache, KeyStore
        
        # Проверяем инициализацию компонентов
        assert isinstance(self.key_manager.derivation, KeyDerivation)
        assert isinstance(self.key_manager.cache, KeyCache)
        assert isinstance(self.key_manager.store, KeyStore)
        
        # Проверяем параметры
        assert self.key_manager.derivation.config == self.mock_config
        
        # Проверяем вызов config.get для timeout
        self.mock_config.get.assert_called_once_with('key_cache_timeout', 3600)
        
    def test_setup_master_password(self):
        """Тест setup_master_password()"""
        test_password = "test_master_password"
        
        # Настраиваем mock для derivation
        mock_auth_hash = "mock_auth_hash"
        mock_salt = b"mock_salt"
        mock_enc_key = b"mock_encryption_key"
        
        self.key_manager.derivation.create_auth_hash = Mock(return_value=mock_auth_hash)
        self.key_manager.derivation.generate_enc_salt = Mock(return_value=mock_salt)
        self.key_manager.derivation.derive_encryption_key = Mock(return_value=mock_enc_key)
        
        # Вызываем метод
        self.key_manager.setup_master_password(test_password)
        
        # Проверяем вызовы
        self.key_manager.derivation.create_auth_hash.assert_called_once_with(test_password)
        self.key_manager.derivation.generate_enc_salt.assert_called_once()
        self.key_manager.derivation.derive_encryption_key.assert_called_once_with(test_password, mock_salt)
        
        # Проверяем сохранение в store
        self.key_manager.store.save_auth_hash.assert_called_once_with(mock_auth_hash)
        self.key_manager.store.save_enc_salt.assert_called_once_with(mock_salt)
        
        # Проверяем установку в cache
        self.key_manager.cache.set_key.assert_called_once_with(mock_enc_key)
        
    def test_authenticate_success(self):
        """Тест authenticate() успешная аутентификация"""
        test_password = "correct_password"
        
        # Настраиваем mock для store
        mock_stored_hash = "stored_auth_hash"
        mock_salt = b"stored_salt"
        
        self.key_manager.store.get_latest_auth_hash = Mock(return_value=mock_stored_hash)
        self.key_manager.store.get_latest_enc_salt = Mock(return_value=mock_salt)
        
        # Настраиваем mock для derivation
        self.key_manager.derivation.verify_password = Mock(return_value=True)
        
        mock_enc_key = b"derived_encryption_key"
        self.key_manager.derivation.derive_encryption_key = Mock(return_value=mock_enc_key)
        
        # Вызываем метод
        result = self.key_manager.authenticate(test_password)
        
        # Проверяем результат
        assert result is True
        
        # Проверяем вызовы
        self.key_manager.store.get_latest_auth_hash.assert_called_once()
        self.key_manager.store.get_latest_enc_salt.assert_called_once()
        self.key_manager.derivation.verify_password.assert_called_once_with(test_password, mock_stored_hash)
        self.key_manager.derivation.derive_encryption_key.assert_called_once_with(test_password, mock_salt)
        self.key_manager.cache.set_key.assert_called_once_with(mock_enc_key)
        
    def test_authenticate_failure_no_stored_data(self):
        """Тест authenticate() когда нет сохраненных данных"""
        test_password = "any_password"
        
        # Настраиваем store чтобы возвращал None
        self.key_manager.store.get_latest_auth_hash = Mock(return_value=None)
        self.key_manager.store.get_latest_enc_salt = Mock(return_value=None)
        
        # Вызываем метод
        result = self.key_manager.authenticate(test_password)
        
        # Проверяем результат
        assert result is False
        
        # Проверяем, что verify_password не вызывался
        self.key_manager.derivation.verify_password.assert_not_called()
        
    def test_authenticate_failure_wrong_password(self):
        """Тест authenticate() с неверным паролем"""
        test_password = "wrong_password"
        
        # Настраиваем store
        mock_stored_hash = "stored_auth_hash"
        mock_salt = b"stored_salt"
        
        self.key_manager.store.get_latest_auth_hash = Mock(return_value=mock_stored_hash)
        self.key_manager.store.get_latest_enc_salt = Mock(return_value=mock_salt)
        
        # Настраиваем derivation для неудачной проверки
        self.key_manager.derivation.verify_password = Mock(return_value=False)
        
        # Вызываем метод
        result = self.key_manager.authenticate(test_password)
        
        # Проверяем результат
        assert result is False
        
        # Проверяем вызовы
        self.key_manager.derivation.verify_password.assert_called_once_with(test_password, mock_stored_hash)
        # Derive encryption key не должен вызываться
        self.key_manager.derivation.derive_encryption_key.assert_not_called()
        # Cache set не должен вызываться
        self.key_manager.cache.set_key.assert_not_called()
        
    def test_get_encryption_key(self):
        """Тест get_encryption_key()"""
        mock_key = b"cached_encryption_key"
        
        # Настраиваем cache
        self.key_manager.cache.get_key = Mock(return_value=mock_key)
        
        # Вызываем метод
        result = self.key_manager.get_encryption_key()
        
        # Проверяем результат
        assert result == mock_key
        
        # Проверяем вызов
        self.key_manager.cache.get_key.assert_called_once()
        
    def test_get_encryption_key_none(self):
        """Тест get_encryption_key() возвращает None"""
        # Настраиваем cache чтобы возвращал None
        self.key_manager.cache.get_key = Mock(return_value=None)
        
        # Вызываем метод
        result = self.key_manager.get_encryption_key()
        
        # Проверяем результат
        assert result is None
        
    def test_get_audit_signing_seed_cached(self):
        """Тест get_audit_signing_seed() с кешированным значением"""
        mock_seed = b"cached_audit_seed"
        
        # Настраиваем cache чтобы возвращал значение
        self.key_manager.cache.get_audit_seed = Mock(return_value=mock_seed)
        
        # Вызываем метод без пароля
        result = self.key_manager.get_audit_signing_seed()
        
        # Проверяем результат
        assert result == mock_seed
        
        # Проверяем, что derivation не вызывался
        self.key_manager.derivation.derive_audit_signing_key.assert_not_called()
        
    def test_get_audit_signing_seed_no_cache_with_password(self):
        """Тест get_audit_signing_seed() без кеша, но с паролем"""
        test_password = "test_password"
        mock_salt = b"test_salt"
        mock_seed = b"derived_audit_seed"
        mock_enc_key = b"derived_audit_enc_key"
        
        # Настраиваем cache чтобы возвращал None
        self.key_manager.cache.get_audit_seed = Mock(return_value=None)
        
        # Настраиваем store
        self.key_manager.store.get_latest_enc_salt = Mock(return_value=mock_salt)
        
        # Настраиваем derivation
        self.key_manager.derivation.derive_audit_signing_key = Mock(return_value=mock_seed)
        self.key_manager.derivation.derive_audit_encryption_key = Mock(return_value=mock_enc_key)
        
        # Вызываем метод с паролем
        result = self.key_manager.get_audit_signing_seed(test_password)
        
        # Проверяем результат
        assert result == mock_seed
        
        # Проверяем вызовы
        self.key_manager.cache.get_audit_seed.assert_called_once()
        self.key_manager.store.get_latest_enc_salt.assert_called_once()
        self.key_manager.derivation.derive_audit_signing_key.assert_called_once_with(test_password, mock_salt)
        self.key_manager.derivation.derive_audit_encryption_key.assert_called_once_with(test_password, mock_salt)
        self.key_manager.cache.set_audit_seed.assert_called_once_with(mock_seed)
        self.key_manager.cache.set_audit_enc_key.assert_called_once_with(mock_enc_key)
        
    def test_get_audit_signing_seed_no_cache_no_password(self):
        """Тест get_audit_signing_seed() без кеша и без пароля"""
        # Настраиваем cache чтобы возвращал None
        self.key_manager.cache.get_audit_seed = Mock(return_value=None)
        
        # Вызываем метод без пароля
        result = self.key_manager.get_audit_signing_seed()
        
        # Проверяем результат
        assert result is None
        
        # Проверяем, что store и derivation не вызывались
        self.key_manager.store.get_latest_enc_salt.assert_not_called()
        self.key_manager.derivation.derive_audit_signing_key.assert_not_called()
        
    def test_get_audit_signing_seed_no_salt(self):
        """Тест get_audit_signing_seed() когда нет соли"""
        test_password = "test_password"
        
        # Настраиваем cache чтобы возвращал None
        self.key_manager.cache.get_audit_seed = Mock(return_value=None)
        
        # Настраиваем store чтобы возвращал None
        self.key_manager.store.get_latest_enc_salt = Mock(return_value=None)
        
        # Вызываем метод
        result = self.key_manager.get_audit_signing_seed(test_password)
        
        # Проверяем результат
        assert result is None
        
        # Проверяем, что derivation не вызывался
        self.key_manager.derivation.derive_audit_signing_key.assert_not_called()
        
    def test_get_audit_encryption_key_cached(self):
        """Тест get_audit_encryption_key() с кешированным значением"""
        mock_key = b"cached_audit_enc_key"
        
        # Настраиваем cache
        self.key_manager.cache.get_audit_enc_key = Mock(return_value=mock_key)
        
        # Вызываем метод без пароля
        result = self.key_manager.get_audit_encryption_key()
        
        # Проверяем результат
        assert result == mock_key
        
        # Проверяем, что derivation не вызывался
        self.key_manager.derivation.derive_audit_encryption_key.assert_not_called()
        
    def test_get_audit_encryption_key_no_cache_with_password(self):
        """Тест get_audit_encryption_key() без кеша, но с паролем"""
        test_password = "test_password"
        mock_salt = b"test_salt"
        mock_key = b"derived_audit_enc_key"
        
        # Настраиваем cache чтобы возвращал None
        self.key_manager.cache.get_audit_enc_key = Mock(return_value=None)
        
        # Настраиваем store
        self.key_manager.store.get_latest_enc_salt = Mock(return_value=mock_salt)
        
        # Настраиваем derivation
        self.key_manager.derivation.derive_audit_encryption_key = Mock(return_value=mock_key)
        
        # Вызываем метод с паролем
        result = self.key_manager.get_audit_encryption_key(test_password)
        
        # Проверяем результат
        assert result == mock_key
        
        # Проверяем вызовы
        self.key_manager.cache.get_audit_enc_key.assert_called_once()
        self.key_manager.store.get_latest_enc_salt.assert_called_once()
        self.key_manager.derivation.derive_audit_encryption_key.assert_called_once_with(test_password, mock_salt)
        self.key_manager.cache.set_audit_enc_key.assert_called_once_with(mock_key)
        
    def test_clear_keys(self):
        """Тест clear_keys()"""
        # Вызываем метод
        self.key_manager.clear_keys()
        
        # Проверяем вызов
        self.key_manager.cache.clear.assert_called_once()
        

class TestKeyManagerRotateMasterPassword:
    """Тесты для метода rotate_master_password()"""
    
    def setup_method(self):
        """Настройка перед каждым тестом"""
        from src.core.key_manager import KeyManager
        
        # Создаем mock объекты
        self.mock_config = Mock()
        self.mock_db_connection = Mock()
        self.mock_config.get.return_value = 3600
        
        # Создаем KeyManager
        self.key_manager = KeyManager(self.mock_config, self.mock_db_connection)
        
    def test_rotate_master_password_success(self):
        """Тест успешной ротации мастер-пароля"""
        old_password = "old_password"
        new_password = "new_password"
        
        # Создаем mock для БД
        mock_db = Mock()
        mock_conn = Mock()
        mock_cursor = Mock()
        mock_db.connection = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        
        # Настраиваем authenticate для успеха
        self.key_manager.authenticate = Mock(return_value=True)
        
        # Настраиваем get_encryption_key
        mock_old_key = b"old_encryption_key"
        self.key_manager.get_encryption_key = Mock(return_value=mock_old_key)
        
        # Настраиваем store для соли
        mock_old_salt = b"old_salt"
        self.key_manager.store.get_latest_enc_salt = Mock(return_value=mock_old_salt)
        
        # Настраиваем derivation для новых значений
        mock_new_auth_hash = "new_auth_hash"
        mock_new_salt = b"new_salt"
        mock_new_key = b"new_encryption_key"
        
        self.key_manager.derivation.create_auth_hash = Mock(return_value=mock_new_auth_hash)
        self.key_manager.derivation.generate_enc_salt = Mock(return_value=mock_new_salt)
        self.key_manager.derivation.derive_encryption_key = Mock(return_value=mock_new_key)
        
        # Настраиваем mock для записей в БД
        mock_rows = [
            {"id": 1, "encrypted_password": b"encrypted_data_1"},
            {"id": 2, "encrypted_password": b"encrypted_data_2"},
            {"id": 3, "encrypted_password": None},  # Запись без пароля
        ]
        mock_cursor.fetchall.return_value = mock_rows
        
        # Импортируем и настраиваем mock для AES256Placeholder
        with patch('src.core.key_manager.AES256Placeholder') as mock_aes_class:
            mock_crypto = Mock()
            mock_aes_class.return_value = mock_crypto
            
            # Настраиваем decrypt/encrypt
            mock_crypto.decrypt.side_effect = lambda data, key: f"decrypted_{data}"
            mock_crypto.encrypt.side_effect = lambda data, key: f"encrypted_{data}"
            
            # Вызываем метод
            self.key_manager.rotate_master_password(old_password, new_password, mock_db)
            
            # Проверяем вызовы
            self.key_manager.authenticate.assert_called_once_with(old_password)
            self.key_manager.get_encryption_key.assert_called_once()
            self.key_manager.store.get_latest_enc_salt.assert_called_once()
            
            # Проверяем derivation вызовы
            self.key_manager.derivation.create_auth_hash.assert_called_once_with(new_password)
            self.key_manager.derivation.generate_enc_salt.assert_called_once()
            self.key_manager.derivation.derive_encryption_key.assert_called_once_with(new_password, mock_new_salt)
            
            # Проверяем БД операции
            mock_conn.execute.assert_called_once_with("BEGIN")
            mock_cursor.execute.assert_any_call("SELECT id, encrypted_password FROM vault_entries")
            
            # Проверяем update вызовы только для записей с паролями
            expected_update_calls = [
                call("UPDATE vault_entries SET encrypted_password = ? WHERE id = ?", 
                     ("encrypted_decrypted_encrypted_data_1", 1)),
                call("UPDATE vault_entries SET encrypted_password = ? WHERE id = ?", 
                     ("encrypted_decrypted_encrypted_data_2", 2))
            ]
            
            # Проверяем что update не вызывался для записи с None
            assert call("UPDATE vault_entries SET encrypted_password = ? WHERE id = ?", 
                       (mock_crypto.encrypt.return_value, 3)) not in mock_cursor.execute.call_args_list
            
            # Проверяем сохранение новых значений
            self.key_manager.store.save_auth_hash.assert_called_once_with(mock_new_auth_hash, version=2)
            self.key_manager.store.save_enc_salt.assert_called_once_with(mock_new_salt, version=2)
            
            # Проверяем коммит
            mock_conn.commit.assert_called_once()
            
            # Проверяем обновление кеша
            self.key_manager.cache.set_key.assert_called_once_with(mock_new_key)
            
    def test_rotate_master_password_authentication_failure(self):
        """Тест ротации с неверным текущим паролем"""
        old_password = "wrong_password"
        new_password = "new_password"
        
        # Настраиваем authenticate для неудачи
        self.key_manager.authenticate = Mock(return_value=False)
        
        mock_db = Mock()
        
        # Вызываем метод - должно вызвать ValueError
        with pytest.raises(ValueError, match="Неверный текущий пароль"):
            self.key_manager.rotate_master_password(old_password, new_password, mock_db)
            
    def test_rotate_master_password_no_old_key(self):
        """Тест ротации когда старый ключ недоступен"""
        old_password = "old_password"
        new_password = "new_password"
        
        # Настраиваем authenticate для успеха
        self.key_manager.authenticate = Mock(return_value=True)
        
        # Настраиваем get_encryption_key чтобы возвращал None
        self.key_manager.get_encryption_key = Mock(return_value=None)
        
        mock_db = Mock()
        
        # Вызываем метод - должно вызвать ValueError
        with pytest.raises(ValueError, match="Старый ключ недоступен"):
            self.key_manager.rotate_master_password(old_password, new_password, mock_db)
            
    def test_rotate_master_password_db_exception(self):
        """Тест ротации с исключением в БД"""
        old_password = "old_password"
        new_password = "new_password"
        
        # Настраиваем базовые mock
        self.key_manager.authenticate = Mock(return_value=True)
        self.key_manager.get_encryption_key = Mock(return_value=b"old_key")
        self.key_manager.store.get_latest_enc_salt = Mock(return_value=b"old_salt")
        
        # Настраиваем derivation
        self.key_manager.derivation.create_auth_hash = Mock(return_value="new_hash")
        self.key_manager.derivation.generate_enc_salt = Mock(return_value=b"new_salt")
        self.key_manager.derivation.derive_encryption_key = Mock(return_value=b"new_key")
        
        # Создаем mock для БД с исключением
        mock_db = Mock()
        mock_conn = Mock()
        mock_cursor = Mock()
        mock_db.connection = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        
        # Настраиваем исключение при выполнении SELECT
        mock_cursor.execute.side_effect = sqlite3.Error("Test DB error")
        
        # Вызываем метод - должно подняться исключение
        with pytest.raises(sqlite3.Error, match="Test DB error"):
            self.key_manager.rotate_master_password(old_password, new_password, mock_db)
            
        # Проверяем, что был rollback
        mock_conn.rollback.assert_called_once()
        
    def test_rotate_master_password_with_encryption_error(self):
        """Тест ротации с ошибкой шифрования/дешифрования"""
        old_password = "old_password"
        new_password = "new_password"
        
        # Настраиваем базовые mock
        self.key_manager.authenticate = Mock(return_value=True)
        self.key_manager.get_encryption_key = Mock(return_value=b"old_key")
        self.key_manager.store.get_latest_enc_salt = Mock(return_value=b"old_salt")
        
        # Настраиваем derivation
        self.key_manager.derivation.create_auth_hash = Mock(return_value="new_hash")
        self.key_manager.derivation.generate_enc_salt = Mock(return_value=b"new_salt")
        self.key_manager.derivation.derive_encryption_key = Mock(return_value=b"new_key")
        
        # Создаем mock для БД
        mock_db = Mock()
        mock_conn = Mock()
        mock_cursor = Mock()
        mock_db.connection = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        
        # Настраиваем записи
        mock_rows = [{"id": 1, "encrypted_password": b"encrypted_data"}]
        mock_cursor.fetchall.return_value = mock_rows
        
        # Импортируем и настраиваем mock для AES256Placeholder с ошибкой
        with patch('src.core.key_manager.AES256Placeholder') as mock_aes_class:
            mock_crypto = Mock()
            mock_aes_class.return_value = mock_crypto
            
            # Настраиваем decrypt чтобы вызвал исключение
            mock_crypto.decrypt.side_effect = Exception("Decryption error")
            
            # Вызываем метод - должно подняться исключение
            with pytest.raises(Exception, match="Decryption error"):
                self.key_manager.rotate_master_password(old_password, new_password, mock_db)
                
            # Проверяем, что был rollback
            mock_conn.rollback.assert_called_once()
            

class TestKeyManagerIntegration:
    """Интеграционные тесты для KeyManager"""
    
    def setup_method(self):
        """Настройка перед каждым тестом"""
        import tempfile
        import sqlite3
        
        # Создаем временную БД
        self.temp_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        self.temp_db.close()
        
        self.conn = sqlite3.connect(self.temp_db.name)
        self.conn.row_factory = sqlite3.Row
        
        # Создаем необходимые таблицы
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE key_store (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_type TEXT NOT NULL,
                key_data BLOB NOT NULL,
                version INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        cursor.execute("""
            CREATE TABLE vault_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                encrypted_password BLOB
            )
        """)
        
        cursor.execute("""
            CREATE TABLE settings (
                setting_key TEXT PRIMARY KEY,
                setting_value TEXT
            )
        """)
        
        self.conn.commit()
        
    def teardown_method(self):
        """Очистка после каждого теста"""
        self.conn.close()
        os.unlink(self.temp_db.name)
        
    def test_key_manager_lifecycle(self):
        """Тест полного жизненного цикла KeyManager"""
        from src.core.key_manager import KeyManager
        
        # Создаем mock config
        mock_config = Mock()
        mock_config.get.return_value = 3600
        
        # Создаем KeyManager
        key_manager = KeyManager(mock_config, self.conn)
        
        # Устанавливаем мастер-пароль
        master_password = "secure_master_password_123"
        key_manager.setup_master_password(master_password)
        
        # Проверяем, что данные сохранились в БД
        cursor = self.conn.cursor()
        cursor.execute("SELECT key_type, COUNT(*) FROM key_store GROUP BY key_type")
        rows = cursor.fetchall()
        
        # Должно быть 2 записи: auth_hash и enc_salt
        key_types = {row[0] for row in rows}
        assert "auth_hash" in key_types
        assert "enc_salt" in key_types
        
        # Аутентифицируемся
        auth_result = key_manager.authenticate(master_password)
        assert auth_result is True
        
        # Получаем ключ шифрования
        enc_key = key_manager.get_encryption_key()
        assert enc_key is not None
        
        # Получаем audit seed
        audit_seed = key_manager.get_audit_signing_seed(master_password)
        assert audit_seed is not None
        
        # Получаем audit encryption key
        audit_enc_key = key_manager.get_audit_encryption_key(master_password)
        assert audit_enc_key is not None
        
        # Очищаем ключи
        key_manager.clear_keys()
        
        # После очистки ключ должен быть None
        enc_key_after_clear = key_manager.get_encryption_key()
        assert enc_key_after_clear is None
        
    def test_cache_behavior(self):
        """Тест поведения кеша"""
        from src.core.key_manager import KeyManager
        
        mock_config = Mock()
        mock_config.get.return_value = 1  # 1 секунда timeout для тестов
        
        key_manager = KeyManager(mock_config, self.conn)
        
        # Настраиваем мастер-пароль
        master_password = "test_password"
        
        # Mock derivation чтобы не зависеть от реальной криптографии
        with patch.object(key_manager.derivation, 'create_auth_hash') as mock_create_hash, \
             patch.object(key_manager.derivation, 'generate_enc_salt') as mock_generate_salt, \
             patch.object(key_manager.derivation, 'derive_encryption_key') as mock_derive_key:
            
            mock_create_hash.return_value = "mock_hash"
            mock_generate_salt.return_value = b"mock_salt"
            mock_derive_key.return_value = b"mock_key"
            
            key_manager.setup_master_password(master_password)
            
        # Получаем ключ - должен быть в кеше
        key1 = key_manager.get_encryption_key()
        assert key1 == b"mock_key"
        
        # Ждем больше чем timeout
        import time
        time.sleep(1.1)
        
        # Получаем ключ снова - должен быть None (истек таймаут)
        key2 = key_manager.get_encryption_key()
        assert key2 is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])