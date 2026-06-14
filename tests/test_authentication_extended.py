"""
Расширенные тесты для модуля authentication.py
Цель: повысить покрытие с 44% до 80%
"""

import pytest
pytestmark = pytest.mark.crypto

from unittest.mock import Mock, patch, MagicMock
import time
import os
import sys

# Добавляем путь к src для импорта
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


class TestAuthenticationService:
    """Тесты для AuthenticationService"""
    
    def setup_method(self):
        """Настройка перед каждым тестом"""
        from src.core.crypto.authentication import AuthenticationService
        from src.core.events import EventSystem, EventType
        
        # Создаем mock объекты
        self.mock_key_manager = Mock()
        self.mock_events = Mock(spec=EventSystem)
        
        # Создаем сервис
        self.service = AuthenticationService(self.mock_key_manager, self.mock_events)
        
    def test_logout(self):
        """Тест метода logout()"""
        # Имитируем вход пользователя
        self.service.session.logged_in = True
        self.service.session.login_timestamp = time.time()
        self.service.session.last_activity = time.time()
        self.service.session.failed_attempts = 2
        
        # Вызываем logout
        self.service.logout()
        
        # Проверяем, что сессия сброшена
        assert self.service.session.logged_in is False
        assert self.service.session.login_timestamp is None
        assert self.service.session.last_activity is None
        assert self.service.session.failed_attempts == 0
        
        # Проверяем вызовы зависимостей
        self.mock_key_manager.clear_keys.assert_called_once()
        self.mock_events.emit.assert_called_once()
        
        # Проверяем, что вызван правильный тип события
        call_args = self.mock_events.emit.call_args
        assert call_args[0][0].value == "user_logged_out"
        
    def test_logout_when_not_logged_in(self):
        """Тест logout() когда пользователь не вошел"""
        # Убеждаемся, что пользователь не вошел
        self.service.session.logged_in = False
        
        # Вызываем logout
        self.service.logout()
        
        # Проверяем, что сессия осталась в начальном состоянии
        assert self.service.session.logged_in is False
        assert self.service.session.login_timestamp is None
        
        # Проверяем, что методы все равно вызываются
        self.mock_key_manager.clear_keys.assert_called_once()
        self.mock_events.emit.assert_called_once()
        
    def test_update_activity_when_logged_in(self):
        """Тест update_activity() когда пользователь вошел"""
        # Имитируем вход
        self.service.session.logged_in = True
        initial_time = time.time()
        self.service.session.last_activity = initial_time
        
        # Вызываем update_activity
        with patch('time.time', return_value=initial_time + 10):
            self.service.update_activity()
            
        # Проверяем обновление времени активности
        assert self.service.session.last_activity == initial_time + 10
        
    def test_update_activity_when_not_logged_in(self):
        """Тест update_activity() когда пользователь не вошел"""
        # Убеждаемся, что пользователь не вошел
        self.service.session.logged_in = False
        initial_time = time.time()
        self.service.session.last_activity = initial_time
        
        # Вызываем update_activity
        with patch('time.time', return_value=initial_time + 10):
            self.service.update_activity()
            
        # Проверяем, что время не изменилось
        assert self.service.session.last_activity == initial_time
        
    def test_calculate_delay(self):
        """Тест метода _calculate_delay()"""
        # Тест различных значений failed_attempts
        
        # 0 попыток
        self.service.session.failed_attempts = 0
        assert self.service._calculate_delay() == 1
        
        # 1 попытка
        self.service.session.failed_attempts = 1
        assert self.service._calculate_delay() == 1
        
        # 2 попытки
        self.service.session.failed_attempts = 2
        assert self.service._calculate_delay() == 1
        
        # 3 попытки
        self.service.session.failed_attempts = 3
        assert self.service._calculate_delay() == 5
        
        # 4 попытки
        self.service.session.failed_attempts = 4
        assert self.service._calculate_delay() == 5
        
        # 5 попыток
        self.service.session.failed_attempts = 5
        assert self.service._calculate_delay() == 30
        
        # 10 попыток
        self.service.session.failed_attempts = 10
        assert self.service._calculate_delay() == 30
        
    @patch('time.sleep')
    def test_login_success_with_events(self, mock_sleep):
        """Тест успешного входа с проверкой событий"""
        # Настраиваем mock для успешной аутентификации
        self.mock_key_manager.authenticate.return_value = True
        self.mock_key_manager.get_audit_signing_seed = Mock()
        
        test_password = "correct_password"
        
        # Вызываем login
        result = self.service.login(test_password)
        
        # Проверяем результат
        assert result is True
        
        # Проверяем вызовы зависимостей
        self.mock_key_manager.authenticate.assert_called_once_with(test_password)
        self.mock_key_manager.get_audit_signing_seed.assert_called_once_with(test_password)
        
        # Проверяем вызов sleep с правильной задержкой (1 секунда для 0 попыток)
        mock_sleep.assert_called_once_with(1)
        
        # Проверяем, что было 2 вызова emit (login и аудит)
        assert self.mock_events.emit.call_count == 2
        
        # Проверяем первый вызов (USER_LOGGED_IN)
        first_call_args = self.mock_events.emit.call_args_list[0]
        assert first_call_args[0][0].value == "USER_LOGGED_IN"
        
    @patch('time.sleep')
    def test_login_failure_with_events(self, mock_sleep):
        """Тест неуспешного входа с проверкой событий"""
        # Настраиваем mock для неудачной аутентификации
        self.mock_key_manager.authenticate.return_value = False
        
        test_password = "wrong_password"
        
        # Вызываем login
        result = self.service.login(test_password)
        
        # Проверяем результат
        assert result is False
        
        # Проверяем вызовы зависимостей
        self.mock_key_manager.authenticate.assert_called_once_with(test_password)
        
        # Проверяем вызов sleep с правильной задержкой
        mock_sleep.assert_called_once_with(1)
        
        # Проверяем вызов emit для аудита
        self.mock_events.emit.assert_called_once()
        
        # Проверяем аргументы вызова
        call_args = self.mock_events.emit.call_args
        assert call_args[0][0].value == "audit_log_entry"
        assert call_args[0][1]["reason"] == "auth_failed"
        assert call_args[0][1]["attempts"] == 1  # Первая неудачная попытка
        
    def test_session_info_default_values(self):
        """Тест значений по умолчанию SessionInfo"""
        from src.core.crypto.authentication import SessionInfo
        
        session = SessionInfo()
        
        assert session.logged_in is False
        assert session.login_timestamp is None
        assert session.last_activity is None
        assert session.failed_attempts == 0
        
    def test_session_info_custom_values(self):
        """Тест SessionInfo с пользовательскими значениями"""
        from src.core.crypto.authentication import SessionInfo
        
        test_time = time.time()
        session = SessionInfo(
            logged_in=True,
            login_timestamp=test_time,
            last_activity=test_time + 100,
            failed_attempts=3
        )
        
        assert session.logged_in is True
        assert session.login_timestamp == test_time
        assert session.last_activity == test_time + 100
        assert session.failed_attempts == 3
        
    @patch('time.sleep')
    def test_multiple_failed_logins(self, mock_sleep):
        """Тест нескольких неудачных попыток входа"""
        # Настраиваем mock для неудачной аутентификации
        self.mock_key_manager.authenticate.return_value = False
        
        test_password = "wrong_password"
        
        # Первая неудачная попытка
        result1 = self.service.login(test_password)
        assert result1 is False
        assert self.service.session.failed_attempts == 1
        mock_sleep.assert_called_with(1)
        
        # Вторая неудачная попытка
        result2 = self.service.login(test_password)
        assert result2 is False
        assert self.service.session.failed_attempts == 2
        mock_sleep.assert_called_with(1)
        
        # Третья неудачная попытка (задержка увеличивается)
        result3 = self.service.login(test_password)
        assert result3 is False
        assert self.service.session.failed_attempts == 3
        mock_sleep.assert_called_with(5)  # Задержка увеличилась до 5 секунд
        
        # Четвертая неудачная попытка
        result4 = self.service.login(test_password)
        assert result4 is False
        assert self.service.session.failed_attempts == 4
        mock_sleep.assert_called_with(5)
        
        # Пятая неудачная попытка (максимальная задержка)
        result5 = self.service.login(test_password)
        assert result5 is False
        assert self.service.session.failed_attempts == 5
        mock_sleep.assert_called_with(30)  # Максимальная задержка
        
        # Проверяем общее количество вызовов
        assert self.mock_key_manager.authenticate.call_count == 5
        assert mock_sleep.call_count == 5
        
    @patch('time.sleep')
    def test_success_after_failed_logins(self, mock_sleep):
        """Тест успешного входа после неудачных попыток"""
        # Настраиваем mock: сначала неудача, потом успех
        self.mock_key_manager.authenticate.side_effect = [False, False, True]
        self.mock_key_manager.get_audit_signing_seed = Mock()
        
        test_password = "eventually_correct_password"
        
        # Первая неудачная попытка
        result1 = self.service.login(test_password)
        assert result1 is False
        assert self.service.session.failed_attempts == 1
        
        # Вторая неудачная попытка
        result2 = self.service.login(test_password)
        assert result2 is False
        assert self.service.session.failed_attempts == 2
        
        # Третья (успешная) попытка
        result3 = self.service.login(test_password)
        assert result3 is True
        assert self.service.session.failed_attempts == 0  # Счетчик сброшен
        
        # Проверяем состояние сессии после успеха
        assert self.service.session.logged_in is True
        assert self.service.session.login_timestamp is not None
        assert self.service.session.last_activity is not None
        
    def test_clear_keys_called_on_logout(self):
        """Тест вызова clear_keys() при logout"""
        # Имитируем вход
        self.service.session.logged_in = True
        
        # Вызываем logout
        self.service.logout()
        
        # Проверяем вызов clear_keys
        self.mock_key_manager.clear_keys.assert_called_once()
        
    def test_get_audit_signing_seed_called_on_success(self):
        """Тест вызова get_audit_signing_seed() при успешном входе"""
        # Настраиваем mock
        self.mock_key_manager.authenticate.return_value = True
        mock_get_seed = Mock()
        self.mock_key_manager.get_audit_signing_seed = mock_get_seed
        
        test_password = "test_password"
        
        # Вызываем login
        with patch('time.sleep'):
            self.service.login(test_password)
            
        # Проверяем вызов get_audit_signing_seed
        mock_get_seed.assert_called_once_with(test_password)
        
    def test_secrets_compare_digest_called_on_failure(self):
        """Тест вызова secrets.compare_digest() при неудачном входе"""
        # Настраиваем mock для неудачной аутентификации
        self.mock_key_manager.authenticate.return_value = False
        
        # Патчим secrets.compare_digest
        with patch('secrets.compare_digest') as mock_compare_digest:
            with patch('time.sleep'):
                self.service.login("wrong_password")
                
            # Проверяем вызов compare_digest
            mock_compare_digest.assert_called_once_with(b'dummy', b'dummy')


class TestAuthenticationEdgeCases:
    """Тесты для пограничных случаев AuthenticationService"""
    
    def setup_method(self):
        """Настройка перед каждым тестом"""
        from src.core.crypto.authentication import AuthenticationService
        from src.core.events import EventSystem
        
        self.mock_key_manager = Mock()
        self.mock_events = Mock(spec=EventSystem)
        self.service = AuthenticationService(self.mock_key_manager, self.mock_events)
        
    def test_empty_password(self):
        """Тест входа с пустым паролем"""
        self.mock_key_manager.authenticate.return_value = False
        
        with patch('time.sleep'):
            result = self.service.login("")
            
        assert result is False
        self.mock_key_manager.authenticate.assert_called_once_with("")
        
    def test_very_long_password(self):
        """Тест входа с очень длинным паролем"""
        long_password = "a" * 1000
        self.mock_key_manager.authenticate.return_value = True
        
        with patch('time.sleep'):
            result = self.service.login(long_password)
            
        assert result is True
        self.mock_key_manager.authenticate.assert_called_once_with(long_password)
        
    def test_password_with_special_chars(self):
        """Тест входа с паролем содержащим специальные символы"""
        special_password = "P@ssw0rd!№%:?*()"
        self.mock_key_manager.authenticate.return_value = True
        
        with patch('time.sleep'):
            result = self.service.login(special_password)
            
        assert result is True
        self.mock_key_manager.authenticate.assert_called_once_with(special_password)
        
    @patch('time.sleep')
    def test_concurrent_login_attempts(self, mock_sleep):
        """Тест нескольких последовательных попыток входа"""
        # Настраиваем mock для чередования успеха и неудачи
        self.mock_key_manager.authenticate.side_effect = [
            False, True, False, True
        ]
        
        test_password = "test_password"
        
        # Первая попытка: неудача
        result1 = self.service.login(test_password)
        assert result1 is False
        assert self.service.session.failed_attempts == 1
        
        # Вторая попытка: успех
        result2 = self.service.login(test_password)
        assert result2 is True
        assert self.service.session.failed_attempts == 0  # Счетчик сброшен
        
        # Третья попытка: неудача
        result3 = self.service.login(test_password)
        assert result3 is False
        assert self.service.session.failed_attempts == 1  # Счетчик снова начался
        
        # Четвертая попытка: успех
        result4 = self.service.login(test_password)
        assert result4 is True
        assert self.service.session.failed_attempts == 0  # Счетчик сброшен
        
        # Проверяем общее количество вызовов
        assert self.mock_key_manager.authenticate.call_count == 4
        
    def test_session_timeout_simulation(self):
        """Тест имитации таймаута сессии"""
        # Имитируем вход
        self.service.session.logged_in = True
        login_time = time.time()
        self.service.session.login_timestamp = login_time
        
        # Обновляем активность через 5 минут
        activity_time = login_time + 300  # 5 минут
        self.service.session.last_activity = activity_time
        
        # Проверяем, что сессия все еще активна
        assert self.service.session.logged_in is True
        assert self.service.session.login_timestamp == login_time
        assert self.service.session.last_activity == activity_time
        
        # Вызываем logout для имитации таймаута
        self.service.logout()
        
        # Проверяем сброс сессии
        assert self.service.session.logged_in is False
        assert self.service.session.login_timestamp is None
        assert self.service.session.last_activity is None
        
    @patch('time.sleep')
    def test_login_with_zero_delay(self, mock_sleep):
        """Тест входа с нулевой задержкой (для тестирования)"""
        # Меняем метод _calculate_delay чтобы возвращать 0
        self.service._calculate_delay = lambda: 0
        
        self.mock_key_manager.authenticate.return_value = True
        
        result = self.service.login("password")
        
        assert result is True
        # Проверяем, что sleep не вызывался или вызвался с 0
        if mock_sleep.called:
            mock_sleep.assert_called_with(0)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])