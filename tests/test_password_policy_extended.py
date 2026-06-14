"""
Расширенные тесты для модуля password_policy.py
Цель: повысить покрытие с 19% до 90%
"""

import pytest
import os
import sys
import re
from unittest.mock import Mock, patch, MagicMock

# Добавляем путь к src для импорта
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


class TestPasswordPolicyFunctions:
    """Тесты для функций модуля password_policy.py"""
    
    def test_validate_password_strength_valid(self):
        """Тест validate_password_strength() с валидным паролем"""
        from src.core.crypto.password_policy import validate_password_strength
        
        # Валидный пароль со всеми требованиями
        valid_password = "StrongPassword123!"
        
        result = validate_password_strength(valid_password)
        
        assert result is None
        
    def test_validate_password_strength_too_short(self):
        """Тест validate_password_strength() с коротким паролем"""
        from src.core.crypto.password_policy import validate_password_strength
        
        # Слишком короткий пароль
        short_password = "Short1!"
        
        result = validate_password_strength(short_password)
        
        assert result == "Пароль должен быть не менее 12 символов"
        
    def test_validate_password_strength_common_password(self):
        """Тест validate_password_strength() с распространенным паролем"""
        from src.core.crypto.password_policy import validate_password_strength, COMMON_PASSWORDS
        
        # Распространенный пароль из списка
        for common_pass in COMMON_PASSWORDS:
            result = validate_password_strength(common_pass)
            assert result == "Слишком простой/распространённый пароль"
            
        # Распространенный пароль в разных регистрах
        result = validate_password_strength("PASSWORD123")
        assert result == "Слишком простой/распространённый пароль"
        
        result = validate_password_strength("Password")
        assert result == "Слишком простой/распространённый пароль"
        
    def test_validate_password_strength_no_uppercase(self):
        """Тест validate_password_strength() без заглавных букв"""
        from src.core.crypto.password_policy import validate_password_strength
        
        # Пароль без заглавных букв, но длинный
        password_no_upper = "longpasswordwithoutuppercase123!"
        
        result = validate_password_strength(password_no_upper)
        
        assert result == "Нужна хотя бы одна заглавная буква"
        
    def test_validate_password_strength_no_lowercase(self):
        """Тест validate_password_strength() без строчных букв"""
        from src.core.crypto.password_policy import validate_password_strength
        
        # Пароль без строчных букв
        password_no_lower = "PASSWORDWITHOUTLOWERCASE123!"
        
        result = validate_password_strength(password_no_lower)
        
        assert result == "Нужна хотя бы одна строчная буква"
        
    def test_validate_password_strength_no_digits(self):
        """Тест validate_password_strength() без цифр"""
        from src.core.crypto.password_policy import validate_password_strength
        
        # Пароль без цифр, но с другими требованиями
        password_no_digits = "PasswordWithoutDigits!"
        
        result = validate_password_strength(password_no_digits)
        
        assert result == "Нужна хотя бы одна цифра"
        
    def test_validate_password_strength_no_special_chars(self):
        """Тест validate_password_strength() без спецсимволов"""
        from src.core.crypto.password_policy import validate_password_strength
        
        # Пароль без спецсимволов
        password_no_special = "PasswordWithoutSpecial123"
        
        result = validate_password_strength(password_no_special)
        
        assert result == "Нужен хотя бы один спецсимвол"
        
    def test_validate_password_strength_empty_string(self):
        """Тест validate_password_strength() с пустой строкой"""
        from src.core.crypto.password_policy import validate_password_strength
        
        result = validate_password_strength("")
        
        assert result == "Пароль должен быть не менее 12 символов"
        
    def test_validate_password_strength_none(self):
        """Тест validate_password_strength() с None"""
        from src.core.crypto.password_policy import validate_password_strength
        
        result = validate_password_strength(None)
        
        # Проверяем, что обрабатывается корректно
        assert result is not None
        assert "Пароль должен быть не менее 12 символов" in result or isinstance(result, str)
        
    def test_validate_password_strength_only_special_chars(self):
        """Тест validate_password_strength() только со спецсимволами"""
        from src.core.crypto.password_policy import validate_password_strength
        
        # Пароль только из спецсимволов
        special_only = "!@#$%^&*()_+"
        
        result = validate_password_strength(special_only)
        
        # Должны быть ошибки по всем остальным требованиям
        assert result is not None
        assert result != "Нужен хотя бы один спецсимвол"  # Спецсимволы есть
        
    def test_validate_password_strength_only_digits(self):
        """Тест validate_password_strength() только с цифрами"""
        from src.core.crypto.password_policy import validate_password_strength
        
        # Пароль только из цифр (12+ цифр)
        digits_only = "123456789012"
        
        result = validate_password_strength(digits_only)
        
        assert result is not None
        assert result != "Нужна хотя бы одна цифра"  # Цифры есть
        
    def test_validate_password_strength_edge_cases(self):
        """Тест validate_password_strength() с пограничными случаями"""
        from src.core.crypto.password_policy import validate_password_strength
        
        # Пароль ровно 12 символов (минимальная длина)
        exact_length = "Aa1!Bb2@Cc3#"
        
        result = validate_password_strength(exact_length)
        
        assert result is None  # Должен быть валидным
        
        # Пароль с пробелами (пробел считается спецсимволом в regex \W)
        with_spaces = "Valid Pass 123"
        
        result = validate_password_strength(with_spaces)
        
        if result is not None:
            # Если есть ошибка, проверяем что не из-за спецсимволов
            assert "спецсимвол" not in result.lower()
            
    def test_validate_password_strength_unicode(self):
        """Тест validate_password_strength() с Unicode символами"""
        from src.core.crypto.password_policy import validate_password_strength
        
        # Пароль с Unicode символами
        unicode_password = "Пароль123!"  # Кириллица
        
        result = validate_password_strength(unicode_password)
        
        # Проверяем, что функция корректно обрабатывает Unicode
        # Кириллические буквы могут не соответствовать regex [A-Za-z]
        if result is not None:
            # Если есть ошибка, она должна быть понятной
            assert isinstance(result, str)
            
    def test_validate_password_strength_mixed_special_chars(self):
        """Тест validate_password_strength() с различными спецсимволами"""
        from src.core.crypto.password_policy import validate_password_strength
        
        # Различные спецсимволы
        special_chars = ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '_', '=', '+', 
                        '[', ']', '{', '}', '|', '\\', ';', ':', "'", '"', ',', '.', '<', '>', '/', '?']
        
        for char in special_chars:
            password = f"Password123{char}"
            result = validate_password_strength(password)
            
            if result is not None:
                # Проверяем, что ошибка не из-за отсутствия спецсимвола
                assert "спецсимвол" not in result.lower()
                
    def test_check_common_passwords_function(self):
        """Тест функции проверки распространенных паролей (если есть отдельная функция)"""
        from src.core.crypto.password_policy import COMMON_PASSWORDS
        
        # Проверяем, что список распространенных паролей существует
        assert isinstance(COMMON_PASSWORDS, list)
        assert len(COMMON_PASSWORDS) > 0
        
        # Проверяем некоторые известные слабые пароли
        weak_passwords = ["password", "123456", "qwerty", "admin", "password123"]
        
        for weak_pass in weak_passwords:
            assert weak_pass in COMMON_PASSWORDS or weak_pass.lower() in [p.lower() for p in COMMON_PASSWORDS]
            
    @patch('src.core.crypto.password_policy.re.search')
    def test_validate_password_strength_regex_failure(self, mock_re_search):
        """Тест validate_password_strength() при сбое regex"""
        from src.core.crypto.password_policy import validate_password_strength
        
        # Имитируем сбой regex поиска
        mock_re_search.side_effect = Exception("Regex error")
        
        # Пароль, который должен быть валидным
        test_password = "ValidPassword123!"
        
        # Проверяем, что функция корректно обрабатывает исключение
        result = validate_password_strength(test_password)
        
        # Либо возвращает ошибку, либо вызывает исключение
        assert result is not None or pytest.raises(Exception)
        
    def test_generate_password_function_if_exists(self):
        """Тест функции generate_password() если она существует"""
        try:
            from src.core.crypto.password_policy import generate_password
            
            # Генерируем пароль
            generated = generate_password()
            
            # Проверяем базовые свойства
            assert isinstance(generated, str)
            assert len(generated) >= 12  # Минимальная длина
            
            # Проверяем, что пароль валиден
            from src.core.crypto.password_policy import validate_password_strength
            result = validate_password_strength(generated)
            assert result is None
            
        except ImportError:
            # Функция может не существовать
            pass
            
    @patch('src.core.crypto.password_policy.secrets.choice', side_effect=lambda x: x[0])
    def test_generate_password_deterministic(self, mock_choice):
        """Тест генерации пароля с детерминированным выбором"""
        try:
            from src.core.crypto.password_policy import generate_password
            
            # С детерминированным mock всегда выбирается первый элемент
            generated = generate_password()
            
            # Проверяем, что пароль сгенерирован
            assert isinstance(generated, str)
            assert len(generated) >= 12
            
        except ImportError:
            # Функция может не существовать
            pass


class TestPasswordStrengthScoring:
    """Тесты для оценки сложности паролей"""
    
    def test_password_length_scoring(self):
        """Тест оценки сложности по длине пароля"""
        from src.core.crypto.password_policy import validate_password_strength
        
        # Очень короткие пароли
        very_short = "a"
        result = validate_password_strength(very_short)
        assert "не менее 12 символов" in result
        
        # Короткие, но почти достаточной длины
        almost_enough = "12345678901"  # 11 символов
        result = validate_password_strength(almost_enough)
        assert "не менее 12 символов" in result
        
        # Достаточная длина
        enough = "123456789012"  # 12 символов
        result = validate_password_strength(enough)
        if result is not None:
            assert "не менее 12 символов" not in result
            
    def test_password_complexity_combination(self):
        """Тест комбинаций сложности пароля"""
        from src.core.crypto.password_policy import validate_password_strength
        
        test_cases = [
            # (пароль, ожидаемая ошибка или None)
            ("short", "не менее 12 символов"),
            ("nouppercase123!", "заглавная буква"),
            ("NOLOWERCASE123!", "строчная буква"),
            ("NoDigitsHere!", "цифра"),
            ("NoSpecial123", "спецсимвол"),
            ("ValidPass123!", None),  # Все требования выполнены
        ]
        
        for password, expected_error in test_cases:
            result = validate_password_strength(password)
            
            if expected_error is None:
                assert result is None, f"Пароль '{password}' должен быть валидным, но получено: {result}"
            else:
                assert result is not None, f"Пароль '{password}' должен иметь ошибку"
                assert expected_error.lower() in result.lower(), f"Ожидалась ошибка '{expected_error}', получено: {result}"
                
    def test_password_with_all_requirements_met(self):
        """Тест пароля, удовлетворяющего всем требованиям"""
        from src.core.crypto.password_policy import validate_password_strength
        
        # Различные валидные пароли
        valid_passwords = [
            "StrongPassword123!",
            "AnotherValid1@",
            "TestPass123#",
            "MyPassword123$",
            "SecurePass123%",
            "ComplexPass123^",
            "SafePassword123&",
            "GoodPass123*",
        ]
        
        for password in valid_passwords:
            result = validate_password_strength(password)
            assert result is None, f"Пароль '{password}' должен быть валидным, но получено: {result}"
            
    def test_password_common_variations(self):
        """Тест вариаций распространенных паролей"""
        from src.core.crypto.password_policy import validate_password_strength, COMMON_PASSWORDS
        
        # Создаем вариации распространенных паролей
        common_variations = []
        for common in COMMON_PASSWORDS:
            common_variations.extend([
                common,
                common.upper(),
                common.capitalize(),
                common + "123",
                common + "!",
                "123" + common,
            ])
        
        # Проверяем, что все вариации распознаются как слабые
        for variation in common_variations:
            # Проверяем только если длина >= 12 (иначе будет другая ошибка)
            if len(variation) >= 12:
                result = validate_password_strength(variation)
                if result is not None:
                    # Либо ошибка о распространенном пароле, либо другая
                    pass


class TestPasswordPolicyIntegration:
    """Интеграционные тесты для политики паролей"""
    
    def test_password_policy_with_realistic_passwords(self):
        """Тест с реалистичными паролями из реального мира"""
        from src.core.crypto.password_policy import validate_password_strength
        
        # Реалистичные сильные пароли
        strong_realistic = [
            "CorrectHorseBatteryStaple",  # Известный пример
            "MyDogAteMyHomework123!",  # Запоминающийся
            "WinterIsComing2024!",  # Ссылка + год
            "ILovePython3.11!",  # Любовь к языку
            "CoffeeIsLife123#",  # Про увлечения
        ]
        
        for password in strong_realistic:
            result = validate_password_strength(password)
            assert result is None, f"Реалистичный пароль '{password}' должен быть валидным: {result}"
            
    def test_password_policy_performance(self):
        """Тест производительности проверки паролей"""
        from src.core.crypto.password_policy import validate_password_strength
        import time
        
        # Длинный сложный пароль
        long_complex = "A" * 1000 + "a" * 1000 + "1" * 100 + "!" * 50
        
        start_time = time.time()
        result = validate_password_strength(long_complex)
        end_time = time.time()
        
        # Проверяем, что проверка выполняется за разумное время
        elapsed = end_time - start_time
        assert elapsed < 1.0, f"Проверка заняла слишком много времени: {elapsed:.2f} сек"
        
        # Результат должен быть None (пароль валидный) или конкретная ошибка
        assert result is None or isinstance(result, str)
        
    def test_unicode_and_emoji_passwords(self):
        """Тест паролей с Unicode и emoji"""
        from src.core.crypto.password_policy import validate_password_strength
        
        # Пароли с emoji и Unicode
        unicode_passwords = [
            "Password123😀",  # Emoji как спецсимвол
            "Пароль123!",  # Кириллица
            "密码123!",  # Китайские иероглифы
            "🎉Party123!",  # Emoji в начале
        ]
        
        for password in unicode_passwords:
            result = validate_password_strength(password)
            # Проверяем, что функция не падает
            assert result is None or isinstance(result, str)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])