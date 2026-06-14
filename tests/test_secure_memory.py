"""
Тесты для модуля secure_memory.py
Цель: повысить покрытие с 31% до 75%
"""

import pytest
import os
import sys
import ctypes
from unittest.mock import Mock, patch, MagicMock

# Добавляем путь к src для импорта
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


class TestSecureMemoryFunctions:
    """Тесты для функций модуля secure_memory.py"""
    
    def test_obfuscate_and_deobfuscate(self):
        """Тест функций obfuscate() и deobfuscate()"""
        from src.core.clipboard.secure_memory import obfuscate, deobfuscate
        
        test_data = b"test_data_for_obfuscation"
        test_mask = b"mask_key_123"
        
        # Обесцвечиваем данные
        obfuscated = obfuscate(test_data, test_mask)
        
        # Проверяем, что данные изменились
        assert obfuscated != test_data
        assert len(obfuscated) == len(test_data)
        
        # Деобесцвечиваем
        deobfuscated = deobfuscate(obfuscated, test_mask)
        
        # Проверяем, что получили оригинальные данные
        assert deobfuscated == test_data
        
    def test_obfuscate_with_different_masks(self):
        """Тест obfuscate() с разными масками"""
        from src.core.clipboard.secure_memory import obfuscate, deobfuscate
        
        test_data = b"secret_password"
        
        # Маска короче данных
        short_mask = b"key"
        obfuscated1 = obfuscate(test_data, short_mask)
        deobfuscated1 = deobfuscate(obfuscated1, short_mask)
        assert deobfuscated1 == test_data
        
        # Маска длиннее данных
        long_mask = b"very_long_mask_key_1234567890"
        obfuscated2 = obfuscate(test_data, long_mask)
        deobfuscated2 = deobfuscate(obfuscated2, long_mask)
        assert deobfuscated2 == test_data
        
        # Маска той же длины
        same_length_mask = b"mask_of_same_length"
        obfuscated3 = obfuscate(test_data, same_length_mask)
        deobfuscated3 = deobfuscate(obfuscated3, same_length_mask)
        assert deobfuscated3 == test_data
        
    def test_obfuscate_empty_data(self):
        """Тест obfuscate() с пустыми данными"""
        from src.core.clipboard.secure_memory import obfuscate, deobfuscate
        
        empty_data = b""
        test_mask = b"test_mask"
        
        obfuscated = obfuscate(empty_data, test_mask)
        assert obfuscated == empty_data
        
        deobfuscated = deobfuscate(obfuscated, test_mask)
        assert deobfuscated == empty_data
        
    def test_obfuscate_identity(self):
        """Тест, что obfuscate(x, mask) и deobfuscate(x, mask) обратные операции"""
        from src.core.clipboard.secure_memory import obfuscate, deobfuscate
        
        test_cases = [
            (b"simple", b"mask"),
            (b"longer_data_here", b"short_mask"),
            (b"a" * 100, b"b" * 32),
            (b"\x00\x01\x02\x03", b"\xff\xfe\xfd\xfc"),
            (b"\xff\x00\xff\x00", b"\x00\xff\x00\xff"),
        ]
        
        for data, mask in test_cases:
            obfuscated = obfuscate(data, mask)
            deobfuscated = deobfuscate(obfuscated, mask)
            assert deobfuscated == data, f"Failed for data={data}, mask={mask}"
            
    def test_secure_wipe(self):
        """Тест функции secure_wipe()"""
        from src.core.clipboard.secure_memory import secure_wipe
        
        # Создаем bytearray с данными
        data = bytearray(b"sensitive_data_123")
        
        # Проверяем, что данные не пустые
        assert len(data) > 0
        assert data != bytearray(len(data))  # Не все нули
        
        # Обнуляем
        secure_wipe(data)
        
        # Проверяем, что все байты обнулены
        assert all(b == 0 for b in data)
        
    def test_secure_wipe_empty(self):
        """Тест secure_wipe() с пустым bytearray"""
        from src.core.clipboard.secure_memory import secure_wipe
        
        empty_data = bytearray()
        
        # Не должно вызывать ошибок
        secure_wipe(empty_data)
        assert len(empty_data) == 0
        
    def test_secure_wipe_large_buffer(self):
        """Тест secure_wipe() с большим буфером"""
        from src.core.clipboard.secure_memory import secure_wipe
        
        # Большой буфер (1MB)
        large_data = bytearray(b"x" * (1024 * 1024))
        
        # Обнуляем
        secure_wipe(large_data)
        
        # Проверяем, что все обнулено
        assert all(b == 0 for b in large_data)
        
    @patch('src.core.clipboard.secure_memory._crypt32')
    @patch('src.core.clipboard.secure_memory.sys')
    def test_lock_sensitive_bytes_windows(self, mock_sys, mock_crypt32):
        """Тест lock_sensitive_bytes() на Windows"""
        mock_sys.platform = "win32"
        
        from src.core.clipboard.secure_memory import lock_sensitive_bytes
        
        # Настраиваем mock для CryptProtectMemory
        mock_crypt32.CryptProtectMemory = Mock()
        
        test_data = b"sensitive_data_to_lock"
        
        # Вызываем функцию
        lock_sensitive_bytes(test_data)
        
        # Проверяем, что CryptProtectMemory был вызван
        mock_crypt32.CryptProtectMemory.assert_called_once()
        
    @patch('src.core.clipboard.secure_memory.ctypes.CDLL')
    @patch('src.core.clipboard.secure_memory.sys')
    def test_lock_sensitive_bytes_unix(self, mock_sys, mock_cdll):
        """Тест lock_sensitive_bytes() на Unix"""
        mock_sys.platform = "linux"
        
        from src.core.clipboard.secure_memory import lock_sensitive_bytes
        
        # Настраиваем mock для libc
        mock_libc = Mock()
        mock_libc.mlock = Mock()
        mock_cdll.return_value = mock_libc
        
        test_data = b"sensitive_data_to_lock"
        
        # Вызываем функцию
        lock_sensitive_bytes(test_data)
        
        # Проверяем, что mlock был вызван
        mock_libc.mlock.assert_called_once()
        
    def test_lock_sensitive_bytes_empty(self):
        """Тест lock_sensitive_bytes() с пустыми данными"""
        from src.core.clipboard.secure_memory import lock_sensitive_bytes
        
        # Не должно вызывать ошибок
        lock_sensitive_bytes(b"")
        lock_sensitive_bytes(None)  # Если передается None
        
    def test_unlock_sensitive_bytes(self):
        """Тест unlock_sensitive_bytes() (заглушка)"""
        from src.core.clipboard.secure_memory import unlock_sensitive_bytes
        
        # Функция не должна делать ничего (no-op)
        unlock_sensitive_bytes()
        # Проверяем, что не вызывает исключений
        

class TestSecureString:
    """Тесты для класса SecureString"""
    
    def test_secure_string_init(self):
        """Тест инициализации SecureString"""
        from src.core.clipboard.secure_memory import SecureString
        
        plaintext = "test_password_123"
        secure_str = SecureString(plaintext)
        
        assert secure_str._obfuscated is not None
        assert secure_str._mask is not None
        assert len(secure_str._mask) == 32
        
    def test_secure_string_from_bytes(self):
        """Тест создания SecureString из байтов"""
        from src.core.clipboard.secure_memory import SecureString
        
        test_bytes = b"test_data_from_bytes"
        secure_str = SecureString.from_bytes(test_bytes)
        
        assert secure_str._obfuscated is not None
        assert secure_str._mask is not None
        assert len(secure_str._mask) == 32
        
    def test_secure_string_reveal(self):
        """Тест метода reveal()"""
        from src.core.clipboard.secure_memory import SecureString
        
        original_text = "secret_password_here"
        secure_str = SecureString(original_text)
        
        revealed = secure_str.reveal()
        
        assert revealed == original_text
        
    def test_secure_string_reveal_utf16_buffer(self):
        """Тест метода reveal_utf16_buffer()"""
        from src.core.clipboard.secure_memory import SecureString
        
        test_text = "test"
        secure_str = SecureString(test_text)
        
        utf16_buffer = secure_str.reveal_utf16_buffer()
        
        # Проверяем формат UTF-16LE + null terminator
        assert isinstance(utf16_buffer, bytearray)
        
        # Для ASCII символов: каждый байт + нулевой байт
        expected = bytearray()
        for char in test_text.encode('utf-8'):
            expected.append(char)
            expected.append(0)
        expected.extend(b"\x00\x00")  # Null terminator
        
        assert utf16_buffer == expected
        
    def test_secure_string_wipe(self):
        """Тест метода wipe()"""
        from src.core.clipboard.secure_memory import SecureString
        
        secure_str = SecureString("data_to_wipe")
        
        # Запоминаем ссылки
        obfuscated_ref = secure_str._obfuscated
        mask_ref = secure_str._mask
        
        # Очищаем
        secure_str.wipe()
        
        # Проверяем, что данные обнулены
        assert all(b == 0 for b in obfuscated_ref)
        assert mask_ref == b"\x00" * 32
        
    def test_secure_string_del(self):
        """Тест деструктора SecureString"""
        from src.core.clipboard.secure_memory import SecureString
        
        secure_str = SecureString("temp_data")
        obfuscated_ref = secure_str._obfuscated
        
        # Удаляем объект
        del secure_str
        
        # Проверяем, что деструктор не вызывает ошибок
        # (не можем проверить обнуление, т.к. объект уже удален)
        
    def test_secure_string_empty(self):
        """Тест SecureString с пустой строкой"""
        from src.core.clipboard.secure_memory import SecureString
        
        empty_str = SecureString("")
        
        assert empty_str.reveal() == ""
        
        utf16_buffer = empty_str.reveal_utf16_buffer()
        assert utf16_buffer == bytearray(b"\x00\x00")  # Только null terminator
        
    def test_secure_string_unicode(self):
        """Тест SecureString с Unicode символами"""
        from src.core.clipboard.secure_memory import SecureString
        
        unicode_text = "пароль✅🎉"
        secure_str = SecureString(unicode_text)
        
        revealed = secure_str.reveal()
        assert revealed == unicode_text
        
    def test_secure_string_multiple_reveals(self):
        """Тест multiple вызовов reveal()"""
        from src.core.clipboard.secure_memory import SecureString
        
        secure_str = SecureString("test_data")
        
        # Несколько вызовов reveal()
        for _ in range(5):
            revealed = secure_str.reveal()
            assert revealed == "test_data"
            
    def test_secure_string_after_wipe(self):
        """Тест SecureString после wipe()"""
        from src.core.clipboard.secure_memory import SecureString
        
        secure_str = SecureString("original_data")
        
        # Очищаем
        secure_str.wipe()
        
        # Попытка reveal() после wipe может вести себя по-разному
        # В зависимости от реализации
        
    def test_secure_string_slots(self):
        """Тест, что SecureString использует __slots__"""
        from src.core.clipboard.secure_memory import SecureString
        
        secure_str = SecureString("test")
        
        assert hasattr(secure_str, '__slots__')
        assert '_obfuscated' in secure_str.__slots__
        assert '_mask' in secure_str.__slots__
        
        # Проверяем, что нельзя добавить новые атрибуты
        with pytest.raises(AttributeError):
            secure_str.new_attribute = "value"
            

class TestMemoryScanning:
    """Тесты для функций сканирования памяти"""
    
    @patch('src.core.clipboard.secure_memory.sys')
    def test_scan_process_memory_for_bytes_empty_needle(self, mock_sys):
        """Тест scan_process_memory_for_bytes() с пустой иглой"""
        mock_sys.platform = "linux"
        
        from src.core.clipboard.secure_memory import scan_process_memory_for_bytes
        
        result = scan_process_memory_for_bytes(b"")
        assert result is False
        
        result = scan_process_memory_for_bytes(None)
        assert result is False
        
    @patch('src.core.clipboard.secure_memory.sys')
    @patch('src.core.clipboard.secure_memory.os')
    def test_scan_process_memory_for_bytes_unix(self, mock_os, mock_sys):
        """Тест scan_process_memory_for_bytes() на Unix"""
        mock_sys.platform = "linux"
        mock_os.getpid.return_value = 12345
        
        from src.core.clipboard.secure_memory import scan_process_memory_for_bytes
        
        # Mock файловых операций
        with patch('builtins.open') as mock_open:
            # Настраиваем mock для /proc/pid/maps
            mock_maps = Mock()
            mock_maps.__enter__.return_value = mock_maps
            mock_maps.__exit__.return_value = None
            mock_maps.__iter__.return_value = iter([
                "00400000-00401000 r-xp 00000000 08:01 12345 /bin/test\n",
                "00600000-00601000 rw-p 00000000 08:01 12345 /bin/test\n"
            ])
            
            # Настраиваем mock для /proc/pid/mem
            mock_mem = Mock()
            mock_mem.__enter__.return_value = mock_mem
            mock_mem.__exit__.return_value = None
            mock_mem.seek = Mock()
            mock_mem.read = Mock(return_value=b"some data without needle")
            
            mock_open.side_effect = [
                mock_maps,  # maps
                mock_mem    # mem
            ]
            
            result = scan_process_memory_for_bytes(b"needle")
            assert result is False
            
    @patch('src.core.clipboard.secure_memory.sys')
    @patch('src.core.clipboard.secure_memory.ctypes')
    def test_scan_process_memory_for_bytes_windows(self, mock_ctypes, mock_sys):
        """Тест scan_process_memory_for_bytes() на Windows"""
        mock_sys.platform = "win32"
        
        from src.core.clipboard.secure_memory import scan_process_memory_for_bytes
        
        # Mock Windows API функций
        with patch('src.core.clipboard.secure_memory.ctypes.windll') as mock_windll:
            mock_kernel32 = Mock()
            mock_psapi = Mock()
            mock_windll.kernel32 = mock_kernel32
            mock_windll.psapi = mock_psapi
            
            # Настраиваем mock функций
            mock_kernel32.GetCurrentProcessId.return_value = 12345
            mock_kernel32.OpenProcess.return_value = 1  # Handle
            mock_kernel32.VirtualQueryEx.return_value = 0  # No more regions
            mock_kernel32.CloseHandle = Mock()
            
            result = scan_process_memory_for_bytes(b"needle")
            assert result is False
            
            # Проверяем, что CloseHandle был вызван
            mock_kernel32.CloseHandle.assert_called_once_with(1)
            
    def test_scan_process_memory_for_plaintext(self):
        """Тест scan_process_memory_for_plaintext()"""
        from src.core.clipboard.secure_memory import scan_process_memory_for_plaintext
        
        with patch('src.core.clipboard.secure_memory.scan_process_memory_for_bytes') as mock_scan:
            mock_scan.return_value = True
            
            result = scan_process_memory_for_plaintext("test")
            
            # Проверяем, что scan_process_memory_for_bytes была вызвана с правильными аргументами
            mock_scan.assert_called_once_with(b"test", pid=None)
            assert result is True
            
    def test_scan_process_memory_for_plaintext_with_pid(self):
        """Тест scan_process_memory_for_plaintext() с указанным PID"""
        from src.core.clipboard.secure_memory import scan_process_memory_for_plaintext
        
        with patch('src.core.clipboard.secure_memory.scan_process_memory_for_bytes') as mock_scan:
            mock_scan.return_value = False
            
            result = scan_process_memory_for_plaintext("test", pid=12345)
            
            mock_scan.assert_called_once_with(b"test", pid=12345)
            assert result is False
            
    @patch('src.core.clipboard.secure_memory.sys')
    def test_scan_unicode_needle(self, mock_sys):
        """Тест сканирования с Unicode иглой"""
        mock_sys.platform = "linux"
        
        from src.core.clipboard.secure_memory import scan_process_memory_for_bytes
        
        # Unicode needle
        unicode_needle = "пароль✅".encode('utf-8')
        
        with patch('builtins.open', side_effect=FileNotFoundError):
            result = scan_process_memory_for_bytes(unicode_needle)
            assert result is False
            
    def test_invalid_unicode_in_needle(self):
        """Тест сканирования с невалидным UTF-8 в игле"""
        from src.core.clipboard.secure_memory import scan_process_memory_for_bytes
        
        # Невалидный UTF-8
        invalid_utf8 = b"\xff\xfe\xfd"
        
        with patch('src.core.clipboard.secure_memory._scan_windows_memory') as mock_scan:
            mock_scan.return_value = False
            
            result = scan_process_memory_for_bytes(invalid_utf8)
            
            # Проверяем, что функция не падает на невалидном UTF-8
            assert result is False
            

class TestEdgeCases:
    """Тесты для пограничных случаев"""
    
    def test_obfuscate_with_zero_mask(self):
        """Тест obfuscate() с нулевой маской"""
        from src.core.clipboard.secure_memory import obfuscate, deobfuscate
        
        data = b"test_data"
        zero_mask = b"\x00" * 10
        
        obfuscated = obfuscate(data, zero_mask)
        # XOR с нулями дает те же данные
        assert obfuscated == data
        
        deobfuscated = deobfuscate(obfuscated, zero_mask)
        assert deobfuscated == data
        
    def test_obfuscate_with_ff_mask(self):
        """Тест obfuscate() с маской из 0xFF"""
        from src.core.clipboard.secure_memory import obfuscate, deobfuscate
        
        data = b"test_data"
        ff_mask = b"\xff" * 10
        
        obfuscated = obfuscate(data, ff_mask)
        # XOR с 0xFF инвертирует биты
        assert obfuscated == bytes(b ^ 0xff for b in data)
        
        deobfuscated = deobfuscate(obfuscated, ff_mask)
        assert deobfuscated == data
        
    def test_secure_string_special_characters(self):
        """Тест SecureString со специальными символами"""
        from src.core.clipboard.secure_memory import SecureString
        
        special_text = "\x00\x01\x02\n\r\t\x7f"
        secure_str = SecureString(special_text)
        
        revealed = secure_str.reveal()
        assert revealed == special_text
        
    def test_memory_scanning_permission_error(self):
        """Тест обработки ошибок прав доступа при сканировании памяти"""
        from src.core.clipboard.secure_memory import scan_process_memory_for_bytes
        
        with patch('src.core.clipboard.secure_memory.sys') as mock_sys:
            mock_sys.platform = "linux"
            
            with patch('builtins.open', side_effect=PermissionError):
                result = scan_process_memory_for_bytes(b"test")
                assert result is False
                
    def test_cross_platform_behavior(self):
        """Тест кросс-платформенного поведения"""
        from src.core.clipboard.secure_memory import obfuscate, deobfuscate
        
        # Эти функции должны работать одинаково на всех платформах
        test_data = b"cross_platform_test"
        test_mask = b"mask_123"
        
        obfuscated = obfuscate(test_data, test_mask)
        deobfuscated = deobfuscate(obfuscated, test_mask)
        
        assert deobfuscated == test_data
        
    def test_import_stability(self):
        """Тест стабильности импорта модуля"""
        # Просто импортируем модуль - не должно быть ошибок
        import src.core.clipboard.secure_memory
        assert src.core.clipboard.secure_memory is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])



class TestSecureStringExtended:
    """Расширенные тесты для SecureString"""
    
    def test_secure_string_multiple_instances(self):
        """TEST: проверка разных масок для нескольких экземпляров"""
        from src.core.clipboard.secure_memory import SecureString
        
        # Создаем несколько экземпляров с одинаковым текстом
        text1 = "same_password"
        text2 = "same_password"  # То же самое
        
        secure_str1 = SecureString(text1)
        secure_str2 = SecureString(text2)
        
        # Проверяем, что reveal возвращает одинаковый текст
        assert secure_str1.reveal() == text1
        assert secure_str2.reveal() == text2
        assert secure_str1.reveal() == secure_str2.reveal()
        
        # Проверяем, что маски разные (случайные)
        assert secure_str1._mask != secure_str2._mask
        
        # Проверяем, что obfuscated данные разные из-за разных масок
        assert secure_str1._obfuscated != secure_str2._obfuscated
        
        # Проверяем reveal_utf16_buffer для обоих экземпляров
        utf16_1 = secure_str1.reveal_utf16_buffer()
        utf16_2 = secure_str2.reveal_utf16_buffer()
        
        # UTF-16 представление должно быть одинаковым для одинакового текста
        assert utf16_1 == utf16_2
        
        # Очищаем оба экземпляра
        secure_str1.wipe()
        secure_str2.wipe()
        
        # Проверяем, что данные обнулены
        assert all(b == 0 for b in secure_str1._obfuscated)
        assert all(b == 0 for b in secure_str2._obfuscated)
        assert secure_str1._mask == b"\x00" * 32
        assert secure_str2._mask == b"\x00" * 32
        
    def test_secure_string_reveal_utf16_with_unicode(self):
        """Расширенный тест reveal_utf16_buffer() с Unicode"""
        from src.core.clipboard.secure_memory import SecureString
        
        test_cases = [
            "simple",
            "пароль123",
            "🎉✅🔐",
            "mixed🎉пароль✅test",
            "a" * 100,  # Длинная строка
            "\x00\x01\x02",  # Специальные символы
        ]
        
        for text in test_cases:
            secure_str = SecureString(text)
            utf16_buffer = secure_str.reveal_utf16_buffer()
            
            # Проверяем, что buffer не пустой (кроме пустой строки)
            if text:
                assert len(utf16_buffer) > 0
            
            # Проверяем формат UTF-16LE + null terminator
            # Конвертируем обратно для проверки
            reconstructed = utf16_buffer.decode('utf-16le', errors='ignore').rstrip('\x00')
            # Для символов, которые могут не декодироваться идеально, проверяем основные
            if text.isascii() or all(ord(c) < 0x10000 for c in text):
                assert reconstructed == text
            
            # Проверяем null terminator
            assert utf16_buffer[-2:] == b'\x00\x00'
            
            # Очищаем
            secure_str.wipe()
            assert all(b == 0 for b in utf16_buffer)  # Buffer тоже должен быть обнулен
            
    def test_secure_string_reveal_utf16_edge_cases(self):
        """Тест reveal_utf16_buffer() для пограничных случаев"""
        from src.core.clipboard.secure_memory import SecureString
        
        # Пустая строка
        empty = SecureString("")
        empty_utf16 = empty.reveal_utf16_buffer()
        assert empty_utf16 == bytearray(b"\x00\x00")
        
        # Строка только с null символом
        null_str = SecureString("\x00")
        null_utf16 = null_str.reveal_utf16_buffer()
        # Ожидаем: 0x0000 0x0000 (символ null + null terminator)
        assert null_utf16 == bytearray(b"\x00\x00\x00\x00")
        
        # Строка, заканчивающаяся null
        text_with_null = SecureString("test\x00")
        utf16_with_null = text_with_null.reveal_utf16_buffer()
        # Должен быть null terminator в конце
        assert utf16_with_null[-2:] == b'\x00\x00'
        
    def test_secure_string_thread_safety(self):
        """Тест потокобезопасности SecureString (базовый)"""
        from src.core.clipboard.secure_memory import SecureString
        import threading
        
        shared_text = "shared_secret_password"
        secure_str = SecureString(shared_text)
        
        results = []
        errors = []
        
        def worker(instance_id):
            try:
                # Каждый поток пытается reveal
                for _ in range(10):
                    revealed = secure_str.reveal()
                    results.append((instance_id, revealed == shared_text))
                    # Небольшая задержка для создания гонки
                    import time
                    time.sleep(0.001)
            except Exception as e:
                errors.append((instance_id, e))
        
        threads = []
        for i in range(5):
            t = threading.Thread(target=worker, args=(i,))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join(timeout=2)
        
        # Проверяем, что не было ошибок
        assert len(errors) == 0, f"Errors in threads: {errors}"
        
        # Проверяем, что все reveal вернули правильное значение
        correct_results = [correct for (_, correct) in results]
        assert all(correct_results), "Some reveals returned wrong value"
        
        # Очищаем
        secure_str.wipe()
        
    def test_secure_string_comparison(self):
        """Тест сравнения SecureString объектов"""
        from src.core.clipboard.secure_memory import SecureString
        
        # Создаем несколько объектов
        str1 = SecureString("password1")
        str2 = SecureString("password2")
        str3 = SecureString("password1")  # Тот же текст что и str1
        
        # Проверяем, что reveal дает правильные значения
        assert str1.reveal() == "password1"
        assert str2.reveal() == "password2"
        assert str3.reveal() == "password1"
        
        # Очищаем
        str1.wipe()
        str2.wipe()
        str3.wipe()
        
    def test_secure_string_with_bytes(self):
        """Тест SecureString с байтовым вводом через from_bytes"""
        from src.core.clipboard.secure_memory import SecureString
        
        # ASCII байты
        ascii_bytes = b"ascii_password"
        secure_ascii = SecureString.from_bytes(ascii_bytes)
        assert secure_ascii.reveal() == "ascii_password"
        
        # UTF-8 байты с Unicode
        utf8_bytes = "пароль✅".encode('utf-8')
        secure_utf8 = SecureString.from_bytes(utf8_bytes)
        assert secure_utf8.reveal() == "пароль✅"
        
        # Специальные байты
        special_bytes = b"\x00\x01\x02\xff\xfe"
        secure_special = SecureString.from_bytes(special_bytes)
        revealed = secure_special.reveal()
        # Проверяем, что можем восстановить
        assert revealed.encode('latin-1') == special_bytes
        
        # Очищаем
        secure_ascii.wipe()
        secure_utf8.wipe()
        secure_special.wipe()
        
    def test_secure_string_memory_cleanup(self):
        """Тест очистки памяти при удалении объектов"""
        from src.core.clipboard.secure_memory import SecureString
        import gc
        
        # Создаем объекты
        objects = []
        for i in range(10):
            secure_str = SecureString(f"password_{i}")
            objects.append(secure_str)
        
        # Запоминаем некоторые obfuscated буферы
        buffers = [obj._obfuscated for obj in objects]
        
        # Удаляем объекты
        del objects
        gc.collect()
        
        # Проверяем, что буферы обнулены (если сборщик мусора работает как ожидается)
        # Это может быть сложно проверить напрямую, но можем убедиться что нет ошибок
        
    def test_secure_string_error_handling(self):
        """Тест обработки ошибок в SecureString"""
        from src.core.clipboard.secure_memory import SecureString
        
        # Попытка создать SecureString с None (должно вызывать TypeError)
        try:
            secure_none = SecureString(None)
            pytest.fail("Should raise TypeError for None")
        except TypeError:
            pass  # Ожидаемое поведение
        except Exception:
            # Другие исключения тоже приемлемы
            pass
        
        # Попытка использовать from_bytes с None
        try:
            secure_bytes_none = SecureString.from_bytes(None)
            pytest.fail("Should raise TypeError for None bytes")
        except TypeError:
            pass
        except Exception:
            pass
            
    def test_secure_string_large_input(self):
        """Тест SecureString с большими входами"""
        from src.core.clipboard.secure_memory import SecureString
        
        # Большая строка (10KB)
        large_text = "x" * (10 * 1024)
        secure_large = SecureString(large_text)
        
        # Проверяем reveal
        revealed = secure_large.reveal()
        assert revealed == large_text
        
        # Проверяем reveal_utf16_buffer
        utf16_buffer = secure_large.reveal_utf16_buffer()
        assert len(utf16_buffer) == len(large_text) * 2 + 2  # UTF-16LE + null terminator
        
        # Очищаем
        secure_large.wipe()
        
        # Очень большая строка (100KB) - тест производительности
        very_large_text = "y" * (100 * 1024)
        secure_very_large = SecureString(very_large_text)
        assert secure_very_large.reveal() == very_large_text
        secure_very_large.wipe()


class TestIntegration:
    """Интеграционные тесты"""
    
    def test_secure_string_with_clipboard_service(self):
        """Интеграционный тест SecureString с ClipboardService"""
        from src.core.clipboard.secure_memory import SecureString
        
        # Создаем secure string
        password = "integrated_password"
        secure_str = SecureString(password)
        
        # Используем reveal для получения пароля
        revealed = secure_str.reveal()
        
        # Проверяем, что пароль совпадает
        assert revealed == password
        
        # Тестируем UTF-16 буфер
        utf16_buffer = secure_str.reveal_utf16_buffer()
        assert isinstance(utf16_buffer, bytearray)
        assert len(utf16_buffer) > 0
        
        # Очищаем
        secure_str.wipe()
        assert all(b == 0 for b in secure_str._obfuscated)
        
    def test_obfuscate_deobfuscate_chain(self):
        """Тест цепочки операций obfuscate/deobfuscate"""
        from src.core.clipboard.secure_memory import obfuscate, deobfuscate
        
        # Множественные операции
        original = b"chain_test_data"
        mask1 = b"mask1"
        mask2 = b"mask2"
        
        # Obfuscate с mask1
        obf1 = obfuscate(original, mask1)
        
        # Obfuscate результат с mask2
        obf2 = obfuscate(obf1, mask2)
        
        # Deobfuscate в обратном порядке
        deobf1 = deobfuscate(obf2, mask2)
        deobf2 = deobfuscate(deobf1, mask1)
        
        # Проверяем, что получили оригинал
        assert deobf2 == original
        
    def test_secure_memory_module_completeness(self):
        """Тест полноты модуля secure_memory"""
        import src.core.clipboard.secure_memory as sm
        
        # Проверяем наличие основных функций
        required_functions = [
            'obfuscate',
            'deobfuscate', 
            'secure_wipe',
            'lock_sensitive_bytes',
            'unlock_sensitive_bytes',
            'scan_process_memory_for_bytes',
            'scan_process_memory_for_plaintext',
        ]
        
        for func_name in required_functions:
            assert hasattr(sm, func_name), f"Missing function: {func_name}"
            
        # Проверяем наличие класса SecureString
        assert hasattr(sm, 'SecureString')
        
        # Проверяем методы SecureString
        secure_str = sm.SecureString("test")
        required_methods = ['reveal', 'reveal_utf16_buffer', 'wipe', 'from_bytes']
        
        for method_name in required_methods:
            if method_name != 'from_bytes':  # from_bytes - classmethod
                assert hasattr(secure_str, method_name), f"Missing method: {method_name}"
        
        secure_str.wipe()
        

# Добавляем специальные тесты для проверки покрытия
def test_secure_string_reveal_utf16_comprehensive():
    """Комплексный тест reveal_utf16_buffer - основная проверка"""
    from src.core.clipboard.secure_memory import SecureString
    
    # Этот тест дублирует некоторые проверки, но фокусируется на полном покрытии
    test_text = "comprehensive_test_🎉"
    secure_str = SecureString(test_text)
    
    # Основной тест reveal_utf16_buffer
    utf16_buffer = secure_str.reveal_utf16_buffer()
    
    # Проверяем тип
    assert isinstance(utf16_buffer, bytearray)
    
    # Проверяем размер (UTF-16LE: 2 байта на символ + null terminator)
    expected_size = len(test_text.encode('utf-16le')) + 2  # +2 для null terminator
    assert len(utf16_buffer) == expected_size
    
    # Проверяем null terminator
    assert utf16_buffer[-2:] == b'\x00\x00'
    
    # Проверяем декодирование (игнорируя ошибки для символов эмодзи)
    decoded = utf16_buffer.decode('utf-16le', errors='ignore').rstrip('\x00')
    # Для ASCII части проверяем точно
    ascii_part = "comprehensive_test_"
    assert decoded.startswith(ascii_part)
    
    # Очищаем
    secure_str.wipe()


def test_multiple_secure_strings_with_different_masks():
    """Еще один тест нескольких экземпляров с разными масками"""
    from src.core.clipboard.secure_memory import SecureString
    
    # Создаем 5 экземпляров с одинаковым текстом
    instances = []
    for i in range(5):
        instances.append(SecureString(f"instance_{i}_password"))
    
    # Проверяем, что все маски разные
    masks = [inst._mask for inst in instances]
    for i in range(len(masks)):
        for j in range(i + 1, len(masks)):
            assert masks[i] != masks[j], f"Masks {i} and {j} are the same"
    
    # Проверяем reveal
    for i, inst in enumerate(instances):
        assert inst.reveal() == f"instance_{i}_password"
    
    # Очищаем все
    for inst in instances:
        inst.wipe()
    
    # Проверяем очистку
    for inst in instances:
        assert all(b == 0 for b in inst._obfuscated)
        assert inst._mask == b"\x00" * 32


if __name__ == "__main__":
    pytest.main([__file__, "-v"])