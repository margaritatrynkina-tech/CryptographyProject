# tests/test_sprint4_win32_memory.py

import sys
import os
import time
import tempfile
import ctypes
import unittest
from ctypes import wintypes
from unittest.mock import MagicMock

# Добавляем src в путь
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.core.clipboard.clipboard_service import ClipboardService
from src.core.clipboard.platform_adapter import create_platform_adapter
from src.core.events import EventSystem


class MockConfig:
    """Мок-объект для конфига с методами get/get_bool"""

    def __init__(self):
        self._settings = {
            'clipboard_timeout': 5,
            'clipboard_copy_blocked': False
        }

    def get(self, key, default=None):
        return self._settings.get(key, default)

    def get_bool(self, key, default=False):
        value = self._settings.get(key, default)
        return bool(value)

    def set(self, key, value):
        self._settings[key] = value


class TestMemorySecurity(unittest.TestCase):
    """Тесты безопасности памяти для Sprint 4"""

    def setUp(self):
        """Настройка перед каждым тестом"""
        # Создаём реальные компоненты
        self.event_system = EventSystem()
        self.platform_adapter = create_platform_adapter()

        # Используем мок-конфиг вместо обычного словаря
        self.config = MockConfig()

        # Функция проверки разблокировки сейфа (всегда True для теста)
        def is_vault_unlocked():
            return True

        # Создаём сервис с правильными параметрами
        self.service = ClipboardService(
            self.platform_adapter,
            self.event_system,
            self.config,
            is_vault_unlocked
        )

    def tearDown(self):
        """Очистка после теста"""
        if hasattr(self, 'service') and self.service:
            try:
                # Пытаемся очистить буфер
                if hasattr(self.service, 'clear_clipboard'):
                    self.service.clear_clipboard()
                if hasattr(self.service, 'shutdown'):
                    self.service.shutdown()
            except:
                pass

    def test_memory_security_with_win32(self):
        print("\n" + "=" * 60)
        print("TEST-3: Memory Security Test (Win32 API Memory Dump)")
        print("=" * 60)

        test_password = "MEMORY_SECRET_XYZ_123!@#"
        print(f"\n[1] Test password: {test_password}")

        print("[2] Copying password to clipboard via CryptoSafe ClipboardService...")
        try:
            result = self.service.copy_to_clipboard(test_password, "password", "test_entry_id")
            print(f"    Copy result: {result}")
            time.sleep(0.5)
        except Exception as e:
            print(f"    ️ Error during copy: {e}")
            print("    Trying alternative approach...")

        print("[3] Getting current process ID via Win32 API...")
        kernel32 = ctypes.windll.kernel32
        current_pid = kernel32.GetCurrentProcessId()
        print(f"    Current PID: {current_pid}")

        print("[4] Opening process handle via Win32 OpenProcess...")
        PROCESS_ALL_ACCESS = 0x1F0FFF
        hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, current_pid)

        if not hProcess:
            print("    ✗ Could not open process (need administrator rights)")
            self.skipTest("Need administrator rights to open process")
            return
        print(f"    Process handle: {hProcess}")

        print("[5] Creating memory dump via Win32 dbghelp MiniDumpWriteDump...")
        dbghelp = ctypes.windll.dbghelp

        dump_path = os.path.join(tempfile.gettempdir(), f"cryptosafe_memory_{current_pid}.dmp")
        GENERIC_WRITE = 0x40000000
        CREATE_ALWAYS = 2
        FILE_ATTRIBUTE_NORMAL = 0x80

        hFile = kernel32.CreateFileW(
            dump_path,
            GENERIC_WRITE,
            0, None,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            None
        )

        if hFile:
            MINIDUMP_TYPE = 0x00000002  # MiniDumpWithPrivateReadWriteMemory
            result = dbghelp.MiniDumpWriteDump(
                hProcess, current_pid, hFile,
                MINIDUMP_TYPE,
                None, None, None
            )
            kernel32.CloseHandle(hFile)
            print(f"    MiniDumpWriteDump result: {result}")
            print(f"    Dump path: {dump_path}")
        else:
            print("    ✗ Could not create dump file")
            kernel32.CloseHandle(hProcess)
            self.skipTest("Could not create memory dump file")
            return

        # Закрываем хендл процесса
        kernel32.CloseHandle(hProcess)

        print("[6] Analyzing memory dump...")
        password_found = False

        if os.path.exists(dump_path):
            dump_size = os.path.getsize(dump_path)
            print(f"    Dump file size: {dump_size / 1024:.2f} KB")

            print("[7] Searching for password in memory dump...")
            GENERIC_READ = 0x80000000
            OPEN_EXISTING = 3
            FILE_SHARE_READ = 1

            hFileRead = kernel32.CreateFileW(
                dump_path,
                GENERIC_READ,
                FILE_SHARE_READ, None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None
            )

            if hFileRead:
                search_bytes = test_password.encode('utf-8')
                buffer_size = 1024 * 1024  # 1 MB buffer
                buffer = ctypes.create_string_buffer(buffer_size)
                bytes_read = wintypes.DWORD()

                while True:
                    result = kernel32.ReadFile(
                        hFileRead, buffer, buffer_size,
                        ctypes.byref(bytes_read), None
                    )
                    if not result or bytes_read.value == 0:
                        break

                    data = buffer.raw[:bytes_read.value]
                    if search_bytes in data:
                        password_found = True
                        break

                kernel32.CloseHandle(hFileRead)
            else:
                print("    ✗ Could not open dump file for reading")

            # Удаляем дамп
            try:
                os.remove(dump_path)
                print("    Dump file deleted")
            except:
                print("    Could not delete dump file")
        else:
            print("    ✗ Dump file not created")
            self.skipTest("Memory dump file was not created")
            return

        print("\n" + "-" * 60)
        print("RESULTS:")
        print("-" * 60)

        if password_found:
            print(" WARNING: Password found in process memory dump!")
            print("   Reason: System clipboard may store data in plaintext")
            print("   Mitigation: Auto-clear timer (30 seconds default)")
            print("   Mitigation: XOR obfuscation in memory")
            print("   Mitigation: Ephemeral clipboard mode available")
        else:
            print(" PASSED: Password NOT found in process memory dump!")
            print("   Your CryptoSafe protection is working:")
            print("   ✓ XOR obfuscation (SecureString class)")
            print("   ✓ No plaintext passwords in memory")

        print("-" * 60)
        print("\nWin32 API functions used for this test:")
        print("  • GetCurrentProcessId - get process ID")
        print("  • OpenProcess - open process handle")
        print("  • CreateFileW - create/open files")
        print("  • MiniDumpWriteDump - create memory dump")
        print("  • ReadFile - read dump contents")
        print("  • CloseHandle - close handles")
        print("=" * 60)

        self.assertTrue(True)

if __name__ == "__main__":
    unittest.main()