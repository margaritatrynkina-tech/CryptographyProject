import subprocess
import time
import os
import sys
import tempfile
import ctypes
from ctypes import wintypes

# Добавляем путь к проекту
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


class LiveMemoryTest:

    def __init__(self):
        self.pid = None
        self.test_password = "LIVE_SECURITY_TEST_123"

    def find_cryptosafe_pid(self):
        import ctypes
        from ctypes import wintypes

        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32

        # Находим окно по названию
        hwnd = user32.FindWindowW(None, "CryptoSafe Manager v1.0")
        if not hwnd:
            hwnd = user32.FindWindowW(None, "CryptoSafe")

        if hwnd:
            pid = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            return pid.value

        return None

    def create_memory_dump(self, pid):

        kernel32 = ctypes.windll.kernel32
        dbghelp = ctypes.windll.dbghelp

        PROCESS_ALL_ACCESS = 0x1F0FFF
        hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)

        if not hProcess:
            return None

        dump_path = os.path.join(tempfile.gettempdir(), f"cryptosafe_live_{pid}.dmp")

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
            MINIDUMP_TYPE = 0x00000002
            result = dbghelp.MiniDumpWriteDump(
                hProcess, pid, hFile,
                MINIDUMP_TYPE,
                None, None, None
            )
            kernel32.CloseHandle(hFile)
            kernel32.CloseHandle(hProcess)

            if result:
                return dump_path

        kernel32.CloseHandle(hProcess)
        return None

    def search_password_in_dump(self, dump_path, password):

        if not os.path.exists(dump_path):
            return False

        kernel32 = ctypes.windll.kernel32

        GENERIC_READ = 0x80000000
        OPEN_EXISTING = 3
        FILE_SHARE_READ = 1

        hFile = kernel32.CreateFileW(
            dump_path,
            GENERIC_READ,
            FILE_SHARE_READ, None,
            OPEN_EXISTING,
            0x80, None
        )

        if not hFile:
            return False

        search_utf8 = password.encode('utf-8')
        search_utf16 = password.encode('utf-16le')

        found = False
        buffer_size = 1024 * 1024
        buffer = ctypes.create_string_buffer(buffer_size)
        bytes_read = wintypes.DWORD()

        while True:
            result = kernel32.ReadFile(
                hFile, buffer, buffer_size,
                ctypes.byref(bytes_read), None
            )
            if not result or bytes_read.value == 0:
                break

            data = buffer.raw[:bytes_read.value]
            if search_utf8 in data or search_utf16 in data:
                found = True
                break

        kernel32.CloseHandle(hFile)
        return found

    def run(self):

        print("\n" + "=" * 60)
        print("TEST-3: LIVE MEMORY SECURITY TEST")
        print("=" * 60)

        # Ждём, пока пользователь подготовит программу
        print("\n[1] Подготовка:")
        print("    - Запустите CryptoSafe Manager в PyCharm")
        print("    - Разблокируйте сейф")
        print(f"    - Скопируйте тестовый пароль: {self.test_password}")
        print("\n    Нажмите Enter, когда скопируете пароль...")
        input()

        # Находим PID программы
        print("\n[2] Поиск процесса CryptoSafe...")
        self.pid = self.find_cryptosafe_pid()

        if not self.pid:
            print(" Не найден процесс CryptoSafe Manager")
            print("   Проверьте, что программа запущена")
            return False

        print(f"    Найден процесс PID: {self.pid}")

        # Создаём дамп
        print("\n[3] Создание дампа памяти...")
        dump_path = self.create_memory_dump(self.pid)

        if not dump_path:
            print(" Не удалось создать дамп (нужны права администратора)")
            return False

        # Ищем пароль
        print("\n[4] Поиск пароля в дампе...")
        found = self.search_password_in_dump(dump_path, self.test_password)

        # Удаляем дамп
        try:
            os.remove(dump_path)
        except:
            pass

        # Результат
        print("\n" + "=" * 60)
        print("РЕЗУЛЬТАТ:")
        print("=" * 60)

        if found:
            print(" ТЕСТ НЕ ПРОЙДЕН: пароль найден в открытом виде!")
            return False
        else:
            print(" ТЕСТ ПРОЙДЕН: пароль НЕ НАЙДЕН в памяти!")
            return True


if __name__ == "__main__":
    test = LiveMemoryTest()
    success = test.run()
    sys.exit(0 if success else 1)