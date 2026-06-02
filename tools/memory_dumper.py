import ctypes
import tempfile
import os
import sys


def create_memory_dump(pid: int, output_path: str = None):

    kernel32 = ctypes.windll.kernel32
    dbghelp = ctypes.windll.dbghelp

    # Открываем процесс
    PROCESS_ALL_ACCESS = 0x1F0FFF
    hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)

    if not hProcess:
        print(f" Не удалось открыть процесс {pid}")
        print("   Запусти PowerShell от имени администратора!")
        return None

    # Создаём файл для дампа
    if not output_path:
        output_path = os.path.join(tempfile.gettempdir(), f"cryptosafe_{pid}.dmp")

    GENERIC_WRITE = 0x40000000
    CREATE_ALWAYS = 2
    FILE_ATTRIBUTE_NORMAL = 0x80

    hFile = kernel32.CreateFileW(
        output_path,
        GENERIC_WRITE,
        0, None,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        None
    )

    if not hFile:
        print(" Не удалось создать файл дампа")
        kernel32.CloseHandle(hProcess)
        return None

    # Создаём дамп
    MINIDUMP_TYPE = 0x00000002
    result = dbghelp.MiniDumpWriteDump(
        hProcess, pid, hFile,
        MINIDUMP_TYPE,
        None, None, None
    )

    kernel32.CloseHandle(hFile)
    kernel32.CloseHandle(hProcess)

    if result:
        size = os.path.getsize(output_path) / 1024
        print(f" Дамп создан: {output_path}")
        print(f"   Размер: {size:.2f} KB")
        return output_path
    else:
        print(" Ошибка при создании дампа")
        return None


def search_password_in_dump(dump_path: str, password: str) -> bool:

    if not os.path.exists(dump_path):
        print(f" Файл дампа не найден: {dump_path}")
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
        print(" Не удалось открыть файл дампа для чтения")
        return False

    # Ищем пароль в UTF-8
    search_utf8 = password.encode('utf-8')
    search_utf16 = password.encode('utf-16le')

    found = False
    buffer_size = 1024 * 1024  # 1 MB
    buffer = ctypes.create_string_buffer(buffer_size)
    bytes_read = ctypes.c_ulong()

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


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("=" * 50)
        print("Memory Dumper - инструмент для анализа памяти")
        print("=" * 50)
        print("\nИспользование:")
        print("  python memory_dumper.py <PID> [пароль]")
        print("\nПример:")
        print("  python memory_dumper.py 17488")
        print("  python memory_dumper.py 17488 \"test123\"")
        print("\nКак узнать PID:")
        print("  Get-Process python | Select-Object Id")
        sys.exit(1)

    pid = int(sys.argv[1])
    password = sys.argv[2] if len(sys.argv) > 2 else None

    print(f"\n[1] Создание дампа процесса PID: {pid}")
    dump_path = create_memory_dump(pid)

    if dump_path and password:
        print(f"\n[2] Поиск пароля '{password}' в дампе...")
        found = search_password_in_dump(dump_path, password)

        print("\n" + "=" * 50)
        print("РЕЗУЛЬТАТ:")
        print("=" * 50)

        if found:
            print(" ПАРОЛЬ НАЙДЕН в открытом виде!")
        else:
            print("Пароль НЕ НАЙДЕН в открытом виде")

        # Удаляем дамп
        os.remove(dump_path)
        print("\nДамп удалён")