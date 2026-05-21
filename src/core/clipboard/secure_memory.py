import ctypes
import secrets
import sys
from typing import Optional

# Windows CryptProtectMemory (crypt32.dll)
if sys.platform == "win32":
    _CRYPTPROTECTMEMORY_SAME_PROCESS = 0x00
    try:
        _crypt32 = ctypes.windll.crypt32
    except Exception:
        _crypt32 = None
else:
    _crypt32 = None
    try:
        _libc = ctypes.CDLL("libc.so.6")
    except Exception:
        _libc = None


def obfuscate(data: bytes, mask: bytes) -> bytes:
    return bytes(b ^ mask[i % len(mask)] for i, b in enumerate(data))


def deobfuscate(obfuscated: bytes, mask: bytes) -> bytes:
    return obfuscate(obfuscated, mask)


def secure_wipe(buf: bytearray) -> None:
    for i in range(len(buf)):
        buf[i] = 0


def lock_sensitive_bytes(data: bytes) -> None:
    if not data:
        return
    size = ((len(data) + 15) // 16) * 16
    buf = bytearray(data) + bytearray(size - len(data))
    if sys.platform == "win32" and _crypt32:
        try:
            c_buf = (ctypes.c_char * len(buf)).from_buffer(buf)
            _crypt32.CryptProtectMemory(
                ctypes.byref(c_buf),
                len(buf),
                _CRYPTPROTECTMEMORY_SAME_PROCESS,
            )
        except Exception:
            pass
    elif sys.platform != "win32":
        try:
            _libc = ctypes.CDLL("libc.so.6")
            _libc.mlock(ctypes.byref(buf), ctypes.c_size_t(len(data)))
        except Exception:
            pass


def unlock_sensitive_bytes() -> None:
    """No-op placeholder — CryptProtectMemory is process-scoped until exit."""
    pass


class SecureString:

    __slots__ = ("_obfuscated", "_mask")

    def __init__(self, plaintext: str):
        raw = plaintext.encode("utf-8")
        self._init_from_bytes(raw)
        del raw

    @classmethod
    def from_bytes(cls, data: bytes) -> "SecureString":
        """Create from UTF-8 bytes without an intermediate str in caller."""
        inst = cls.__new__(cls)
        inst._init_from_bytes(bytes(data))
        return inst

    def _init_from_bytes(self, raw: bytes) -> None:
        self._mask = secrets.token_bytes(32)
        self._obfuscated = bytearray(obfuscate(raw, self._mask))

    def reveal(self) -> str:
        buf = bytearray(deobfuscate(bytes(self._obfuscated), self._mask))
        try:
            return buf.decode("utf-8")
        finally:
            secure_wipe(buf)

    def reveal_utf16_buffer(self) -> bytearray:
        """UTF-16LE + null terminator without creating a Python str (ASCII-safe)."""
        utf8 = bytearray(deobfuscate(bytes(self._obfuscated), self._mask))
        try:
            out = bytearray()
            for byte in utf8:
                out.append(byte)
                out.append(0)
            out.extend(b"\x00\x00")
            return out
        finally:
            secure_wipe(utf8)

    def wipe(self) -> None:
        secure_wipe(self._obfuscated)
        self._mask = b"\x00" * 32

    def __del__(self):
        try:
            if hasattr(self, "_obfuscated"):
                secure_wipe(self._obfuscated)
        except Exception:
            pass


def scan_process_memory_for_bytes(needle_utf8: bytes, pid: Optional[int] = None) -> bool:
    import os
    import sys

    if not needle_utf8:
        return False
    try:
        needle_utf16 = needle_utf8.decode("utf-8").encode("utf-16-le")
    except UnicodeDecodeError:
        needle_utf16 = b""

    if sys.platform == "win32":
        return _scan_windows_memory(needle_utf8, needle_utf16)
    return _scan_unix_memory(needle_utf8, needle_utf16, pid or os.getpid())


def scan_process_memory_for_plaintext(needle: str, pid: Optional[int] = None) -> bool:
    return scan_process_memory_for_bytes(needle.encode("utf-8"), pid=pid)


def _scan_unix_memory(needle_utf8: bytes, needle_utf16: bytes, pid: int) -> bool:
    maps_path = f"/proc/{pid}/maps"
    mem_path = f"/proc/{pid}/mem"
    try:
        with open(maps_path, "r", encoding="utf-8") as f:
            regions = []
            for line in f:
                parts = line.split()
                if len(parts) < 2 or "r" not in parts[1]:
                    continue
                addr = parts[0].split("-")
                if len(addr) != 2:
                    continue
                start, end = int(addr[0], 16), int(addr[1], 16)
                if end - start > 50 * 1024 * 1024:
                    continue
                regions.append((start, end))
        with open(mem_path, "rb", buffering=0) as mem:
            chunk_size = 1024 * 1024
            for start, end in regions:
                size = end - start
                if size <= 0:
                    continue
                try:
                    mem.seek(start)
                    remaining = size
                    while remaining > 0:
                        to_read = min(chunk_size, remaining)
                        chunk = mem.read(to_read)
                        if not chunk:
                            break
                        if needle_utf8 in chunk or needle_utf16 in chunk:
                            return True
                        remaining -= len(chunk)
                except (OSError, OverflowError, ValueError):
                    continue
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        pass
    return False


def _scan_windows_memory(needle_utf8: bytes, needle_utf16: bytes) -> bool:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.windll.kernel32
    psapi = ctypes.windll.psapi

    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010
    MEM_COMMIT = 0x1000
    PAGE_NOACCESS = 0x01
    PAGE_GUARD = 0x100

    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_void_p),
            ("AllocationBase", ctypes.c_void_p),
            ("AllocationProtect", wintypes.DWORD),
            ("RegionSize", ctypes.c_size_t),
            ("State", wintypes.DWORD),
            ("Protect", wintypes.DWORD),
            ("Type", wintypes.DWORD),
        ]

    pid = kernel32.GetCurrentProcessId()
    handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not handle:
        return False

    mbi = MEMORY_BASIC_INFORMATION()
    address = 0
    max_addr = 0x7FFFFFFFFFFF if ctypes.sizeof(ctypes.c_void_p) == 8 else 0x7FFFFFFF
    chunk_size = 1024 * 1024

    try:
        while address < max_addr:
            if kernel32.VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0:
                break
            base = mbi.BaseAddress or 0
            region_size = mbi.RegionSize or 0
            next_addr = base + region_size
            if (
                mbi.State == MEM_COMMIT
                and mbi.Protect not in (PAGE_NOACCESS, PAGE_GUARD)
                and region_size > 0
                and region_size < 50 * 1024 * 1024
            ):
                buf = (ctypes.c_char * region_size)()
                bytes_read = ctypes.c_size_t(0)
                if kernel32.ReadProcessMemory(
                    handle, ctypes.c_void_p(base), buf, region_size, ctypes.byref(bytes_read)
                ):
                    data = bytes(buf[: bytes_read.value])
                    if needle_utf8 in data or needle_utf16 in data:
                        return True
            if next_addr <= address:
                break
            address = next_addr
    finally:
        kernel32.CloseHandle(handle)
    return False
