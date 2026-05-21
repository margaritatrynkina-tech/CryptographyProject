"""Windows CryptProtectMemory + MiniDumpWriteDump helpers for TEST-3."""
import ctypes
import gc
import os
import sys
from ctypes import wintypes
from typing import Optional

CRYPTPROTECTMEMORY_SAME_PROCESS = 0x00
CRYPTPROTECTMEMORY_BLOCK_SIZE = 16
MiniDumpWithDataSegs = 0x00000001
MiniDumpWithFullMemory = 0x00000002
MiniDumpWithPrivateReadWriteMemory = 0x00000100

if sys.platform == "win32":
    _kernel32 = ctypes.windll.kernel32
    _crypt32 = ctypes.windll.crypt32
    _user32 = ctypes.windll.user32
    _kernel32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
    _kernel32.GlobalAlloc.restype = wintypes.HGLOBAL
    _kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
    _kernel32.GlobalLock.restype = ctypes.c_void_p
    _kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
    _kernel32.GlobalUnlock.restype = wintypes.BOOL
    _kernel32.GlobalFree.argtypes = [wintypes.HGLOBAL]
    _kernel32.GlobalSize.argtypes = [wintypes.HGLOBAL]
    _kernel32.GlobalSize.restype = ctypes.c_size_t
    _user32.OpenClipboard.argtypes = [wintypes.HWND]
    _user32.OpenClipboard.restype = wintypes.BOOL
    _user32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
    _user32.SetClipboardData.restype = wintypes.HANDLE
    try:
        _dbghelp = ctypes.windll.dbghelp
    except Exception:
        _dbghelp = None
else:
    _user32 = None
    _kernel32 = None
    _crypt32 = None
    _dbghelp = None


def _aligned_size(n: int) -> int:
    return ((n + CRYPTPROTECTMEMORY_BLOCK_SIZE - 1) // CRYPTPROTECTMEMORY_BLOCK_SIZE) * CRYPTPROTECTMEMORY_BLOCK_SIZE


def crypt_protect_buffer(buf: bytearray) -> None:
    """Encrypt buffer in-place with CryptProtectMemory (crypt32, same process)."""
    if not _crypt32 or not buf:
        return
    size = _aligned_size(len(buf))
    while len(buf) < size:
        buf.append(0)
    c_buf = (ctypes.c_char * len(buf)).from_buffer(buf)
    if not _crypt32.CryptProtectMemory(
        ctypes.byref(c_buf),
        len(buf),
        CRYPTPROTECTMEMORY_SAME_PROCESS,
    ):
        raise OSError("CryptProtectMemory failed")


def crypt_unprotect_buffer(buf: bytearray) -> None:
    """Decrypt buffer in-place with CryptUnprotectMemory."""
    if not _crypt32 or not buf:
        return
    size = _aligned_size(len(buf))
    c_buf = (ctypes.c_char * len(buf)).from_buffer(buf)
    if not _crypt32.CryptUnprotectMemory(
        ctypes.byref(c_buf),
        len(buf),
        CRYPTPROTECTMEMORY_SAME_PROCESS,
    ):
        raise OSError("CryptUnprotectMemory failed")


def secure_wipe_buffer(buf: bytearray) -> None:
    for i in range(len(buf)):
        buf[i] = 0


def utf16_buffer_from_text(text: str) -> bytearray:
    """Build null-terminated UTF-16LE buffer without retaining the str reference."""
    raw = text.encode("utf-16-le") + b"\x00\x00"
    buf = bytearray(raw)
    del raw
    return buf


def copy_text_via_protected_memory(set_clipboard_fn) -> bool:
    """
    Reveal callback pattern: set_clipboard_fn receives bytearray (utf-16) briefly unprotected.
    Used internally by WindowsClipboardAdapter.
    """
    raise NotImplementedError


def set_clipboard_from_utf16_buffer(buf: bytearray, unicode_format: int) -> bool:
    """Place UTF-16 buffer on clipboard; buffer is wiped after use (no str)."""
    if sys.platform != "win32" or not _kernel32:
        return False
    h_global = None
    work = bytearray(buf)
    try:
        crypt_protect_buffer(work)
        crypt_unprotect_buffer(work)
        size = len(work)
        GMEM_MOVEABLE = 0x0002
        h_global = _kernel32.GlobalAlloc(GMEM_MOVEABLE, size)
        if not h_global:
            return False
        ptr = _kernel32.GlobalLock(h_global)
        if not ptr:
            _kernel32.GlobalFree(h_global)
            return False
        try:
            ctypes.memmove(ptr, (ctypes.c_char * size).from_buffer(work), size)
        finally:
            _kernel32.GlobalUnlock(h_global)
        if not _user32.OpenClipboard(None):
            _kernel32.GlobalFree(h_global)
            return False
        try:
            _user32.EmptyClipboard()
            if not _user32.SetClipboardData(unicode_format, h_global):
                _kernel32.GlobalFree(h_global)
                return False
            h_global = None
            return True
        finally:
            _user32.CloseClipboard()
    except Exception:
        if h_global:
            _kernel32.GlobalFree(h_global)
        return False
    finally:
        secure_wipe_buffer(work)
        del work
        gc.collect()


def set_clipboard_unicode_protected(_unused_module, unicode_format: int, text: str) -> bool:
    """
    Copy to system clipboard with CryptProtectMemory on the UTF-16 buffer.
    Uses user32 OpenClipboard / SetClipboardData (no pywin32 required).
    """
    if sys.platform != "win32" or not _kernel32:
        return False

    buf = utf16_buffer_from_text(text)
    del text
    gc.collect()
    try:
        return set_clipboard_from_utf16_buffer(buf, unicode_format)
    finally:
        secure_wipe_buffer(buf)
        del buf
        gc.collect()


def write_process_minidump(output_path: str, pid: Optional[int] = None) -> bool:
    """Write full memory minidump via dbghelp.MiniDumpWriteDump."""
    if sys.platform != "win32" or not _dbghelp or not _kernel32:
        return False

    pid = pid or _kernel32.GetCurrentProcessId()
    h_process = _kernel32.OpenProcess(0x001F0FFF, False, pid)  # PROCESS_ALL_ACCESS
    if not h_process:
        h_process = _kernel32.GetCurrentProcess()

    GENERIC_WRITE = 0x40000000
    CREATE_ALWAYS = 2
    FILE_ATTRIBUTE_NORMAL = 0x80

    CreateFileW = _kernel32.CreateFileW
    CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    CreateFileW.restype = wintypes.HANDLE

    h_file = CreateFileW(
        output_path,
        GENERIC_WRITE,
        0,
        None,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        None,
    )
    if h_file == wintypes.HANDLE(-1).value:
        if h_process != _kernel32.GetCurrentProcess():
            _kernel32.CloseHandle(h_process)
        return False

    _dbghelp.MiniDumpWriteDump.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.LPVOID,
    ]
    _dbghelp.MiniDumpWriteDump.restype = wintypes.BOOL

    dump_type = MiniDumpWithPrivateReadWriteMemory | MiniDumpWithDataSegs
    ok = _dbghelp.MiniDumpWriteDump(
        h_process,
        pid,
        h_file,
        dump_type,
        None,
        None,
        None,
    )
    _kernel32.CloseHandle(h_file)
    if h_process != _kernel32.GetCurrentProcess():
        _kernel32.CloseHandle(h_process)
    return bool(ok)


def minidump_contains_bytes(dump_path: str, needle_utf8: bytes, needle_utf16: Optional[bytes] = None) -> bool:
    """Scan minidump file for plaintext needle (UTF-8 and UTF-16)."""
    if not needle_utf16 and needle_utf8:
        try:
            needle_utf16 = needle_utf8.decode("utf-8").encode("utf-16-le")
        except UnicodeDecodeError:
            needle_utf16 = b""
    chunk_size = 8 * 1024 * 1024
    with open(dump_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            if needle_utf8 and needle_utf8 in chunk:
                return True
            if needle_utf16 and needle_utf16 in chunk:
                return True
    return False
