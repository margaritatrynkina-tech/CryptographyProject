"""Isolated worker for TEST-3: copy + MiniDumpWriteDump + scan (Windows)."""
import gc
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.core.clipboard.secure_memory import SecureString, secure_wipe
from src.core.events import EventSystem
from src.core.clipboard.clipboard_service import ClipboardService

# UTF-8 bytes only — never instantiate the password as a Python str in this process
NEEDLE_UTF8 = bytes(
    (83, 85, 80, 69, 82, 95, 83, 69, 67, 82, 69, 84, 95, 80, 65, 83, 83, 87, 79, 82, 68, 95, 49, 50, 51)
)


class _Config:
    def get(self, key, default=None):
        return {"clipboard_timeout_seconds": 30, "clipboard_notifications": False}.get(key, default)

    def set(self, key, value):
        pass

    def get_bool(self, key, default=False):
        return False


def main() -> int:
    if sys.platform != "win32":
        return 0

    path = sys.argv[1]
    raw = bytearray(open(path, "rb").read())
    try:
        os.remove(path)
    except OSError:
        pass

    if bytes(raw) != NEEDLE_UTF8:
        secure_wipe(raw)
        return 4

    sec = SecureString.from_bytes(bytes(raw))
    secure_wipe(raw)
    del raw

    if NEEDLE_UTF8 in bytes(sec._obfuscated):
        return 2

    try:
        from src.core.clipboard.platform_adapter import WindowsClipboardAdapter
        adapter = WindowsClipboardAdapter()
    except Exception:
        return 6

    if not adapter.copy_from_secure(sec):
        return 3

    adapter.clear_clipboard()
    sec.wipe()
    del sec
    for _ in range(5):
        gc.collect()

    from src.core.clipboard.windows_protected_memory import (
        write_process_minidump,
        minidump_contains_bytes,
    )

    dump_path = tempfile.mktemp(suffix=".dmp")
    try:
        if not write_process_minidump(dump_path):
            return 7
        if minidump_contains_bytes(dump_path, NEEDLE_UTF8):
            return 1
    finally:
        try:
            os.remove(dump_path)
        except OSError:
            pass

    events = EventSystem()
    service = ClipboardService(adapter, events, _Config(), is_vault_unlocked=lambda: True)
    service.clear_clipboard("test")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
