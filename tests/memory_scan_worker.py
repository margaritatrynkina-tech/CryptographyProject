import gc
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.core.clipboard.clipboard_service import ClipboardService
from src.core.clipboard.secure_memory import SecureString, secure_wipe
from src.core.events import EventSystem


class _Adapter:
    def copy_to_clipboard(self, data: str) -> bool:
        return True

    def clear_clipboard(self) -> bool:
        return True

    def get_clipboard_content(self):
        return None


class _Config:
    def get(self, key, default=None):
        return 30

    def set(self, key, value):
        pass

    def get_bool(self, key, default=False):
        return default


def _needle_bytes() -> bytes:
    return bytes(
        (83, 85, 80, 69, 82, 95, 83, 69, 67, 82, 69, 84, 95, 80, 65, 83, 83, 87, 79, 82, 68, 95, 49, 50, 51)
    )


def main() -> int:
    path = sys.argv[1]
    raw = bytearray(open(path, "rb").read())
    try:
        os.remove(path)
    except OSError:
        pass

    if raw != _needle_bytes():
        secure_wipe(raw)
        return 4

    plaintext = raw.decode("utf-8")
    secure_wipe(raw)
    del raw

    sec = SecureString(plaintext)
    if _needle_bytes() in bytes(sec._obfuscated):
        return 2

    events = EventSystem()
    service = ClipboardService(_Adapter(), events, _Config(), is_vault_unlocked=lambda: True)
    if not service.copy_to_clipboard(plaintext, data_type="password"):
        return 3
    service.clear_clipboard("test")
    sec.wipe()
    if service._current_item is not None:
        return 5
    del plaintext, sec
    gc.collect()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
