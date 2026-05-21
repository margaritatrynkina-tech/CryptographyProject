import ctypes
import os
import platform
import shutil
import subprocess
from abc import ABC, abstractmethod
from typing import Optional


class ClipboardAdapter(ABC):
    @abstractmethod
    def copy_to_clipboard(self, data: str) -> bool:
        raise NotImplementedError

    @abstractmethod
    def clear_clipboard(self) -> bool:
        raise NotImplementedError

    @abstractmethod
    def get_clipboard_content(self) -> Optional[str]:
        raise NotImplementedError


class FallbackClipboardAdapter(ClipboardAdapter):
    def __init__(self):
        try:
            import pyperclip
        except ImportError as exc:
            raise RuntimeError("pyperclip is required for clipboard fallback") from exc
        self._pyperclip = pyperclip

    def copy_to_clipboard(self, data: str) -> bool:
        try:
            self._pyperclip.copy(data)
            return True
        except Exception:
            return False

    def clear_clipboard(self) -> bool:
        return self.copy_to_clipboard("")

    def get_clipboard_content(self) -> Optional[str]:
        try:
            return self._pyperclip.paste()
        except Exception:
            return None


class WindowsClipboardAdapter(ClipboardAdapter):
    CF_UNICODETEXT = 13

    def __init__(self):
        from ctypes import wintypes
        self._user32 = ctypes.windll.user32
        self._kernel32 = ctypes.windll.kernel32
        self._kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
        self._kernel32.GlobalLock.restype = ctypes.c_void_p
        self._kernel32.GlobalSize.argtypes = [wintypes.HGLOBAL]
        self._kernel32.GlobalSize.restype = ctypes.c_size_t
        self._unicode_format = self.CF_UNICODETEXT
        self._clipboard = None

    def copy_to_clipboard(self, data: str) -> bool:
        """Copy via CryptProtectMemory — no long-lived plaintext in process heap."""
        from src.core.clipboard.windows_protected_memory import set_clipboard_unicode_protected
        try:
            return set_clipboard_unicode_protected(None, self._unicode_format, data)
        except Exception:
            return False

    def copy_from_secure(self, secure) -> bool:
        """Copy from SecureString without a persistent plaintext str in memory."""
        import gc
        from src.core.clipboard.windows_protected_memory import set_clipboard_from_utf16_buffer
        buf = secure.reveal_utf16_buffer()
        try:
            return set_clipboard_from_utf16_buffer(buf, self._unicode_format)
        finally:
            from src.core.clipboard.secure_memory import secure_wipe
            secure_wipe(buf)
            del buf
            gc.collect()

    def clear_clipboard(self) -> bool:
        try:
            if not self._user32.OpenClipboard(None):
                return False
            self._user32.EmptyClipboard()
            return True
        except Exception:
            return False
        finally:
            try:
                self._user32.CloseClipboard()
            except Exception:
                pass

    def get_clipboard_content(self) -> Optional[str]:
        try:
            if not self._user32.OpenClipboard(None):
                return None
            h_data = self._user32.GetClipboardData(self._unicode_format)
            if not h_data:
                return None
            ptr = self._kernel32.GlobalLock(h_data)
            if not ptr:
                return None
            try:
                size = self._kernel32.GlobalSize(h_data)
                raw = ctypes.string_at(ptr, size)
                return raw.decode("utf-16-le").rstrip("\x00")
            finally:
                self._kernel32.GlobalUnlock(h_data)
        except Exception:
            return None
        finally:
            try:
                self._user32.CloseClipboard()
            except Exception:
                pass


class MacOSClipboardAdapter(ClipboardAdapter):
    def __init__(self):
        from AppKit import NSPasteboard, NSStringPboardType
        self._pasteboard = NSPasteboard.generalPasteboard()
        self._string_type = NSStringPboardType

    def copy_to_clipboard(self, data: str) -> bool:
        try:
            self._pasteboard.declareTypes_owner_([self._string_type], None)
            self._pasteboard.setString_forType_(data, self._string_type)
            return True
        except Exception:
            return False

    def clear_clipboard(self) -> bool:
        try:
            self._pasteboard.clearContents()
            return True
        except Exception:
            return False

    def get_clipboard_content(self) -> Optional[str]:
        try:
            value = self._pasteboard.stringForType_(self._string_type)
            return str(value) if value is not None else None
        except Exception:
            return None


class LinuxClipboardAdapter(ClipboardAdapter):
    def __init__(self, selection: str = "clipboard"):
        self._selection = selection.lower()
        try:
            import pyperclip
        except ImportError as exc:
            raise RuntimeError("pyperclip is required for Linux clipboard adapter") from exc
        self._pyperclip = pyperclip
        self._wl_copy = shutil.which("wl-copy")
        self._wl_paste = shutil.which("wl-paste")
        self._xclip = shutil.which("xclip")

    def _run_cmd(self, cmd: list[str], stdin_text: Optional[str] = None) -> Optional[str]:
        try:
            proc = subprocess.run(
                cmd,
                input=stdin_text,
                text=True,
                capture_output=True,
                check=False,
            )
            if proc.returncode != 0:
                return None
            return proc.stdout
        except Exception:
            return None

    def copy_to_clipboard(self, data: str) -> bool:
        if self._wl_copy and os.getenv("WAYLAND_DISPLAY"):
            cmd = [self._wl_copy]
            if self._selection == "primary":
                cmd.extend(["--primary"])
            return self._run_cmd(cmd, stdin_text=data) is not None
        if self._xclip:
            clip = "primary" if self._selection == "primary" else "clipboard"
            return self._run_cmd([self._xclip, "-selection", clip], stdin_text=data) is not None
        try:
            self._pyperclip.copy(data)
            return True
        except Exception:
            return False

    def clear_clipboard(self) -> bool:
        return self.copy_to_clipboard("")

    def get_clipboard_content(self) -> Optional[str]:
        if self._wl_paste and os.getenv("WAYLAND_DISPLAY"):
            cmd = [self._wl_paste, "--no-newline"]
            if self._selection == "primary":
                cmd.extend(["--primary"])
            output = self._run_cmd(cmd)
            return output if output is not None else None
        if self._xclip:
            clip = "primary" if self._selection == "primary" else "clipboard"
            return self._run_cmd([self._xclip, "-selection", clip, "-o"])
        try:
            return self._pyperclip.paste()
        except Exception:
            return None


def create_platform_adapter() -> ClipboardAdapter:
    system = platform.system().lower()
    if system == "windows":
        try:
            return WindowsClipboardAdapter()
        except Exception:
            return FallbackClipboardAdapter()
    if system == "darwin":
        try:
            return MacOSClipboardAdapter()
        except Exception:
            return FallbackClipboardAdapter()
    if system == "linux":
        try:
            return LinuxClipboardAdapter(selection="clipboard")
        except Exception:
            return FallbackClipboardAdapter()
    return FallbackClipboardAdapter()
