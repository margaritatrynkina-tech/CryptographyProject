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
    def __init__(self):
        import win32clipboard
        import win32con
        self._clipboard = win32clipboard
        self._unicode_format = win32con.CF_UNICODETEXT

    def copy_to_clipboard(self, data: str) -> bool:
        try:
            self._clipboard.OpenClipboard()
            self._clipboard.EmptyClipboard()
            self._clipboard.SetClipboardData(self._unicode_format, data)
            return True
        except Exception:
            return False
        finally:
            try:
                self._clipboard.CloseClipboard()
            except Exception:
                pass

    def clear_clipboard(self) -> bool:
        try:
            self._clipboard.OpenClipboard()
            self._clipboard.EmptyClipboard()
            return True
        except Exception:
            return False
        finally:
            try:
                self._clipboard.CloseClipboard()
            except Exception:
                pass

    def get_clipboard_content(self) -> Optional[str]:
        try:
            self._clipboard.OpenClipboard()
            data = self._clipboard.GetClipboardData(self._unicode_format)
            return data if isinstance(data, str) else None
        except Exception:
            return None
        finally:
            try:
                self._clipboard.CloseClipboard()
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
