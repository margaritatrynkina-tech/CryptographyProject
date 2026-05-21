import gc
import sys
import time
import threading
from unittest.mock import MagicMock, patch

import pytest

from src.core.clipboard.clipboard_service import ClipboardService
from src.core.clipboard.platform_adapter import (
    ClipboardAdapter,
    FallbackClipboardAdapter,
    WindowsClipboardAdapter,
    MacOSClipboardAdapter,
    LinuxClipboardAdapter,
    create_platform_adapter,
)
from src.core.clipboard.secure_memory import SecureString, scan_process_memory_for_bytes
from src.core.events import EventSystem, EventType


def _test_password() -> str:
    import base64
    return base64.b64decode(b"U1VQRVJfU0VDUkVUX1BBU1NXT1JEXzEyMw==").decode("ascii")


class TransientAdapter:

    def __init__(self):
        self.copy_count = 0
        self.clear_count = 0

    def copy_to_clipboard(self, data: str) -> bool:
        self.copy_count += 1
        buf = bytearray(data.encode("utf-8"))
        try:
            return True
        finally:
            for i in range(len(buf)):
                buf[i] = 0
            del data

    def clear_clipboard(self) -> bool:
        self.clear_count += 1
        return True

    def get_clipboard_content(self):
        return None


class DummyAdapter:
    def __init__(self):
        self.data = ""
        self.copy_count = 0
        self.clear_count = 0

    def copy_to_clipboard(self, data: str) -> bool:
        self.data = data
        self.copy_count += 1
        return True

    def clear_clipboard(self) -> bool:
        self.data = ""
        self.clear_count += 1
        return True

    def get_clipboard_content(self):
        return self.data or None


class DummyConfig:
    def __init__(self, timeout=5):
        self.values = {
            "clipboard_timeout_seconds": timeout,
            "clipboard_notifications": False,
            "clipboard_copy_blocked": False,
        }

    def get(self, key, default=None):
        return self.values.get(key, default)

    def set(self, key, value):
        self.values[key] = value

    def get_bool(self, key, default=False):
        v = self.values.get(key, default)
        return str(v).lower() in ("1", "true", "yes") if not isinstance(v, bool) else v


def _make_service(timeout=1, adapter=None):
    adapter = adapter or DummyAdapter()
    events = EventSystem()
    config = DummyConfig(timeout=timeout)
    return ClipboardService(adapter, events, config, is_vault_unlocked=lambda: True), adapter, events


# TEST-1: Auto-clear timing test
def test_auto_clear_timing_within_100ms():
    service, adapter, _ = _make_service(timeout=5)
    service.set_auto_clear_timeout(5)

    start = time.monotonic()
    assert service.copy_to_clipboard("secret", data_type="password")
    assert adapter.data == "secret"

    deadline = start + 5.15
    while time.monotonic() < deadline:
        if adapter.data == "" and adapter.clear_count >= 1:
            break
        time.sleep(0.01)

    elapsed = time.monotonic() - start
    assert adapter.data == "", "Clipboard was not cleared after timeout"
    assert 4.9 <= elapsed <= 5.1, f"Clear timing {elapsed:.3f}s outside ±100ms of 5s"


# TEST-2: Cross-platform compatibility test
def test_cross_platform_adapters_via_mock():
    with patch("src.core.clipboard.platform_adapter.platform") as mock_plat:
        mock_plat.system.return_value = "Windows"
        with patch.object(WindowsClipboardAdapter, "__init__", lambda self: None):
            with patch.object(WindowsClipboardAdapter, "copy_to_clipboard", return_value=True):
                with patch.object(WindowsClipboardAdapter, "clear_clipboard", return_value=True):
                    with patch.object(WindowsClipboardAdapter, "get_clipboard_content", return_value="x"):
                        adapter = create_platform_adapter()
                        assert isinstance(adapter, WindowsClipboardAdapter)

    with patch("src.core.clipboard.platform_adapter.platform") as mock_plat:
        mock_plat.system.return_value = "Darwin"
        with patch.object(MacOSClipboardAdapter, "__init__", lambda self: None):
            with patch.object(MacOSClipboardAdapter, "copy_to_clipboard", return_value=True):
                adapter = create_platform_adapter()
                assert isinstance(adapter, MacOSClipboardAdapter)

    with patch("src.core.clipboard.platform_adapter.platform") as mock_plat:
        mock_plat.system.return_value = "Linux"
        with patch.object(LinuxClipboardAdapter, "__init__", lambda self, selection="clipboard": None):
            with patch.object(LinuxClipboardAdapter, "copy_to_clipboard", return_value=True):
                adapter = create_platform_adapter()
                assert isinstance(adapter, LinuxClipboardAdapter)

def test_fallback_pyperclip_adapter():
    mock_pc = MagicMock()
    mock_pc.copy = MagicMock()
    mock_pc.paste = MagicMock(return_value="hello")
    import src.core.clipboard.platform_adapter as pa

    with patch.dict("sys.modules", {"pyperclip": mock_pc}):
        fb = pa.FallbackClipboardAdapter()
        assert fb.copy_to_clipboard("data")
        mock_pc.copy.assert_called_once_with("data")


# TEST-3: Memory security test
def test_memory_security_no_plaintext_in_process():
    """
    TEST-3 (TZ):
    1. Copy password to clipboard (Windows + CryptProtectMemory)
    2. MiniDumpWriteDump of isolated process
    3. Assert password NOT in plaintext in dump (only obfuscated in heap)
    """
    import base64
    import subprocess
    import sys
    import tempfile
    from pathlib import Path

    if sys.platform != "win32":
        pytest.skip("TEST-3 minidump requires Windows")

    needle_b = base64.b64decode(b"U1VQRVJfU0VDUkVUX1BBU1NXT1JEXzEyMw==")
    sec = SecureString(needle_b.decode("ascii"))
    assert needle_b not in bytes(sec._obfuscated), "Only obfuscated form in SecureString"
    sec.wipe()

    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(needle_b)
        tmp_path = tmp.name

    worker = Path(__file__).parent / "memory_scan_worker.py"
    result = subprocess.run(
        [sys.executable, str(worker), tmp_path],
        capture_output=True,
        text=True,
    )
    codes = {
        1: "Plaintext password found in MiniDumpWriteDump",
        2: "Obfuscated buffer contained plaintext",
        3: "Clipboard copy failed (CryptProtectMemory / SetClipboardData)",
        4: "Password file mismatch",
        6: "WindowsClipboardAdapter unavailable",
        7: "MiniDumpWriteDump failed",
    }
    if result.returncode in codes:
        pytest.fail(f"{codes[result.returncode]}\nstderr: {result.stderr}")
    assert result.returncode == 0, (
        f"Memory security worker failed (exit {result.returncode}): {result.stderr}"
    )


# TEST-4: Concurrency test
def test_concurrency_rapid_copies_no_leakage():
    service, adapter, _ = _make_service(timeout=60)
    service.set_auto_clear_timeout(60)
    passwords = [f"password_{i:02d}_SECRET" for i in range(10)]

    errors = []

    def copy_loop():
        for pwd in passwords:
            try:
                service.copy_to_clipboard(pwd, data_type="password")
                time.sleep(0.01)
            except Exception as exc:
                errors.append(exc)

    threads = [threading.Thread(target=copy_loop) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    assert not errors
    assert adapter.data == passwords[-1], "Last copied password should remain in clipboard"
    for old in passwords[:-1]:
        assert old not in (adapter.data or ""), f"Stale password leaked: {old}"

    service.clear_clipboard("test")


# TEST-5: Recovery test
def test_recovery_shutdown_clears_clipboard():
    service, adapter, _ = _make_service(timeout=300)
    service.set_auto_clear_timeout(300)
    assert service.copy_to_clipboard("shutdown_test_secret", data_type="password")
    assert adapter.data == "shutdown_test_secret"

    service.shutdown()
    assert adapter.data == "", "Shutdown must clear clipboard"
    assert service.get_status()["active"] is False

    status_after = service.get_status()
    assert not status_after.get("active")
