import base64
import tempfile
from pathlib import Path

import pytest

from src.core.clipboard.totp_generator import generate_totp, totp_seconds_remaining
from src.core.clipboard.ephemeral_bus import EphemeralClipboardBus
from src.core.clipboard.clipboard_service import ClipboardService
from src.core.events import EventSystem
from src.core.settings.clipboard_presets import CLIPBOARD_PRESETS, apply_preset
from src.core.settings.encrypted_settings import EncryptedSettingsStore
from src.core.crypto.key_derivation import KeyDerivation
from src.database.db import DatabaseManager
from src.core.key_manager import KeyManager
from src.core.config import ConfigManager


class DummyAdapter:
    def __init__(self):
        self.data = ""

    def copy_to_clipboard(self, data: str) -> bool:
        self.data = data
        return True

    def clear_clipboard(self) -> bool:
        self.data = ""
        return True

    def get_clipboard_content(self):
        return self.data or None


class MemConfig:
    def __init__(self, values=None):
        self.values = dict(values or {})

    def get(self, key, default=None):
        return self.values.get(key, default)

    def set(self, key, value):
        self.values[key] = value

    def get_bool(self, key, default=False):
        v = self.get(key, default)
        return str(v).lower() in ("1", "true", "yes")


def test_totp_six_digits():
    secret = base64.b32encode(b"test-secret-key!!").decode()
    code = generate_totp(secret)
    assert len(code) == 6
    assert code.isdigit()
    assert 0 <= totp_seconds_remaining() < 30


def test_ephemeral_mode_skips_system_clipboard():
    bus = EphemeralClipboardBus.instance()
    bus.clear()
    adapter = DummyAdapter()
    cfg = MemConfig({"clipboard_ephemeral_mode": True, "clipboard_timeout_seconds": 60})
    svc = ClipboardService(adapter, EventSystem(), cfg, lambda: True)
    assert svc.copy_to_clipboard("secret", data_type="password")
    assert adapter.data == ""
    assert bus.get() == "secret"
    svc.clear_clipboard()
    assert bus.get() is None


def test_clipboard_presets():
    cfg = MemConfig()
    apply_preset(cfg, "public_computer")
    from src.core.settings.clipboard_presets import preset_get_int, preset_get_bool
    assert preset_get_int(cfg, "clipboard_timeout_seconds") == 5
    assert preset_get_bool(cfg, "clipboard_paranoid_mode")
    assert preset_get_bool(cfg, "clipboard_ephemeral_mode")


def test_encrypted_settings_roundtrip():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name
    db = DatabaseManager(path)
    db.connect()
    km = KeyManager(ConfigManager(), db.connection)
    km.setup_master_password("test_password_123!")
    store = EncryptedSettingsStore(db.connection, km)
    store.set("clipboard_timeout_seconds", "15")
    assert store.get("clipboard_timeout_seconds") == "15"
    db.close()
    Path(path).unlink(missing_ok=True)


def test_copy_blocked():
    adapter = DummyAdapter()
    cfg = MemConfig({"clipboard_copy_blocked": True})
    svc = ClipboardService(adapter, EventSystem(), cfg, lambda: True)
    with pytest.raises(PermissionError):
        svc.copy_to_clipboard("x")
