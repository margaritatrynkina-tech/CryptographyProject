"""Unified settings: clipboard keys in encrypted DB, app paths in config file."""
from typing import Any, Optional

from src.core.settings.encrypted_settings import EncryptedSettingsStore

CLIPBOARD_KEYS = frozenset({
    "clipboard_timeout_seconds",
    "clipboard_notifications",
    "clipboard_enhanced_monitoring",
    "clipboard_paranoid_mode",
    "clipboard_ephemeral_mode",
    "clipboard_preset",
    "clipboard_copy_blocked",
})


class SettingsAdapter:
    def __init__(self, config_manager, encrypted_store: Optional[EncryptedSettingsStore] = None):
        self._config = config_manager
        self._enc = encrypted_store

    def get(self, key: str, default: Any = None) -> Any:
        if self._enc and key in CLIPBOARD_KEYS:
            val = self._enc.get(key, None)
            if val is not None:
                return val
        return self._config.get(key, default)

    def set(self, key: str, value: Any) -> None:
        if self._enc and key in CLIPBOARD_KEYS:
            self._enc.set(key, value)
        else:
            self._config.set(key, value)

    def get_bool(self, key: str, default: bool = False) -> bool:
        raw = self.get(key, default)
        if isinstance(raw, bool):
            return raw
        return str(raw).lower() in ("1", "true", "yes", "on")

    def get_int(self, key: str, default: int = 0) -> int:
        raw = self.get(key, default)
        try:
            return int(raw)
        except (TypeError, ValueError):
            return default
