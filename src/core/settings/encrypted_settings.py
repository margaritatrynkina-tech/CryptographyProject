"""Encrypted application settings stored in SQLite settings table."""
import sqlite3
from typing import Any, Optional

from src.core.vault.encryption_service import AESGCMEncryptionService


class EncryptedSettingsStore:
    """Read/write settings with AES-256-GCM when encrypted=1."""

    def __init__(self, db_connection: sqlite3.Connection, key_manager):
        self.db = db_connection
        self.key_manager = key_manager
        self._crypto = AESGCMEncryptionService()

    def get(self, key: str, default: Any = None) -> Any:
        cur = self.db.cursor()
        cur.execute(
            "SELECT setting_value, encrypted FROM settings WHERE setting_key = ?",
            (key,),
        )
        row = cur.fetchone()
        if not row:
            return default
        value, encrypted = row[0], row[1]
        if not value:
            return default
        if encrypted:
            try:
                plain = self._crypto.decrypt_entry(value, self.key_manager)
                if isinstance(plain, dict) and "value" in plain:
                    return plain["value"]
                return plain
            except Exception:
                return default
        return value

    def set(self, key: str, value: Any, encrypt: bool = True) -> None:
        str_value = str(value) if value is not None else ""
        if encrypt:
            blob = self._crypto.encrypt_entry({"value": str_value}, self.key_manager)
            enc_flag = 1
            store_value = blob
        else:
            store_value = str_value
            enc_flag = 0
        cur = self.db.cursor()
        cur.execute(
            """
            INSERT INTO settings (setting_key, setting_value, encrypted)
            VALUES (?, ?, ?)
            ON CONFLICT(setting_key) DO UPDATE SET
                setting_value = excluded.setting_value,
                encrypted = excluded.encrypted
            """,
            (key, store_value, enc_flag),
        )
        self.db.commit()

    def get_int(self, key: str, default: int = 0) -> int:
        raw = self.get(key, default)
        try:
            return int(raw)
        except (TypeError, ValueError):
            return default

    def get_bool(self, key: str, default: bool = False) -> bool:
        raw = self.get(key, default)
        if isinstance(raw, bool):
            return raw
        return str(raw).lower() in ("1", "true", "yes", "on")
