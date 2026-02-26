import sqlite3
import threading
from pathlib import Path
from typing import Optional  # ← ТОЛЬКО Optional!
from core.crypto.placeholder import AES256Placeholder
from core.key_manager import KeyManager
class DatabaseManager:
    def __init__(self, db_path: str):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn: Optional[sqlite3.Connection] = None
        self.crypto = AES256Placeholder()
        self.master_key: Optional[bytes] = None
    def __enter__(self) -> 'DatabaseManager':
        self.connect()
        return self
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
    def connect(self):
        with self._lock:
            if self._conn is None:
                self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
                self._init_schema()
    def close(self):
        with self._lock:
            if self._conn:
                self._conn.close()
                self._conn = None
    def _init_schema(self):
        if self._conn:
            cursor = self._conn.cursor()
            # Таблица записей хранилища
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS vault_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    username TEXT,
                    encrypted_password BLOB,
                    url TEXT,
                    notes TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    tags TEXT DEFAULT ''
                )
            """)
            # Журнал аудита
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    entry_id INTEGER,
                    details TEXT,
                    signature BLOB
                )
            """)
            # Настройки
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    setting_key TEXT UNIQUE NOT NULL,
                    setting_value TEXT,
                    encrypted BOOLEAN DEFAULT 0
                )
            """)
            # Хранилище ключей
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS key_store (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key_type TEXT NOT NULL,
                    salt BLOB,
                    hash BLOB,
                    params TEXT
                )
            """)
            self._conn.commit()
    def set_master_password(self, password: str):
        salt = KeyManager.generate_salt()
        self.master_key = KeyManager.derive_key(password, salt)
    def encrypt_field(self, data: str) -> bytes:
        if not self.master_key:
            raise ValueError("Мастер-пароль не установлен")
        return self.crypto.encrypt(data.encode(), self.master_key)
    def decrypt_field(self, encrypted_data: bytes) -> str:
        if not self.master_key:
            raise ValueError("Мастер-пароль не установлен")
        return self.crypto.decrypt(encrypted_data, self.master_key).decode()
