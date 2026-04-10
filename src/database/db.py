import sqlite3
import threading
import os
from pathlib import Path
from typing import Optional, List, Dict, Any
from src.core.crypto.placeholder import AES256Placeholder
from src.core.key_manager import KeyManager
class DatabaseManager:
    def __init__(self, db_path: str):
        self.crypto = AES256Placeholder()
        self.key_manager = None
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn: Optional[sqlite3.Connection] = None
        self.crypto = AES256Placeholder()
      #  self.master_key: Optional[bytes] = None
    def __enter__(self) -> 'DatabaseManager':
        self.connect()
        return self
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
    def connect(self):
        with self._lock:
            if self._conn is None:
                #путь валидный?
                db_path_str = str(self.db_path)
                print(f"Подключение к БД: {db_path_str}")
                # создаем соединение
                self._conn = sqlite3.connect(db_path_str, check_same_thread=False)
                self._conn.row_factory = sqlite3.Row
                # инициализируем схему
                self._init_schema()
                print("Соединение с БД установлено")
    @property
    def connection(self):
        if self._conn is None:
            self.connect()
        return self._conn

    def close(self):
        with self._lock:
            if self._conn:
                self._conn.close()
                self._conn = None
                print("Соединение с БД закрыто")

    def _init_schema(self):
        if not self._conn:
            raise Exception("Нет соединения с БД")
        cursor = self._conn.cursor()

        cursor.execute("PRAGMA user_version")
        version = cursor.fetchone()[0]
        print(f"Текущая версия схемы: {version}")
        if version < 3:
            # Миграция vault_entries
            cursor.execute("""
                ALTER TABLE vault_entries ADD COLUMN encrypted_data BLOB;
                ALTER TABLE vault_entries ADD COLUMN tags TEXT DEFAULT '';
            """)
            cursor.execute("PRAGMA user_version = 3")
        cursor.execute("""
                CREATE TABLE IF NOT EXISTS vault_entries (
                    id TEXT PRIMARY KEY,              -- UUID
                    encrypted_data BLOB NOT NULL,     -- nonce+ciphertext+tag
                    created_at DATETIME NOT NULL,
                    updated_at DATETIME NOT NULL,
                    tags TEXT DEFAULT ''
                )
            """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vault_updated ON vault_entries(updated_at)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vault_tags ON vault_entries(tags)")

        #таблица записей хранилища
        cursor.execute("""
            INSERT OR IGNORE INTO settings (setting_key, setting_value, encrypted)
            VALUES 
            ('password_min_length', '12', 0),
            ('password_require_upper', '1', 0),
            ('password_require_lower', '1', 0),
            ('password_require_digit', '1', 0),
            ('password_require_symbol', '1', 0),
            ('argon2_time', '3', 0),
            ('argon2_memory', '65536', 0),
            ('argon2_parallelism', '4', 0),
            ('pbkdf2_iterations', '100000', 0),
            ('auto_lock_timeout', '3600', 0)
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
                   key_data BLOB NOT NULL,
                   version INTEGER NOT NULL DEFAULT 1,
                   created_at DATETIME DEFAULT CURRENT_TIMESTAMP
               )
        """)
        if version < 2:
            cursor.execute("PRAGMA user_version = 2")
            print("Схема обновлена до версии 2")

        self._conn.commit()
        print("Схема БД инициализирована")

    def encrypt_field(self, data: str) -> bytes:
        if not self.key_manager:
            raise ValueError("KeyManager не установлен")
        if not data:
            return b""
        key = self.key_manager.get_encryption_key()
        if not key:
            raise ValueError("Ключ шифрования не доступен (сессия не активна)")
        return self.crypto.encrypt(data.encode(), key)

    def decrypt_field(self, encrypted_data: bytes) -> str:
        if not self.key_manager:
            raise ValueError("KeyManager не установлен")
        if not encrypted_data:
            return ""
        key = self.key_manager.get_encryption_key()
        if not key:
            return "[Сессия заблокирована]"
        return self.crypto.decrypt(encrypted_data, key).decode()

    def add_encrypted_entry(self, entry_id: str, encrypted_data: bytes, tags: str = "") -> int:
        """DATA-1"""
        cursor = self._conn.cursor()
        cursor.execute("""
            INSERT INTO vault_entries (id, encrypted_data, created_at, updated_at, tags)
            VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, ?)
        """, (entry_id, encrypted_data, tags))
        self._conn.commit()
        return cursor.lastrowid
    def get_all_entries(self) -> List[Dict[str, Any]]:
        if not self._conn:
            self.connect()
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute("""
                SELECT id, title, username, url, notes, created_at, updated_at, tags
                FROM vault_entries ORDER BY updated_at DESC
            """)
            entries = []
            for row in cursor.fetchall():
                entries.append(dict(row))
            return entries
    def get_entry(self, entry_id: int) -> Optional[Dict[str, Any]]:
        if not self._conn:
            self.connect()
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute("SELECT * FROM vault_entries WHERE id = ?", (entry_id,))
            row = cursor.fetchone()
            if row:
                entry = dict(row)
                if entry['encrypted_password']:
                    try:
                        entry['password'] = self.decrypt_field(entry['encrypted_password'])
                    except:
                        entry['password'] = "[Ошибка расшифровки]"
                else:
                    entry['password'] = ""
                return entry
            return None