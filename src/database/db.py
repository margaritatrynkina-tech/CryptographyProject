import sqlite3
import threading
import os
from pathlib import Path
from typing import Optional, List, Dict, Any
from core.crypto.placeholder import AES256Placeholder
from core.key_manager import KeyManager
class DatabaseManager:
    def __init__(self, db_path: str):
        self.db_path = Path(db_path)
        # Создаем папку, если её нет
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
                # Проверяем, что путь валидный
                db_path_str = str(self.db_path)
                print(f"Подключение к БД: {db_path_str}")
                # Создаем соединение
                self._conn = sqlite3.connect(db_path_str, check_same_thread=False)
                self._conn.row_factory = sqlite3.Row
                # Инициализируем схему
                self._init_schema()
                print("Соединение с БД установлено")
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
        print("Схема БД инициализирована")
    def set_master_password(self, password: str):
        salt = KeyManager.generate_salt()
        self.master_key = KeyManager.derive_key(password, salt)
        print("Мастер-пароль установлен")
    def encrypt_field(self, data: str) -> bytes:
        if not self.master_key:
            raise ValueError("Мастер-пароль не установлен")
        if not data:
            return b""
        return self.crypto.encrypt(data.encode(), self.master_key)
    def decrypt_field(self, encrypted_data: bytes) -> str:
        if not self.master_key:
            raise ValueError("Мастер-пароль не установлен")
        if not encrypted_data:
            return ""
        return self.crypto.decrypt(encrypted_data, self.master_key).decode()
    def add_entry(self, title: str, username: str = "", password: str = "",
                  url: str = "", notes: str = "", tags: str = "") -> int:
        if not self._conn:
            self.connect()
        with self._lock:
            encrypted_password = self.encrypt_field(password) if password else None
            cursor = self._conn.cursor()
            cursor.execute("""
                INSERT INTO vault_entries 
                (title, username, encrypted_password, url, notes, tags)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (title, username, encrypted_password, url, notes, tags))
            entry_id = cursor.lastrowid
            self._conn.commit()
            print(f"Запись добавлена: ID={entry_id}, title={title}")
            return entry_id
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