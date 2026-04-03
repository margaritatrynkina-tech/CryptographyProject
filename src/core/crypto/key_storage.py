import threading
import time
from typing import Optional
import sqlite3


class KeyCache:
    def __init__(self, inactivity_timeout: int = 3600):
        self._key: Optional[bytearray] = None
        self._lock = threading.RLock()
        self._last_activity = 0.0
        self._timeout = inactivity_timeout

    def set_key(self, key: bytes):
        with self._lock:
            self._zero_key()
            self._key = bytearray(key)
            self._last_activity = time.time()

    def get_key(self) -> Optional[bytes]:
        with self._lock:
            if self._key is None:
                return None
            if time.time() - self._last_activity > self._timeout:
                self._zero_key()
                return None
            self._last_activity = time.time()
            return bytes(self._key)

    def _zero_key(self):
        if isinstance(self._key, bytearray):
            for i in range(len(self._key)):
                self._key[i] = 0
        self._key = None

    def clear(self):
        with self._lock:
            self._zero_key()


class KeyStore:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def save_auth_hash(self, hash_str: str, version: int = 1):
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO key_store (key_type, key_data, version, created_at) "
            "VALUES (?, ?, ?, CURRENT_TIMESTAMP)",
            ("auth_hash", hash_str.encode('utf-8'), version),
        )
        self.conn.commit()

    def get_latest_auth_hash(self) -> Optional[str]:
        cur = self.conn.cursor()
        cur.execute(
            "SELECT key_data FROM key_store "
            "WHERE key_type = ? ORDER BY id DESC LIMIT 1",
            ("auth_hash",),
        )
        row = cur.fetchone()
        if row:
            return row[0].decode('utf-8')
        return None

    def save_enc_salt(self, salt: bytes, version: int = 1):
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO key_store (key_type, key_data, version, created_at) "
            "VALUES (?, ?, ?, CURRENT_TIMESTAMP)",
            ("enc_salt", salt, version),
        )
        self.conn.commit()

    def get_latest_enc_salt(self) -> Optional[bytes]:
        cur = self.conn.cursor()
        cur.execute(
            "SELECT key_data FROM key_store "
            "WHERE key_type = ? ORDER BY id DESC LIMIT 1",
            ("enc_salt",),
        )
        row = cur.fetchone()
        if row:
            return row[0]
        return None