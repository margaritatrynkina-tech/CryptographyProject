import uuid
from typing import Any, Dict, List, Optional
from src.core.crypto.abstract import EncryptionKeyProvider
from src.core.events import EventSystem, EventType
from src.core.vault.encryption_service import AESGCMEncryptionService
class EntryManager:
    def __init__(self, db_connection, key_manager: EncryptionKeyProvider, events: EventSystem):
        self.db = db_connection
        self.key_manager = key_manager
        self.events = events
        self.crypto = AESGCMEncryptionService()
    def create_entry(self, data_dict: Dict[str, Any]) -> str:
        entry_id = str(uuid.uuid4())
        payload = dict(data_dict)
        payload["id"] = entry_id
        encrypted_data = self.crypto.encrypt_entry(payload, self.key_manager)
        cursor = self.db.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO vault_entries (id, encrypted_data, created_at, updated_at, tags)
                VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, ?)
                """,
                (entry_id, encrypted_data, payload.get("tags", "")),
            )
            self.db.commit()
            self.events.emit(EventType.ENTRY_ADDED, {"entry_id": entry_id})
            return entry_id
        except Exception:
            self.db.rollback()
            raise
    def get_entry(self, entry_id: str) -> Optional[Dict[str, Any]]:
        cursor = self.db.cursor()
        cursor.execute(
            """
            SELECT id, encrypted_data, created_at, updated_at, tags
            FROM vault_entries
            WHERE id = ?
            """,
            (entry_id,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        data = self.crypto.decrypt_entry(row["encrypted_data"], self.key_manager)
        data["id"] = row["id"]
        data["created_at"] = row["created_at"]
        data["updated_at"] = row["updated_at"]
        data["tags"] = row["tags"]
        return data

    def get_all_entries(self) -> List[Dict[str, Any]]:
        cursor = self.db.cursor()
        cursor.execute(
            """
            SELECT id, encrypted_data, created_at, updated_at, tags
            FROM vault_entries
            ORDER BY updated_at DESC
            """
        )
        entries: List[Dict[str, Any]] = []
        for row in cursor.fetchall():
            data = self.crypto.decrypt_entry(row["encrypted_data"], self.key_manager)
            data["id"] = row["id"]
            data["created_at"] = row["created_at"]
            data["updated_at"] = row["updated_at"]
            data["tags"] = row["tags"]
            entries.append(data)
        return entries

    def update_entry(self, entry_id: str, data_dict: Dict[str, Any]) -> bool:
        cursor = self.db.cursor()
        cursor.execute("SELECT id FROM vault_entries WHERE id = ?", (entry_id,))
        if not cursor.fetchone():
            return False
        payload = dict(data_dict)
        payload["id"] = entry_id
        encrypted_data = self.crypto.encrypt_entry(payload, self.key_manager)
        try:
            cursor.execute(
                """
                UPDATE vault_entries
                SET encrypted_data = ?, updated_at = CURRENT_TIMESTAMP, tags = ?
                WHERE id = ?
                """,
                (encrypted_data, payload.get("tags", ""), entry_id),
            )
            self.db.commit()
            self.events.emit(EventType.ENTRY_UPDATED, {"entry_id": entry_id})
            return True
        except Exception:
            self.db.rollback()
            raise
    def delete_entry(self, entry_id: str, soft_delete: bool = True) -> bool:
        cursor = self.db.cursor()
        cursor.execute("SELECT id FROM vault_entries WHERE id = ?", (entry_id,))
        if not cursor.fetchone():
            return False
        try:
            if soft_delete:
                cursor.execute(
                    """
                    INSERT INTO deleted_entries (entry_id, deleted_at, expires_at)
                    VALUES (?, CURRENT_TIMESTAMP, datetime('now', '+30 days'))
                    """,
                    (entry_id,),
                )
            cursor.execute("DELETE FROM vault_entries WHERE id = ?", (entry_id,))
            self.db.commit()
            self.events.emit(EventType.ENTRY_DELETED, {"entry_id": entry_id, "soft_delete": soft_delete})
            return True
        except Exception:
            self.db.rollback()
            raise