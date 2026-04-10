import uuid
import json
from typing import Dict, Any, List, Optional
from src.core.events import EventSystem, EventType
from src.core.vault.encryption_service import AESGCMEncryptionService
from src.core.crypto.abstract import EncryptionKeyProvider


class EntryManager:
    def __init__(self, db_connection, key_manager: EncryptionKeyProvider, events: EventSystem):
        self.db = db_connection
        self.key_manager = key_manager
        self.crypto = AESGCMEncryptionService()
        self.events = events

    # CRUD-1: CREATE
    def create_entry(self, data: Dict[str, Any]) -> str:
        entry_id = str(uuid.uuid4())
        # шифрование
        encrypted_data = self.crypto.encrypt_entry(data, self.key_manager)
        # сохранение
        self.db.add_encrypted_entry(entry_id, encrypted_data, data.get('tags', ''))
        #событие
        self.events.emit(EventType.ENTRY_ADDED, {'entry_id': entry_id})
        return entry_id
    def get_entry(self, entry_id: str) -> Optional[Dict[str, Any]]:
        cursor = self.db.connection.cursor()
        cursor.execute("SELECT encrypted_data FROM vault_entries WHERE id = ?", (entry_id,))
        row = cursor.fetchone()
        if row:
            return self.crypto.decrypt_entry(row[0], self.key_manager)
        return None

    def get_all_entries(self) -> List[Dict[str, Any]]:
        cursor = self.db.connection.cursor()
        cursor.execute("""
            SELECT id, encrypted_data, tags 
            FROM vault_entries 
            ORDER BY updated_at DESC
        """)
        entries = []
        for row in cursor.fetchall():
            entry = self.crypto.decrypt_entry(row[2], self.key_manager)  # encrypted_data
            entry['id'] = row[0]
            entry['tags'] = row[1]
            entries.append(entry)
        return entries

    # CRUD-1: UPDATE
    def update_entry(self, entry_id: str, data: Dict[str, Any]) -> bool:
        data['id'] = entry_id  # Сохраняем ID
        encrypted_data = self.crypto.encrypt_entry(data, self.key_manager)

        cursor = self.db.connection.cursor()
        cursor.execute("""
            UPDATE vault_entries 
            SET encrypted_data = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (encrypted_data, entry_id))

        if cursor.rowcount > 0:
            self.events.emit(EventType.ENTRY_UPDATED, {'entry_id': entry_id})
            self.db.connection.commit()
            return True
        return False
    def delete_entry(self, entry_id: str) -> bool:
        cursor = self.db.connection.cursor()
        cursor.execute("""
            UPDATE vault_entries 
            SET deleted_at = CURRENT_TIMESTAMP 
            WHERE id = ?
        """, (entry_id,))
        if cursor.rowcount > 0:
            self.events.emit(EventType.ENTRY_DELETED, {'entry_id': entry_id})
            self.db.connection.commit()
            return True
        return False