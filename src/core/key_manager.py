from typing import Optional
from src.core.crypto.key_derivation import KeyDerivation
from src.core.crypto.key_storage import KeyCache, KeyStore


class KeyManager:
    def __init__(self, config, db_connection):
        self.derivation = KeyDerivation(config)
        self.cache = KeyCache(
            inactivity_timeout=int(config.get('key_cache_timeout', 3600))
        )
        self.store = KeyStore(db_connection)

    def setup_master_password(self, password: str):
        auth_hash = self.derivation.create_auth_hash(password)
        self.store.save_auth_hash(auth_hash)

        salt = self.derivation.generate_enc_salt()
        self.store.save_enc_salt(salt)
        enc_key = self.derivation.derive_encryption_key(password, salt)
        self.cache.set_key(enc_key)

    def authenticate(self, password: str) -> bool:
        stored_hash = self.store.get_latest_auth_hash()
        salt = self.store.get_latest_enc_salt()
        if not stored_hash or not salt:
            return False

        if not self.derivation.verify_password(password, stored_hash):
            return False

        enc_key = self.derivation.derive_encryption_key(password, salt)
        self.cache.set_key(enc_key)
        return True

    def get_encryption_key(self) -> Optional[bytes]:
        return self.cache.get_key()
    def rotate_master_password(self, old_password: str, new_password: str, db):
        #проверить старый пароль
        if not self.authenticate(old_password):
            raise ValueError("Неверный текущий пароль")

        # старый ключ уже в cache
        old_key = self.get_encryption_key()
        if not old_key:
            raise ValueError("Старый ключ недоступен")

        # получить старую соль (используем ту же структуру)
        old_salt = self.store.get_latest_enc_salt()

        #создать новый хеш и соль
        new_auth_hash = self.derivation.create_auth_hash(new_password)
        new_salt = self.derivation.generate_enc_salt()
        new_key = self.derivation.derive_encryption_key(new_password, new_salt)

        conn = db.connection
        cur = conn.cursor()

        #начать транзакцию
        try:
            conn.execute("BEGIN")

            # пере-шифровать все записи
            cur.execute("SELECT id, encrypted_password FROM vault_entries")
            rows = cur.fetchall()

            from src.core.crypto.placeholder import AES256Placeholder
            crypto = AES256Placeholder()

            for row in rows:
                eid = row["id"]
                enc_pwd = row["encrypted_password"]
                if enc_pwd:
                    # расшифровать старым ключом
                    plain = crypto.decrypt(enc_pwd, old_key)
                    #зашифровать новым
                    new_enc = crypto.encrypt(plain, new_key)
                    cur.execute(
                        "UPDATE vault_entries SET encrypted_password = ? WHERE id = ?",
                        (new_enc, eid)
                    )

            #обновить key_store
            self.store.save_auth_hash(new_auth_hash, version=2)
            self.store.save_enc_salt(new_salt, version=2)

            conn.commit()
        except Exception:
            conn.rollback()
            raise

        # обновить кэш
        self.cache.set_key(new_key)

    def clear_keys(self):
        self.cache.clear()
