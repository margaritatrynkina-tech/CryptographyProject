from typing import Optional
from .crypto.key_derivation import KeyDerivation
from .crypto.key_storage import KeyCache, KeyStore


class KeyManager:
    def __init__(self, config, db_connection):
        self.derivation = KeyDerivation(config)
        self.cache = KeyCache(
            inactivity_timeout=config.get('key_cache_timeout', 3600)
        )
        self.store = KeyStore(db_connection)

    def setup_master_password(self, password: str):
        auth_hash = self.derivation.create_auth_hash(password)
        self.store.save_auth_hash(auth_hash)

        salt = self.derivation.generate_enc_salt()
        self.store.save_enc_salt(salt)

        # Одновременно кладём ключ в кэш
        enc_key = self.derivation.derive_encryption_key(password, salt)
        self.cache.set_key(enc_key)

    # --- логин ---

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

    def clear_keys(self):
        self.cache.clear()
