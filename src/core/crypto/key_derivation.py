from argon2 import PasswordHasher, Type
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os
import secrets
from typing import Dict, Any

class KeyDerivation:
    def __init__(self, config):
        time_cost = int(getattr(config, "time_cost", 3))
        memory_cost = int(getattr(config, "memory_cost", 65536))
        parallelism = int(getattr(config, "parallelism", 4))

        self.argon2_hasher = PasswordHasher(
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=32,
            salt_len=16,
            type=Type.ID
        )
        self.pbkdf2_iterations = config.get('pbkdf2_iterations', 100000)
    def create_auth_hash(self, password: str) -> str:
        return self.argon2_hasher.hash(password)

    def verify_password(self, password: str, stored_hash: str) -> bool:
        try:
            return self.argon2_hasher.verify(stored_hash, password)
        except Exception:
            # «пустая» константная операция
            secrets.compare_digest(b'dummy', b'dummy')
            return False
    @staticmethod
    def generate_enc_salt() -> bytes:
        return os.urandom(16)

    def derive_encryption_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.pbkdf2_iterations,
        )
        return kdf.derive(password.encode('utf-8'))
