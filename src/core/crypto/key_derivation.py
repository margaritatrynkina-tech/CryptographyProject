from argon2 import PasswordHasher, Type
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os
import secrets
from typing import Dict, Any

class KeyDerivation:
    def __init__(self, config):
        time_cost = max(1, min(int(config.get('argon2_time', 3)), 10))
        memory_cost = max(8192, min(int(config.get('argon2_memory', 65536)), 262144))
        parallelism = max(1, min(int(config.get('argon2_parallelism', 4)), 8))
        iterations = max(100000, min(int(config.get('pbkdf2_iterations', 100000)), 1000000))
        self.argon2_hasher = PasswordHasher(
            time_cost=config.get('argon2_time', 3),
            memory_cost=config.get('argon2_memory', 65536),  # 64 MiB в KiB
            parallelism=config.get('argon2_parallelism', 4),
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
