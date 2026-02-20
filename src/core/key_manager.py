import hashlib
import os


class KeyManager:
    """Управление ключами (заглушка для Спринта 2)"""

    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        """Получение ключа из пароля (простой хэш)"""
        # TODO: Заменить на PBKDF2/Argon2 в Спринте 2
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        return key[:32]  # 256 бит

    @staticmethod
    def generate_salt() -> bytes:
        return os.urandom(16)
