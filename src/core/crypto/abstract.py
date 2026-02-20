from abc import ABC, abstractmethod


class EncryptionService(ABC):
    """Абстрактный сервис шифрования"""

    @abstractmethod
    def encrypt(self, data: bytes, key: bytes) -> bytes:
        """Шифрует данные"""
        pass

    @abstractmethod
    def decrypt(self, ciphertext: bytes, key: bytes) -> bytes:
        """Дешифрует данные"""
        pass
