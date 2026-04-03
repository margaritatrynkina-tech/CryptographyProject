from abc import ABC, abstractmethod
from typing import Protocol
class EncryptionKeyProvider(Protocol):
    def get_encryption_key(self) -> bytes:
        ...
class EncryptionService(ABC):
    @abstractmethod
    def encrypt(self, data: bytes, key: bytes) -> bytes:
        pass

    @abstractmethod
    def decrypt(self, ciphertext: bytes, key: bytes) -> bytes:
        pass
    def encrypt_with_provider(
        self,
        data: bytes,
        provider: EncryptionKeyProvider
    ) -> bytes:
        key = provider.get_encryption_key()
        return self.encrypt(data, key)

    def decrypt_with_provider(
        self,
        ciphertext: bytes,
        provider: EncryptionKeyProvider
    ) -> bytes:
        key = provider.get_encryption_key()
        return self.decrypt(ciphertext, key)
