import pytest
from src.core.crypto.placeholder import AES256Placeholder


def test_xor_encryption():
    crypto = AES256Placeholder()
    key = b'secret'
    data = b'hello'

    encrypted = crypto.encrypt(data, key)
    decrypted = crypto.decrypt(encrypted, key)

    assert decrypted == data
    assert encrypted != data
