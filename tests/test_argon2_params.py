import pytest
from src.core.crypto.key_derivation import KeyDerivation
from src.core.config import ConfigManager
def test_argon2_different_params_produce_valid_hashes():
    config = ConfigManager()
    config.set('argon2_time', 3)
    config.set('argon2_memory', 65536)
    config.set('argon2_parallelism', 4)

    kd1 = KeyDerivation(config)
    h1 = kd1.create_auth_hash("test-password")
    config.set('argon2_time', 4)
    config.set('argon2_memory', 65536)
    config.set('argon2_parallelism', 2)

    kd2 = KeyDerivation(config)
    h2 = kd2.create_auth_hash("test-password")

    assert h1 != h2
    assert kd1.verify_password("test-password", h1)
    assert kd2.verify_password("test-password", h2)