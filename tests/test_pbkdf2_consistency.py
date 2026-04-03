from src.core.crypto.key_derivation import KeyDerivation
from src.core.config import ConfigManager
def test_pbkdf2_consistency():
    config = ConfigManager()
    kd = KeyDerivation(config)

    password = "test-password"
    salt = kd.generate_enc_salt()
    keys = [kd.derive_encryption_key(password, salt) for _ in range(100)]
    first = keys[0]
    assert all(k == first for k in keys)