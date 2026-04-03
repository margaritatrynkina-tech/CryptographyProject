import time
from src.core.crypto.key_derivation import KeyDerivation
from src.core.config import ConfigManager
def test_verify_timing():
    config = ConfigManager()
    kd = KeyDerivation(config)
    stored = kd.create_auth_hash("secret")

    def measure(pwd):
        start = time.perf_counter()
        for _ in range(50):
            kd.verify_password(pwd, stored)
        return time.perf_counter() - start

    t_ok = measure("secret")
    t_bad = measure("wrong")
    ratio = t_ok / t_bad if t_bad else 1
    assert 0.5 < ratio < 2.0