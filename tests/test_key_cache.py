from src.core.crypto.key_storage import KeyCache


def test_key_cache_clears_memory():
    cache = KeyCache(inactivity_timeout=1_000_000)  # большой таймаут, чтобы не срабатывал сам
    key = b"X" * 32
    cache.set_key(key)

    # убедимся, что ключ сейчас доступен
    assert cache.get_key() == key
    cache.clear()
    assert cache.get_key() is None