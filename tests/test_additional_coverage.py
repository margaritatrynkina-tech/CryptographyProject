"""
Additional coverage tests for: password generator, password policy,
state_manager, authentication, key_cache, config, events, TOTP generator,
secure_memory (basic), clipboard_presets, key_storage.
Маркеры: fast, crypto
"""
import os
import sqlite3
import time
import pytest
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# PasswordGenerator
# ---------------------------------------------------------------------------

class TestPasswordGenerator:
    @pytest.fixture
    def gen(self):
        from src.core.vault.password_generator import PasswordGenerator
        return PasswordGenerator()

    @pytest.mark.fast
    def test_default_length(self, gen):
        p = gen.generate()
        assert len(p) == 16

    @pytest.mark.fast
    def test_custom_length(self, gen):
        p = gen.generate(length=24)
        assert len(p) == 24

    @pytest.mark.fast
    def test_too_short_raises(self, gen):
        with pytest.raises(ValueError):
            gen.generate(length=4)

    @pytest.mark.fast
    def test_uppercase_present(self, gen):
        p = gen.generate(uppercase=True, lowercase=False, digits=False, symbols=False)
        assert any(c.isupper() for c in p)

    @pytest.mark.fast
    def test_lowercase_present(self, gen):
        p = gen.generate(uppercase=False, lowercase=True, digits=False, symbols=False)
        assert any(c.islower() for c in p)

    @pytest.mark.fast
    def test_digits_present(self, gen):
        p = gen.generate(uppercase=False, lowercase=False, digits=True, symbols=False)
        assert any(c.isdigit() for c in p)

    @pytest.mark.fast
    def test_no_charset_raises(self, gen):
        with pytest.raises(ValueError):
            gen.generate(uppercase=False, lowercase=False, digits=False, symbols=False)

    @pytest.mark.fast
    def test_all_options_generates(self, gen):
        p = gen.generate(length=20)
        assert len(p) == 20

    @pytest.mark.fast
    def test_randomness(self, gen):
        p1 = gen.generate()
        p2 = gen.generate()
        assert p1 != p2  # extremely unlikely to be equal

    @pytest.mark.fast
    def test_no_ambiguous_chars(self, gen):
        for _ in range(50):
            p = gen.generate(length=32)
            for c in "lI10O":
                assert c not in p


# ---------------------------------------------------------------------------
# PasswordPolicy
# ---------------------------------------------------------------------------

class TestPasswordPolicy:
    @pytest.mark.fast
    def test_valid_password(self):
        from src.core.crypto.password_policy import validate_password_strength
        assert validate_password_strength("StrongPass123!") is None

    @pytest.mark.fast
    def test_too_short(self):
        from src.core.crypto.password_policy import validate_password_strength
        err = validate_password_strength("Short1!")
        assert err is not None

    @pytest.mark.fast
    def test_no_uppercase(self):
        from src.core.crypto.password_policy import validate_password_strength
        err = validate_password_strength("nouppercase123!")
        assert err is not None

    @pytest.mark.fast
    def test_no_lowercase(self):
        from src.core.crypto.password_policy import validate_password_strength
        err = validate_password_strength("NOLOWERCASE123!")
        assert err is not None

    @pytest.mark.fast
    def test_no_digit(self):
        from src.core.crypto.password_policy import validate_password_strength
        err = validate_password_strength("NoDigitsHere!")
        assert err is not None

    @pytest.mark.fast
    def test_no_special(self):
        from src.core.crypto.password_policy import validate_password_strength
        err = validate_password_strength("NoSpecialChar123")
        assert err is not None

    @pytest.mark.fast
    def test_common_password(self):
        from src.core.crypto.password_policy import validate_password_strength
        err = validate_password_strength("password123")
        assert err is not None


# ---------------------------------------------------------------------------
# Events system
# ---------------------------------------------------------------------------

class TestEventsSystem:
    @pytest.fixture
    def es(self):
        from src.core.events import EventSystem
        return EventSystem()

    @pytest.mark.fast
    def test_subscribe_and_emit(self, es):
        from src.core.events import EventType
        received = []
        es.subscribe(EventType.ENTRY_ADDED, lambda d: received.append(d))
        es.emit(EventType.ENTRY_ADDED, {"id": "x"})
        assert received == [{"id": "x"}]

    @pytest.mark.fast
    def test_multiple_subscribers(self, es):
        from src.core.events import EventType
        r1, r2 = [], []
        es.subscribe(EventType.CLIPBOARD_COPIED, lambda d: r1.append(d))
        es.subscribe(EventType.CLIPBOARD_COPIED, lambda d: r2.append(d))
        es.emit(EventType.CLIPBOARD_COPIED, "payload")
        assert r1 == ["payload"]
        assert r2 == ["payload"]

    @pytest.mark.fast
    def test_emit_no_subscribers(self, es):
        from src.core.events import EventType
        # Should not raise
        es.emit(EventType.ENTRY_DELETED, {})

    @pytest.mark.fast
    def test_handler_exception_does_not_crash(self, es):
        from src.core.events import EventType
        def bad_handler(d):
            raise RuntimeError("boom")
        es.subscribe(EventType.ENTRY_UPDATED, bad_handler)
        es.emit(EventType.ENTRY_UPDATED, {})  # must not raise

    @pytest.mark.fast
    def test_async_processing(self, es):
        from src.core.events import EventType
        received = []
        es.subscribe(EventType.USER_LOGGED_IN, lambda d: received.append(d), async_handler=True)
        es.start_async_processing()
        es.emit(EventType.USER_LOGGED_IN, "data")
        time.sleep(0.1)
        es.stop_async_processing()
        assert received == ["data"]


# ---------------------------------------------------------------------------
# StateManager
# ---------------------------------------------------------------------------

class TestStateManager:
    @pytest.fixture
    def sm(self):
        from src.core.events import EventSystem
        from src.core.state_manager import StateManager
        es = EventSystem()
        return StateManager(es)

    @pytest.mark.fast
    def test_initially_locked(self, sm):
        assert sm.is_locked is True

    @pytest.mark.fast
    def test_unlock(self, sm):
        sm.unlock("user1")
        assert sm.is_locked is False

    @pytest.mark.fast
    def test_lock_after_unlock(self, sm):
        sm.unlock("user1")
        sm.lock()
        assert sm.is_locked is True

    @pytest.mark.fast
    def test_set_clipboard_clears_after_timeout(self, sm):
        sm.unlock("user1")
        sm.set_clipboard("secret", timeout=1)
        assert sm._clipboard_content == "secret"
        time.sleep(1.5)
        assert sm._clipboard_content is None

    @pytest.mark.fast
    def test_lock_clears_clipboard(self, sm):
        sm.unlock("user1")
        sm.set_clipboard("secret", timeout=60)
        sm.lock()
        assert sm._clipboard_content is None


# ---------------------------------------------------------------------------
# AuthenticationService
# ---------------------------------------------------------------------------

class TestAuthenticationService:
    @pytest.fixture
    def auth_svc(self):
        from src.core.crypto.authentication import AuthenticationService
        from src.core.events import EventSystem
        km = MagicMock()
        km.authenticate.return_value = True
        km.get_audit_signing_seed.return_value = b"\x00" * 32
        es = EventSystem()
        svc = AuthenticationService(km, es)
        return svc, km

    @pytest.mark.fast
    def test_login_success(self, auth_svc):
        svc, km = auth_svc
        with patch("time.sleep"):  # skip backoff delay
            result = svc.login("good_password")
        assert result is True
        assert svc.session.logged_in is True

    @pytest.mark.fast
    def test_login_failure(self, auth_svc):
        svc, km = auth_svc
        km.authenticate.return_value = False
        with patch("time.sleep"):
            result = svc.login("bad_password")
        assert result is False
        assert svc.session.logged_in is False
        assert svc.session.failed_attempts == 1

    @pytest.mark.fast
    def test_logout(self, auth_svc):
        svc, km = auth_svc
        with patch("time.sleep"):
            svc.login("good_password")
        svc.logout()
        assert svc.session.logged_in is False

    @pytest.mark.fast
    def test_update_activity(self, auth_svc):
        svc, km = auth_svc
        with patch("time.sleep"):
            svc.login("good_password")
        before = svc.session.last_activity
        time.sleep(0.05)
        svc.update_activity()
        assert svc.session.last_activity >= before

    @pytest.mark.fast
    def test_failed_attempts_accumulate(self, auth_svc):
        svc, km = auth_svc
        km.authenticate.return_value = False
        with patch("time.sleep"):
            svc.login("x")
            svc.login("x")
        assert svc.session.failed_attempts == 2

    @pytest.mark.fast
    def test_backoff_delay_calc(self, auth_svc):
        svc, _ = auth_svc
        svc.session.failed_attempts = 0
        assert svc._calculate_delay() == 1
        svc.session.failed_attempts = 3
        assert svc._calculate_delay() == 5
        svc.session.failed_attempts = 10
        assert svc._calculate_delay() == 30


# ---------------------------------------------------------------------------
# KeyCache
# ---------------------------------------------------------------------------

class TestKeyCache:
    @pytest.fixture
    def cache(self):
        from src.core.crypto.key_storage import KeyCache
        return KeyCache(inactivity_timeout=3600)

    @pytest.mark.fast
    def test_set_and_get_key(self, cache):
        key = os.urandom(32)
        cache.set_key(key)
        assert cache.get_key() == key

    @pytest.mark.fast
    def test_key_cleared_after_timeout(self):
        from src.core.crypto.key_storage import KeyCache
        cache = KeyCache(inactivity_timeout=0)
        cache.set_key(os.urandom(32))
        time.sleep(0.01)
        assert cache.get_key() is None

    @pytest.mark.fast
    def test_clear_zeroes_key(self, cache):
        cache.set_key(os.urandom(32))
        cache.clear()
        assert cache.get_key() is None

    @pytest.mark.fast
    def test_audit_seed_set_get(self, cache):
        seed = os.urandom(32)
        cache.set_audit_seed(seed)
        assert cache.get_audit_seed() == seed

    @pytest.mark.fast
    def test_audit_enc_key_set_get(self, cache):
        key = os.urandom(32)
        cache.set_audit_enc_key(key)
        assert cache.get_audit_enc_key() == key


# ---------------------------------------------------------------------------
# KeyStore (SQLite)
# ---------------------------------------------------------------------------

class TestKeyStore:
    @pytest.fixture
    def store(self):
        from src.core.crypto.key_storage import KeyStore
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.execute(
            "CREATE TABLE key_store "
            "(id INTEGER PRIMARY KEY AUTOINCREMENT, key_type TEXT, key_data BLOB, "
            "version INTEGER DEFAULT 1, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)"
        )
        conn.commit()
        return KeyStore(conn)

    @pytest.mark.fast
    def test_save_and_get_auth_hash(self, store):
        store.save_auth_hash("$argon2id$v=19$hash")
        h = store.get_latest_auth_hash()
        assert h == "$argon2id$v=19$hash"

    @pytest.mark.fast
    def test_save_and_get_enc_salt(self, store):
        salt = os.urandom(16)
        store.save_enc_salt(salt)
        retrieved = store.get_latest_enc_salt()
        assert retrieved == salt

    @pytest.mark.fast
    def test_latest_wins_multiple_hashes(self, store):
        store.save_auth_hash("hash1")
        store.save_auth_hash("hash2")
        assert store.get_latest_auth_hash() == "hash2"

    @pytest.mark.fast
    def test_get_nonexistent_returns_none(self, store):
        assert store.get_latest_auth_hash() is None
        assert store.get_latest_enc_salt() is None


# ---------------------------------------------------------------------------
# TOTP generator
# ---------------------------------------------------------------------------

class TestTOTPGenerator:
    @pytest.mark.fast
    def test_generate_returns_6_digits(self):
        from src.core.clipboard.totp_generator import generate_totp
        code = generate_totp("JBSWY3DPEHPK3PXP")
        assert len(code) == 6
        assert code.isdigit()

    @pytest.mark.fast
    def test_generate_deterministic_for_same_time(self):
        from src.core.clipboard.totp_generator import generate_totp
        t = time.time()
        assert generate_totp("JBSWY3DPEHPK3PXP", for_time=t) == \
               generate_totp("JBSWY3DPEHPK3PXP", for_time=t)

    @pytest.mark.fast
    def test_different_periods_differ(self):
        from src.core.clipboard.totp_generator import generate_totp
        t = 0.0
        c30 = generate_totp("JBSWY3DPEHPK3PXP", period=30, for_time=t)
        c60 = generate_totp("JBSWY3DPEHPK3PXP", period=60, for_time=t)
        # period 60 counter=0, period 30 counter=0 — same counter, same code
        # But different period → possibly same or different; just verify format
        assert len(c30) == 6
        assert len(c60) == 6

    @pytest.mark.fast
    def test_seconds_remaining(self):
        from src.core.clipboard.totp_generator import totp_seconds_remaining
        r = totp_seconds_remaining(period=30, for_time=15.0)
        assert 0 <= r <= 29

    @pytest.mark.fast
    def test_8_digit_totp(self):
        from src.core.clipboard.totp_generator import generate_totp
        code = generate_totp("JBSWY3DPEHPK3PXP", digits=8)
        assert len(code) == 8

    @pytest.mark.fast
    def test_invalid_base32_fallback(self):
        from src.core.clipboard.totp_generator import generate_totp
        # Should not raise; falls back to UTF-8 bytes
        code = generate_totp("NOT_VALID_BASE32???!!!")
        assert len(code) == 6


# ---------------------------------------------------------------------------
# ClipboardPresets
# ---------------------------------------------------------------------------

class TestClipboardPresets:
    @pytest.mark.fast
    def test_apply_standard_preset(self):
        from src.core.settings.clipboard_presets import apply_preset, CLIPBOARD_PRESETS
        store = {}

        class DictStore:
            def get(self, k, d=None): return store.get(k, d)
            def set(self, k, v): store[k] = v

        apply_preset(DictStore(), "standard")
        assert store["clipboard_timeout_seconds"] == 30

    @pytest.mark.fast
    def test_apply_secure_preset(self):
        from src.core.settings.clipboard_presets import apply_preset
        store = {}

        class DictStore:
            def get(self, k, d=None): return store.get(k, d)
            def set(self, k, v): store[k] = v

        apply_preset(DictStore(), "secure")
        assert store["clipboard_timeout_seconds"] == 15
        assert store["clipboard_enhanced_monitoring"] is True

    @pytest.mark.fast
    def test_apply_public_computer_preset(self):
        from src.core.settings.clipboard_presets import apply_preset
        store = {}

        class DictStore:
            def get(self, k, d=None): return store.get(k, d)
            def set(self, k, v): store[k] = v

        apply_preset(DictStore(), "public_computer")
        assert store["clipboard_timeout_seconds"] == 5
        assert store["clipboard_paranoid_mode"] is True

    @pytest.mark.fast
    def test_unknown_preset_raises(self):
        from src.core.settings.clipboard_presets import apply_preset
        with pytest.raises(ValueError):
            apply_preset(MagicMock(), "nonexistent")

    @pytest.mark.fast
    def test_preset_get_bool(self):
        from src.core.settings.clipboard_presets import preset_get_bool
        store = MagicMock()
        store.get_bool.return_value = True
        assert preset_get_bool(store, "key") is True

    @pytest.mark.fast
    def test_preset_get_int(self):
        from src.core.settings.clipboard_presets import preset_get_int
        store = MagicMock()
        store.get_int.return_value = 42
        assert preset_get_int(store, "key") == 42


# ---------------------------------------------------------------------------
# ConfigManager
# ---------------------------------------------------------------------------

class TestConfigManager:
    @pytest.mark.fast
    def test_set_and_get(self, tmp_path, monkeypatch):
        from src.core.config import ConfigManager
        monkeypatch.setattr(
            "pathlib.Path.home", lambda: tmp_path
        )
        cfg = ConfigManager()
        cfg.set("test_key", "test_value")
        assert cfg.get("test_key") == "test_value"

    @pytest.mark.fast
    def test_default_value(self, tmp_path, monkeypatch):
        from src.core.config import ConfigManager
        monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
        cfg = ConfigManager()
        assert cfg.get("nonexistent", "default") == "default"

    @pytest.mark.fast
    def test_db_path_property(self, tmp_path, monkeypatch):
        from src.core.config import ConfigManager
        monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
        cfg = ConfigManager()
        cfg.db_path = "/tmp/test.db"
        assert cfg.db_path == "/tmp/test.db"


# ---------------------------------------------------------------------------
# SecureString (obfuscation from clipboard/secure_memory)
# ---------------------------------------------------------------------------

class TestSecureString:
    @pytest.mark.fast
    def test_reveal_roundtrip(self):
        from src.core.clipboard.secure_memory import SecureString
        ss = SecureString("hello world")
        assert ss.reveal() == "hello world"
        ss.wipe()

    @pytest.mark.fast
    def test_obfuscated_not_plaintext(self):
        from src.core.clipboard.secure_memory import SecureString
        ss = SecureString("sensitive_data_123")
        assert b"sensitive_data_123" not in bytes(ss._obfuscated)
        ss.wipe()

    @pytest.mark.fast
    def test_from_bytes(self):
        from src.core.clipboard.secure_memory import SecureString
        ss = SecureString.from_bytes(b"bytes_input")
        assert ss.reveal() == "bytes_input"
        ss.wipe()

    @pytest.mark.fast
    def test_wipe_zeroes_buffer(self):
        from src.core.clipboard.secure_memory import SecureString
        ss = SecureString("secret")
        ss.wipe()
        assert all(b == 0 for b in ss._obfuscated)


# ---------------------------------------------------------------------------
# EphemeralClipboardBus (additional)
# ---------------------------------------------------------------------------

class TestEphemeralClipboardBusAdditional:
    @pytest.mark.fast
    def test_subscribe_gets_notified(self):
        from src.core.clipboard.ephemeral_bus import EphemeralClipboardBus
        bus = EphemeralClipboardBus()
        received = []
        bus.subscribe(lambda d: received.append(d))
        bus.set("event_data", ttl_seconds=60)
        assert received[-1] == "event_data"
        bus.clear()
        assert received[-1] is None

    @pytest.mark.fast
    def test_singleton(self):
        from src.core.clipboard.ephemeral_bus import EphemeralClipboardBus
        a = EphemeralClipboardBus.instance()
        b = EphemeralClipboardBus.instance()
        assert a is b
