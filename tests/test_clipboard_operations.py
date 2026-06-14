"""
TEST-1: Функциональность буфера обмена
Покрывает: копирование, авто-очистку, статус, TOTP, ephemeral режим
Маркеры: fast
"""
import time
import pytest
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_adapter():
    adapter = MagicMock()
    adapter.copy_to_clipboard.return_value = True
    adapter.clear_clipboard.return_value = True
    adapter.get_clipboard_content.return_value = "some_content"
    return adapter


@pytest.fixture
def mock_config():
    cfg = MagicMock()
    cfg.get.side_effect = lambda key, default=None: {
        "clipboard_timeout_seconds": 30,
        "clipboard_notifications": True,
        "clipboard_ephemeral_mode": False,
        "clipboard_copy_blocked": False,
        "clipboard_paranoid_mode": False,
        "clipboard_enhanced_monitoring": False,
    }.get(key, default)
    cfg.get_bool.side_effect = lambda key, default=False: {
        "clipboard_notifications": True,
        "clipboard_ephemeral_mode": False,
        "clipboard_copy_blocked": False,
        "clipboard_paranoid_mode": False,
    }.get(key, default)
    cfg.set = MagicMock()
    return cfg


@pytest.fixture
def events():
    from src.core.events import EventSystem
    return EventSystem()


@pytest.fixture
def clipboard_svc(mock_adapter, mock_config, events):
    from src.core.clipboard.clipboard_service import ClipboardService
    svc = ClipboardService(
        adapter=mock_adapter,
        events=events,
        config=mock_config,
        is_vault_unlocked=lambda: True,
        on_notify=None,
    )
    yield svc
    svc.clear_clipboard("teardown")


# ---------------------------------------------------------------------------
# Copy to clipboard
# ---------------------------------------------------------------------------

class TestClipboardCopy:
    @pytest.mark.fast
    def test_copy_returns_true(self, clipboard_svc):
        assert clipboard_svc.copy_to_clipboard("secret") is True

    @pytest.mark.fast
    def test_copy_empty_raises(self, clipboard_svc):
        with pytest.raises(ValueError):
            clipboard_svc.copy_to_clipboard("   ")

    @pytest.mark.fast
    def test_copy_non_string_raises(self, clipboard_svc):
        with pytest.raises(ValueError):
            clipboard_svc.copy_to_clipboard(12345)

    @pytest.mark.fast
    def test_copy_when_blocked_raises(self, mock_adapter, mock_config, events):
        from src.core.clipboard.clipboard_service import ClipboardService
        cfg = MagicMock()
        cfg.get.side_effect = lambda key, default=None: default
        cfg.get_bool.side_effect = lambda key, default=False: (
            True if key == "clipboard_copy_blocked" else default
        )
        cfg.set = MagicMock()
        svc = ClipboardService(
            adapter=mock_adapter, events=events, config=cfg,
            is_vault_unlocked=lambda: True,
        )
        svc.set_copy_blocked(True)
        with pytest.raises(PermissionError):
            svc.copy_to_clipboard("data")

    @pytest.mark.fast
    def test_copy_when_vault_locked_raises(self, mock_adapter, mock_config, events):
        from src.core.clipboard.clipboard_service import ClipboardService
        svc = ClipboardService(
            adapter=mock_adapter, events=events, config=mock_config,
            is_vault_unlocked=lambda: False,
        )
        with pytest.raises(PermissionError):
            svc.copy_to_clipboard("data")

    @pytest.mark.fast
    def test_copy_sets_active_status(self, clipboard_svc):
        clipboard_svc.copy_to_clipboard("hello")
        st = clipboard_svc.get_status()
        assert st["active"] is True

    @pytest.mark.fast
    def test_copy_stores_data_type(self, clipboard_svc):
        clipboard_svc.copy_to_clipboard("pass", data_type="password")
        assert clipboard_svc.get_status()["data_type"] == "password"

    @pytest.mark.fast
    def test_copy_source_entry_id(self, clipboard_svc):
        clipboard_svc.copy_to_clipboard("pass", source_entry_id="entry-uuid-123")
        st = clipboard_svc.get_status()
        assert st["source_entry_id"] == "entry-uuid-123"


# ---------------------------------------------------------------------------
# Clear clipboard
# ---------------------------------------------------------------------------

class TestClipboardClear:
    @pytest.mark.fast
    def test_clear_sets_inactive(self, clipboard_svc):
        clipboard_svc.copy_to_clipboard("secret")
        clipboard_svc.clear_clipboard("test")
        assert clipboard_svc.get_status()["active"] is False

    @pytest.mark.fast
    def test_clear_when_empty(self, clipboard_svc):
        result = clipboard_svc.clear_clipboard("no_data")
        assert isinstance(result, bool)

    @pytest.mark.fast
    def test_on_vault_lock_clears(self, clipboard_svc):
        clipboard_svc.copy_to_clipboard("secret")
        clipboard_svc.on_vault_lock()
        assert clipboard_svc.get_status()["active"] is False


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

class TestClipboardStatus:
    @pytest.mark.fast
    def test_initial_status_inactive(self, clipboard_svc):
        st = clipboard_svc.get_status()
        assert st["active"] is False

    @pytest.mark.fast
    def test_status_remaining_seconds(self, clipboard_svc):
        clipboard_svc.copy_to_clipboard("data")
        st = clipboard_svc.get_status()
        assert st["remaining_seconds"] is not None
        assert st["remaining_seconds"] > 0

    @pytest.mark.fast
    def test_copy_blocked_reflected_in_status(self, clipboard_svc):
        clipboard_svc.set_copy_blocked(True)
        assert clipboard_svc.get_status()["copy_blocked"] is True
        clipboard_svc.set_copy_blocked(False)


# ---------------------------------------------------------------------------
# Masked preview
# ---------------------------------------------------------------------------

class TestClipboardMaskedPreview:
    @pytest.mark.fast
    def test_password_masked(self, clipboard_svc):
        clipboard_svc.copy_to_clipboard("MySecretPassword", data_type="password")
        preview = clipboard_svc.get_masked_preview()
        assert preview is not None
        assert "MySecretPassword" not in preview
        assert "•" in preview

    @pytest.mark.fast
    def test_text_partially_shown(self, clipboard_svc):
        clipboard_svc.copy_to_clipboard("plaintext_value", data_type="text")
        preview = clipboard_svc.get_masked_preview()
        assert preview is not None
        assert "•" in preview

    @pytest.mark.fast
    def test_no_active_returns_none(self, clipboard_svc):
        assert clipboard_svc.get_masked_preview() is None


# ---------------------------------------------------------------------------
# Timeout settings
# ---------------------------------------------------------------------------

class TestClipboardTimeout:
    def _make_svc_with_real_config(self, mock_adapter, events):
        """ClipboardService with a real dict-backed config for set/get round-trips."""
        from src.core.clipboard.clipboard_service import ClipboardService

        store = {"clipboard_timeout_seconds": 30, "clipboard_notifications": False,
                 "clipboard_ephemeral_mode": False, "clipboard_copy_blocked": False,
                 "clipboard_paranoid_mode": False}

        class DictConfig:
            def get(self, key, default=None):
                return store.get(key, default)
            def get_bool(self, key, default=False):
                v = store.get(key, default)
                return bool(v) if not isinstance(v, bool) else v
            def set(self, key, value):
                store[key] = value

        return ClipboardService(
            adapter=mock_adapter, events=events, config=DictConfig(),
            is_vault_unlocked=lambda: True,
        )

    @pytest.mark.fast
    def test_set_valid_timeout(self, mock_adapter, events):
        svc = self._make_svc_with_real_config(mock_adapter, events)
        svc.set_auto_clear_timeout(60)
        assert svc.get_auto_clear_timeout() == 60

    @pytest.mark.fast
    def test_set_never_timeout(self, mock_adapter, events):
        svc = self._make_svc_with_real_config(mock_adapter, events)
        svc.set_auto_clear_timeout(None)
        assert svc.get_auto_clear_timeout() is None

    @pytest.mark.fast
    def test_set_too_short_raises(self, clipboard_svc):
        with pytest.raises(ValueError):
            clipboard_svc.set_auto_clear_timeout(1)

    @pytest.mark.fast
    def test_set_too_long_raises(self, clipboard_svc):
        with pytest.raises(ValueError):
            clipboard_svc.set_auto_clear_timeout(301)


# ---------------------------------------------------------------------------
# Accelerate clear
# ---------------------------------------------------------------------------

class TestAccelerateClear:
    @pytest.mark.fast
    def test_accelerate_zero_clears_immediately(self, clipboard_svc):
        clipboard_svc.copy_to_clipboard("secret")
        clipboard_svc.accelerate_clear(0)
        assert clipboard_svc.get_status()["active"] is False

    @pytest.mark.fast
    def test_accelerate_no_item_no_crash(self, clipboard_svc):
        clipboard_svc.accelerate_clear(1)  # no active item – should not raise


# ---------------------------------------------------------------------------
# Suspicious activity
# ---------------------------------------------------------------------------

class TestSuspiciousActivity:
    @pytest.mark.fast
    def test_report_calls_callback(self, mock_adapter, mock_config, events):
        from src.core.clipboard.clipboard_service import ClipboardService
        received = []
        svc = ClipboardService(
            adapter=mock_adapter, events=events, config=mock_config,
            is_vault_unlocked=lambda: True,
            on_suspicious_activity=lambda p: received.append(p),
        )
        svc.report_suspicious_activity("test_reason")
        assert len(received) == 1
        assert received[0]["reason"] == "test_reason"


# ---------------------------------------------------------------------------
# TOTP copy
# ---------------------------------------------------------------------------

class TestTOTPCopy:
    @pytest.mark.fast
    def test_copy_totp_returns_6_digit_code(self, clipboard_svc):
        secret = "JBSWY3DPEHPK3PXP"
        code = clipboard_svc.copy_totp(secret)
        assert isinstance(code, str)
        assert len(code) == 6
        assert code.isdigit()

    @pytest.mark.fast
    def test_copy_totp_sets_active(self, clipboard_svc):
        clipboard_svc.copy_totp("JBSWY3DPEHPK3PXP")
        assert clipboard_svc.get_status()["active"] is True
        assert clipboard_svc.get_status()["data_type"] == "totp"


# ---------------------------------------------------------------------------
# Ephemeral mode
# ---------------------------------------------------------------------------

class TestEphemeralMode:
    @pytest.mark.fast
    def test_ephemeral_copy_does_not_call_adapter(self, mock_adapter, mock_config, events):
        from src.core.clipboard.clipboard_service import ClipboardService
        cfg = MagicMock()
        cfg.get_bool.side_effect = lambda key, default=False: (
            True if key == "clipboard_ephemeral_mode" else default
        )
        cfg.get.side_effect = lambda key, default=None: {
            "clipboard_timeout_seconds": 30,
        }.get(key, default)
        cfg.set = MagicMock()
        svc = ClipboardService(
            adapter=mock_adapter, events=events, config=cfg,
            is_vault_unlocked=lambda: True,
        )
        svc.copy_to_clipboard("secret", force_ephemeral=True)
        mock_adapter.copy_to_clipboard.assert_not_called()

    @pytest.mark.fast
    def test_ephemeral_bus_set_get(self):
        from src.core.clipboard.ephemeral_bus import EphemeralClipboardBus
        bus = EphemeralClipboardBus()
        bus.set("hello", ttl_seconds=60)
        assert bus.get() == "hello"
        bus.clear()
        assert bus.get() is None

    @pytest.mark.fast
    def test_ephemeral_bus_ttl_expires(self):
        from src.core.clipboard.ephemeral_bus import EphemeralClipboardBus
        bus = EphemeralClipboardBus()
        bus.set("data", ttl_seconds=0)
        time.sleep(0.1)
        assert bus.get() is None


# ---------------------------------------------------------------------------
# Observer subscribe / unsubscribe
# ---------------------------------------------------------------------------

class TestClipboardObservers:
    @pytest.mark.fast
    def test_subscribe_receives_event(self, clipboard_svc):
        received = []
        clipboard_svc.subscribe(lambda p: received.append(p))
        clipboard_svc.copy_to_clipboard("data")
        assert len(received) >= 1

    @pytest.mark.fast
    def test_unsubscribe_stops_events(self, clipboard_svc):
        received = []
        cb = lambda p: received.append(p)
        clipboard_svc.subscribe(cb)
        clipboard_svc.unsubscribe(cb)
        clipboard_svc.copy_to_clipboard("data")
        assert len(received) == 0
