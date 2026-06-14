from __future__ import annotations

import sys
import time
import tempfile
import os
from pathlib import Path
from unittest.mock import MagicMock, patch, call
import pytest

pytestmark = pytest.mark.crypto

sys.path.insert(0, str(Path(__file__).parent.parent))

class TestSideChannelProtection:
    """TEST-1: Verify constant-time operations don't leak via timing."""

    def test_constant_time_compare_equal(self):
        from src.core.security.side_channel_protection import constant_time_compare
        assert constant_time_compare("password123", "password123") is True

    def test_constant_time_compare_not_equal(self):
        from src.core.security.side_channel_protection import constant_time_compare
        assert constant_time_compare("password123", "password124") is False

    def test_constant_time_compare_bytes(self):
        from src.core.security.side_channel_protection import constant_time_compare
        assert constant_time_compare(b"secret", b"secret") is True
        assert constant_time_compare(b"secret", b"Secret") is False

    def test_constant_time_compare_mixed_types(self):
        from src.core.security.side_channel_protection import constant_time_compare
        assert constant_time_compare("hello", b"hello") is True

    def test_secure_string_compare(self):
        from src.core.security.side_channel_protection import secure_string_compare
        assert secure_string_compare("abc", "abc") is True
        assert secure_string_compare("abc", "ABC") is False

    def test_timing_is_consistent(self):
        """Timing difference between equal and unequal must be < 5 ms."""
        from src.core.security.side_channel_protection import constant_time_compare

        iterations = 500
        a = "a" * 64
        b = "b" * 64

        # Time equal comparison
        t0 = time.perf_counter()
        for _ in range(iterations):
            constant_time_compare(a, a)
        equal_time = (time.perf_counter() - t0) / iterations

        # Time unequal comparison
        t0 = time.perf_counter()
        for _ in range(iterations):
            constant_time_compare(a, b)
        unequal_time = (time.perf_counter() - t0) / iterations

        # Difference must be < 5 ms per call
        diff_ms = abs(equal_time - unequal_time) * 1000
        assert diff_ms < 5.0, (
            f"Timing difference {diff_ms:.3f} ms exceeds 5 ms threshold — "
            "possible timing leak"
        )

    def test_secure_buffer_constant_time_compare(self):
        from src.core.security.side_channel_protection import SecureBuffer
        buf1 = SecureBuffer(b"secret data")
        buf2 = SecureBuffer(b"secret data")
        buf3 = SecureBuffer(b"different!!")
        assert buf1.compare(buf2) is True
        assert buf1.compare(buf3) is False

    def test_secure_buffer_clears_on_exit(self):
        from src.core.security.side_channel_protection import SecureBuffer
        with SecureBuffer(b"sensitive") as buf:
            assert len(buf) == 9
        # After context exit the buffer should be zeroed
        assert len(buf) == 0

class TestMemoryGuard:
    """TEST-2: Verify SecureMemory zeroes data before releasing."""

    def test_secure_zero_bytearray(self):
        from src.core.security.memory_guard import secure_zero
        import ctypes

        buf = (ctypes.c_char * 16)(*b"sensitive data!!")
        # Verify data is there
        assert bytes(buf) == b"sensitive data!!"
        secure_zero(buf)
        assert bytes(buf) == b"\x00" * 16

    def test_secure_memory_allocate_and_zero(self):
        from src.core.security.memory_guard import SecureMemory, copy_to_secure_buffer
        with SecureMemory() as mem:
            buf = mem.allocate(32, lock=False)
            copy_to_secure_buffer(buf, b"A" * 32)
            assert bytes(buf) == b"A" * 32
            mem.zero(buf)
            assert bytes(buf) == b"\x00" * 32

    def test_secure_memory_clears_on_context_exit(self):
        """Memory must be zeroed when the context manager exits."""
        from src.core.security.memory_guard import SecureMemory
        import ctypes

        mem = SecureMemory()
        from src.core.security.memory_guard import copy_to_secure_buffer

        buf = mem.allocate(16, lock=False)
        copy_to_secure_buffer(buf, b"B" * 16)
        # Get the raw address before freeing
        raw_addr = ctypes.addressof(ctypes.c_char.from_buffer(buf))

        mem.clear_all()

        # Read the memory at the same address — should be zeroed
        raw = (ctypes.c_char * 16).from_address(raw_addr)
        assert bytes(raw) == b"\x00" * 16

    def test_secure_string_compare(self):
        from src.core.security.memory_guard import SecureString
        with SecureString("password123") as s:
            assert s.compare("password123") is True
            assert s.compare("password124") is False

    def test_secure_string_clears_on_exit(self):
        from src.core.security.memory_guard import SecureString
        s = SecureString("secret")
        s.clear()
        assert s._buffer is None
        assert s._length == 0

    def test_global_allocator(self):
        from src.core.security.memory_guard import (
            allocate_secure, free_secure, copy_to_secure_buffer
        )
        buf = allocate_secure(8, lock=False)
        copy_to_secure_buffer(buf, b"12345678")
        assert bytes(buf) == b"12345678"
        free_secure(buf)
        # Should not raise
class TestAutoLock:
    """TEST-3: Auto-lock triggers lock callback after idle timeout."""

    def test_lock_callback_called(self):
        from src.core.security.auto_lock import AutoLockService
        from src.core.security.activity_monitor import ActivityMonitor

        monitor = MagicMock(spec=ActivityMonitor)
        monitor._monitoring = False

        service = AutoLockService(activity_monitor=monitor)
        service._enabled = True
        service._lock_timeout = 1  # 1 second for test speed

        lock_called = []
        service.register_lock_callback(lambda: lock_called.append(True))

        service.lock("test")

        assert service.is_locked()
        assert len(lock_called) == 1

    def test_unlock_callback_called(self):
        from src.core.security.auto_lock import AutoLockService
        from src.core.security.activity_monitor import ActivityMonitor

        monitor = MagicMock(spec=ActivityMonitor)
        monitor._monitoring = False

        service = AutoLockService(activity_monitor=monitor)
        service._enabled = True

        unlock_called = []
        service.register_unlock_callback(lambda: unlock_called.append(True))

        service.lock("test")
        assert service.is_locked()

        result = service.unlock("any_password")
        assert result is True
        assert not service.is_locked()
        assert len(unlock_called) == 1

    def test_lock_timeout_configuration(self):
        from src.core.security.auto_lock import AutoLockService
        from src.core.security.activity_monitor import ActivityMonitor

        monitor = MagicMock(spec=ActivityMonitor)
        monitor._monitoring = False

        service = AutoLockService(activity_monitor=monitor)
        service.set_lock_timeout(120)
        assert service.get_lock_timeout() == 120

    def test_lock_timeout_clamped(self):
        from src.core.security.auto_lock import AutoLockService
        from src.core.security.activity_monitor import ActivityMonitor

        monitor = MagicMock(spec=ActivityMonitor)
        monitor._monitoring = False

        service = AutoLockService(activity_monitor=monitor)
        service.set_lock_timeout(10)       # below minimum (60)
        assert service.get_lock_timeout() == 60
        service.set_lock_timeout(999999)   # above maximum (28800)
        assert service.get_lock_timeout() == 28800

    def test_lock_duration_tracking(self):
        from src.core.security.auto_lock import AutoLockService
        from src.core.security.activity_monitor import ActivityMonitor

        monitor = MagicMock(spec=ActivityMonitor)
        monitor._monitoring = False

        service = AutoLockService(activity_monitor=monitor)
        service._enabled = True

        assert service.get_lock_duration() == 0.0

        service.lock("test")
        time.sleep(0.05)
        duration = service.get_lock_duration()
        assert duration >= 0.04

    def test_double_lock_is_idempotent(self):
        from src.core.security.auto_lock import AutoLockService
        from src.core.security.activity_monitor import ActivityMonitor

        monitor = MagicMock(spec=ActivityMonitor)
        monitor._monitoring = False

        service = AutoLockService(activity_monitor=monitor)
        service._enabled = True

        lock_calls = []
        service.register_lock_callback(lambda: lock_calls.append(1))

        service.lock("first")
        service.lock("second")  # Should be ignored

        assert len(lock_calls) == 1

    def test_event_emitted_on_lock(self):
        from src.core.security.auto_lock import AutoLockService
        from src.core.security.activity_monitor import ActivityMonitor
        from src.core.events import EventType

        monitor = MagicMock(spec=ActivityMonitor)
        monitor._monitoring = False

        events = MagicMock()
        service = AutoLockService(activity_monitor=monitor, events=events)
        service._enabled = True

        service.lock("auto_lock")

        events.emit.assert_called_once_with(
            EventType.VAULT_AUTO_LOCKED, {"reason": "auto_lock"}
        )


class TestPanicMode:
    """TEST-4: Panic mode activates/deactivates correctly under stress."""

    def test_activate_changes_state(self):
        from src.core.security.panic_mode import PanicMode, PanicModeState

        panic = PanicMode()
        assert panic.get_state() == PanicModeState.NORMAL

        panic.activate(stealth=False)
        assert panic.get_state() == PanicModeState.ACTIVE
        assert panic.is_active()

    def test_deactivate_restores_state(self):
        from src.core.security.panic_mode import PanicMode, PanicModeState

        panic = PanicMode()
        panic.activate(stealth=False)
        panic.deactivate()
        assert panic.get_state() == PanicModeState.NORMAL
        assert not panic.is_active()

    def test_panic_callback_called(self):
        from src.core.security.panic_mode import PanicMode

        panic = PanicMode()
        called = []
        panic.register_panic_callback(lambda: called.append(True))

        panic.activate(stealth=False)
        assert len(called) == 1

    def test_recovery_callback_called(self):
        from src.core.security.panic_mode import PanicMode

        panic = PanicMode()
        recovered = []
        panic.register_recovery_callback(lambda: recovered.append(True))

        panic.activate(stealth=False)
        panic.deactivate()
        assert len(recovered) == 1

    def test_activation_time_tracked(self):
        from src.core.security.panic_mode import PanicMode

        panic = PanicMode()
        assert panic.get_activation_time() is None

        panic.activate(stealth=False)
        assert panic.get_activation_time() is not None
        assert panic.get_activation_duration() >= 0.0

        panic.deactivate()
        assert panic.get_activation_time() is None

    def test_double_activate_is_idempotent(self):
        from src.core.security.panic_mode import PanicMode

        panic = PanicMode()
        calls = []
        panic.register_panic_callback(lambda: calls.append(1))

        panic.activate(stealth=False)
        panic.activate(stealth=False)  # Should be ignored

        assert len(calls) == 1

    def test_configure_stealth_mode(self):
        from src.core.security.panic_mode import PanicMode

        panic = PanicMode()
        panic.configure(stealth_mode=True, fake_error_message="Test error")
        cfg = panic.get_configuration()
        assert cfg["stealth_mode"] is True
        assert cfg["fake_error_message"] == "Test error"

    def test_stress_activate_deactivate(self):
        """Rapid activate/deactivate cycles must not corrupt state."""
        from src.core.security.panic_mode import PanicMode, PanicModeState

        panic = PanicMode()
        for _ in range(10):
            panic.activate(stealth=False)
            assert panic.is_active()
            panic.deactivate()
            assert panic.get_state() == PanicModeState.NORMAL


class TestSecurityProfiles:
    """TEST-5: Profile switching persists and applies correctly."""

    def test_default_profile_is_enhanced(self, tmp_path):
        from src.core.security.profiles import SecurityProfileManager, SecurityProfile

        manager = SecurityProfileManager(config_path=str(tmp_path / "profile.json"))
        assert manager.get_current_profile() == SecurityProfile.ENHANCED

    def test_switch_to_paranoid(self, tmp_path):
        from src.core.security.profiles import SecurityProfileManager, SecurityProfile

        manager = SecurityProfileManager(config_path=str(tmp_path / "profile.json"))
        manager.set_profile(SecurityProfile.PARANOID)
        assert manager.get_current_profile() == SecurityProfile.PARANOID

    def test_profile_persists_across_instances(self, tmp_path):
        from src.core.security.profiles import SecurityProfileManager, SecurityProfile

        config_path = str(tmp_path / "profile.json")
        m1 = SecurityProfileManager(config_path=config_path)
        m1.set_profile(SecurityProfile.STANDARD)

        m2 = SecurityProfileManager(config_path=config_path)
        assert m2.get_current_profile() == SecurityProfile.STANDARD

    def test_paranoid_has_shorter_timeout(self, tmp_path):
        from src.core.security.profiles import SecurityProfileManager, SecurityProfile

        manager = SecurityProfileManager(config_path=str(tmp_path / "profile.json"))

        manager.set_profile(SecurityProfile.ENHANCED)
        enhanced_timeout = manager.get_feature("auto_lock_timeout")

        manager.set_profile(SecurityProfile.PARANOID)
        paranoid_timeout = manager.get_feature("auto_lock_timeout")

        assert paranoid_timeout < enhanced_timeout

    def test_standard_has_no_auto_lock(self, tmp_path):
        from src.core.security.profiles import SecurityProfileManager, SecurityProfile

        manager = SecurityProfileManager(config_path=str(tmp_path / "profile.json"))
        manager.set_profile(SecurityProfile.STANDARD)
        assert manager.is_feature_enabled("auto_lock") is False

    def test_paranoid_has_stealth_mode(self, tmp_path):
        from src.core.security.profiles import SecurityProfileManager, SecurityProfile

        manager = SecurityProfileManager(config_path=str(tmp_path / "profile.json"))
        manager.set_profile(SecurityProfile.PARANOID)
        assert manager.is_feature_enabled("stealth_mode") is True

    def test_custom_config_overrides_default(self, tmp_path):
        from src.core.security.profiles import SecurityProfileManager, SecurityProfile

        manager = SecurityProfileManager(config_path=str(tmp_path / "profile.json"))
        manager.set_profile(SecurityProfile.ENHANCED)

        manager.set_custom_config(
            SecurityProfile.ENHANCED,
            {"features": {"auto_lock_timeout": 999}}
        )
        assert manager.get_feature("auto_lock_timeout") == 999

    def test_reset_custom_config(self, tmp_path):
        from src.core.security.profiles import SecurityProfileManager, SecurityProfile

        manager = SecurityProfileManager(config_path=str(tmp_path / "profile.json"))
        manager.set_profile(SecurityProfile.ENHANCED)

        original_timeout = manager.get_feature("auto_lock_timeout")
        manager.set_custom_config(
            SecurityProfile.ENHANCED,
            {"features": {"auto_lock_timeout": 999}}
        )
        manager.reset_custom_config(SecurityProfile.ENHANCED)
        assert manager.get_feature("auto_lock_timeout") == original_timeout

    def test_all_profiles_available(self, tmp_path):
        from src.core.security.profiles import (
            SecurityProfileManager, SecurityProfile
        )

        manager = SecurityProfileManager(config_path=str(tmp_path / "profile.json"))
        profiles = manager.get_available_profiles()
        assert SecurityProfile.STANDARD in profiles
        assert SecurityProfile.ENHANCED in profiles
        assert SecurityProfile.PARANOID in profiles

    def test_configuration_summary(self, tmp_path):
        from src.core.security.profiles import SecurityProfileManager, SecurityProfile

        manager = SecurityProfileManager(config_path=str(tmp_path / "profile.json"))
        manager.set_profile(SecurityProfile.ENHANCED)
        summary = manager.get_configuration_summary()

        assert summary["profile"] == "enhanced"
        assert "enabled_features" in summary
        assert "disabled_features" in summary
        assert "performance_impact" in summary



def test_secure_zero():
    """Проверка обнуления памяти (ctypes.memset)."""
    import ctypes
    from src.core.security.memory_guard import secure_zero

    buf = (ctypes.c_char * 16)(*b"sensitive data!!")
    assert bytes(buf) == b"sensitive data!!"
    secure_zero(buf)
    assert bytes(buf) == b"\x00" * 16


def test_auto_lock():
    """Auto-lock без Tk root (MagicMock для ActivityMonitor)."""
    from src.core.security.auto_lock import AutoLockService
    from src.core.security.activity_monitor import ActivityMonitor

    monitor = MagicMock(spec=ActivityMonitor)
    monitor._monitoring = False

    service = AutoLockService(activity_monitor=monitor)
    service._enabled = True

    lock_called = []
    service.register_lock_callback(lambda: lock_called.append(True))
    service.lock("test")

    assert service.is_locked()
    assert len(lock_called) == 1


def test_panic_mode():
    """Panic mode: зарегистрированные обработчики вызываются при activate."""
    from src.core.security.panic_mode import PanicMode

    panic = PanicMode()
    called = []
    panic.register_panic_callback(lambda: called.append("panic"))

    panic.activate(stealth=False)
    assert called == ["panic"]



class TestSecurityEvents:
    """Verify Sprint 7 EventType values are present."""

    def test_new_event_types_exist(self):
        from src.core.events import EventType

        assert hasattr(EventType, "VAULT_AUTO_LOCKED")
        assert hasattr(EventType, "VAULT_UNLOCKED")
        assert hasattr(EventType, "PANIC_MODE_ACTIVATED")
        assert hasattr(EventType, "PANIC_MODE_DEACTIVATED")
        assert hasattr(EventType, "SECURITY_PROFILE_CHANGED")

    def test_new_events_in_audit_map(self):
        from src.core.audit.audit_logger import EVENT_MAP
        from src.core.events import EventType

        assert EventType.VAULT_AUTO_LOCKED in EVENT_MAP
        assert EventType.PANIC_MODE_ACTIVATED in EVENT_MAP
        assert EVENT_MAP[EventType.PANIC_MODE_ACTIVATED][1] == "CRITICAL"
