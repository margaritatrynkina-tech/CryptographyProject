import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional

from src.core.events import EventSystem, EventType
from src.core.clipboard.platform_adapter import ClipboardAdapter
from src.core.clipboard.secure_memory import SecureString, lock_sensitive_bytes, unlock_sensitive_bytes
from src.core.clipboard.ephemeral_bus import EphemeralClipboardBus
from src.core.clipboard.totp_generator import generate_totp, totp_seconds_remaining


@dataclass
class ClipboardItem:
    data_type: str
    source_entry_id: Optional[str]
    copied_at: float
    timeout_seconds: Optional[int]
    secure_data: Optional[SecureString] = None
    ephemeral_only: bool = False


class ClipboardService:
    DEFAULT_TIMEOUT = 30
    MIN_TIMEOUT = 5
    MAX_TIMEOUT = 300
    NEVER_TIMEOUT = 0
    WARNING_BEFORE_CLEAR = 5

    def __init__(
        self,
        adapter: ClipboardAdapter,
        events: EventSystem,
        config,
        is_vault_unlocked: Callable[[], bool],
        on_notify: Optional[Callable[[str, str], None]] = None,
        on_suspicious_activity: Optional[Callable[[dict], None]] = None,
    ):
        self.adapter = adapter
        self.events = events
        self.config = config
        self.is_vault_unlocked = is_vault_unlocked
        self.on_notify = on_notify
        self.on_suspicious_activity = on_suspicious_activity

        self._timer: Optional[threading.Timer] = None
        self._warning_timer: Optional[threading.Timer] = None
        self._lock = threading.RLock()
        self._observers: list[Callable[[dict], None]] = []
        self._current_item: Optional[ClipboardItem] = None
        self._ephemeral = EphemeralClipboardBus.instance()
        self._copy_blocked = False

    def subscribe(self, callback: Callable[[dict], None]) -> None:
        with self._lock:
            self._observers.append(callback)

    def unsubscribe(self, callback: Callable[[dict], None]) -> None:
        with self._lock:
            self._observers = [cb for cb in self._observers if cb != callback]

    @property
    def copy_blocked(self) -> bool:
        return self._copy_blocked or self.config.get_bool("clipboard_copy_blocked", False)

    def set_copy_blocked(self, blocked: bool) -> None:
        self._copy_blocked = blocked
        self.config.set("clipboard_copy_blocked", "1" if blocked else "0")

    def is_ephemeral_mode(self) -> bool:
        return self.config.get_bool("clipboard_ephemeral_mode", False)

    def copy_to_clipboard(
        self,
        data: str,
        data_type: str = "text",
        source_entry_id: Optional[str] = None,
        force_ephemeral: Optional[bool] = None,
    ) -> bool:
        if self.copy_blocked:
            raise PermissionError("Clipboard copy is blocked due to suspicious activity")
        if not isinstance(data, str):
            raise ValueError("Clipboard data must be a string")
        if data.strip() == "":
            raise ValueError("Clipboard data cannot be empty")
        if not self.is_vault_unlocked():
            raise PermissionError("Vault is locked. Clipboard copy is denied.")

        ephemeral = force_ephemeral if force_ephemeral is not None else self.is_ephemeral_mode()

        with self._lock:
            self._clear_locked("replaced")
            secure = SecureString(data)
            lock_sensitive_bytes(bytes(secure._obfuscated))

            try:
                plaintext = secure.reveal()
                if ephemeral:
                    self._ephemeral.set(plaintext, ttl_seconds=self.get_auto_clear_timeout() or 60)
                    copied = True
                else:
                    copied = self.adapter.copy_to_clipboard(plaintext)
            finally:
                del plaintext
                unlock_sensitive_bytes()

            if not copied:
                secure.wipe()
                return False

            timeout = self.get_auto_clear_timeout()
            self._current_item = ClipboardItem(
                data_type=data_type,
                source_entry_id=source_entry_id,
                copied_at=time.time(),
                timeout_seconds=timeout,
                secure_data=secure,
                ephemeral_only=ephemeral,
            )
            self._start_timers(timeout)
            self.events.emit(
                EventType.CLIPBOARD_COPIED,
                {
                    "data_type": data_type,
                    "source_entry_id": source_entry_id,
                    "timeout": timeout,
                    "ephemeral": ephemeral,
                },
            )
            if self.config.get_bool("clipboard_notifications", True):
                self._notify("info", f"Copied {data_type} to clipboard")
            self._notify_observers(self.get_status())
            return True

    def copy_totp(
        self,
        totp_secret: str,
        source_entry_id: Optional[str] = None,
    ) -> str:
        code = generate_totp(totp_secret)
        if not self.copy_to_clipboard(code, data_type="totp", source_entry_id=source_entry_id):
            raise RuntimeError("Failed to copy TOTP to clipboard")
        return code

    def clear_clipboard(self, reason: str = "manual") -> bool:
        with self._lock:
            return self._clear_locked(reason)

    def on_vault_lock(self) -> None:
        self.clear_clipboard(reason="vault_locked")

    def shutdown(self) -> None:
        self.clear_clipboard(reason="application_shutdown")

    def get_auto_clear_timeout(self) -> Optional[int]:
        raw = self.config.get("clipboard_timeout_seconds", self.DEFAULT_TIMEOUT)
        if raw is None:
            return None
        try:
            timeout = int(raw)
        except (ValueError, TypeError):
            timeout = self.DEFAULT_TIMEOUT

        if timeout == self.NEVER_TIMEOUT:
            return None
        return max(self.MIN_TIMEOUT, min(self.MAX_TIMEOUT, timeout))

    def set_auto_clear_timeout(self, timeout_seconds: Optional[int]) -> None:
        if timeout_seconds is None:
            self.config.set("clipboard_timeout_seconds", self.NEVER_TIMEOUT)
            return

        timeout = int(timeout_seconds)
        if timeout == self.NEVER_TIMEOUT:
            self.config.set("clipboard_timeout_seconds", self.NEVER_TIMEOUT)
            return
        if timeout < self.MIN_TIMEOUT or timeout > self.MAX_TIMEOUT:
            raise ValueError(
                f"Timeout must be {self.MIN_TIMEOUT}-{self.MAX_TIMEOUT} seconds or 0 for never"
            )
        self.config.set("clipboard_timeout_seconds", timeout)

    def accelerate_clear(self, seconds: int = 1) -> None:
        with self._lock:
            if not self._current_item:
                return
            if seconds <= 0:
                self._clear_locked("accelerated")
                return
            self._cancel_timers()
            self._timer = threading.Timer(seconds, lambda: self.clear_clipboard("accelerated"))
            self._timer.daemon = True
            self._timer.start()

    def report_suspicious_activity(self, reason: str, details: Optional[dict] = None) -> None:
        payload = {"reason": reason, **(details or {})}
        if self.on_suspicious_activity:
            self.on_suspicious_activity(payload)
        if self.config.get_bool("clipboard_notifications", True):
            self._notify(
                "warning",
                f"Suspicious clipboard activity: {reason}. "
                "Further copies may be blocked.",
            )
        if self.config.get_bool("clipboard_paranoid_mode", False):
            self.set_copy_blocked(True)

    def get_status(self) -> dict:
        with self._lock:
            if not self._current_item:
                return {"active": False, "copy_blocked": self.copy_blocked}
            timeout = self._current_item.timeout_seconds
            if timeout is None:
                remaining = None
            else:
                elapsed = time.time() - self._current_item.copied_at
                remaining = max(0.0, timeout - elapsed)
            return {
                "active": True,
                "data_type": self._current_item.data_type,
                "source_entry_id": self._current_item.source_entry_id,
                "remaining_seconds": remaining,
                "ephemeral": self._current_item.ephemeral_only,
                "copy_blocked": self.copy_blocked,
            }

    def get_masked_preview(self) -> Optional[str]:
        with self._lock:
            if not self._current_item or not self._current_item.secure_data:
                return None
            plain = self._current_item.secure_data.reveal()
            try:
                dt = self._current_item.data_type
                if dt in ("password", "totp", "all"):
                    return (plain[:3] + "•" * 6) if len(plain) >= 3 else "•••"
                if len(plain) <= 4:
                    return "••••"
                return plain[:4] + "••••"
            finally:
                del plain

    def get_revealed_content(self) -> Optional[str]:
        with self._lock:
            if not self._current_item or not self._current_item.secure_data:
                return None
            return self._current_item.secure_data.reveal()

    def get_ephemeral_content(self) -> Optional[str]:
        return self._ephemeral.get()

    def _start_timers(self, timeout: Optional[int]) -> None:
        self._cancel_timers()
        if timeout is None:
            return
        warn_at = timeout - self.WARNING_BEFORE_CLEAR
        if warn_at > 0 and self.config.get_bool("clipboard_notifications", True):
            self._warning_timer = threading.Timer(warn_at, self._on_warning_timeout)
            self._warning_timer.daemon = True
            self._warning_timer.start()
        self._timer = threading.Timer(timeout, lambda: self.clear_clipboard("timeout"))
        self._timer.daemon = True
        self._timer.start()

    def _on_warning_timeout(self) -> None:
        if not self._current_item:
            return
        self._notify("warning", "Clipboard will be cleared in 5 seconds...")

    def _cancel_timers(self) -> None:
        if self._timer:
            self._timer.cancel()
            self._timer = None
        if self._warning_timer:
            self._warning_timer.cancel()
            self._warning_timer = None

    def _clear_locked(self, reason: str) -> bool:
        self._cancel_timers()
        cleared = True
        if self._current_item is None:
            if not self.is_ephemeral_mode():
                cleared = self.adapter.clear_clipboard()
            self._ephemeral.clear()
            return cleared

        if self._current_item.ephemeral_only:
            self._ephemeral.clear()
        else:
            cleared = self.adapter.clear_clipboard()

        if self._current_item.secure_data:
            self._current_item.secure_data.wipe()
        self._current_item = None
        self.events.emit(EventType.CLIPBOARD_CLEARED, {"reason": reason})
        if reason == "timeout" and self.config.get_bool("clipboard_notifications", True):
            self._notify("info", "Clipboard cleared automatically")
        self._notify_observers(self.get_status())
        return cleared

    def _notify(self, level: str, message: str) -> None:
        if self.on_notify:
            try:
                self.on_notify(level, message)
            except Exception:
                pass

    def _notify_observers(self, payload: dict) -> None:
        for observer in list(self._observers):
            try:
                observer(payload)
            except Exception:
                continue
