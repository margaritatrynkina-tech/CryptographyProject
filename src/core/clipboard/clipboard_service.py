import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional

from src.core.events import EventSystem, EventType
from src.core.clipboard.platform_adapter import ClipboardAdapter


@dataclass
class ClipboardItem:
    data_type: str
    source_entry_id: Optional[str]
    copied_at: float
    timeout_seconds: Optional[int]


class ClipboardService:
    DEFAULT_TIMEOUT = 30
    MIN_TIMEOUT = 5
    MAX_TIMEOUT = 300
    NEVER_TIMEOUT = 0

    def __init__(
        self,
        adapter: ClipboardAdapter,
        events: EventSystem,
        config,
        is_vault_unlocked: Callable[[], bool],
    ):
        self.adapter = adapter
        self.events = events
        self.config = config
        self.is_vault_unlocked = is_vault_unlocked

        self._timer: Optional[threading.Timer] = None
        self._lock = threading.RLock()
        self._observers: list[Callable[[dict], None]] = []
        self._current_item: Optional[ClipboardItem] = None

    def subscribe(self, callback: Callable[[dict], None]) -> None:
        with self._lock:
            self._observers.append(callback)

    def unsubscribe(self, callback: Callable[[dict], None]) -> None:
        with self._lock:
            self._observers = [cb for cb in self._observers if cb != callback]

    def copy_to_clipboard(
        self,
        data: str,
        data_type: str = "text",
        source_entry_id: Optional[str] = None,
    ) -> bool:
        if not isinstance(data, str):
            raise ValueError("Clipboard data must be a string")
        if data.strip() == "":
            raise ValueError("Clipboard data cannot be empty")
        if not self.is_vault_unlocked():
            raise PermissionError("Vault is locked. Clipboard copy is denied.")

        with self._lock:
            self._clear_locked("replaced")
            copied = self.adapter.copy_to_clipboard(data)
            if not copied:
                return False

            timeout = self.get_auto_clear_timeout()
            self._current_item = ClipboardItem(
                data_type=data_type,
                source_entry_id=source_entry_id,
                copied_at=time.time(),
                timeout_seconds=timeout,
            )
            self._start_timer(timeout)
            self.events.emit(
                EventType.CLIPBOARD_COPIED,
                {
                    "data_type": data_type,
                    "source_entry_id": source_entry_id,
                    "timeout": timeout,
                },
            )
            self._notify_observers(self.get_status())
            return True

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
            self._cancel_timer()
            self._timer = threading.Timer(seconds, lambda: self.clear_clipboard("accelerated"))
            self._timer.daemon = True
            self._timer.start()

    def get_status(self) -> dict:
        with self._lock:
            if not self._current_item:
                return {"active": False}
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
            }

    def _start_timer(self, timeout: Optional[int]) -> None:
        self._cancel_timer()
        if timeout is None:
            return
        self._timer = threading.Timer(timeout, lambda: self.clear_clipboard("timeout"))
        self._timer.daemon = True
        self._timer.start()

    def _cancel_timer(self) -> None:
        if self._timer:
            self._timer.cancel()
            self._timer = None

    def _clear_locked(self, reason: str) -> bool:
        self._cancel_timer()
        if self._current_item is None:
            return self.adapter.clear_clipboard()

        cleared = self.adapter.clear_clipboard()
        self._current_item = None
        self.events.emit(EventType.CLIPBOARD_CLEARED, {"reason": reason})
        self._notify_observers(self.get_status())
        return cleared

    def _notify_observers(self, payload: dict) -> None:
        for observer in list(self._observers):
            try:
                observer(payload)
            except Exception:
                continue
