import time
import threading
from typing import Optional, Any
from .events import EventSystem, EventType
class StateManager:
    def __init__(self, events: EventSystem):
        self.events = events
        self._locked = True
        self._current_user: Optional[str] = None
        self._clipboard_content: Optional[str] = None
        self._clipboard_timer: Optional[threading.Timer] = None
        self._inactivity_timer: Optional[threading.Timer] = None
        self._last_activity = time.time()
        self._lock = threading.RLock()
    @property
    def is_locked(self) -> bool:
        return self._locked
    def unlock(self, username: str = "user"):
        with self._lock:
            self._locked = False
            self._current_user = username
            self._update_activity()
            self.events.emit(EventType.USER_LOGGED_IN, {"username": username})
    def lock(self):
        with self._lock:
            self._locked = True
            self._current_user = None
            self._clear_clipboard()
            self.events.emit(EventType.USER_LOGGED_OUT)
    def set_clipboard(self, content: str, timeout: int = 10):
        with self._lock:
            self._clipboard_content = content
            self.events.emit(EventType.CLIPBOARD_COPIED, {"timeout": timeout})
            # Отмена предыдущего таймера
            if self._clipboard_timer and self._clipboard_timer.is_alive():
                self._clipboard_timer.cancel()
            # Установка нового таймера
            self._clipboard_timer = threading.Timer(timeout, self._clear_clipboard)
            self._clipboard_timer.daemon = True
            self._clipboard_timer.start()
    def _clear_clipboard(self):
        with self._lock:
            self._clipboard_content = None
            self.events.emit(EventType.CLIPBOARD_CLEARED)
    def _update_activity(self):
        self._last_activity = time.time()
    def start_inactivity_timer(self, timeout: int = 300):
        def check_inactivity():
            if not self._locked and (time.time() - self._last_activity) >= timeout:
                self.lock()
        if self._inactivity_timer and self._inactivity_timer.is_alive():
            self._inactivity_timer.cancel()
        self._inactivity_timer = threading.Timer(1.0, check_inactivity)
        self._inactivity_timer.daemon = True
        self._inactivity_timer.start()