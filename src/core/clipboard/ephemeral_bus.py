import threading
import time
from typing import Callable, List, Optional


class EphemeralClipboardBus:
    _instance: Optional["EphemeralClipboardBus"] = None
    _lock = threading.Lock()

    def __init__(self):
        self._data: Optional[str] = None
        self._listeners: List[Callable[[Optional[str]], None]] = []
        self._bus_lock = threading.RLock()
        self._expires_at: float = 0.0

    @classmethod
    def instance(cls) -> "EphemeralClipboardBus":
        with cls._lock:
            if cls._instance is None:
                cls._instance = EphemeralClipboardBus()
            return cls._instance

    def set(self, data: str, ttl_seconds: int = 60) -> None:
        with self._bus_lock:
            self._data = data
            self._expires_at = time.time() + ttl_seconds
            for cb in list(self._listeners):
                try:
                    cb(data)
                except Exception:
                    pass

    def get(self) -> Optional[str]:
        with self._bus_lock:
            if self._data is None:
                return None
            if time.time() > self._expires_at:
                self._data = None
                return None
            return self._data

    def clear(self) -> None:
        with self._bus_lock:
            self._data = None
            self._expires_at = 0.0
            for cb in list(self._listeners):
                try:
                    cb(None)
                except Exception:
                    pass

    def subscribe(self, callback: Callable[[Optional[str]], None]) -> None:
        self._listeners.append(callback)
