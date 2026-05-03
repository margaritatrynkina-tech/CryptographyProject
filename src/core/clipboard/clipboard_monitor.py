import threading
import time
from typing import Optional

from src.core.events import EventSystem, EventType
from src.core.clipboard.clipboard_service import ClipboardService


class ClipboardMonitor:
    def __init__(
        self,
        clipboard_service: ClipboardService,
        events: EventSystem,
        poll_interval: float = 1.0,
    ):
        self.clipboard_service = clipboard_service
        self.events = events
        self.poll_interval = poll_interval

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._last_content: Optional[str] = None

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=2)
            self._thread = None

    def _loop(self) -> None:
        while self._running:
            try:
                status = self.clipboard_service.get_status()
                content = self.clipboard_service.adapter.get_clipboard_content()
                if status.get("active"):
                    if self._last_content is not None and content != self._last_content:
                        self.clipboard_service.accelerate_clear(1)
                        self.events.emit(
                            EventType.AUDIT_LOG_ENTRY,
                            {"reason": "external_change_detected", "source": "clipboard_monitor"},
                        )
                self._last_content = content
            except Exception:
                pass
            time.sleep(self.poll_interval)
