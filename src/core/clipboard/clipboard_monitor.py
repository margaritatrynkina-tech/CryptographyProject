import threading
import time
from typing import Callable, Optional

from src.core.events import EventSystem, EventType
from src.core.clipboard.clipboard_service import ClipboardService


class ClipboardMonitor:
    def __init__(
        self,
        clipboard_service: ClipboardService,
        events: EventSystem,
        poll_interval: float = 1.0,
        on_suspicious: Optional[Callable[[str, dict], None]] = None,
    ):
        self.clipboard_service = clipboard_service
        self.events = events
        self.poll_interval = poll_interval
        self.on_suspicious = on_suspicious

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
                if status.get("active") and not status.get("ephemeral"):
                    content = self.clipboard_service.adapter.get_clipboard_content()
                    if self._last_content is not None and content != self._last_content:
                        self.clipboard_service.accelerate_clear(1)
                        details = {
                            "reason": "external_change_detected",
                            "source": "clipboard_monitor",
                        }
                        self.events.emit(EventType.AUDIT_LOG_ENTRY, details)
                        self.clipboard_service.report_suspicious_activity(
                            "external clipboard change detected",
                            details,
                        )
                        if self.on_suspicious:
                            self.on_suspicious("external_change", details)
                    self._last_content = content
                else:
                    self._last_content = None
            except Exception:
                pass
            interval = self.poll_interval
            if self.clipboard_service.config.get_bool("clipboard_enhanced_monitoring", False):
                interval = min(interval, 0.5)
            time.sleep(interval)
