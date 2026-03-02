from typing import Dict, Callable, List, Any, Union
from enum import Enum
import threading
from queue import Queue
class EventType(Enum):
    ENTRY_ADDED = "entry_added"
    ENTRY_UPDATED = "entry_updated"
    ENTRY_DELETED = "entry_deleted"
    USER_LOGGED_IN = "user_logged_in"
    USER_LOGGED_OUT = "user_logged_out"
    CLIPBOARD_COPIED = "clipboard_copied"
    CLIPBOARD_CLEARED = "clipboard_cleared"
    AUDIT_LOG_ENTRY = "audit_log_entry"  # Для Sprint 5
class EventSystem:
    def __init__(self):
        self._handlers: Dict[EventType, List[Callable]] = {}
        self._async_queue = Queue()
        self._running = False
        self._async_thread: Optional[threading.Thread] = None
    def subscribe(self, event_type: EventType, handler: Callable, async_handler: bool = False):
        if event_type not in self._handlers:
            self._handlers[event_type] = []
        self._handlers[event_type].append((handler, async_handler))
    def emit(self, event_type: EventType, data: Any = None):
        if event_type in self._handlers:
            for handler, is_async in self._handlers[event_type]:
                if is_async:
                    self._async_queue.put((handler, event_type, data))
                else:
                    try:
                        handler(data)
                    except Exception as e:
                        print(f"Error in sync handler for {event_type}: {e}")
    def start_async_processing(self):
        self._running = True
        self._async_thread = threading.Thread(target=self._process_async_queue, daemon=True)
        self._async_thread.start()
    def _process_async_queue(self):
        while self._running:
            try:
                handler, event_type, data = self._async_queue.get(timeout=1)
                try:
                    handler(data)
                except Exception as e:
                    print(f"Error in async handler for {event_type}: {e}")
            except:
                pass
    def stop_async_processing(self):
        self._running = False
        if self._async_thread:
            self._async_thread.join(timeout=2)