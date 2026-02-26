from typing import Dict, Callable, List, Any
from enum import Enum
class EventType(Enum):
    ENTRY_ADDED = "entry_added"
    ENTRY_UPDATED = "entry_updated"
    ENTRY_DELETED = "entry_deleted"
    USER_LOGGED_IN = "user_logged_in"
    USER_LOGGED_OUT = "user_logged_out"
class EventSystem:
    def __init__(self):
        self._handlers: Dict[EventType, List[Callable]] = {}
    def subscribe(self, event_type: EventType, handler: Callable):
        if event_type not in self._handlers:
            self._handlers[event_type] = []
        self._handlers[event_type].append(handler)
    def emit(self, event_type: EventType, data: Any = None):
        if event_type in self._handlers:
            for handler in self._handlers[event_type]:
                handler(data)
