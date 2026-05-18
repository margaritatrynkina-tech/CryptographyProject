import time
import secrets
from dataclasses import dataclass
from typing import Optional
from src.core.events import EventSystem, EventType
from src.core.key_manager import KeyManager
@dataclass
class SessionInfo:
    logged_in: bool = False
    login_timestamp: Optional[float] = None
    last_activity: Optional[float] = None
    failed_attempts: int = 0


class AuthenticationService:
    def __init__(self, key_manager: KeyManager, events: EventSystem):
        self.key_manager = key_manager
        self.events = events
        self.session = SessionInfo()

    def _calculate_delay(self) -> int:
        n = self.session.failed_attempts
        if n <= 2:
            return 1
        if n <= 4:
            return 5
        return 30

    def login(self, password: str) -> bool:
        delay = self._calculate_delay()
        time.sleep(delay)  # экспоненциальный backoff

        ok = self.key_manager.authenticate(password)
        if ok:
            self.session.logged_in = True
            now = time.time()
            self.session.login_timestamp = now
            self.session.last_activity = now
            self.session.failed_attempts = 0
            self.key_manager.get_audit_signing_seed(password)
            self.events.emit(EventType.USER_LOGGED_IN, {})
            return True
        else:
            self.session.failed_attempts += 1
            self.events.emit(
                EventType.AUDIT_LOG_ENTRY,
                {"reason": "auth_failed", "attempts": self.session.failed_attempts},
            )
            secrets.compare_digest(b'dummy', b'dummy')
            return False

    def logout(self):
        self.session = SessionInfo()
        self.key_manager.clear_keys()
        self.events.emit(EventType.USER_LOGGED_OUT, {})

    def update_activity(self):
        if self.session.logged_in:
            self.session.last_activity = time.time()
