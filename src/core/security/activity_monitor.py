import time
import threading
from typing import Optional, Callable, List
from datetime import datetime, timedelta
from enum import Enum
import logging

from .platform import ActivityMonitorImpl


class ActivityType(Enum):
    MOUSE_MOVE = "mouse_move"
    MOUSE_CLICK = "mouse_click"
    KEYBOARD = "keyboard"
    APPLICATION_FOCUS = "application_focus"
    USER_PRESENCE = "user_presence"


class ActivityEvent:
    
    def __init__(self, activity_type: ActivityType, timestamp: Optional[float] = None):
        self.activity_type = activity_type
        self.timestamp = timestamp or time.time()
    
    def __repr__(self):
        return f"ActivityEvent(type={self.activity_type}, time={self.timestamp})"


class ActivityMonitor:
    
    def __init__(self, platform_monitor: Optional[ActivityMonitorImpl] = None):
        self.logger = logging.getLogger(__name__)
        self._platform_monitor = platform_monitor or ActivityMonitorImpl()
        self._last_activity_time = time.time()
        self._activity_callbacks: List[Callable[[ActivityEvent], None]] = []
        self._monitoring = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        
        # Configuration
        self._poll_interval = 1.0  # seconds
        self._min_activity_interval = 0.5  # seconds between activity events
        
        # Statistics
        self._activity_count = 0
        self._last_activity_type: Optional[ActivityType] = None
    
    def start(self) -> None:
        if self._monitoring:
            raise RuntimeError("Activity monitoring is already started")
        
        self.logger.info("Starting activity monitor")
        self._monitoring = True
        self._stop_event.clear()
        
        # Start platform monitor
        try:
            self._platform_monitor.start()
        except Exception as e:
            self.logger.warning(f"Platform monitor failed to start: {e}")
        
        # Start monitoring thread
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            name="ActivityMonitor",
            daemon=True
        )
        self._monitor_thread.start()
    
    def stop(self) -> None:
        """Stop monitoring user activity."""
        if not self._monitoring:
            return
        
        self.logger.info("Stopping activity monitor")
        self._monitoring = False
        self._stop_event.set()
        
        # Stop platform monitor
        try:
            self._platform_monitor.stop()
        except Exception as e:
            self.logger.warning(f"Platform monitor failed to stop: {e}")
        
        # Wait for monitor thread to finish
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=5.0)
        
        self._monitor_thread = None
    
    def _monitor_loop(self) -> None:
        self.logger.debug("Activity monitor loop started")
        
        last_poll_time = time.time()
        
        while not self._stop_event.is_set():
            try:
                current_time = time.time()
                
                # Check for platform-specific activity
                platform_activity = self._check_platform_activity()
                if platform_activity:
                    self._record_activity(platform_activity)
                
                # Check time since last activity
                idle_time = self.get_idle_time()
                
                # Poll at regular intervals
                if current_time - last_poll_time >= self._poll_interval:
                    self._poll_activity()
                    last_poll_time = current_time
                
                # Sleep to prevent CPU spinning
                time.sleep(0.1)
                
            except Exception as e:
                self.logger.error(f"Error in activity monitor loop: {e}")
                time.sleep(1.0)  # Longer sleep on error
    
    def _check_platform_activity(self) -> Optional[ActivityEvent]:
        try:
            if self._platform_monitor.has_activity():
                activity_type = self._platform_monitor.get_activity_type()
                return ActivityEvent(ActivityType(activity_type))
        except Exception as e:
            self.logger.debug(f"Platform activity check failed: {e}")
        
        return None
    
    def _poll_activity(self) -> None:
        # This is a fallback method that can be overridden by subclasses
        # or platform-specific implementations
        pass
    
    def _record_activity(self, event: ActivityEvent) -> None:

        current_time = time.time()
        
        # Prevent recording activity too frequently
        if current_time - self._last_activity_time < self._min_activity_interval:
            return
        
        self._last_activity_time = current_time
        self._last_activity_type = event.activity_type
        self._activity_count += 1
        
        self.logger.debug(f"Activity recorded: {event.activity_type}")
        
        # Notify callbacks
        for callback in self._activity_callbacks:
            try:
                callback(event)
            except Exception as e:
                self.logger.error(f"Activity callback failed: {e}")
    
    def register_activity_callback(self, callback: Callable[[ActivityEvent], None]) -> None:

        if callback not in self._activity_callbacks:
            self._activity_callbacks.append(callback)
    
    def unregister_activity_callback(self, callback: Callable[[ActivityEvent], None]) -> None:

        if callback in self._activity_callbacks:
            self._activity_callbacks.remove(callback)
    
    def get_idle_time(self) -> float:

        return time.time() - self._last_activity_time
    
    def get_idle_time_formatted(self) -> str:

        idle_seconds = self.get_idle_time()
        
        if idle_seconds < 60:
            return f"{int(idle_seconds)}s"
        elif idle_seconds < 3600:
            minutes = int(idle_seconds // 60)
            seconds = int(idle_seconds % 60)
            return f"{minutes}m {seconds}s"
        else:
            hours = int(idle_seconds // 3600)
            minutes = int((idle_seconds % 3600) // 60)
            return f"{hours}h {minutes}m"
    
    def is_user_present(self, max_idle_seconds: float = 300) -> bool:

        return self.get_idle_time() < max_idle_seconds
    
    def force_activity(self, activity_type: ActivityType = ActivityType.USER_PRESENCE) -> None:

        event = ActivityEvent(activity_type)
        self._record_activity(event)
    
    def get_statistics(self) -> dict:

        return {
            'monitoring': self._monitoring,
            'last_activity_time': self._last_activity_time,
            'last_activity_type': self._last_activity_type,
            'idle_time': self.get_idle_time(),
            'activity_count': self._activity_count,
            'callbacks_registered': len(self._activity_callbacks),
        }
    
    def reset(self) -> None:

        self._last_activity_time = time.time()
        self._activity_count = 0
        self._last_activity_type = None
    
    def __enter__(self):
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()


# Default activity monitor instance
_default_monitor: Optional[ActivityMonitor] = None


def get_default_activity_monitor() -> ActivityMonitor:

    global _default_monitor
    if _default_monitor is None:
        _default_monitor = ActivityMonitor()
    return _default_monitor


def start_activity_monitoring() -> None:

    monitor = get_default_activity_monitor()
    if not monitor._monitoring:
        monitor.start()


def stop_activity_monitoring() -> None:
    monitor = get_default_activity_monitor()
    if monitor._monitoring:
        monitor.stop()


def get_idle_time() -> float:
    monitor = get_default_activity_monitor()
    return monitor.get_idle_time()


def is_user_present(max_idle_seconds: float = 300) -> bool:
    monitor = get_default_activity_monitor()
    return monitor.is_user_present(max_idle_seconds)


# Test the module
if __name__ == "__main__":
    import logging
    
    # Configure logging
    logging.basicConfig(level=logging.DEBUG)
    
    # Test ActivityMonitor
    def on_activity(event: ActivityEvent):
        print(f"Activity detected: {event.activity_type} at {event.timestamp}")
    
    with ActivityMonitor() as monitor:
        monitor.register_activity_callback(on_activity)
        
        print("Monitoring activity for 5 seconds...")
        print("Move your mouse or press keys to see activity events")
        
        time.sleep(5)
        
        print(f"Idle time: {monitor.get_idle_time_formatted()}")
        print(f"User present: {monitor.is_user_present()}")
        print(f"Statistics: {monitor.get_statistics()}")
        
        # Force activity
        monitor.force_activity(ActivityType.USER_PRESENCE)
        print(f"After forced activity - Idle time: {monitor.get_idle_time_formatted()}")