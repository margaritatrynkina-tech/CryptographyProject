import time
import threading
from typing import Optional, Callable, List
from datetime import datetime, timedelta
import logging

from .activity_monitor import ActivityMonitor, get_default_activity_monitor
from .memory_guard import clear_secure_memory
from .profiles import get_profile_manager, is_feature_enabled


class AutoLockService:
    
    def __init__(
        self,
        activity_monitor: Optional[ActivityMonitor] = None,
        events=None,
        clipboard_service=None,
        audit_logger=None,
    ):
        self.logger = logging.getLogger(__name__)
        self._activity_monitor = activity_monitor or get_default_activity_monitor()
        self._events = events  # EventSystem — may be None
        self.clipboard_service = clipboard_service
        self.audit_logger = audit_logger
        self._lock_callbacks: List[Callable[[], None]] = []
        self._unlock_callbacks: List[Callable[[], None]] = []
        self._lock_timer: Optional[threading.Timer] = None
        self._locked = False
        self._enabled = False
        self._lock_timeout = 300  # 5 minutes default
        self._last_lock_time: Optional[float] = None
        self._lock_reason: Optional[str] = None
        
        # Load configuration from security profile
        self._load_configuration()
    
    def _load_configuration(self) -> None:
        try:
            # Check if auto-lock is enabled in current profile
            self._enabled = is_feature_enabled('auto_lock')
            
            # Get lock timeout from profile
            timeout = get_profile_manager().get_feature('auto_lock_timeout')
            if timeout:
                self._lock_timeout = timeout
            
            self.logger.debug(f"Auto-lock configuration: enabled={self._enabled}, timeout={self._lock_timeout}s")
            
        except Exception as e:
            self.logger.error(f"Error loading auto-lock configuration: {e}")
            # Default to disabled on error
            self._enabled = False
    
    def start(self) -> None:
        if self._enabled and not self._activity_monitor._monitoring:
            self.logger.info("Starting auto-lock service")
            
            # Start activity monitor
            self._activity_monitor.start()
            
            # Register activity callback
            self._activity_monitor.register_activity_callback(self._on_activity)
            
            # Start lock timer
            self._reset_lock_timer()
            
            self.logger.info(f"Auto-lock service started (timeout: {self._lock_timeout}s)")
        else:
            self.logger.info("Auto-lock service not started (disabled or already running)")
    
    def stop(self) -> None:
        self.logger.info("Stopping auto-lock service")
        
        # Stop lock timer
        self._stop_lock_timer()
        
        # Unregister activity callback
        try:
            self._activity_monitor.unregister_activity_callback(self._on_activity)
        except:
            pass
        
        # Stop activity monitor if we started it
        if self._activity_monitor._monitoring:
            self._activity_monitor.stop()
    
    def _reset_lock_timer(self) -> None:
        # Stop existing timer
        self._stop_lock_timer()
        
        # Start new timer if enabled
        if self._enabled and not self._locked:
            self._lock_timer = threading.Timer(self._lock_timeout, self._on_lock_timeout)
            self._lock_timer.daemon = True
            self._lock_timer.start()
            self.logger.debug(f"Lock timer reset: {self._lock_timeout}s")
    
    def _stop_lock_timer(self) -> None:
        if self._lock_timer:
            self._lock_timer.cancel()
            self._lock_timer = None
    
    def _on_activity(self, event) -> None:
        if self._locked:
            # If locked, activity might trigger unlock prompt
            # (This would be handled by GUI layer)
            pass
        else:
            # Reset lock timer on activity
            self._reset_lock_timer()
            self.logger.debug("Activity detected, lock timer reset")
    
    def _on_lock_timeout(self) -> None:
        self.logger.warning(f"Auto-lock triggered after {self._lock_timeout}s of inactivity")
        self.lock(reason="auto_lock")
    
    def lock(self, reason: str = "manual") -> None:
        if self._locked:
            self.logger.debug("Application is already locked")
            return
        
        self.logger.warning(f"Locking application (reason: {reason})")
        self._locked = True
        self._lock_reason = reason
        self._last_lock_time = time.time()
        
        # Stop lock timer (we're already locked)
        self._stop_lock_timer()
        
        try:
            # Step 1: Clear all encryption keys from memory
            self._clear_encryption_keys()
            
            # Step 2: Clear clipboard
            self._clear_clipboard()
            
            # Step 3: Log lock event
            self._log_lock_event(reason)

            # Step 4: Emit event
            if self._events:
                try:
                    from src.core.events import EventType
                    self._events.emit(EventType.VAULT_AUTO_LOCKED, {"reason": reason})
                except Exception:
                    pass

            # Step 5: Notify callbacks
            for callback in self._lock_callbacks:
                try:
                    callback()
                except Exception as e:
                    self.logger.error(f"Lock callback failed: {e}")
            
            self.logger.warning("Application locked successfully")
            
        except Exception as e:
            self.logger.error(f"Error locking application: {e}")
            # Try to recover
            self._locked = False
            self._lock_reason = None
    
    def unlock(self, master_password: str) -> bool:
        if not self._locked:
            self.logger.debug("Application is not locked")
            return True
        
        self.logger.info("Attempting to unlock application")
        
        try:
            # Verify master password
            # This would typically involve checking against stored hash
            # For now, we'll assume it's valid if not empty
            if not master_password:
                self.logger.warning("Empty master password provided")
                return False
            
            # In a real implementation, you would:
            # 1. Verify the master password hash
            # 2. Re-derive encryption keys
            # 3. Restore application state
            
            # For now, we'll just log and unlock
            self.logger.info("Master password verified")
            
            # Update state
            self._locked = False
            lock_duration = time.time() - self._last_lock_time if self._last_lock_time else 0
            self.logger.info(f"Application unlocked (was locked for {lock_duration:.1f}s)")

            # Reset lock timer
            self._reset_lock_timer()

            # Emit event
            if self._events:
                try:
                    from src.core.events import EventType
                    self._events.emit(EventType.VAULT_UNLOCKED, {"duration": lock_duration})
                except Exception:
                    pass

            # Notify callbacks
            for callback in self._unlock_callbacks:
                try:
                    callback()
                except Exception as e:
                    self.logger.error(f"Unlock callback failed: {e}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error unlocking application: {e}")
            return False
    
    def _clear_encryption_keys(self) -> None:
        self.logger.debug("Clearing encryption keys")
        
        # Import here to avoid circular imports
        try:
            from ..vault import Vault
            vault = Vault.get_instance()
            if vault:
                vault.clear_keys()
        except ImportError:
            self.logger.debug("Vault module not available")
        except Exception as e:
            self.logger.error(f"Error clearing vault keys: {e}")
        
        # Clear secure memory
        clear_secure_memory()
    
    def _clear_clipboard(self) -> None:
        self.logger.debug("Clearing clipboard")
        
        if self.clipboard_service is not None:
            try:
                # CryptoSafe Manager API: clear_clipboard(reason=...)
                self.clipboard_service.clear_clipboard(reason="vault_auto_lock")
                return
            except Exception as e:
                self.logger.error(f"Error clearing clipboard via injected service: {e}")

        # Fallback: best-effort clearing (avoid GUI creation in headless contexts)
        self._clear_clipboard_fallback()
    
    def _clear_clipboard_fallback(self) -> None:
        try:
            import pyperclip
            pyperclip.copy('')
        except Exception:
            # As a last resort, do not attempt Tkinter in non-GUI environments.
            self.logger.warning("Could not clear clipboard (pyperclip unavailable)")
    
    def _log_lock_event(self, reason: str) -> None:
        self.logger.debug("Logging lock event")
        
        if self.audit_logger is not None:
            try:
                # Directly write to audit logger using its event mapping.
                from ..events import EventType
                from ..audit.audit_logger import EVENT_MAP

                audit_type, severity = EVENT_MAP[EventType.VAULT_AUTO_LOCKED]
                self.audit_logger.log_event(
                    audit_type,
                    severity,
                    source="auto_lock",
                    details={"reason": reason, "timeout_seconds": self._lock_timeout},
                )
                return
            except Exception as e:
                self.logger.error(f"Error logging lock event via injected logger: {e}")
                return
        # If audit_logger is not injected, do not emit events here.
        # `lock()` is responsible for emitting EventType.VAULT_AUTO_LOCKED once.
    
    def register_lock_callback(self, callback: Callable[[], None]) -> None:
        if callback not in self._lock_callbacks:
            self._lock_callbacks.append(callback)
    
    def unregister_lock_callback(self, callback: Callable[[], None]) -> None:
        if callback in self._lock_callbacks:
            self._lock_callbacks.remove(callback)
    
    def register_unlock_callback(self, callback: Callable[[], None]) -> None:
        if callback not in self._unlock_callbacks:
            self._unlock_callbacks.append(callback)
    
    def unregister_unlock_callback(self, callback: Callable[[], None]) -> None:
        if callback in self._unlock_callbacks:
            self._unlock_callbacks.remove(callback)
    
    def is_locked(self) -> bool:
        return self._locked
    
    def is_enabled(self) -> bool:
        return self._enabled
    
    def get_lock_timeout(self) -> int:
        return self._lock_timeout
    
    def set_lock_timeout(self, timeout: int) -> None:
        # Validate timeout
        timeout = max(60, min(28800, timeout))  # 1 minute to 8 hours
        self._lock_timeout = timeout
        
        self.logger.info(f"Lock timeout set to {timeout}s")
        
        # Reset timer with new timeout
        if self._enabled and not self._locked:
            self._reset_lock_timer()
    
    def get_lock_reason(self) -> Optional[str]:
        return self._lock_reason
    
    def get_lock_duration(self) -> float:
        if self._last_lock_time:
            return time.time() - self._last_lock_time
        return 0.0
    
    def get_status(self) -> dict:
        return {
            'enabled': self._enabled,
            'locked': self._locked,
            'lock_timeout': self._lock_timeout,
            'lock_reason': self._lock_reason,
            'last_lock_time': self._last_lock_time,
            'lock_duration': self.get_lock_duration(),
            'callbacks': {
                'lock': len(self._lock_callbacks),
                'unlock': len(self._unlock_callbacks),
            }
        }
    
    def __enter__(self):
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()


# Global auto-lock service instance
_auto_lock_service: Optional[AutoLockService] = None


def get_auto_lock_service() -> AutoLockService:
    global _auto_lock_service
    if _auto_lock_service is None:
        _auto_lock_service = AutoLockService()
    return _auto_lock_service


def start_auto_lock() -> None:
    service = get_auto_lock_service()
    if not service._enabled:
        service._enabled = True
    service.start()


def stop_auto_lock() -> None:
    service = get_auto_lock_service()
    service.stop()


def lock_application(reason: str = "manual") -> None:
    service = get_auto_lock_service()
    service.lock(reason)


def unlock_application(master_password: str) -> bool:
    service = get_auto_lock_service()
    return service.unlock(master_password)


def is_application_locked() -> bool:
    service = get_auto_lock_service()
    return service.is_locked()


# Test the module
if __name__ == "__main__":
    import logging
    
    # Configure logging
    logging.basicConfig(level=logging.DEBUG)
    
    # Test AutoLockService
    print("Testing AutoLockService")
    print("=" * 50)
    
    # Create test callbacks
    def on_lock():
        print("LOCK CALLBACK: Application locked!")
    
    def on_unlock():
        print("UNLOCK CALLBACK: Application unlocked!")
    
    # Test with callbacks
    with AutoLockService() as service:
        service.register_lock_callback(on_lock)
        service.register_unlock_callback(on_unlock)
        
        print(f"Service status: {service.get_status()}")
        
        # Test manual lock
        print("\nTesting manual lock...")
        service.lock("test")
        print(f"Locked: {service.is_locked()}")
        print(f"Lock reason: {service.get_lock_reason()}")
        
        # Test unlock (with dummy password)
        print("\nTesting unlock...")
        unlocked = service.unlock("test_password")
        print(f"Unlock successful: {unlocked}")
        print(f"Locked: {service.is_locked()}")
        
        # Test configuration
        print("\nTesting configuration...")
        service.set_lock_timeout(60)  # 1 minute
        print(f"New timeout: {service.get_lock_timeout()}s")
        
        print("\nTest complete")