import time
import threading
from typing import Optional, Callable, List
from enum import Enum
import logging
import sys

from .memory_guard import clear_secure_memory


class PanicModeState(Enum):
    NORMAL = "normal"
    ACTIVATING = "activating"
    ACTIVE = "active"
    DEACTIVATING = "deactivating"


class PanicMode:
    
    def __init__(
        self,
        clipboard_service=None,
        audit_logger=None,
        config: Optional[dict] = None,
    ):
        self.logger = logging.getLogger(__name__)
        self._state = PanicModeState.NORMAL
        self._activation_time: Optional[float] = None
        self._panic_callbacks: List[Callable[[], None]] = []
        self._recovery_callbacks: List[Callable[[], None]] = []
        
        # Configuration
        self._hotkey = "ctrl+shift+esc"
        self._stealth_mode = False
        self._fake_error_message = "Application has encountered a critical error and must close."
        self._auto_recovery_delay = 0  # seconds (0 = manual recovery only)

        self.clipboard_service = clipboard_service
        self.audit_logger = audit_logger

        if config:
            if "stealth_mode" in config:
                self._stealth_mode = bool(config["stealth_mode"])
            if "fake_error_message" in config and config["fake_error_message"]:
                self._fake_error_message = str(config["fake_error_message"])
            if "auto_recovery_delay" in config:
                try:
                    self._auto_recovery_delay = max(0, int(config["auto_recovery_delay"]))
                except Exception:
                    pass
        
        # Hotkey registration
        self._hotkey_registered = False
        self._hotkey_thread: Optional[threading.Thread] = None
        self._stop_hotkey = threading.Event()
    
    def activate(self, stealth: Optional[bool] = None) -> None:
        if self._state != PanicModeState.NORMAL:
            self.logger.warning(f"Cannot activate panic mode from state {self._state}")
            return
        
        self.logger.warning("ACTIVATING PANIC MODE")
        self._state = PanicModeState.ACTIVATING
        
        # Use provided stealth mode or configured value
        use_stealth = stealth if stealth is not None else self._stealth_mode
        
        try:
            # Step 1: Clear all encryption keys from memory
            self._clear_encryption_keys()
            
            # Step 2: Clear clipboard
            self._clear_clipboard()
            
            # Step 3: Close all application windows
            self._close_windows()
            
            # Step 4: Display stealth message if enabled
            if use_stealth:
                self._display_stealth_message()
            
            # Step 5: Log panic event
            self._log_panic_event(use_stealth)
            
            # Update state
            self._state = PanicModeState.ACTIVE
            self._activation_time = time.time()
            
            self.logger.warning("PANIC MODE ACTIVATED")
            
            # Notify callbacks
            for callback in self._panic_callbacks:
                try:
                    callback()
                except Exception as e:
                    self.logger.error(f"Panic callback failed: {e}")
            
            # Start auto-recovery timer if configured
            if self._auto_recovery_delay > 0:
                self._start_auto_recovery_timer()
                
        except Exception as e:
            self.logger.error(f"Error activating panic mode: {e}")
            # Try to recover to normal state
            self._state = PanicModeState.NORMAL
    
    def deactivate(self) -> None:
        if self._state != PanicModeState.ACTIVE:
            self.logger.warning(f"Cannot deactivate panic mode from state {self._state}")
            return
        
        self.logger.info("Deactivating panic mode")
        self._state = PanicModeState.DEACTIVATING
        
        try:
            # Stop auto-recovery timer if running
            self._stop_auto_recovery_timer()
            
            # Clear any remaining secure memory
            clear_secure_memory()
            
            # Update state
            self._state = PanicModeState.NORMAL
            self._activation_time = None
            
            self.logger.info("Panic mode deactivated")
            
            # Notify recovery callbacks
            for callback in self._recovery_callbacks:
                try:
                    callback()
                except Exception as e:
                    self.logger.error(f"Recovery callback failed: {e}")
                    
        except Exception as e:
            self.logger.error(f"Error deactivating panic mode: {e}")
            self._state = PanicModeState.ACTIVE  # Stay in panic mode on error
    
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
                self.clipboard_service.clear_clipboard(reason="panic_mode")
                return
            except Exception as e:
                self.logger.error(f"Error clearing clipboard via injected service: {e}")

        # Fallback: avoid instantiating ClipboardService without required args.
        self._clear_clipboard_fallback()
    
    def _clear_clipboard_fallback(self) -> None:
        try:
            import pyperclip
            pyperclip.copy('')
        except Exception:
            # Avoid GUI creation in non-GUI contexts.
            self.logger.warning("Could not clear clipboard (pyperclip unavailable)")
    
    def _close_windows(self) -> None:
        self.logger.debug("Closing application windows")
        
        # This should be implemented by the GUI layer
        # We'll just log it here and rely on callbacks
        pass
    
    def _display_stealth_message(self) -> None:
        self.logger.debug("Displaying stealth message")
        
        try:
            import tkinter as tk
            from tkinter import messagebox
            
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror("Critical Error", self._fake_error_message)
            root.destroy()
        except:
            # If GUI is not available, just log it
            self.logger.info(f"Stealth message: {self._fake_error_message}")
    
    def _log_panic_event(self, stealth: bool) -> None:
        self.logger.debug("Logging panic event")

        if self.audit_logger is None:
            return

        try:
            from ..events import EventType
            from ..audit.audit_logger import EVENT_MAP

            audit_type, severity = EVENT_MAP[EventType.PANIC_MODE_ACTIVATED]
            self.audit_logger.log_event(
                audit_type,
                severity,
                source="panic_mode",
                details={"stealth_mode": stealth},
            )
        except Exception as e:
            self.logger.error(f"Error logging panic event via injected logger: {e}")
    
    def _start_auto_recovery_timer(self) -> None:
        if self._auto_recovery_delay <= 0:
            return
        
        self.logger.debug(f"Starting auto-recovery timer: {self._auto_recovery_delay}s")
        
        def auto_recover():
            time.sleep(self._auto_recovery_delay)
            if self._state == PanicModeState.ACTIVE:
                self.logger.info("Auto-recovery triggered")
                self.deactivate()
        
        recovery_thread = threading.Thread(
            target=auto_recover,
            name="PanicAutoRecovery",
            daemon=True
        )
        recovery_thread.start()
    
    def _stop_auto_recovery_timer(self) -> None:
        # The timer runs in a daemon thread, so it will stop automatically
        # when the main thread exits. We just need to clear any state.
        pass
    
    def register_hotkey(self, hotkey: Optional[str] = None) -> None:
        if hotkey:
            self._hotkey = hotkey
        
        if self._hotkey_registered:
            self.unregister_hotkey()
        
        self.logger.info(f"Registering panic hotkey: {self._hotkey}")
        
        try:
            import keyboard
            
            def on_hotkey():
                self.logger.warning(f"Panic hotkey pressed: {self._hotkey}")
                self.activate()
            
            keyboard.add_hotkey(self._hotkey, on_hotkey)
            self._hotkey_registered = True
            
            # Start hotkey monitoring thread
            self._stop_hotkey.clear()
            self._hotkey_thread = threading.Thread(
                target=self._hotkey_monitor_loop,
                name="PanicHotkeyMonitor",
                daemon=True
            )
            self._hotkey_thread.start()
            
        except ImportError:
            self.logger.warning("keyboard module not available, hotkey registration disabled")
        except Exception as e:
            self.logger.error(f"Error registering hotkey: {e}")
    
    def unregister_hotkey(self) -> None:
        if not self._hotkey_registered:
            return
        
        self.logger.info("Unregistering panic hotkey")
        
        self._stop_hotkey.set()
        if self._hotkey_thread and self._hotkey_thread.is_alive():
            self._hotkey_thread.join(timeout=2.0)
        
        try:
            import keyboard
            keyboard.remove_hotkey(self._hotkey)
        except:
            pass
        
        self._hotkey_registered = False
        self._hotkey_thread = None
    
    def _hotkey_monitor_loop(self) -> None:
        try:
            import keyboard
            while not self._stop_hotkey.is_set():
                time.sleep(0.1)
        except:
            pass
    
    def register_panic_callback(self, callback: Callable[[], None]) -> None:
        if callback not in self._panic_callbacks:
            self._panic_callbacks.append(callback)
    
    def unregister_panic_callback(self, callback: Callable[[], None]) -> None:
        if callback in self._panic_callbacks:
            self._panic_callbacks.remove(callback)
    
    def register_recovery_callback(self, callback: Callable[[], None]) -> None:
        if callback not in self._recovery_callbacks:
            self._recovery_callbacks.append(callback)
    
    def unregister_recovery_callback(self, callback: Callable[[], None]) -> None:
        if callback in self._recovery_callbacks:
            self._recovery_callbacks.remove(callback)
    
    def get_state(self) -> PanicModeState:
        return self._state
    
    def is_active(self) -> bool:
        return self._state == PanicModeState.ACTIVE
    
    def get_activation_time(self) -> Optional[float]:
        return self._activation_time
    
    def get_activation_duration(self) -> float:
        if self._activation_time:
            return time.time() - self._activation_time
        return 0.0
    
    def configure(self, **kwargs) -> None:
        if 'hotkey' in kwargs:
            self._hotkey = kwargs['hotkey']
            if self._hotkey_registered:
                self.register_hotkey(self._hotkey)
        
        if 'stealth_mode' in kwargs:
            self._stealth_mode = kwargs['stealth_mode']
        
        if 'fake_error_message' in kwargs:
            self._fake_error_message = kwargs['fake_error_message']
        
        if 'auto_recovery_delay' in kwargs:
            self._auto_recovery_delay = max(0, kwargs['auto_recovery_delay'])
    
    def get_configuration(self) -> dict:
        return {
            'state': self._state.value,
            'hotkey': self._hotkey,
            'stealth_mode': self._stealth_mode,
            'fake_error_message': self._fake_error_message,
            'auto_recovery_delay': self._auto_recovery_delay,
            'hotkey_registered': self._hotkey_registered,
            'activation_time': self._activation_time,
            'callbacks': {
                'panic': len(self._panic_callbacks),
                'recovery': len(self._recovery_callbacks),
            }
        }
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.unregister_hotkey()


# Global panic mode instance
_panic_mode: Optional[PanicMode] = None


def get_panic_mode() -> PanicMode:
    global _panic_mode
    if _panic_mode is None:
        _panic_mode = PanicMode()
    return _panic_mode


def activate_panic_mode(stealth: Optional[bool] = None) -> None:
    panic = get_panic_mode()
    panic.activate(stealth)


def deactivate_panic_mode() -> None:
    panic = get_panic_mode()
    panic.deactivate()


def is_panic_mode_active() -> bool:
    panic = get_panic_mode()
    return panic.is_active()


# Test the module
if __name__ == "__main__":
    import logging
    
    # Configure logging
    logging.basicConfig(level=logging.DEBUG)
    
    # Test PanicMode
    panic = PanicMode()
    
    print("Testing panic mode...")
    print(f"Initial state: {panic.get_state()}")
    print(f"Configuration: {panic.get_configuration()}")
    
    # Test activation
    print("\nActivating panic mode (non-stealth)...")
    panic.activate(stealth=False)
    print(f"State after activation: {panic.get_state()}")
    print(f"Is active: {panic.is_active()}")
    
    # Wait a bit
    time.sleep(1)
    print(f"Activation duration: {panic.get_activation_duration():.1f}s")
    
    # Test deactivation
    print("\nDeactivating panic mode...")
    panic.deactivate()
    print(f"State after deactivation: {panic.get_state()}")
    
    # Test with callbacks
    def on_panic():
        print("PANIC CALLBACK: Panic mode activated!")
    
    def on_recovery():
        print("RECOVERY CALLBACK: Panic mode deactivated!")
    
    panic.register_panic_callback(on_panic)
    panic.register_recovery_callback(on_recovery)
    
    print("\nTesting with callbacks...")
    panic.activate(stealth=False)
    time.sleep(0.5)
    panic.deactivate()
    
    print("\nTest complete")