"""
Fallback activity monitor for platforms without native support.

This module provides a cross-platform fallback implementation that
uses polling and basic event detection.
"""

import time
import threading
from typing import Optional
import logging


class FallbackActivityMonitor:
    """
    Fallback activity monitor using polling.
    
    This implementation provides basic activity detection for platforms
    without native support. It's less efficient but works everywhere.
    """
    
    def __init__(self):
        """Initialize fallback activity monitor."""
        self.logger = logging.getLogger(__name__)
        self._monitoring = False
        self._last_mouse_position = None
        self._last_keyboard_state = None
        self._has_activity = False
        self._activity_type = None
        self._poll_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        
        # Configuration
        self._poll_interval = 0.5  # seconds
        self._mouse_threshold = 2  # pixels
    
    def start(self) -> None:
        """Start activity monitoring."""
        if self._monitoring:
            return
        
        self.logger.info("Starting fallback activity monitor")
        self._monitoring = True
        self._stop_event.clear()
        
        # Initialize state
        self._last_mouse_position = self._get_mouse_position()
        self._last_keyboard_state = self._get_keyboard_state()
        
        # Start polling thread
        self._poll_thread = threading.Thread(
            target=self._poll_loop,
            name="FallbackActivityMonitor",
            daemon=True
        )
        self._poll_thread.start()
    
    def stop(self) -> None:
        """Stop activity monitoring."""
        if not self._monitoring:
            return
        
        self.logger.info("Stopping fallback activity monitor")
        self._monitoring = False
        self._stop_event.set()
        
        if self._poll_thread and self._poll_thread.is_alive():
            self._poll_thread.join(timeout=5.0)
        
        self._poll_thread = None
    
    def _poll_loop(self) -> None:
        """Main polling loop."""
        self.logger.debug("Fallback activity monitor loop started")
        
        while not self._stop_event.is_set():
            try:
                self._check_activity()
                time.sleep(self._poll_interval)
            except Exception as e:
                self.logger.error(f"Error in poll loop: {e}")
                time.sleep(1.0)
    
    def _check_activity(self) -> None:
        """Check for activity by polling system state."""
        # Check mouse movement
        current_mouse_pos = self._get_mouse_position()
        if current_mouse_pos and self._last_mouse_position:
            dx = abs(current_mouse_pos[0] - self._last_mouse_position[0])
            dy = abs(current_mouse_pos[1] - self._last_mouse_position[1])
            
            if dx > self._mouse_threshold or dy > self._mouse_threshold:
                self._has_activity = True
                self._activity_type = "mouse_move"
                self._last_mouse_position = current_mouse_pos
                return
        
        # Check keyboard state
        current_keyboard_state = self._get_keyboard_state()
        if current_keyboard_state != self._last_keyboard_state:
            self._has_activity = True
            self._activity_type = "keyboard"
            self._last_keyboard_state = current_keyboard_state
            return
        
        # No activity detected
        self._has_activity = False
        self._activity_type = None
    
    def _get_mouse_position(self) -> Optional[tuple]:
        """
        Get current mouse position.
        
        Returns:
            Tuple (x, y) or None if not available
        """
        try:
            # Try different methods to get mouse position
            import tkinter as tk
            
            # Create a hidden tkinter window
            root = tk.Tk()
            root.withdraw()
            
            # Get mouse position
            x = root.winfo_pointerx()
            y = root.winfo_pointery()
            
            root.destroy()
            return (x, y)
        except:
            try:
                # Try pyautogui if available
                import pyautogui
                return pyautogui.position()
            except:
                # Last resort: return a dummy position
                return (0, 0)
    
    def _get_keyboard_state(self) -> str:
        """
        Get current keyboard state as a string.
        
        Returns:
            String representing keyboard state
        """
        try:
            # Simple implementation: check if any key is pressed
            # This is a basic fallback - real implementations would be more sophisticated
            import keyboard  # Requires keyboard library
            
            # Get pressed keys
            pressed_keys = keyboard._pressed_events.copy()
            return str(sorted(pressed_keys.keys()))
        except:
            # Fallback: use time-based state
            return str(int(time.time() // 10))
    
    def has_activity(self) -> bool:
        """
        Check if activity has been detected since last call.
        
        Returns:
            True if activity detected, False otherwise
        """
        has_activity = self._has_activity
        self._has_activity = False  # Reset after checking
        return has_activity
    
    def get_activity_type(self) -> Optional[str]:
        """
        Get the type of last detected activity.
        
        Returns:
            Activity type string or None
        """
        return self._activity_type
    
    def get_idle_time(self) -> float:
        """
        Get idle time (not implemented in fallback).
        
        Returns:
            Always returns 0 in fallback implementation
        """
        return 0.0
    
    def __enter__(self):
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()


# Test the module
if __name__ == "__main__":
    import logging
    
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Test fallback monitor
    with FallbackActivityMonitor() as monitor:
        print("Fallback activity monitor started")
        print("Move your mouse or press keys to see activity detection")
        
        for i in range(10):
            time.sleep(1)
            if monitor.has_activity():
                print(f"Activity detected: {monitor.get_activity_type()}")
            else:
                print("No activity detected")
        
        print("Test complete")