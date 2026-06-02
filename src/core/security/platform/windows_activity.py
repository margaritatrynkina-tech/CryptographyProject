"""
Windows-specific activity monitor.

This module uses Windows API to detect user activity with high accuracy.
"""

import ctypes
import ctypes.wintypes
import time
from typing import Optional
import logging


class WindowsActivityMonitor:
    """
    Windows activity monitor using Win32 API.
    
    This implementation provides accurate activity detection on Windows
    using native API calls.
    """
    
    def __init__(self):
        """Initialize Windows activity monitor."""
        self.logger = logging.getLogger(__name__)
        self._monitoring = False
        self._last_input_info = self._get_last_input_info_struct()
        self._has_activity = False
        self._activity_type = None
        
        # Load user32.dll
        self._user32 = ctypes.windll.user32
        
        # Constants
        self.SM_MOUSEPRESENT = 19
        self.SM_CMOUSEBUTTONS = 43
        
        # Check if mouse is present
        self._mouse_present = self._user32.GetSystemMetrics(self.SM_MOUSEPRESENT) != 0
        self._mouse_buttons = self._user32.GetSystemMetrics(self.SM_CMOUSEBUTTONS)
    
    def _get_last_input_info_struct(self):
        """Create and return a LASTINPUTINFO structure."""
        class LASTINPUTINFO(ctypes.Structure):
            _fields_ = [
                ('cbSize', ctypes.wintypes.UINT),
                ('dwTime', ctypes.wintypes.DWORD)
            ]
        
        info = LASTINPUTINFO()
        info.cbSize = ctypes.sizeof(LASTINPUTINFO)
        return info
    
    def start(self) -> None:
        """Start activity monitoring."""
        if self._monitoring:
            return
        
        self.logger.info("Starting Windows activity monitor")
        self._monitoring = True
        
        # Initialize last input time
        self._update_last_input_time()
    
    def stop(self) -> None:
        """Stop activity monitoring."""
        if not self._monitoring:
            return
        
        self.logger.info("Stopping Windows activity monitor")
        self._monitoring = False
    
    def _update_last_input_time(self) -> None:
        """Update the last input time from system."""
        if self._user32.GetLastInputInfo(ctypes.byref(self._last_input_info)):
            self._last_input_time = self._last_input_info.dwTime
        else:
            self._last_input_time = 0
    
    def has_activity(self) -> bool:
        """
        Check if activity has been detected.
        
        Returns:
            True if activity detected since last check, False otherwise
        """
        if not self._monitoring:
            return False
        
        # Get current last input time
        old_time = self._last_input_time
        self._update_last_input_time()
        
        # Check if time has changed
        if self._last_input_time > old_time:
            self._has_activity = True
            self._activity_type = self._detect_activity_type()
        else:
            self._has_activity = False
            self._activity_type = None
        
        return self._has_activity
    
    def _detect_activity_type(self) -> str:
        """
        Detect the type of activity.
        
        Returns:
            Activity type string
        """
        try:
            # Check mouse state
            class POINT(ctypes.Structure):
                _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]
            
            point = POINT()
            if self._user32.GetCursorPos(ctypes.byref(point)):
                # Mouse movement detected
                return "mouse_move"
            
            # Check keyboard state
            # This is a simplified check - real implementation would be more complex
            VK_SHIFT = 0x10
            VK_CONTROL = 0x11
            VK_MENU = 0x12  # ALT key
            
            # Check modifier keys
            for vk_code in [VK_SHIFT, VK_CONTROL, VK_MENU]:
                state = self._user32.GetAsyncKeyState(vk_code)
                if state & 0x8000:  # Key is pressed
                    return "keyboard"
            
            # Default to generic activity
            return "user_presence"
            
        except Exception as e:
            self.logger.debug(f"Error detecting activity type: {e}")
            return "unknown"
    
    def get_activity_type(self) -> Optional[str]:
        """
        Get the type of last detected activity.
        
        Returns:
            Activity type string or None
        """
        return self._activity_type
    
    def get_idle_time(self) -> float:
        """
        Get system idle time in seconds.
        
        Returns:
            Seconds since last input
        """
        if not self._monitoring:
            return 0.0
        
        # Get tick count
        tick_count = self._user32.GetTickCount()
        
        # Calculate idle time in milliseconds
        idle_time_ms = tick_count - self._last_input_time
        
        # Convert to seconds
        return idle_time_ms / 1000.0
    
    def get_system_idle_time(self) -> float:
        """
        Get system-wide idle time.
        
        Returns:
            Seconds since last system input
        """
        self._update_last_input_time()
        return self.get_idle_time()
    
    def is_mouse_present(self) -> bool:
        """
        Check if mouse is present.
        
        Returns:
            True if mouse is detected, False otherwise
        """
        return self._mouse_present
    
    def get_mouse_button_count(self) -> int:
        """
        Get number of mouse buttons.
        
        Returns:
            Number of mouse buttons
        """
        return self._mouse_buttons
    
    def __enter__(self):
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()


# Helper functions for external use
def get_system_idle_time() -> float:
    """
    Get system idle time.
    
    Returns:
        Seconds since last system input
    """
    monitor = WindowsActivityMonitor()
    monitor.start()
    idle_time = monitor.get_system_idle_time()
    monitor.stop()
    return idle_time


def is_user_present(max_idle_seconds: float = 300) -> bool:
    """
    Check if user is present based on system idle time.
    
    Args:
        max_idle_seconds: Maximum idle time to consider user present
        
    Returns:
        True if user is present, False otherwise
    """
    idle_time = get_system_idle_time()
    return idle_time < max_idle_seconds


# Test the module
if __name__ == "__main__":
    import logging
    
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Test Windows activity monitor
    with WindowsActivityMonitor() as monitor:
        print("Windows activity monitor started")
        print(f"Mouse present: {monitor.is_mouse_present()}")
        print(f"Mouse buttons: {monitor.get_mouse_button_count()}")
        
        for i in range(10):
            time.sleep(1)
            idle_time = monitor.get_idle_time()
            print(f"Idle time: {idle_time:.1f}s")
            
            if monitor.has_activity():
                print(f"Activity detected: {monitor.get_activity_type()}")
        
        print("Test complete")