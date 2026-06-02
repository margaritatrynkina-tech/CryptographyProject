"""
Platform-specific implementations for security features.

This module provides platform-specific implementations for:
- Activity detection (Windows, Linux, macOS)
- Memory locking (mlock/VirtualLock)
- System tray integration
"""

import sys

if sys.platform == 'win32':
    from .windows_activity import WindowsActivityMonitor
    ActivityMonitorImpl = WindowsActivityMonitor
elif sys.platform == 'darwin':
    from .macos_activity import MacOSActivityMonitor
    ActivityMonitorImpl = MacOSActivityMonitor
elif sys.platform.startswith('linux'):
    from .linux_activity import LinuxActivityMonitor
    ActivityMonitorImpl = LinuxActivityMonitor
else:
    from .fallback_activity import FallbackActivityMonitor
    ActivityMonitorImpl = FallbackActivityMonitor

__all__ = ['ActivityMonitorImpl']