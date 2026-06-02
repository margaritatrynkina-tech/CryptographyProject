"""
System tray integration for CryptoSafe Manager.

Implements TRAY-1 through TRAY-4:
- Icon with lock/unlock status indicator
- Context menu: Lock/Unlock, Show Window, Quick Search, Settings, Exit
- Background mode: clipboard monitoring continues while minimised
- Minimise-to-tray instead of closing

Requires the `pystray` and `Pillow` packages.
If they are not installed the tray silently degrades — the application
still works without a tray icon.
"""

from __future__ import annotations

import threading
import tkinter as tk
from typing import Callable, Optional

# ---------------------------------------------------------------------------
# Optional heavy imports — guarded so the app starts without pystray/Pillow
# ---------------------------------------------------------------------------
try:
    import pystray
    from pystray import MenuItem as TrayItem, Menu as TrayMenu
    _PYSTRAY_AVAILABLE = True
except ImportError:
    _PYSTRAY_AVAILABLE = False

try:
    from PIL import Image, ImageDraw
    _PIL_AVAILABLE = True
except ImportError:
    _PIL_AVAILABLE = False


# ---------------------------------------------------------------------------
# Icon image helpers
# ---------------------------------------------------------------------------

def _make_icon_image(locked: bool, size: int = 64) -> "Image.Image":
    """Create a simple lock/unlock icon as a PIL Image.

    Args:
        locked: True → closed padlock (red), False → open padlock (green).
        size: Icon size in pixels.

    Returns:
        PIL Image object.
    """
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Background circle
    bg_color = (200, 50, 50, 255) if locked else (50, 180, 50, 255)
    draw.ellipse([2, 2, size - 2, size - 2], fill=bg_color)

    # Simple padlock body
    body_x0 = size // 4
    body_y0 = size // 2
    body_x1 = size * 3 // 4
    body_y1 = size * 7 // 8
    draw.rectangle([body_x0, body_y0, body_x1, body_y1], fill=(255, 255, 255, 220))

    # Shackle (arc)
    shackle_x0 = size // 3
    shackle_y0 = size // 6
    shackle_x1 = size * 2 // 3
    shackle_y1 = size // 2
    if locked:
        draw.arc([shackle_x0, shackle_y0, shackle_x1, shackle_y1],
                 start=180, end=0, fill=(255, 255, 255, 220), width=max(2, size // 12))
    else:
        # Open shackle — shifted right
        draw.arc([shackle_x0 + size // 8, shackle_y0 - size // 8,
                  shackle_x1 + size // 8, shackle_y1 - size // 8],
                 start=180, end=0, fill=(255, 255, 255, 220), width=max(2, size // 12))

    return img


# ---------------------------------------------------------------------------
# SystemTray
# ---------------------------------------------------------------------------

class SystemTray:
    """System tray icon with context menu for CryptoSafe Manager.

    Args:
        root: The main Tkinter root window.
        on_show: Callback to show/restore the main window.
        on_lock: Callback to lock the vault.
        on_unlock: Callback to unlock the vault (shows login dialog).
        on_quick_search: Callback to open quick-search dialog.
        on_settings: Callback to open settings dialog.
        on_clear_clipboard: Callback to clear clipboard.
        on_panic_mode: Callback to activate panic mode.
        on_exit: Callback to exit the application.
    """

    def __init__(
        self,
        root: tk.Tk,
        on_show: Optional[Callable[[], None]] = None,
        on_lock: Optional[Callable[[], None]] = None,
        on_unlock: Optional[Callable[[], None]] = None,
        on_quick_search: Optional[Callable[[], None]] = None,
        on_settings: Optional[Callable[[], None]] = None,
        on_clear_clipboard: Optional[Callable[[], None]] = None,
        on_panic_mode: Optional[Callable[[], None]] = None,
        on_exit: Optional[Callable[[], None]] = None,
    ) -> None:
        self._root = root
        self._on_show = on_show or self._default_show
        self._on_lock = on_lock or (lambda: None)
        self._on_unlock = on_unlock or (lambda: None)
        self._on_quick_search = on_quick_search or (lambda: None)
        self._on_settings = on_settings or (lambda: None)
        self._on_clear_clipboard = on_clear_clipboard or (lambda: None)
        self._on_panic_mode = on_panic_mode or (lambda: None)
        self._on_exit = on_exit or self._default_exit

        self._locked = False
        self._tray_icon: Optional["pystray.Icon"] = None
        self._tray_thread: Optional[threading.Thread] = None
        self._running = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Create and start the system tray icon in a background thread."""
        if not _PYSTRAY_AVAILABLE or not _PIL_AVAILABLE:
            print("[SystemTray] pystray or Pillow not installed — tray disabled")
            return

        if self._running:
            return

        self._running = True
        self._tray_thread = threading.Thread(
            target=self._run_tray,
            name="SystemTray",
            daemon=True,
        )
        self._tray_thread.start()

    def stop(self) -> None:
        """Stop and remove the system tray icon."""
        self._running = False
        if self._tray_icon:
            try:
                self._tray_icon.stop()
            except Exception:
                pass
            self._tray_icon = None

    def set_locked(self, locked: bool) -> None:
        """Update the tray icon to reflect the vault lock state.

        Args:
            locked: True if the vault is locked.
        """
        self._locked = locked
        if self._tray_icon:
            try:
                self._tray_icon.icon = _make_icon_image(locked)
                self._tray_icon.title = (
                    "CryptoSafe — Заблокировано" if locked
                    else "CryptoSafe — Разблокировано"
                )
                self._tray_icon.update_menu()
            except Exception:
                pass

    def show_notification(self, title: str, message: str) -> None:
        """Show a system notification balloon from the tray icon.

        Args:
            title: Notification title.
            message: Notification body text.
        """
        if self._tray_icon and _PYSTRAY_AVAILABLE:
            try:
                self._tray_icon.notify(message, title)
            except Exception:
                pass

    def is_available(self) -> bool:
        """Return True if pystray and Pillow are installed."""
        return _PYSTRAY_AVAILABLE and _PIL_AVAILABLE

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _run_tray(self) -> None:
        """Entry point for the tray background thread."""
        try:
            icon_image = _make_icon_image(self._locked)
            menu = self._build_menu()

            self._tray_icon = pystray.Icon(
                name="cryptosafe",
                icon=icon_image,
                title="CryptoSafe Manager",
                menu=menu,
            )
            self._tray_icon.run()
        except Exception as exc:
            print(f"[SystemTray] Error running tray: {exc}")

    def _build_menu(self) -> "TrayMenu":
        """Build the context menu."""
        return TrayMenu(
            TrayItem("Показать окно", self._action_show, default=True),
            TrayMenu.SEPARATOR,
            TrayItem(
                "Заблокировать",
                self._action_lock,
                enabled=lambda item: not self._locked,
            ),
            TrayItem(
                "Разблокировать",
                self._action_unlock,
                enabled=lambda item: self._locked,
            ),
            TrayMenu.SEPARATOR,
            TrayItem("Быстрый поиск", self._action_quick_search),
            TrayItem("Очистить буфер", self._action_clear_clipboard),
            TrayItem("Panic Mode", self._action_panic_mode),
            TrayItem("Настройки", self._action_settings),
            TrayMenu.SEPARATOR,
            TrayItem("Выход", self._action_exit),
        )

    # ---- action wrappers (called from tray thread → schedule on Tk thread) ----

    def _action_show(self, icon=None, item=None) -> None:
        self._root.after(0, self._on_show)

    def _action_lock(self, icon=None, item=None) -> None:
        self._root.after(0, self._on_lock)

    def _action_unlock(self, icon=None, item=None) -> None:
        self._root.after(0, self._on_unlock)

    def _action_quick_search(self, icon=None, item=None) -> None:
        self._root.after(0, self._on_quick_search)

    def _action_clear_clipboard(self, icon=None, item=None) -> None:
        self._root.after(0, self._on_clear_clipboard)

    def _action_panic_mode(self, icon=None, item=None) -> None:
        self._root.after(0, self._on_panic_mode)

    def _action_settings(self, icon=None, item=None) -> None:
        self._root.after(0, self._on_settings)

    def _action_exit(self, icon=None, item=None) -> None:
        self._root.after(0, self._on_exit)

    # ---- defaults ----

    def _default_show(self) -> None:
        """Restore and raise the main window."""
        try:
            self._root.deiconify()
            self._root.lift()
            self._root.focus_force()
        except Exception:
            pass

    def _default_exit(self) -> None:
        """Exit the application."""
        self.stop()
        try:
            self._root.quit()
        except Exception:
            pass
