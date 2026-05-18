"""Simple toast notifications for tkinter."""
import tkinter as tk
from typing import Optional


class ToastManager:
    def __init__(self, root: tk.Tk):
        self.root = root
        self._toasts: list[tk.Toplevel] = []

    def show(self, message: str, level: str = "info", duration_ms: int = 4000) -> None:
        toast = tk.Toplevel(self.root)
        toast.overrideredirect(True)
        toast.attributes("-topmost", True)
        colors = {
            "info": ("#e8f4fd", "#1565c0"),
            "warning": ("#fff8e1", "#e65100"),
            "error": ("#ffebee", "#c62828"),
        }
        bg, fg = colors.get(level, colors["info"])
        frame = tk.Frame(toast, bg=bg, padx=12, pady=8, highlightthickness=1, highlightbackground=fg)
        frame.pack()
        tk.Label(frame, text=message, bg=bg, fg=fg, font=("Segoe UI", 10), wraplength=360).pack()
        self.root.update_idletasks()
        x = self.root.winfo_x() + self.root.winfo_width() - 400
        y = self.root.winfo_y() + 60 + len(self._toasts) * 70
        toast.geometry(f"+{max(x, 0)}+{max(y, 0)}")
        self._toasts.append(toast)
        toast.after(duration_ms, lambda: self._dismiss(toast))

    def _dismiss(self, toast: tk.Toplevel) -> None:
        try:
            toast.destroy()
        except tk.TclError:
            pass
        if toast in self._toasts:
            self._toasts.remove(toast)
