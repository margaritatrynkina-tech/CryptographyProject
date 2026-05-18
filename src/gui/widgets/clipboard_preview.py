"""Clipboard preview with masked content (UI-4)."""
import tkinter as tk
from tkinter import ttk, simpledialog
from typing import Callable, Optional


def mask_value(value: str, data_type: str) -> str:
    if not value:
        return "—"
    if data_type in ("password", "totp", "all"):
        if len(value) <= 3:
            return "•••"
        return value[:3] + "•" * min(len(value) - 3, 8)
    if len(value) <= 4:
        return "••••"
    return value[:4] + "••••"


class ClipboardPreviewPanel(ttk.LabelFrame):
    def __init__(
        self,
        parent,
        clipboard_service,
        verify_master_password: Callable[[str], bool],
    ):
        super().__init__(parent, text="Clipboard Preview")
        self.clipboard_service = clipboard_service
        self.verify_master_password = verify_master_password
        self._revealed = False

        self.type_var = tk.StringVar(value="—")
        self.preview_var = tk.StringVar(value="—")
        ttk.Label(self, text="Type:").grid(row=0, column=0, sticky=tk.W, padx=4, pady=2)
        ttk.Label(self, textvariable=self.type_var).grid(row=0, column=1, sticky=tk.W, padx=4)
        ttk.Label(self, text="Content:").grid(row=1, column=0, sticky=tk.W, padx=4, pady=2)
        ttk.Label(self, textvariable=self.preview_var, font=("Consolas", 11)).grid(
            row=1, column=1, sticky=tk.W, padx=4
        )
        ttk.Button(self, text="Reveal", command=self._reveal).grid(row=2, column=1, sticky=tk.E, padx=4, pady=4)
        self.grid_columnconfigure(1, weight=1)

    def refresh(self) -> None:
        self._revealed = False
        status = self.clipboard_service.get_status()
        if not status.get("active"):
            self.type_var.set("—")
            self.preview_var.set("—")
            return
        data_type = status.get("data_type", "text")
        self.type_var.set(data_type)
        masked = self.clipboard_service.get_masked_preview()
        self.preview_var.set(masked or "••••••")

    def _reveal(self) -> None:
        if not self.clipboard_service.get_status().get("active"):
            return
        pwd = simpledialog.askstring(
            "Подтверждение",
            "Введите мастер-пароль для просмотра:",
            show="*",
            parent=self.winfo_toplevel(),
        )
        if pwd is None:
            return
        if not self.verify_master_password(pwd):
            from tkinter import messagebox
            messagebox.showwarning("Ошибка", "Неверный мастер-пароль", parent=self.winfo_toplevel())
            return
        full = self.clipboard_service.get_revealed_content()
        if full:
            self.preview_var.set(full)
            self._revealed = True
