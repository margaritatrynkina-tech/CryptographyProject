import tkinter as tk
from tkinter import ttk


class PasswordEntry(ttk.Entry):
    """Маскированный ввод пароля с кнопкой показа"""

    def __init__(self, parent, *args, **kwargs):
        super().__init__(parent, show="*", *args, **kwargs)
        self.show_password = False

        self.toggle_btn = ttk.Button(parent, text="👁", width=3,
                                     command=self.toggle_visibility)
        self.toggle_btn.pack(side="right", padx=(0, 5))

    def toggle_visibility(self):
        self.show_password = not self.show_password
        self.config(show="" if self.show_password else "*")
        self.toggle_btn.config(text="🙈" if self.show_password else "👁")
