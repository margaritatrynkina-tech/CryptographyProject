import tkinter as tk
from tkinter import ttk
import secrets
import string
class PasswordEntry(ttk.Frame):
    def __init__(self, parent, show_generator=True, *args, **kwargs):
        super().__init__(parent)
        self.show_password = False
        self.password_var = tk.StringVar()
        # Поле ввода
        self.entry = ttk.Entry(self, textvariable=self.password_var, show="*", *args, **kwargs)
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        # Кнопка показа/скрытия
        self.toggle_btn = ttk.Button(self, text="👁", width=3,
                                     command=self.toggle_visibility)
        self.toggle_btn.pack(side=tk.LEFT, padx=(2, 0))
        # Кнопка генерации пароля
        if show_generator:
            self.gen_btn = ttk.Button(self, text="🎲", width=3,
                                      command=self.generate_password)
            self.gen_btn.pack(side=tk.LEFT, padx=(2, 0))
        # Индикатор сложности
        self.strength_label = ttk.Label(self, text="", width=10)
        self.strength_label.pack(side=tk.LEFT, padx=(5, 0))
        # Привязка события изменения текста
        self.password_var.trace('w', self._on_password_change)
    def get(self):
        return self.password_var.get()
    def set(self, value):
        self.password_var.set(value)
    def toggle_visibility(self):
        self.show_password = not self.show_password
        self.entry.config(show="" if self.show_password else "*")
        self.toggle_btn.config(text="🔒" if self.show_password else "👁")
    def generate_password(self, length=16):
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        self.set(password)
        # Копируем в буфер обмена
        self.clipboard_clear()
        self.clipboard_append(password)
    def _on_password_change(self, *args):
        """Обработка изменения пароля"""
        password = self.get()
        strength = self._check_strength(password)
        self.strength_label.config(text=strength)
    def _check_strength(self, password):
        if not password:
            return "❌"
        score = 0
        # Длина
        if len(password) >= 12:
            score += 2
        elif len(password) >= 8:
            score += 1
        # Разные типы символов
        if any(c.islower() for c in password):
            score += 1
        if any(c.isupper() for c in password):
            score += 1
        if any(c.isdigit() for c in password):
            score += 1
        if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            score += 1
        if score >= 5:
            return "Надежный"
        elif score >= 3:
            return "️Средний"
        else:
            return "Слабый"
    def clear(self):
        self.password_var.set("")
        # Безопасно очищаем память (заглушка)
        import ctypes
        # В реальном приложении здесь было бы затирание памяти