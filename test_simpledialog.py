import tkinter as tk
from tkinter import simpledialog, messagebox

def test_dialog():
    root = tk.Tk()
    root.withdraw()  # Скрыть главное окно
    
    # Тест 1: простой диалог
    password = simpledialog.askstring(
        "Тест пароля",
        "Введите тестовый пароль:",
        show="*",
    )
    
    if password:
        messagebox.showinfo("Результат", f"Вы ввели пароль длиной {len(password)} символов")
    else:
        messagebox.showinfo("Результат", "Пароль не введён")
    
    root.destroy()

if __name__ == "__main__":
    test_dialog()
