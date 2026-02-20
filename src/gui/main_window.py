import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from pathlib import Path
import sys
import os

# Импорты модулей
from core.config import ConfigManager
from core.events import EventSystem, EventType
from database.db import DatabaseManager


class MainWindow:
    """Главное окно приложения"""

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("CryptoSafe Manager v1.0")
        self.root.geometry("1200x800")
        self.root.minsize(900, 600)

        # Менеджеры
        self.config = ConfigManager()
        self.events = EventSystem()
        self.db_path = None
        self.db: DatabaseManager = None
        self.master_password = None

        self.setup_ui()
        self.check_first_run()

    def setup_ui(self):
        """Настройка интерфейса"""
        # Меню
        self.setup_menu()

        # Центральный фрейм
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Таблица записей
        columns = ('id', 'title', 'username', 'url')
        self.tree = ttk.Treeview(main_frame, columns=columns, show='headings', height=20)

        for col in columns:
            self.tree.heading(col, text=col.capitalize())
            self.tree.column(col, width=150)

        # Скроллбары
        v_scroll = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=self.tree.yview)
        h_scroll = ttk.Scrollbar(main_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)

        self.tree.grid(row=0, column=0, sticky='nsew', padx=(0, 10))
        v_scroll.grid(row=0, column=1, sticky='ns')
        h_scroll.grid(row=1, column=0, sticky='ew')

        # Кнопки действий
        btn_frame = ttk.Frame(main_frame)
        btn_frame.grid(row=2, column=0, sticky='w', pady=(10, 0))

        ttk.Button(btn_frame, text="Добавить", command=self.add_entry).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_frame, text="Редактировать", command=self.edit_entry).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_frame, text="Удалить", command=self.delete_entry).pack(side=tk.LEFT, padx=(0, 5))

        # Настройка растягивания
        main_frame.grid_rowconfigure(0, weight=1)
        main_frame.grid_columnconfigure(0, weight=1)

        # Строка состояния
        self.status_var = tk.StringVar(value="Готов")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def setup_menu(self):
        """Настройка меню"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        # Файл
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Файл", menu=file_menu)
        file_menu.add_command(label="Новая база...", command=self.new_database)
        file_menu.add_command(label="Открыть базу...", command=self.open_database)
        file_menu.add_separator()
        file_menu.add_command(label="Выход", command=self.root.quit)

        # Правка
        edit_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Правка", menu=edit_menu)
        edit_menu.add_command(label="Добавить запись", command=self.add_entry)
        edit_menu.add_command(label="Журнал аудита", command=self.show_audit_log)

        # Вид
        view_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Вид", menu=view_menu)
        view_menu.add_command(label="Настройки", command=self.show_settings)

    def check_first_run(self):
        """Проверка первого запуска"""
        if not self.config.db_path:
            self.show_setup_wizard()
        else:
            self.open_database()

    def show_setup_wizard(self):
        """Мастер первоначальной настройки"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Первоначальная настройка")
        dialog.geometry("500x400")
        dialog.transient(self.root)
        dialog.grab_set()

        ttk.Label(dialog, text="Добро пожаловать в CryptoSafe Manager!",
                  font=('Arial', 14, 'bold')).pack(pady=20)

        # Мастер-пароль
        ttk.Label(dialog, text="Мастер-пароль (невозможно восстановить!):").pack(pady=5)
        pass_frame = ttk.Frame(dialog)
        pass_frame.pack(pady=10, padx=20, fill=tk.X)

        from gui.widgets.password_entry import PasswordEntry
        self.master_pass_entry = PasswordEntry(pass_frame)
        self.master_pass_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        confirm_pass_entry = PasswordEntry(pass_frame)
        confirm_pass_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 0))

        # Путь к БД
        ttk.Label(dialog, text="Расположение базы данных:").pack(pady=(20, 5))
        db_frame = ttk.Frame(dialog)
        db_frame.pack(pady=5, padx=20, fill=tk.X)

        self.db_path_entry = ttk.Entry(db_frame)
        self.db_path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(db_frame, text="Обзор...",
                   command=lambda: self.browse_db_path(self.db_path_entry)).pack(side=tk.RIGHT)

        def setup():
            password = self.master_pass_entry.get()
            confirm_password = confirm_pass_entry.get()

            if not password:
                messagebox.showerror("Ошибка", "Мастер-пароль обязателен!")
                return

            if password != confirm_password:
                messagebox.showerror("Ошибка", "Пароли не совпадают!")
                return

            db_path = self.db_path_entry.get().strip()
            if not db_path:
                messagebox.showerror("Ошибка", "Выберите путь к базе данных!")
                return

            try:
                self.config.db_path = db_path
                self.master_password = password
                self.open_database()
                dialog.destroy()
                messagebox.showinfo("Успех", "Настройка завершена!")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось создать базу: {str(e)}")

        ttk.Button(dialog, text="Создать", command=setup).pack(pady=30)

    def browse_db_path(self, entry):
        """Выбор файла БД"""
        path = filedialog.asksaveasfilename(
            defaultextension=".db",
            filetypes=[("SQLite DB", "*.db"), ("All", "*.*")]
        )
        if path:
            entry.delete(0, tk.END)
            entry.insert(0, path)

    def new_database(self):
        """Создать новую базу"""
        self.show_setup_wizard()

    def open_database(self):
        """Открыть существующую базу"""
        if self.config.db_path:
            try:
                self.db = DatabaseManager(self.config.db_path)
                self.db.set_master_password(self.master_password or "temp")
                self.status_var.set(f"База данных: {self.config.db_path}")
                self.refresh_entries()
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось открыть базу: {str(e)}")

    def add_entry(self):
        """Добавить запись"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Новая запись")
        dialog.geometry("400x500")
        dialog.transient(self.root)
        dialog.grab_set()

        # Форма
        form = ttk.Frame(dialog)
        form.pack(pady=20, padx=20, fill=tk.BOTH, expand=True)

        ttk.Label(form, text="Название:").pack(anchor=tk.W)
        ttk.Entry(form).pack(fill=tk.X, pady=(0, 10))

        ttk.Label(form, text="Пользователь:").pack(anchor=tk.W)
        ttk.Entry(form).pack(fill=tk.X, pady=(0, 10))

        ttk.Label(form, text="Пароль:").pack(anchor=tk.W)
        from gui.widgets.password_entry import PasswordEntry
        PasswordEntry(form).pack(fill=tk.X, pady=(0, 20))

        ttk.Button(form, text="Сохранить",
                   command=lambda: messagebox.showinfo("Успех", "Запись сохранена!")).pack()

    def edit_entry(self):
        messagebox.showinfo("Правка", "Функция в разработке (Спринт 2)")

    def delete_entry(self):
        messagebox.showinfo("Удаление", "Функция в разработке (Спринт 2)")

    def show_audit_log(self):
        messagebox.showinfo("Журнал аудита", "Спринт 5")

    def show_settings(self):
        messagebox.showinfo("Настройки", "Спринт 4")

    def refresh_entries(self):
        """Обновить список записей"""
        for item in self.tree.get_children():
            self.tree.delete(item)
        # TODO: Загрузить из БД

    def run(self):
        """Запуск приложения"""
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.mainloop()

    def on_closing(self):
        if self.db:
            self.db.close()
        self.root.destroy()
