import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
from pathlib import Path
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from src.core.key_manager import KeyManager
from src.core.crypto.authentication import AuthenticationService
from src.core.vault.entry_manager import EntryManager
from src.core.config import ConfigManager
from src.core.events import EventSystem, EventType
from src.database.db import DatabaseManager
from src.core.clipboard.clipboard_service import ClipboardService
from src.core.clipboard.platform_adapter import create_platform_adapter
from src.core.clipboard.clipboard_monitor import ClipboardMonitor


class MainWindow:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("CryptoSafe Manager v1.0")
        self.root.geometry("1200x800")
        self.root.minsize(900, 600)
        self.entry_manager = None
        self.config = ConfigManager()
        if self.config.db_path:
            self.db_path = self.config.db_path
            print(f"Загружен путь к БД из конфига: {self.db_path}")
        else:
            print("Путь к БД не найден — нужен первый запуск")
        self.events = EventSystem()
        self.db_path = None
        self.db = None
        self.key_manager = None
        self.master_password = None
        self.auth_service = None
        self.clipboard_service = None
        self.clipboard_monitor = None
        self._entry_id_map = {}

        self.setup_ui()
        self.events.subscribe(EventType.CLIPBOARD_COPIED, self._on_clipboard_copied)
        self.events.subscribe(EventType.CLIPBOARD_CLEARED, self._on_clipboard_cleared)
        self.events.subscribe(EventType.USER_LOGGED_OUT, self._on_user_logged_out)
        self.check_first_run()

    def setup_ui(self):
        """Настройка пользовательского интерфейса"""
        self.setup_menu()

        # Главный контейнер - используем GRID для всего
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        # Основной фрейм
        main_frame = ttk.Frame(self.root)
        main_frame.grid(row=0, column=0, sticky='nsew', padx=10, pady=10)

        # Настройка сетки для main_frame
        main_frame.grid_rowconfigure(1, weight=1)  # строка с таблицей растягивается
        main_frame.grid_columnconfigure(0, weight=1)  # колонка с таблицей растягивается

        # Панель инструментов (grid row=0)
        toolbar = ttk.Frame(main_frame)
        toolbar.grid(row=0, column=0, sticky='ew', pady=(0, 10))

        ttk.Button(toolbar, text="➕ Добавить", command=self.add_entry).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="✏️ Редактировать", command=self.edit_entry).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="🗑️ Удалить", command=self.delete_entry).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="🔄 Обновить", command=self.refresh_entries).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="📋 Copy Username", command=self.copy_selected_username).pack(side=tk.LEFT, padx=(10, 2))
        ttk.Button(toolbar, text="🔑 Copy Password", command=self.copy_selected_password).pack(side=tk.LEFT, padx=2)

        # Поиск
        ttk.Label(toolbar, text="Поиск:").pack(side=tk.LEFT, padx=(20, 5))
        self.search_var = tk.StringVar()
        self.search_var.trace('w', lambda *args: self._on_search())
        search_entry = ttk.Entry(toolbar, textvariable=self.search_var, width=30)
        search_entry.pack(side=tk.LEFT)

        # Таблица записей (grid row=1)
        columns = ('id', 'title', 'username', 'url', 'updated_at')
        self.tree = ttk.Treeview(main_frame, columns=columns, show='headings', height=20, selectmode='browse')

        # Настройка заголовков
        self.tree.heading('id', text='ID', command=lambda: self._sort_tree('id', False))
        self.tree.heading('title', text='Название', command=lambda: self._sort_tree('title', False))
        self.tree.heading('username', text='Пользователь', command=lambda: self._sort_tree('username', False))
        self.tree.heading('url', text='URL', command=lambda: self._sort_tree('url', False))
        self.tree.heading('updated_at', text='Обновлено', command=lambda: self._sort_tree('updated_at', False))

        # Настройка ширины колонок
        self.tree.column('id', width=50, anchor='center')
        self.tree.column('title', width=200)
        self.tree.column('username', width=150)
        self.tree.column('url', width=200)
        self.tree.column('updated_at', width=150, anchor='center')

        # Скроллбары
        v_scroll = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=self.tree.yview)
        h_scroll = ttk.Scrollbar(main_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)

        # Размещение таблицы и скроллбаров в grid
        self.tree.grid(row=1, column=0, sticky='nsew')
        v_scroll.grid(row=1, column=1, sticky='ns')
        h_scroll.grid(row=2, column=0, sticky='ew')

        # Привязка двойного клика
        self.tree.bind('<Double-1>', lambda e: self.edit_entry())
        self.tree.bind('<Button-3>', self._show_row_context_menu)

        # Строка состояния (отдельно от main_frame, используем grid для root)
        self.status_var = tk.StringVar(value="Готов")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.grid(row=1, column=0, sticky='ew')

    def setup_menu(self):
        """Настройка меню"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        # Файл
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Файл", menu=file_menu)
        file_menu.add_command(label="Новая база...", command=self.new_database, accelerator="Ctrl+N")
        file_menu.add_command(label="Открыть базу...", command=self.open_database, accelerator="Ctrl+O")
        file_menu.add_command(label="Создать резервную копию...", command=self.backup_database)
        file_menu.add_command(label="Восстановить из копии...", command=self.restore_database)
        file_menu.add_separator()
        file_menu.add_command(label="Выход", command=self.on_closing, accelerator="Ctrl+Q")

        # Правка
        edit_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Правка", menu=edit_menu)
        edit_menu.add_command(label="Добавить запись", command=self.add_entry, accelerator="Ctrl+Ins")
        edit_menu.add_command(label="Редактировать запись", command=self.edit_entry, accelerator="F2")
        edit_menu.add_command(label="Удалить запись", command=self.delete_entry, accelerator="Del")
        edit_menu.add_separator()
        edit_menu.add_command(label="Журнал аудита", command=self.show_audit_log)
        edit_menu.add_command(label="Сменить мастер-пароль", command=self.change_master_password)

        # Вид
        view_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Вид", menu=view_menu)
        view_menu.add_command(label="Обновить", command=self.refresh_entries, accelerator="F5")
        view_menu.add_command(label="Настройки", command=self.show_settings)

        # Справка
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Справка", menu=help_menu)
        help_menu.add_command(label="О программе", command=self.show_about)

        # Привязка горячих клавиш
        self.root.bind('<Control-n>', lambda e: self.new_database())
        self.root.bind('<Control-o>', lambda e: self.open_database())
        self.root.bind('<Control-q>', lambda e: self.on_closing())
        self.root.bind('<Control-Insert>', lambda e: self.add_entry())
        self.root.bind('<F2>', lambda e: self.edit_entry())
        self.root.bind('<Delete>', lambda e: self.delete_entry())
        self.root.bind('<F5>', lambda e: self.refresh_entries())

    def _init_clipboard_services(self):
        adapter = create_platform_adapter()
        self.clipboard_service = ClipboardService(
            adapter=adapter,
            events=self.events,
            config=self.config,
            is_vault_unlocked=self.is_vault_unlocked,
        )
        self.clipboard_monitor = ClipboardMonitor(self.clipboard_service, self.events)
        self.clipboard_monitor.start()

    def _sort_tree(self, col, reverse):
        """Сортировка таблицы по колонке"""
        data = [(self.tree.set(child, col), child) for child in self.tree.get_children('')]
        data.sort(reverse=reverse)

        for index, (val, child) in enumerate(data):
            self.tree.move(child, '', index)

        self.tree.heading(col, command=lambda: self._sort_tree(col, not reverse))

    def _on_search(self):
        """Фильтрация записей по поиску"""
        search_text = self.search_var.get().lower()
        for item in self.tree.get_children():
            values = self.tree.item(item)['values']
            if len(values) >= 3:
                if (search_text in str(values[1]).lower() or  # title
                        search_text in str(values[2]).lower()):  # username
                    self.tree.reattach(item, '', self.tree.index(item))
                else:
                    self.tree.detach(item)
    def check_first_run(self):
        if not self.config.db_path:
            self.show_setup_wizard()
        else:
            self.open_database()
            if self.db:
                self.show_login_dialog()

    def show_setup_wizard(self):
        """Мастер первоначальной настройки"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Первоначальная настройка")
        dialog.geometry("600x500")
        dialog.transient(self.root)
        dialog.grab_set()

        # Заголовок
        ttk.Label(dialog, text="Добро пожаловать в CryptoSafe Manager!",
                  font=('Arial', 16, 'bold')).pack(pady=20)

        # Notebook для вкладок
        notebook = ttk.Notebook(dialog)
        notebook.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        # Вкладка 1: Мастер-пароль
        tab1 = ttk.Frame(notebook)
        notebook.add(tab1, text="Мастер-пароль")

        ttk.Label(tab1, text="Создайте мастер-пароль (невозможно восстановить!):",
                  font=('Arial', 10)).pack(pady=20)

        from src.gui.widgets.password_entry import PasswordEntry

        pass_frame = ttk.Frame(tab1)
        pass_frame.pack(pady=10, padx=20, fill=tk.X)

        ttk.Label(pass_frame, text="Пароль:").pack(anchor=tk.W)
        self.master_pass_entry = PasswordEntry(pass_frame)
        self.master_pass_entry.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(pass_frame, text="Подтверждение:").pack(anchor=tk.W)
        self.confirm_pass_entry = PasswordEntry(pass_frame)
        self.confirm_pass_entry.pack(fill=tk.X)

        # Вкладка 2: База данных
        tab2 = ttk.Frame(notebook)
        notebook.add(tab2, text="База данных")

        ttk.Label(tab2, text="Расположение базы данных:").pack(pady=20)

        db_frame = ttk.Frame(tab2)
        db_frame.pack(pady=5, padx=20, fill=tk.X)

        self.db_path_entry = ttk.Entry(db_frame)
        self.db_path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Устанавливаем путь по умолчанию
        default_db_path = os.path.join(os.path.expanduser("~"), "cryptosafe.db")
        self.db_path_entry.insert(0, default_db_path)

        ttk.Button(db_frame, text="Обзор...",
                   command=lambda: self.browse_db_path(self.db_path_entry)).pack(side=tk.RIGHT, padx=(5, 0))

        # Кнопки
        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(fill=tk.X, padx=20, pady=20)

        ttk.Button(btn_frame, text="Отмена", command=dialog.destroy).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="Создать", command=lambda: self._finish_setup(dialog)).pack(side=tk.RIGHT)

    def show_login_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Вход")
        dialog.geometry("400x200")
        dialog.transient(self.root)
        dialog.grab_set()

        ttk.Label(dialog, text="Введите мастер-пароль:").pack(pady=10)

        from src.gui.widgets.password_entry import PasswordEntry
        pass_entry = PasswordEntry(dialog)
        pass_entry.pack(fill=tk.X, padx=20, pady=(0, 10))
        pass_entry.focus()

        status_var = tk.StringVar(value="")
        ttk.Label(dialog, textvariable=status_var, foreground="red").pack()

        def do_login():
            pwd = pass_entry.get()
            if not pwd:
                status_var.set("Введите пароль")
                return
            if not self.auth_service:
                status_var.set("Ошибка аутентификации")
                return
            ok = self.auth_service.login(pwd)
            pass_entry.clear()
            if ok:
                dialog.destroy()
                self.refresh_entries()
            else:
                status_var.set("Неверный пароль")

        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="Войти", command=do_login).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="Отмена", command=dialog.destroy).pack(side=tk.RIGHT)

        dialog.wait_window()

    def _finish_setup(self, dialog):
        password = self.master_pass_entry.get()

        # Быстрая проверка
        if password != "Test123!":
            messagebox.showerror("Тест", "Используй Test123!")
            return

        db_path = r"C:\temp\cryptosafe_test.db"  # Фиксированный путь!

        try:
            print(" Создаём БД...")
            self.config.db_path = db_path
            self.master_password = password

            # Создаём БД
            self.db = DatabaseManager(db_path)
            self.db.connect()

            # Ключи БЕЗ ожидания
            self.key_manager = KeyManager(self.config, self.db.connection)
            self.auth_service = AuthenticationService(self.key_manager, self.events)
            self.entry_manager = EntryManager(self.db.connection, self.key_manager, self.events)
            self._init_clipboard_services()

            self.key_manager.setup_master_password(password)
            self.config.save()  # Сохраняем config

            print(" БД создана!")
            dialog.destroy()
            self.show_login_dialog()  # Логин отдельно

        except Exception as e:
            print(f" Ошибка: {e}")
            messagebox.showerror("Ошибка", f"{e}")

    def change_master_password(self):
        """Смена мастер-пароля с ротацией ключей (CHANGE-1..4)"""
        if not self.db or not self.key_manager:
            messagebox.showerror("Ошибка", "База данных не открыта или сессия заблокирована")
            return

        dialog = tk.Toplevel(self.root)
        dialog.title("Смена мастер-пароля")
        dialog.geometry("450x350")
        dialog.transient(self.root)
        dialog.grab_set()

        from src.gui.widgets.password_entry import PasswordEntry
        from src.core.crypto.password_policy import validate_password_strength

        # Форма
        form = ttk.Frame(dialog, padding="20")
        form.pack(fill=tk.BOTH, expand=True)

        ttk.Label(form, text="Текущий пароль:").pack(anchor=tk.W, pady=(0, 5))
        old_entry = PasswordEntry(form)
        old_entry.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(form, text="Новый пароль:").pack(anchor=tk.W, pady=(0, 5))
        new_entry = PasswordEntry(form)
        new_entry.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(form, text="Подтверждение:").pack(anchor=tk.W, pady=(0, 5))
        confirm_entry = PasswordEntry(form)
        confirm_entry.pack(fill=tk.X, pady=(0, 20))

        def do_change():
            old_pwd = old_entry.get()
            new_pwd = new_entry.get()
            confirm_pwd = confirm_entry.get()

            if new_pwd != confirm_pwd:
                messagebox.showerror("Ошибка", "Пароли не совпадают")
                return

            if validate_password_strength(new_pwd):
                messagebox.showerror("Ошибка", validate_password_strength(new_pwd))
                return

            try:
                self.key_manager.rotate_master_password(old_pwd, new_pwd, self.db)
                messagebox.showinfo("Успех", "✅ Мастер-пароль успешно изменён!")
                dialog.destroy()
                old_entry.clear()
                new_entry.clear()
                confirm_entry.clear()
            except ValueError as e:
                messagebox.showerror("Ошибка", str(e))
            except Exception as e:
                messagebox.showerror("Ошибка", f"Ошибка ротации ключей: {str(e)}")

        btn_frame = ttk.Frame(form)
        btn_frame.pack(fill=tk.X, pady=10)
        ttk.Button(btn_frame, text="Сменить", command=do_change).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="Отмена", command=dialog.destroy).pack(side=tk.RIGHT)

        new_entry.focus()
        dialog.wait_window()

    def load_config_from_db(self):
        """Загрузить настройки из БД"""
        if self.db and self.db.connection:
            self.config.load_from_db(self.db.connection)

    def browse_db_path(self, entry):
        """Выбор файла БД"""
        path = filedialog.asksaveasfilename(
            defaultextension=".db",
            filetypes=[("SQLite DB", "*.db"), ("All files", "*.*")],
            title="Сохранить базу данных как"
        )
        if path:
            entry.delete(0, tk.END)
            entry.insert(0, path)

    def new_database(self):
        """Создать новую базу"""
        self.show_setup_wizard()

    def open_database(self):
        """Открыть существующую базу"""
        if not self.config.db_path:
            return

        try:
            from src.database.db import DatabaseManager

            db_path = self.config.db_path
            print(f"Попытка открыть БД: {db_path}")

            # Проверяем и корректируем путь
            if os.path.isdir(db_path):
                db_path = os.path.join(db_path, "cryptosafe.db")
                self.config.db_path = db_path
                print(f"Путь скорректирован: {db_path}")

            self.db = DatabaseManager(db_path)
            self.db.connect()
            self.config.load_from_db(self.db.connection)
            from src.core.key_manager import KeyManager
            from src.core.crypto.authentication import AuthenticationService

            self.key_manager = KeyManager(self.config, self.db.connection)
            self.auth_service = AuthenticationService(self.key_manager, self.events)
            self.db.key_manager = self.key_manager
            self.entry_manager = EntryManager(self.db.connection, self.key_manager, self.events)
            self._init_clipboard_services()

            self.status_var.set(f"База данных: {db_path}")
            self.refresh_entries()
            print("База данных успешно открыта")

        except Exception as e:
            print(f"Ошибка открытия БД: {e}")
            import traceback
            traceback.print_exc()
            messagebox.showerror("Ошибка", f"Не удалось открыть базу: {str(e)}")

    def backup_database(self):
        """Создание резервной копии"""
        if not self.db:
            messagebox.showerror("Ошибка", "База данных не открыта")
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".backup",
            filetypes=[("Backup files", "*.backup"), ("All files", "*.*")],
            title="Сохранить резервную копию как"
        )

        if filename:
            if self.db.backup_database(filename):
                messagebox.showinfo("Успех", f"Резервная копия создана: {filename}")
            else:
                messagebox.showerror("Ошибка", "Не удалось создать резервную копию")

    def restore_database(self):
        """Восстановление из резервной копии"""
        if messagebox.askyesno("Подтверждение",
                               "Восстановление заменит текущую базу данных. Продолжить?"):
            filename = filedialog.askopenfilename(
                filetypes=[("Backup files", "*.backup"), ("All files", "*.*")],
                title="Выберите резервную копию"
            )

            if filename:
                if self.db and self.db.restore_database(filename):
                    messagebox.showinfo("Успех", "База данных восстановлена")
                    self.refresh_entries()
                else:
                    messagebox.showerror("Ошибка", "Не удалось восстановить базу данных")

    def add_entry(self):
        """Добавить запись"""
        if not self.db:
            messagebox.showerror("Ошибка", "База данных не открыта")
            return

        dialog = tk.Toplevel(self.root)
        dialog.title("Новая запись")
        dialog.geometry("500x600")
        dialog.transient(self.root)
        dialog.grab_set()

        # Форма
        form = ttk.Frame(dialog, padding="20")
        form.pack(fill=tk.BOTH, expand=True)

        # Поля ввода
        ttk.Label(form, text="Название:*").pack(anchor=tk.W, pady=(10, 0))
        title_entry = ttk.Entry(form)
        title_entry.pack(fill=tk.X, pady=(0, 10))
        title_entry.focus()

        ttk.Label(form, text="Пользователь:").pack(anchor=tk.W, pady=(10, 0))
        username_entry = ttk.Entry(form)
        username_entry.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(form, text="Пароль:").pack(anchor=tk.W, pady=(10, 0))
        from src.gui.widgets.password_entry import PasswordEntry
        password_entry = PasswordEntry(form)
        password_entry.pack(fill=tk.X, pady=(0, 10))
        gen_btn = ttk.Button(form, text="🔑 Генерировать",
                             command=lambda: password_entry.insert(0, self.generate_password()))
        gen_btn.pack(pady=(0, 5))

        def generate_password(self):
            from src.core.vault.password_generator import PasswordGenerator
            gen = PasswordGenerator()
            return gen.generate(length=16)
        ttk.Label(form, text="URL:").pack(anchor=tk.W, pady=(10, 0))
        url_entry = ttk.Entry(form)
        url_entry.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(form, text="Заметки:").pack(anchor=tk.W, pady=(10, 0))
        notes_text = tk.Text(form, height=4, width=50)
        notes_text.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(form, text="Теги:").pack(anchor=tk.W, pady=(10, 0))
        tags_entry = ttk.Entry(form)
        tags_entry.pack(fill=tk.X, pady=(0, 10))

        # Кнопки
        btn_frame = ttk.Frame(form)
        btn_frame.pack(fill=tk.X, pady=20)

        def save_entry():
            data = {
                'title': title_entry.get(),
                'username': username_entry.get(),
                'password': password_entry.get(),
                'url': url_entry.get(),
                'notes': notes_text.get('1.0', tk.END).strip(),
                'tags': tags_entry.get()
            }
            try:
                entry_id = self.entry_manager.create_entry(data)  # 🆕
                dialog.destroy()
                self.refresh_entries()
            except Exception as e:
                messagebox.showerror("Ошибка", str(e))
        ttk.Button(btn_frame, text="Сохранить", command=save_entry).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="Отмена", command=dialog.destroy).pack(side=tk.RIGHT)

    def edit_entry(self):
        """Редактировать запись"""
        if not self.db:
            messagebox.showerror("Ошибка", "База данных не открыта")
            return

        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Предупреждение", "Выберите запись для редактирования")
            return

        entry_id = self._selected_entry_id()

        try:
            entry = self.db.get_entry(entry_id)
            if not entry:
                messagebox.showerror("Ошибка", "Запись не найдена")
                return

            # Здесь будет диалог редактирования
            messagebox.showinfo("Редактирование", f"Редактирование записи #{entry_id}\nФункция в разработке (Спринт 2)")

        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось загрузить запись: {str(e)}")

    def delete_entry(self):
        """Удалить запись"""
        if not self.db:
            messagebox.showerror("Ошибка", "База данных не открыта")
            return

        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Предупреждение", "Выберите запись для удаления")
            return

        item = self.tree.item(selected[0])
        entry_id = self._selected_entry_id()
        title = item['values'][1]

        if messagebox.askyesno("Подтверждение", f"Удалить запись '{title}'?"):
            try:
                # TODO: реализовать удаление в Sprint 2
                messagebox.showinfo("Удаление", "Функция удаления в разработке (Спринт 2)")
                # self.db.delete_entry(entry_id)
                # self.refresh_entries()
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось удалить: {str(e)}")

    def show_audit_log(self):
        """Показать журнал аудита"""
        messagebox.showinfo("Журнал аудита", "Функция будет реализована в Sprint 5")

    def show_settings(self):
        """Показать настройки"""
        timeout = self.config.get("clipboard_timeout_seconds", ClipboardService.DEFAULT_TIMEOUT)
        if timeout == 0:
            timeout_display = "never"
        else:
            timeout_display = str(timeout)
        value = simpledialog.askstring(
            "Clipboard timeout",
            "Введите таймер автоочистки (5-300 сек) или 'never':",
            initialvalue=timeout_display,
            parent=self.root,
        )
        if value is None:
            return
        if not self.clipboard_service:
            messagebox.showerror("Ошибка", "Clipboard service не инициализирован")
            return
        try:
            if value.strip().lower() == "never":
                self.clipboard_service.set_auto_clear_timeout(None)
            else:
                self.clipboard_service.set_auto_clear_timeout(int(value))
            messagebox.showinfo("Настройки", "Таймер автоочистки сохранен")
        except Exception as exc:
            messagebox.showerror("Ошибка", str(exc))

    def show_about(self):
        """О программе"""
        about_text = """CryptoSafe Manager v1.0

Безопасный менеджер паролей с открытым кодом

Разработка по спринтам:
• Sprint 1: Фундамент и архитектура
• Sprint 2: Управление ключами
• Sprint 3: Настоящее шифрование (AES-256)
• Sprint 4: Буфер обмена и UX
• Sprint 5: Аудит и журналы
• Sprint 6: Теги и организация
• Sprint 7: Автоблокировка
• Sprint 8: Упаковка и дистрибуция
"""

        messagebox.showinfo("О программе", about_text)

    def refresh_entries(self):
        if not self.entry_manager:
            return

        entries = self.entry_manager.get_all_entries()  # 🆕

        # Очищаем таблицу
        for item in self.tree.get_children():
            self.tree.delete(item)
        self._entry_id_map = {}

        for entry in entries:
            # Маск username (GUI-1)
            username = entry.get('username', '')
            masked = username[:4] + '••••' if len(username) > 4 else '••••'

            values = (
                entry['id'][:8],  # Короткий ID
                entry['title'],
                masked,
                entry.get('url', '')[:30] + '...' if len(entry.get('url', '')) > 30 else entry.get('url', ''),
                entry.get('updated_at', '')[:16]
            )
            self._entry_id_map[entry['id'][:8]] = entry['id']
            self.tree.insert('', tk.END, iid=entry['id'], values=values)

    def is_vault_unlocked(self) -> bool:
        if not self.auth_service:
            return False
        session_ok = getattr(self.auth_service.session, "logged_in", False)
        key_ok = self.key_manager is not None and self.key_manager.get_encryption_key() is not None
        return bool(session_ok and key_ok)

    def _selected_entry_id(self):
        selected = self.tree.selection()
        if not selected:
            return None
        candidate = selected[0]
        if candidate in self._entry_id_map.values():
            return candidate
        item = self.tree.item(candidate)
        if item and item.get("values"):
            short_id = item["values"][0]
            return self._entry_id_map.get(short_id, short_id)
        return None

    def copy_selected_username(self):
        self._copy_selected_field("username", "username")

    def copy_selected_password(self):
        self._copy_selected_field("password", "password")

    def copy_selected_all(self):
        entry_id = self._selected_entry_id()
        if not entry_id:
            messagebox.showwarning("Предупреждение", "Выберите запись для копирования")
            return
        if not self.clipboard_service:
            messagebox.showerror("Ошибка", "Clipboard service недоступен")
            return
        entry = self.entry_manager.get_entry(entry_id)
        if not entry:
            messagebox.showerror("Ошибка", "Запись не найдена")
            return
        payload = f"{entry.get('username', '')}:{entry.get('password', '')}"
        try:
            self.clipboard_service.copy_to_clipboard(payload, data_type="all", source_entry_id=entry_id)
            self.status_var.set("Скопирован username:password")
        except PermissionError:
            messagebox.showwarning("Сейф заблокирован", "Сначала разблокируйте сейф для копирования")
        except Exception as exc:
            messagebox.showerror("Ошибка", str(exc))

    def _copy_selected_field(self, field_name: str, data_type: str):
        entry_id = self._selected_entry_id()
        if not entry_id:
            messagebox.showwarning("Предупреждение", "Выберите запись для копирования")
            return
        if not self.clipboard_service:
            messagebox.showerror("Ошибка", "Clipboard service недоступен")
            return
        entry = self.entry_manager.get_entry(entry_id)
        if not entry:
            messagebox.showerror("Ошибка", "Запись не найдена")
            return
        value = entry.get(field_name, "")
        if not value:
            messagebox.showwarning("Предупреждение", f"Поле {field_name} пустое")
            return
        try:
            self.clipboard_service.copy_to_clipboard(value, data_type=data_type, source_entry_id=entry_id)
            self.status_var.set(f"Скопировано поле: {field_name}")
        except PermissionError:
            messagebox.showwarning("Сейф заблокирован", "Сначала разблокируйте сейф для копирования")
        except Exception as exc:
            messagebox.showerror("Ошибка", str(exc))

    def _show_row_context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="Copy Username", command=self.copy_selected_username)
        menu.add_command(label="Copy Password", command=self.copy_selected_password)
        menu.add_command(label="Copy All", command=self.copy_selected_all)
        menu.tk_popup(event.x_root, event.y_root)

    def _on_clipboard_copied(self, data):
        timeout = data.get("timeout") if isinstance(data, dict) else None
        if timeout is None:
            self.status_var.set("Clipboard активен (без автоочистки)")
        else:
            self.status_var.set(f"Clipboard активен, автоочистка через {timeout}с")

    def _on_clipboard_cleared(self, data):
        reason = data.get("reason") if isinstance(data, dict) else "unknown"
        self.status_var.set(f"Clipboard очищен ({reason})")

    def _on_user_logged_out(self, _data):
        if self.clipboard_service:
            self.clipboard_service.on_vault_lock()
    def on_closing(self):
        """Обработка закрытия окна"""
        if self.clipboard_monitor:
            self.clipboard_monitor.stop()
        if self.clipboard_service:
            self.clipboard_service.shutdown()
        if self.auth_service:
            self.auth_service.logout()  # ← ОЧИСТКА КЛЮЧЕЙ!
        if self.db:
            try:
                self.db.close()
            except:
                pass
        self.root.destroy()


    def run(self):
        """Запуск приложения"""
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.mainloop()