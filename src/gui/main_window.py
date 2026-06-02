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
from src.core.audit.audit_logger import AuditLogger
from src.core.audit.log_signer import AuditLogSigner
from src.core.audit.log_formatters import export_logs
from src.gui.widgets.audit_viewer import AuditViewerWindow
from src.gui.widgets.toast import ToastManager
from src.gui.widgets.clipboard_preview import ClipboardPreviewPanel
from src.core.settings.encrypted_settings import EncryptedSettingsStore
from src.core.settings.settings_adapter import SettingsAdapter
from src.core.settings.clipboard_presets import CLIPBOARD_PRESETS, apply_preset


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
        self.audit_logger = None
        self._audit_viewer = None
        self.settings_adapter = SettingsAdapter(self.config, None)
        self.toast = ToastManager(self.root)
        self._clipboard_tick_id = None
        self._export_schedule_timer = None
        self._entry_id_map = {}
        self._display_order_ids = []

        # Sprint 7: security service handles (None until login)
        self._activity_monitor = None
        self._auto_lock = None
        self._panic_mode = None
        self._lock_overlay = None
        self._security_tick_id = None
        # Sprint 7: system tray (None until setup_ui completes)
        self._system_tray = None

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
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.grid(row=0, column=0, sticky='nsew', padx=10, pady=10)
        main_frame = self.main_frame        # Настройка сетки для main_frame
        main_frame.grid_rowconfigure(2, weight=1)
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

        # Clipboard preview (UI-4)
        self.clipboard_preview = None

        # Таблица записей (grid row=2)
        columns = ('id', 'title', 'username', 'url', 'updated_at', 'copy_user', 'copy_pass', 'copy_totp')
        self.tree = ttk.Treeview(main_frame, columns=columns, show='headings', height=18, selectmode='browse')

        self.tree.heading('id', text='ID', command=lambda: self._sort_tree('id', False))
        self.tree.heading('title', text='Название', command=lambda: self._sort_tree('title', False))
        self.tree.heading('username', text='Пользователь', command=lambda: self._sort_tree('username', False))
        self.tree.heading('url', text='URL', command=lambda: self._sort_tree('url', False))
        self.tree.heading('updated_at', text='Обновлено', command=lambda: self._sort_tree('updated_at', False))
        self.tree.heading('copy_user', text='👤')
        self.tree.heading('copy_pass', text='🔑')
        self.tree.heading('copy_totp', text='⏱')

        self.tree.column('id', width=50, anchor='center')
        self.tree.column('title', width=180)
        self.tree.column('username', width=120)
        self.tree.column('url', width=160)
        self.tree.column('updated_at', width=120, anchor='center')
        self.tree.column('copy_user', width=36, anchor='center')
        self.tree.column('copy_pass', width=36, anchor='center')
        self.tree.column('copy_totp', width=36, anchor='center')

        # Скроллбары
        v_scroll = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=self.tree.yview)
        h_scroll = ttk.Scrollbar(main_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)

        # Размещение таблицы и скроллбаров в grid
        self.tree.grid(row=2, column=0, sticky='nsew')
        v_scroll.grid(row=2, column=1, sticky='ns')
        h_scroll.grid(row=3, column=0, sticky='ew')

        self.tree.bind('<Double-1>', lambda e: self.edit_entry())
        self.tree.bind('<Button-3>', self._show_row_context_menu)
        self.tree.bind('<Button-1>', self._on_tree_click)

        # Строка состояния (отдельно от main_frame, используем grid для root)
        self.status_var = tk.StringVar(value="Готов")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.grid(row=1, column=0, sticky='ew')

        # Sprint 7: System Tray (TRAY-1)
        # Initialise early so the user can minimise-to-tray immediately.
        self._init_system_tray()

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
        # Sprint 6: Import/Export (UI-1, UI-2)
        self._export_menu_item_index = None
        self._import_menu_item_index = None
        file_menu.add_command(
            label="Экспорт...",
            command=self.show_export_dialog,
            accelerator="Ctrl+E",
            state=tk.DISABLED,
        )
        file_menu.add_command(
            label="Импорт...",
            command=self.show_import_dialog,
            accelerator="Ctrl+I",
            state=tk.DISABLED,
        )
        self._file_menu = file_menu
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
        view_menu.add_command(
            label="Настройки безопасности",
            command=self.show_security_settings,
        )

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
        # Sprint 6: Import/Export shortcuts (UI-1, UI-2)
        self.root.bind('<Control-e>', lambda e: self.show_export_dialog())
        self.root.bind('<Control-i>', lambda e: self.show_import_dialog())

    def _init_settings_adapter(self) -> None:
        if self.db and self.key_manager:
            enc = EncryptedSettingsStore(self.db.connection, self.key_manager)
            self.settings_adapter = SettingsAdapter(self.config, enc)
            if self.settings_adapter.get("clipboard_timeout_seconds") is None:
                apply_preset(self.settings_adapter, "standard")

    def _init_clipboard_services(self):
        self._init_settings_adapter()
        adapter = create_platform_adapter()
        self.clipboard_service = ClipboardService(
            adapter=adapter,
            events=self.events,
            config=self.settings_adapter,
            is_vault_unlocked=self.is_vault_unlocked,
            on_notify=self._clipboard_toast,
            on_suspicious_activity=self._on_suspicious_clipboard,
        )
        self.clipboard_monitor = ClipboardMonitor(
            self.clipboard_service, self.events, on_suspicious=self._on_monitor_alert
        )
        self.clipboard_monitor.start()
        self._ensure_clipboard_preview()
        self._start_clipboard_status_tick()

    def _ensure_clipboard_preview(self):
        if self.clipboard_preview is None and self.clipboard_service and hasattr(self, "main_frame"):
            self.clipboard_preview = ClipboardPreviewPanel(
                self.main_frame,
                self.clipboard_service,
                self._verify_master_password,
            )
            self.clipboard_preview.grid(row=1, column=0, sticky='ew', pady=(0, 6))

    def _clipboard_toast(self, level: str, message: str) -> None:
        self.root.after(0, lambda: self.toast.show(message, level))

    def _on_suspicious_clipboard(self, payload: dict) -> None:
        def ask():
            block = messagebox.askyesno(
                "Подозрительная активность",
                f"{payload.get('reason', 'detected')}\n\n"
                "Заблокировать дальнейшее копирование в буфер?",
                parent=self.root,
            )
            if block:
                self.clipboard_service.set_copy_blocked(True)
        self.root.after(0, ask)

    def _on_monitor_alert(self, reason: str, details: dict) -> None:
        self._clipboard_toast("warning", f"Clipboard monitor: {reason}")

    def _verify_master_password(self, password: str) -> bool:
        if not self.auth_service:
            return False
        return self.auth_service.key_manager.derivation.verify_password(
            password, self.auth_service.key_manager.store.get_latest_auth_hash() or ""
        )

    def _start_clipboard_status_tick(self) -> None:
        if self._clipboard_tick_id:
            self.root.after_cancel(self._clipboard_tick_id)
        self._update_clipboard_status()
        self._clipboard_tick_id = self.root.after(1000, self._start_clipboard_status_tick)

    def _update_clipboard_status(self) -> None:
        if not self.clipboard_service:
            return
        st = self.clipboard_service.get_status()
        if self.clipboard_preview:
            self.clipboard_preview.refresh()
        if not st.get("active"):
            return
        dtype = st.get("data_type", "text")
        rem = st.get("remaining_seconds")
        if rem is None:
            self.status_var.set(f"Clipboard: {dtype} (no auto-clear)")
        else:
            sec = int(rem)
            self.status_var.set(f"Clipboard: {dtype} ({sec}s remaining)")

    def _init_audit_logger(self, master_password: str) -> None:
        if not self.db or not self.key_manager:
            return
        seed = self.key_manager.get_audit_signing_seed(master_password)
        enc_key = self.key_manager.get_audit_encryption_key(master_password)
        if not seed:
            return
        signer = AuditLogSigner(signing_seed=seed)
        self.audit_logger = AuditLogger(
            self.db.connection,
            signer,
            events=self.events,
            audit_encryption_key=enc_key,
            on_periodic_verify=self._on_periodic_audit_verify,
            verify_interval_hours=24.0,
        )
        self.audit_logger.log_event(
            "SYSTEM_STARTUP",
            "INFO",
            "main_window",
            {"action": "session_started"},
        )

    def _on_periodic_audit_verify(self, result: dict) -> None:
        if not result.get("verified"):
            self.root.after(
                0,
                lambda: self.toast.show("Audit log integrity check FAILED", "error"),
            )

    def _sort_tree(self, col, reverse):
        """Сортировка таблицы по колонке"""
        data = [(self.tree.set(child, col), child) for child in self.tree.get_children('')]
        data.sort(reverse=reverse)

        for index, (val, child) in enumerate(data):
            self.tree.move(child, '', index)

        self.tree.heading(col, command=lambda: self._sort_tree(col, not reverse))

    def _on_search(self):
        """Фильтрация записей по поиску"""
        query = (self.search_var.get() or "").strip().lower()
        row_ids = list(self._display_order_ids) or list(self._entry_id_map.values())
        if not query:
            for iid in row_ids:
                if not self.tree.exists(iid):
                    continue
                try:
                    self.tree.reattach(iid, "", tk.END)
                except tk.TclError as e:
                    print(f"[debug] _on_search reattach {iid!r}: {e}")
            return
        for iid in row_ids:
            if not self.tree.exists(iid):
                continue
            vals = self.tree.item(iid).get("values") or ()
            title = str(vals[1]).lower() if len(vals) > 1 else ""
            user_m = str(vals[2]).lower() if len(vals) > 2 else ""
            if query in title or query in user_m:
                try:
                    self.tree.reattach(iid, "", tk.END)
                except tk.TclError as e:
                    print(f"[debug] _on_search reattach(match) {iid!r}: {e}")
            else:
                try:
                    self.tree.detach(iid)
                except tk.TclError as e:
                    print(f"[debug] _on_search detach {iid!r}: {e}")
    def check_first_run(self):
        if not self.config.db_path:
            self.show_setup_wizard()
        else:
            self.open_database()

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
        pass_entry.focus_force()

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
                # ВАЖНО: Сохраняем мастер-пароль после успешного входа
                self.master_password = pwd
                print(f"[DEBUG] Мастер-пароль установлен после успешного входа: {bool(self.master_password)}")
                
                self._init_audit_logger(pwd)
                self._set_import_export_menu_state(tk.NORMAL)
                dialog.destroy()
                self.refresh_entries()
                # Sprint 7: start security services after successful login
                self._init_security()
                self._update_import_export_menu_state()
            else:
                status_var.set("Неверный пароль")

        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="Войти", command=do_login).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="Отмена", command=dialog.destroy).pack(side=tk.RIGHT)

        dialog.wait_window()

    def _finish_setup(self, dialog):
        password = self.master_pass_entry.get()
        if not password:
            messagebox.showerror("Ошибка", "Введите мастер-пароль")
            return

        db_path = self.db_path_entry.get()
        if not db_path:
            messagebox.showerror("Ошибка", "Укажите путь к базе данных")
            return
        from src.core.crypto.password_policy import validate_password_strength
        error = validate_password_strength(password)
        if error:
            if not messagebox.askyesno("Слабый пароль",
                                       f"{error}\n\nПродолжить с этим паролем?"):
                return

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
            print("База данных успешно открыта — требуется вход")
            self.show_login_dialog()

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

    def _require_encryption_key(self, context: str) -> bool:
        if not self.key_manager:
            print(f"[debug] {context}: key_manager отсутствует")
            messagebox.showerror("Ошибка", "Менеджер ключей недоступен")
            return False
        if self.key_manager.get_encryption_key() is None:
            print(f"[debug] {context}: ключ шифрования не загружен")
            messagebox.showwarning(
                "Сейф заблокирован",
                "Войдите по мастер-паролю (Файл → при открытии БД или после запуска), чтобы работать с записями.",
            )
            return False
        return True

    def add_entry(self):
        """Добавить запись"""
        if not self.db:
            messagebox.showerror("Ошибка", "База данных не открыта")
            return
        if not self.entry_manager or not self._require_encryption_key("add_entry"):
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
        from src.core.vault.password_generator import PasswordGenerator

        def generate_and_set():
            gen = PasswordGenerator()
            password_entry.set(gen.generate(length=16))

        gen_btn = ttk.Button(form, text="🔑 Генерировать", command=generate_and_set)
        gen_btn.pack(pady=(0, 5))

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
        if not self.entry_manager or not self._require_encryption_key("edit_entry"):
            return

        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Предупреждение", "Выберите запись для редактирования")
            return

        entry_id = self._selected_entry_id()
        if not entry_id:
            messagebox.showerror("Ошибка", "Не удалось определить запись")
            return

        try:
            entry = self.entry_manager.get_entry(entry_id)
            if not entry:
                messagebox.showerror("Ошибка", "Запись не найдена")
                return
        except Exception as e:
            print(f"[debug] edit_entry load: {e}")
            messagebox.showerror("Ошибка", f"Не удалось загрузить запись: {e}")
            return

        dialog = tk.Toplevel(self.root)
        dialog.title("Редактировать запись")
        dialog.geometry("500x600")
        dialog.transient(self.root)
        dialog.grab_set()

        form = ttk.Frame(dialog, padding="20")
        form.pack(fill=tk.BOTH, expand=True)

        ttk.Label(form, text="Название:*").pack(anchor=tk.W, pady=(10, 0))
        title_entry = ttk.Entry(form)
        title_entry.pack(fill=tk.X, pady=(0, 10))
        title_entry.insert(0, entry.get("title") or "")

        ttk.Label(form, text="Пользователь:").pack(anchor=tk.W, pady=(10, 0))
        username_entry = ttk.Entry(form)
        username_entry.pack(fill=tk.X, pady=(0, 10))
        username_entry.insert(0, entry.get("username") or "")

        ttk.Label(form, text="Пароль:").pack(anchor=tk.W, pady=(10, 0))
        from src.gui.widgets.password_entry import PasswordEntry
        from src.core.vault.password_generator import PasswordGenerator

        password_entry = PasswordEntry(form)
        password_entry.pack(fill=tk.X, pady=(0, 10))
        password_entry.set(entry.get("password") or "")

        def generate_and_set():
            gen = PasswordGenerator()
            password_entry.set(gen.generate(length=16))

        ttk.Button(form, text="🔑 Генерировать", command=generate_and_set).pack(pady=(0, 5))

        ttk.Label(form, text="URL:").pack(anchor=tk.W, pady=(10, 0))
        url_entry = ttk.Entry(form)
        url_entry.pack(fill=tk.X, pady=(0, 10))
        url_entry.insert(0, entry.get("url") or "")

        ttk.Label(form, text="Заметки:").pack(anchor=tk.W, pady=(10, 0))
        notes_text = tk.Text(form, height=4, width=50)
        notes_text.pack(fill=tk.X, pady=(0, 10))
        notes_text.insert("1.0", entry.get("notes") or "")

        ttk.Label(form, text="Теги:").pack(anchor=tk.W, pady=(10, 0))
        tags_entry = ttk.Entry(form)
        tags_entry.pack(fill=tk.X, pady=(0, 10))
        tags_entry.insert(0, entry.get("tags") or "")

        btn_frame = ttk.Frame(form)
        btn_frame.pack(fill=tk.X, pady=20)
        title_entry.focus()

        def save_entry():
            data = {
                "title": title_entry.get(),
                "username": username_entry.get(),
                "password": password_entry.get(),
                "url": url_entry.get(),
                "notes": notes_text.get("1.0", tk.END).strip(),
                "tags": tags_entry.get(),
            }
            try:
                ok = self.entry_manager.update_entry(entry_id, data)
                if not ok:
                    messagebox.showerror("Ошибка", "Запись не найдена при сохранении")
                    return
                dialog.destroy()
                self.refresh_entries()
            except Exception as e:
                print(f"[debug] edit_entry save: {e}")
                messagebox.showerror("Ошибка", str(e))

        ttk.Button(btn_frame, text="Сохранить", command=save_entry).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="Отмена", command=dialog.destroy).pack(side=tk.RIGHT)

    def delete_entry(self):
        """Удалить запись"""
        if not self.db:
            messagebox.showerror("Ошибка", "База данных не открыта")
            return
        if not self.entry_manager or not self._require_encryption_key("delete_entry"):
            return

        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Предупреждение", "Выберите запись для удаления")
            return

        item = self.tree.item(selected[0])
        entry_id = self._selected_entry_id()
        if not entry_id:
            messagebox.showerror("Ошибка", "Не удалось определить запись")
            return
        vals = item.get("values") or ()
        title = str(vals[1]) if len(vals) > 1 else entry_id

        if messagebox.askyesno("Подтверждение", f"Удалить запись «{title}»?"):
            try:
                if not self.entry_manager.delete_entry(entry_id, soft_delete=False):
                    messagebox.showerror("Ошибка", "Запись не найдена")
                    return
                self.refresh_entries()
                self.status_var.set("Запись удалена")
            except Exception as e:
                print(f"[debug] delete_entry: {e}")
                messagebox.showerror("Ошибка", f"Не удалось удалить: {e}")

    def show_audit_log(self):
        """Показать журнал аудита"""
        if not self.is_vault_unlocked():
            messagebox.showwarning("Журнал аудита", "Сейф должен быть разблокирован")
            return
        if not self.audit_logger:
            messagebox.showerror("Журнал аудита", "Аудит не инициализирован — войдите в сейф")
            return
        self._audit_viewer = AuditViewerWindow(
            self.root,
            self.audit_logger,
            verify_callback=lambda: self.audit_logger.verify_integrity(limit=1000),
            export_callback=self._export_audit_logs,
            on_entry_click=self._highlight_vault_entry,
            schedule_export_callback=self._schedule_audit_export,
        )

    def _export_audit_logs(
        self, fmt: str, path: str, _password: str, date_from=None, date_to=None
    ) -> None:
        if not self.audit_logger:
            return
        rows = self.audit_logger.get_rows_for_export(date_from=date_from, date_to=date_to)
        export_logs(
            rows,
            fmt,
            path,
            signer_public_key_hex=self.audit_logger.signer.get_public_key_hex(),
            metadata={"exporter": "audit_viewer"},
        )
        self.audit_logger.log_event(
            "AUDIT_EXPORT",
            "INFO",
            "audit_viewer",
            {"format": fmt, "path": path, "count": len(rows)},
        )
        messagebox.showinfo("Экспорт", f"Экспортировано {len(rows)} записей в {path}")

    def _highlight_vault_entry(self, entry_id: str) -> None:
        for iid, eid in self._entry_id_map.items():
            if eid == entry_id and self.tree.exists(iid):
                self.tree.selection_set(iid)
                self.tree.see(iid)
                break

    def show_settings(self):
        """Настройки буфера обмена и пресеты (CFG-3, CLIP-3)."""
        dialog = tk.Toplevel(self.root)
        dialog.title("Настройки буфера обмена")
        dialog.geometry("420x320")
        dialog.transient(self.root)

        ttk.Label(dialog, text="Пресет:").pack(anchor=tk.W, padx=12, pady=(12, 2))
        preset_var = tk.StringVar(value=self.settings_adapter.get("clipboard_preset", "standard"))
        preset_cb = ttk.Combobox(
            dialog,
            textvariable=preset_var,
            values=list(CLIPBOARD_PRESETS.keys()),
            state="readonly",
        )
        preset_cb.pack(fill=tk.X, padx=12)

        ttk.Label(dialog, text="Таймер (5-300 или never):").pack(anchor=tk.W, padx=12, pady=(8, 2))
        timeout_raw = self.settings_adapter.get("clipboard_timeout_seconds", 30)
        timeout_var = tk.StringVar(value="never" if str(timeout_raw) == "0" else str(timeout_raw))
        ttk.Entry(dialog, textvariable=timeout_var).pack(fill=tk.X, padx=12)

        block_var = tk.BooleanVar(value=self.clipboard_service.copy_blocked if self.clipboard_service else False)
        ttk.Checkbutton(dialog, text="Блокировать копирование", variable=block_var).pack(anchor=tk.W, padx=12, pady=4)

        def apply_preset_click():
            try:
                apply_preset(self.settings_adapter, preset_var.get())
                messagebox.showinfo("OK", f"Пресет «{preset_var.get()}» применён", parent=dialog)
            except Exception as exc:
                messagebox.showerror("Ошибка", str(exc), parent=dialog)

        def save_custom():
            if not self.clipboard_service:
                return
            try:
                val = timeout_var.get().strip().lower()
                if val == "never":
                    self.clipboard_service.set_auto_clear_timeout(None)
                else:
                    self.clipboard_service.set_auto_clear_timeout(int(val))
                self.clipboard_service.set_copy_blocked(block_var.get())
                messagebox.showinfo("OK", "Настройки сохранены в зашифрованную БД", parent=dialog)
            except Exception as exc:
                messagebox.showerror("Ошибка", str(exc), parent=dialog)

        btn_row = ttk.Frame(dialog)
        btn_row.pack(pady=16)
        ttk.Button(btn_row, text="Применить пресет", command=apply_preset_click).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_row, text="Сохранить", command=save_custom).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_row, text="Закрыть", command=dialog.destroy).pack(side=tk.LEFT, padx=4)

    def show_security_settings(self):
        """Настройки безопасности Sprint 7: автоблокировка и stealth mode."""
        dialog = tk.Toplevel(self.root)
        dialog.title("Настройки безопасности")
        dialog.geometry("440x260")
        dialog.transient(self.root)
        dialog.resizable(False, False)

        notebook = ttk.Notebook(dialog)
        notebook.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        security_tab = ttk.Frame(notebook, padding=12)
        notebook.add(security_tab, text="Security")

        timeout_raw = self.settings_adapter.get("auto_lock_timeout", 300)
        try:
            timeout_sec = int(timeout_raw)
        except (TypeError, ValueError):
            timeout_sec = 300
        timeout_min = max(1, min(30, timeout_sec // 60 if timeout_sec >= 60 else 5))

        stealth_raw = self.settings_adapter.get("stealth_mode", False)
        if isinstance(stealth_raw, str):
            stealth_default = stealth_raw.strip().lower() in ("1", "true", "yes", "on")
        else:
            stealth_default = bool(stealth_raw)

        ttk.Label(
            security_tab,
            text="Таймаут автоблокировки при неактивности (1–30 мин):",
        ).pack(anchor=tk.W)
        timeout_var = tk.IntVar(value=timeout_min)
        timeout_spin = ttk.Spinbox(
            security_tab,
            from_=1,
            to=30,
            textvariable=timeout_var,
            width=8,
        )
        timeout_spin.pack(anchor=tk.W, pady=(4, 12))

        stealth_var = tk.BooleanVar(value=stealth_default)
        ttk.Checkbutton(
            security_tab,
            text="Stealth mode (скрытое сообщение об ошибке при panic)",
            variable=stealth_var,
        ).pack(anchor=tk.W)

        def save_security():
            try:
                minutes = int(timeout_var.get())
            except (tk.TclError, ValueError):
                messagebox.showerror(
                    "Ошибка",
                    "Укажите целое число минут от 1 до 30.",
                    parent=dialog,
                )
                return
            if minutes < 1 or minutes > 30:
                messagebox.showerror(
                    "Ошибка",
                    "Таймаут автоблокировки: от 1 до 30 минут.",
                    parent=dialog,
                )
                return

            seconds = minutes * 60
            self.settings_adapter.set("auto_lock_timeout", seconds)
            self.settings_adapter.set("stealth_mode", stealth_var.get())

            if hasattr(self, "_auto_lock") and self._auto_lock:
                self.set_auto_lock_timeout(seconds)

            if hasattr(self, "_panic_mode") and self._panic_mode:
                self._panic_mode.configure(stealth_mode=stealth_var.get())

            messagebox.showinfo("OK", "Настройки безопасности сохранены", parent=dialog)

        btn_row = ttk.Frame(dialog)
        btn_row.pack(pady=(0, 12))
        ttk.Button(btn_row, text="Сохранить", command=save_security).pack(
            side=tk.LEFT, padx=4
        )
        ttk.Button(btn_row, text="Закрыть", command=dialog.destroy).pack(
            side=tk.LEFT, padx=4
        )

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
            print("[debug] refresh_entries: entry_manager отсутствует")
            return
        if not self.key_manager or self.key_manager.get_encryption_key() is None:
            print("[debug] refresh_entries: ключ шифрования недоступен — очистка таблицы")
            for item in self.tree.get_children():
                self.tree.delete(item)
            self._entry_id_map.clear()
            self._display_order_ids.clear()
            return

        try:
            entries = self.entry_manager.get_all_entries()
        except ValueError as e:
            print(f"[debug] refresh_entries: {e}")
            messagebox.showerror("Ошибка", str(e))
            return
        except Exception as e:
            print(f"[debug] refresh_entries: неожиданная ошибка: {e}")
            import traceback
            traceback.print_exc()
            messagebox.showerror("Ошибка", f"Не удалось загрузить записи: {e}")
            return

        for item in self.tree.get_children():
            self.tree.delete(item)
        self._entry_id_map.clear()
        self._display_order_ids.clear()

        for entry in entries:
            username = entry.get("username") or ""
            if len(username) > 4:
                masked = username[:4] + "••••"
            else:
                masked = "••••"
            url_raw = entry.get("url") or ""
            url_display = (url_raw[:30] + "...") if len(url_raw) > 30 else url_raw
            upd = entry.get("updated_at") or ""
            upd_display = str(upd)[:16] if upd else ""

            eid = entry["id"]
            short = eid[:8]
            has_totp = bool(entry.get("totp_secret") or entry.get("totp"))
            values = (
                short,
                entry.get("title") or "",
                masked,
                url_display,
                upd_display,
                "👤",
                "🔑",
                "⏱" if has_totp else "—",
            )
            self.tree.insert("", tk.END, iid=eid, values=values)
            self._entry_id_map[short] = eid
            self._display_order_ids.append(eid)

        if (self.search_var.get() or "").strip():
            self._on_search()

    def is_vault_unlocked(self) -> bool:
        if not self.auth_service:
            return False
        session_ok = getattr(self.auth_service.session, "logged_in", False)
        key_ok = self.key_manager is not None and self.key_manager.get_encryption_key() is not None
        return bool(session_ok and key_ok)

    def _update_import_export_menu_state(self):
        """Включить/выключить пункты меню импорта/экспорта в зависимости от разблокировки сейфа"""
        if not hasattr(self, '_file_menu'):
            return

        enabled = self.is_vault_unlocked()
        state = tk.NORMAL if enabled else tk.DISABLED

        # Находим пункты меню по индексу (они добавлены в setup_menu в определённом порядке)
        # В setup_menu пункты добавлены так:
        # 0: Новая база...
        # 1: Открыть базу...
        # 2: Создать резервную копию...
        # 3: Восстановить из копии...
        # 4: separator
        # 5: Экспорт...
        # 6: Импорт...
        # 7: separator
        # 8: Выход

        menu = self._file_menu
        try:
            # Экспорт - индекс 5
            menu.entryconfig(5, state=state)
            # Импорт - индекс 6
            menu.entryconfig(6, state=state)
        except Exception:
            pass

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
        menu.add_command(label="Редактировать", command=self.edit_entry)
        menu.add_separator()
        menu.add_command(label="Copy Username", command=self.copy_selected_username)
        menu.add_command(label="Copy Password", command=self.copy_selected_password)
        menu.add_command(label="Copy All", command=self.copy_selected_all)
        menu.add_separator()
        menu.add_command(label="Поделиться записью...", command=self._share_selected_entry)
        menu.add_separator()
        menu.add_command(label="Удалить", command=self.delete_entry)
        menu.tk_popup(event.x_root, event.y_root)

    def _share_selected_entry(self):
        entry_id = self._selected_entry_id()
        if not entry_id:
            messagebox.showwarning("Нет выбора", "Выберите запись для шаринга")
            return
        self.show_sharing_dialog(entry_id)

    def _on_tree_click(self, event):
        region = self.tree.identify_region(event.x, event.y)
        if region != "cell":
            return
        col = self.tree.identify_column(event.x)
        row_id = self.tree.identify_row(event.y)
        if not row_id:
            return
        self.tree.selection_set(row_id)
        entry_id = row_id if row_id in self._entry_id_map.values() else self._entry_id_map.get(
            self.tree.item(row_id)["values"][0], row_id
        )
        if col == "#6":
            self._copy_field_for_entry(entry_id, "username", "username")
        elif col == "#7":
            self._copy_field_for_entry(entry_id, "password", "password")
        elif col == "#8":
            self._copy_totp_for_entry(entry_id)

    def _copy_field_for_entry(self, entry_id: str, field_name: str, data_type: str):
        if not self.clipboard_service or not self.entry_manager:
            return
        entry = self.entry_manager.get_entry(entry_id)
        if not entry:
            messagebox.showerror("Ошибка", "Запись не найдена")
            return
        value = entry.get(field_name, "")
        if not value:
            messagebox.showwarning("Пусто", f"Поле {field_name} пустое")
            return
        try:
            self.clipboard_service.copy_to_clipboard(value, data_type=data_type, source_entry_id=entry_id)
        except PermissionError:
            messagebox.showwarning("Сейф заблокирован", "Разблокируйте сейф")
        except Exception as exc:
            messagebox.showerror("Ошибка", str(exc))

    def _copy_totp_for_entry(self, entry_id: str):
        if not self.clipboard_service or not self.entry_manager:
            return
        entry = self.entry_manager.get_entry(entry_id)
        secret = (entry or {}).get("totp_secret") or (entry or {}).get("totp")
        if not secret:
            messagebox.showinfo("TOTP", "У записи нет TOTP секрета")
            return
        try:
            code = self.clipboard_service.copy_totp(secret, source_entry_id=entry_id)
            self.toast.show(f"TOTP copied: {code} (30s)", "info")
        except PermissionError:
            messagebox.showwarning("Сейф заблокирован", "Разблокируйте сейф")
        except Exception as exc:
            messagebox.showerror("Ошибка", str(exc))

    def _schedule_audit_export(self, frequency: str, path: str, password: str) -> None:
        import threading

        intervals = {"daily": 86400, "weekly": 604800, "monthly": 2592000}
        sec = intervals.get(frequency.lower(), 86400)

        def run_export():
            if self.audit_logger:
                rows = self.audit_logger.get_rows_for_export()
                export_logs(
                    rows,
                    "json",
                    path,
                    signer_public_key_hex=self.audit_logger.signer.get_public_key_hex(),
                )

        def loop():
            run_export()
            t = threading.Timer(sec, loop)
            t.daemon = True
            t.start()
            self._export_schedule_timer = t

        loop()
        messagebox.showinfo("Расписание", f"Экспорт {frequency} → {path}")

    def _on_clipboard_copied(self, data):
        self._update_clipboard_status()

    def _on_clipboard_cleared(self, data):
        reason = data.get("reason") if isinstance(data, dict) else "unknown"
        self.status_var.set(f"Clipboard очищен ({reason})")

    def _on_user_logged_out(self, _data):
        if self.clipboard_service:
            self.clipboard_service.on_vault_lock()
        self.refresh_entries()
    def on_closing(self):
        """Обработка закрытия окна"""
        if self._clipboard_tick_id:
            self.root.after_cancel(self._clipboard_tick_id)
        # Sprint 7: stop security services before closing
        self._shutdown_security()
        if self.audit_logger:
            self.audit_logger.stop_periodic_verification()
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

    def hide_to_tray(self) -> None:
        """Сворачивает окно в трей вместо полного завершения."""
        if self._system_tray and self._system_tray.is_available():
            self.root.withdraw()
            self._system_tray.show_notification(
                "CryptoSafe",
                "Приложение свёрнуто в трей. Нажмите на иконку для восстановления.",
            )
            return
        # Если трей недоступен — закрываем как обычно.
        self.on_closing()

    # ==================== IMPORT/EXPORT METHODS (Sprint 6) ====================

    def show_export_dialog(self):
        """Показать диалог экспорта"""
        try:
            from tkinter import messagebox
            from src.core.import_export.exporter import VaultExporter
            from src.gui.export_dialog import ExportDialog

            # Проверяем, что сейф разблокирован
            if not self.is_vault_unlocked():
                messagebox.showwarning("Предупреждение", "Сейф не разблокирован")
                return

            # Создаём экспортёр
            exporter = VaultExporter(self.entry_manager, self.key_manager)

            dialog = ExportDialog(self.root, exporter)
            result = dialog.show()

            if result:
                format_type = result.get("format")
                password = result.get("password")
                file_path = result.get("path")
                self.export_to_file(format_type, password, file_path)

        except ImportError as e:
            messagebox.showerror("Ошибка", f"Не удалось загрузить модуль экспорта: {e}")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при открытии диалога экспорта: {e}")

    def show_import_dialog(self):
        """Показать диалог импорта"""
        try:
            from tkinter import messagebox
            from src.core.import_export.importer import VaultImporter
            from src.gui.import_dialog import ImportDialog

            # Проверяем, что сейф разблокирован
            if not self.is_vault_unlocked():
                messagebox.showwarning("Предупреждение", "Сейф не разблокирован")
                return

            # Создаём импортёр
            importer = VaultImporter(
                self.entry_manager,
                self.audit_logger,
                None  # encryption_service пока None
            )

            dialog = ImportDialog(self.root, importer)
            result = dialog.show()

            if result:
                file_path = result.get("path")
                conflict = result.get("conflict")
                dry_run = result.get("dry_run", False)
                self.import_from_file(file_path, conflict, dry_run)

        except ImportError as e:
            messagebox.showerror("Ошибка", f"Не удалось загрузить модуль импорта: {e}")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при открытии диалога импорта: {e}")

    def show_sharing_dialog(self, entry_id=None):
        """Показать диалог шаринга записи"""
        try:
            from tkinter import messagebox
            from src.core.import_export.sharing_service import SharingService
            from src.gui.sharing_dialog import SharingDialog

            # Если entry_id не передан, берём выбранную запись
            if entry_id is None:
                entry_id = self._selected_entry_id()
                if not entry_id:
                    messagebox.showwarning("Предупреждение", "Не выбрана запись для шаринга")
                    return

            # Проверяем, что сейф разблокирован
            if not self.is_vault_unlocked():
                messagebox.showwarning("Предупреждение", "Сейф не разблокирован")
                return

            sharing_service = SharingService(self.db.connection, None)

            dialog = SharingDialog(self.root, sharing_service, entry_id)
            result = dialog.show()

            if result:
                recipient = result.get("recipient")
                expires_in = result.get("expires_in")
                permissions = result.get("permissions")
                self.share_entry(entry_id, recipient, expires_in, permissions)

        except ImportError as e:
            messagebox.showerror("Ошибка", f"Не удалось загрузить модуль шаринга: {e}")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при открытии диалога шаринга: {e}")

    def export_to_file(self, format_type, password, file_path):
        """Выполнить экспорт"""
        try:
            from tkinter import messagebox
            # TODO: реальная реализация экспорта
            messagebox.showinfo("Экспорт", f"Экспорт в {format_type} выполнен в {file_path}")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка экспорта: {e}")

    def import_from_file(self, file_path, conflict, dry_run):
        """Выполнить импорт"""
        try:
            from tkinter import messagebox
            if dry_run:
                messagebox.showinfo("Импорт (просмотр)", f"Предпросмотр импорта из {file_path}")
            else:
                messagebox.showinfo("Импорт", f"Импорт из {file_path} выполнен")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка импорта: {e}")

    def share_entry(self, entry_id, recipient, expires_in, permissions):
        """Выполнить шаринг записи"""
        try:
            from tkinter import messagebox
            messagebox.showinfo("Шаринг", f"Запись {entry_id} отправлена {recipient} на {expires_in} дней")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка шаринга: {e}")
    def run(self):
        """Запуск приложения"""
        self.root.protocol("WM_DELETE_WINDOW", self.hide_to_tray)
        self.root.mainloop()

    # ------------------------------------------------------------------
    # Sprint 6: Import / Export / Sharing  (UI-1, UI-2, UI-3)
    # ------------------------------------------------------------------

    def _get_exporter(self):
        """Lazily construct a VaultExporter bound to the current session."""
        from src.core.import_export.exporter import VaultExporter
        if not self.entry_manager or not self.audit_logger:
            return None
        return VaultExporter(
            entry_manager=self.entry_manager,
            encryption_service=None,   # exporter uses its own crypto
            audit_logger=self.audit_logger,
            config=self.config,
        )

    def _get_importer(self):
        """Lazily construct a VaultImporter bound to the current session."""
        from src.core.import_export.importer import VaultImporter
        if not self.entry_manager or not self.audit_logger:
            return None
        return VaultImporter(
            entry_manager=self.entry_manager,
            encryption_service=None,
            audit_logger=self.audit_logger,
            db_manager=self.db,
        )

    def _get_sharing_service(self):
        """Lazily construct a SharingService bound to the current session."""
        from src.core.import_export.sharing_service import SharingService
        if not self.db or not self.entry_manager or not self.audit_logger:
            return None
        return SharingService(
            db_connection=self.db.connection,
            encryption_service=None,
            audit_logger=self.audit_logger,
            entry_manager=self.entry_manager,
        )

    def show_export_dialog(self):
        """Open the Export dialog (Ctrl+E / File → Экспорт)."""
        if not self._require_encryption_key("show_export_dialog"):
            return
        exporter = self._get_exporter()
        if exporter is None:
            messagebox.showerror("Ошибка", "Экспорт недоступен: войдите в систему")
            return

        # Debug: проверяем мастер-пароль
        print(f"[DEBUG] show_export_dialog: master_password установлен = {bool(self.master_password)}")

        # Collect currently selected entry IDs from the tree
        selected_ids = []
        for iid in self.tree.selection():
            eid = iid if iid in self._entry_id_map.values() else \
                self._entry_id_map.get(
                    (self.tree.item(iid).get("values") or [""])[0], iid
                )
            selected_ids.append(eid)

        try:
            from src.gui.dialogs.export_dialog import ExportDialog
            ExportDialog(
                parent=self.root,
                entry_manager=self.entry_manager,
                exporter=exporter,
                selected_ids=selected_ids,
                master_password=self.master_password,
            )
        except Exception as exc:
            messagebox.showerror("Ошибка экспорта", str(exc))

    def show_import_dialog(self):
        """Open the Import dialog (Ctrl+I / File → Импорт)."""
        if not self._require_encryption_key("show_import_dialog"):
            return
        importer = self._get_importer()
        if importer is None:
            messagebox.showerror("Ошибка", "Импорт недоступен: войдите в систему")
            return
        
        # Debug: проверяем мастер-пароль
        print(f"[DEBUG] show_import_dialog: master_password установлен = {bool(self.master_password)}")
        
        try:
            from src.gui.dialogs.import_dialog import ImportDialog
            dlg = ImportDialog(
                parent=self.root,
                importer=importer,
                entry_manager=self.entry_manager,
                master_password=self.master_password,
            )
            # Refresh the entry list after the dialog closes
            self.root.wait_window(dlg.dialog)
            self.refresh_entries()
        except Exception as exc:
            messagebox.showerror("Ошибка импорта", str(exc))

    def show_sharing_dialog(self, entry_id: str):
        """Open the Sharing dialog for *entry_id*."""
        if not self._require_encryption_key("show_sharing_dialog"):
            return
        sharing_service = self._get_sharing_service()
        if sharing_service is None:
            messagebox.showerror("Ошибка", "Шаринг недоступен: войдите в систему")
            return
        try:
            entry = self.entry_manager.get_entry(entry_id)
            title = entry.get("title", "") if entry else ""
            from src.gui.sharing_dialog import SharingDialog
            SharingDialog(
                parent=self.root,
                sharing_service=sharing_service,
                entry_id=entry_id,
                entry_title=title,
                db_connection=self.db.connection if self.db else None,
            )
        except Exception as exc:
            messagebox.showerror("Ошибка шаринга", str(exc))

    def export_to_file(self, format_type: str, password: str, file_path: str):
        """Programmatic export — called from tests or automation.

        Args:
            format_type: One of ``"json"``, ``"csv"``, ``"bitwarden"``,
                ``"lastpass"``.
            password: Export encryption password (JSON only).
            file_path: Destination file path string.

        Returns:
            :class:`ExportResult` on success, or None on failure.
        """
        if not self._require_encryption_key("export_to_file"):
            return None
        exporter = self._get_exporter()
        if exporter is None:
            messagebox.showerror("Ошибка", "Экспорт недоступен")
            return None
        try:
            result = exporter.export_vault(
                entry_ids=None,
                password=password,
                public_key=None,
                format=format_type,
                file_path=Path(file_path),
            )
            messagebox.showinfo(
                "Экспорт завершён",
                f"Экспортировано: {result.entry_count} записей\nФайл: {result.file_path}",
            )
            return result
        except Exception as exc:
            messagebox.showerror("Ошибка экспорта", str(exc))
            return None

    def import_from_file(
        self,
        file_path: str,
        conflict: str = "skip",
        dry_run: bool = False,
    ):
        """Programmatic import — called from tests or automation.

        Args:
            file_path: Path to the import file.
            conflict: Conflict resolution strategy
                (``"skip"``, ``"replace"``, ``"rename"``, ``"merge"``).
            dry_run: When True, validate only without committing changes.

        Returns:
            :class:`ImportResult` on success, or None on failure.
        """
        if not self._require_encryption_key("import_from_file"):
            return None
        importer = self._get_importer()
        if importer is None:
            messagebox.showerror("Ошибка", "Импорт недоступен")
            return None
        try:
            from pathlib import Path as _Path
            p = _Path(file_path)
            ext = p.suffix.lower()

            if dry_run:
                result = importer.validate_import_file(
                    p, "json" if ext == ".json" else "csv"
                )
                messagebox.showinfo(
                    "Предпросмотр импорта",
                    f"Записей: {result.get('entry_count', '?')}\n"
                    f"Ошибок: {len(result.get('errors', []))}",
                )
                return result

            if ext == ".json":
                result = importer.import_json(p, password=None, conflict_strategy=conflict)
            else:
                result = importer.import_csv(p, conflict_strategy=conflict)

            self.refresh_entries()
            messagebox.showinfo(
                "Импорт завершён",
                f"Импортировано: {result.successful_imports} / {result.total_entries}",
            )
            return result
        except Exception as exc:
            messagebox.showerror("Ошибка импорта", str(exc))
            return None

    def share_entry(
        self,
        entry_id: str,
        recipient: str,
        expires_in: int = 7,
        permissions: dict = None,
    ):
        """Programmatic share — called from tests or automation.

        Args:
            entry_id: Vault entry ID to share.
            recipient: Recipient identifier string.
            expires_in: Days until the share expires (1–30).
            permissions: Dict with ``read_only`` key (default True).

        Returns:
            Share result dict on success, or None on failure.
        """
        if not self._require_encryption_key("share_entry"):
            return None
        sharing_service = self._get_sharing_service()
        if sharing_service is None:
            messagebox.showerror("Ошибка", "Шаринг недоступен")
            return None
        try:
            from src.core.import_export.models import EncryptionMethod
            perms = permissions or {"read_only": True}
            result = sharing_service.share_entry(
                entry_id=entry_id,
                recipient=recipient,
                permissions=perms,
                expires_in_days=expires_in,
                encryption_method=EncryptionMethod.PASSWORD,
                password="shared",   # caller should supply a real password
            )
            messagebox.showinfo(
                "Шаринг создан",
                f"Share ID: {result['share_id']}\nИстекает: {result['expires_at']}",
            )
            return result
        except Exception as exc:
            messagebox.showerror("Ошибка шаринга", str(exc))
            return None

    def _set_import_export_menu_state(self, state: str) -> None:
        """Enable or disable the Import/Export menu items (UI-1, UI-2).

        Called after vault unlock / lock events.

        Args:
            state: ``tk.NORMAL`` or ``tk.DISABLED``.
        """
        try:
            # The Export item is at index 5, Import at index 6 in the File menu
            # (after New, Open, Backup, Restore, separator, Export, Import, separator, Quit)
            self._file_menu.entryconfigure("Экспорт...", state=state)
            self._file_menu.entryconfigure("Импорт...", state=state)
        except Exception:
            pass  # Menu may not be initialised yet

    def _on_user_logged_out(self, _data=None) -> None:
        """Handle vault lock — disable import/export menu items."""
        self._set_import_export_menu_state(tk.DISABLED)
        for item in self.tree.get_children():
            self.tree.delete(item)
        self._entry_id_map.clear()
        self._display_order_ids.clear()
        self.status_var.set("Сейф заблокирован")

    # ------------------------------------------------------------------
    # Sprint 7: Security Hardening — ActivityMonitor, AutoLock, PanicMode
    # ------------------------------------------------------------------

    def _init_security(self) -> None:
        """Initialise Sprint 7 security services after successful login.

        Called from the login dialog after the master password is verified.
        All imports are lazy so the security module is only loaded when
        the vault is actually unlocked.
        """
        try:
            from src.core.security.auto_lock import AutoLockService
            from src.core.security.activity_monitor import ActivityMonitor
            from src.core.security.panic_mode import PanicMode

            # ---- ActivityMonitor ----
            self._activity_monitor = ActivityMonitor()
            self._activity_monitor.register_activity_callback(
                self._on_security_activity
            )

            # ---- AutoLockService ----
            self._auto_lock = AutoLockService(
                self._activity_monitor,
                clipboard_service=self.clipboard_service,
                audit_logger=self.audit_logger,
            )
            self._auto_lock.register_lock_callback(self._on_auto_lock)
            self._auto_lock.register_unlock_callback(self._on_auto_unlock)

            # Apply timeout from settings (seconds); default 300 s = 5 min
            try:
                timeout_raw = self.settings_adapter.get("auto_lock_timeout")
                if timeout_raw:
                    self._auto_lock.set_lock_timeout(int(timeout_raw))
            except Exception:
                pass

            self._auto_lock.start()

            # ---- PanicMode ----
            # Config for PanicMode (stealth mode)
            panic_config = {}
            try:
                stealth_cfg = self.settings_adapter.get("stealth_mode", False)
                if isinstance(stealth_cfg, str):
                    stealth_on = stealth_cfg.strip().lower() in ("1", "true", "yes", "on")
                else:
                    stealth_on = bool(stealth_cfg)
                panic_config["stealth_mode"] = stealth_on
            except Exception:
                panic_config["stealth_mode"] = False

            self._panic_mode = PanicMode(
                clipboard_service=self.clipboard_service,
                audit_logger=self.audit_logger,
                config=panic_config,
            )
            self._panic_mode.register_panic_callback(self._on_panic_activated)
            self._panic_mode.register_recovery_callback(self._on_panic_recovered)
            # Register Ctrl+Shift+Esc hotkey (best-effort; requires `keyboard` lib)
            self._panic_mode.register_hotkey("ctrl+shift+esc")

            # Bind Tkinter-level fallback for panic (works without `keyboard` lib)
            self.root.bind_all("<Control-Shift-Escape>", self._on_panic_hotkey)

            # Start the idle-time polling loop (every 10 s)
            self._security_tick_id = None
            self._start_security_tick()

            self.logger_print("[Security] Sprint 7 security services initialised")

        except Exception as exc:
            self.logger_print(f"[Security] Could not initialise security services: {exc}")

    # ---- helpers ----

    def logger_print(self, msg: str) -> None:
        """Thin wrapper so security code can log without importing logging."""
        print(msg)

    def _start_security_tick(self) -> None:
        """Schedule a recurring idle-time check every 10 seconds."""
        self._security_tick()

    def _security_tick(self) -> None:
        """Periodic callback: update status bar with idle time."""
        try:
            if hasattr(self, "_activity_monitor") and self._activity_monitor:
                idle = self._activity_monitor.get_idle_time()
                idle_str = self._activity_monitor.get_idle_time_formatted()
                locked = (
                    hasattr(self, "_auto_lock")
                    and self._auto_lock is not None
                    and self._auto_lock.is_locked()
                )
                if not locked:
                    # Show idle time in status bar only when vault is open
                    if self.is_vault_unlocked():
                        self.status_var.set(
                            f"Бездействие: {idle_str}  |  "
                            + self.status_var.get().split("|")[-1].strip()
                            if "|" in self.status_var.get()
                            else f"Бездействие: {idle_str}"
                        )
        except Exception:
            pass
        finally:
            # Reschedule
            self._security_tick_id = self.root.after(10_000, self._security_tick)

    def _stop_security_tick(self) -> None:
        """Cancel the periodic security tick."""
        if hasattr(self, "_security_tick_id") and self._security_tick_id:
            self.root.after_cancel(self._security_tick_id)
            self._security_tick_id = None

    # ---- event handlers ----

    def _on_security_activity(self, event) -> None:
        """Called by ActivityMonitor whenever user input is detected."""
        # If the vault is locked and user interacts, prompt for unlock
        if (
            hasattr(self, "_auto_lock")
            and self._auto_lock is not None
            and self._auto_lock.is_locked()
        ):
            self.root.after(0, self._prompt_unlock_after_activity)

    def _on_auto_lock(self) -> None:
        """Called by AutoLockService when the idle timeout fires."""
        self.root.after(0, self._apply_lock_ui)

    def _on_auto_unlock(self) -> None:
        """Called by AutoLockService after a successful unlock."""
        self.root.after(0, self._apply_unlock_ui)

    def _on_panic_activated(self) -> None:
        """Called by PanicMode when panic is triggered."""
        self.root.after(0, self._apply_panic_ui)

    def _on_panic_recovered(self) -> None:
        """Called by PanicMode after recovery."""
        self.root.after(0, self._apply_unlock_ui)

    def _on_panic_hotkey(self, _event=None) -> None:
        """Tkinter-level Ctrl+Shift+Esc handler (fallback for no `keyboard` lib)."""
        if hasattr(self, "_panic_mode") and self._panic_mode:
            self._panic_mode.activate()
        else:
            # Panic mode not initialised — just lock
            self._apply_lock_ui()

    # ---- UI state changes ----

    def _apply_lock_ui(self) -> None:
        """Lock the vault and show the security overlay."""
        # Lock via auth service
        if self.auth_service:
            try:
                self.auth_service.logout()
            except Exception:
                pass
        
        # ВАЖНО: Сбрасываем мастер-пароль при блокировке
        self.master_password = None
        print(f"[DEBUG] Мастер-пароль сброшен при блокировке")

        # Clear clipboard
        if self.clipboard_service:
            try:
                self.clipboard_service.on_vault_lock()
            except Exception:
                pass

        # Clear the entry list
        for item in self.tree.get_children():
            self.tree.delete(item)
        self._entry_id_map.clear()
        self._display_order_ids.clear()

        # Disable import/export menu
        self._set_import_export_menu_state(tk.DISABLED)

        # Show lock overlay
        self._show_lock_overlay()

        self.status_var.set("🔒 Сейф заблокирован (автоблокировка)")
        self.toast.show("Сейф заблокирован автоматически", "warning")

    def _apply_unlock_ui(self) -> None:
        """Restore UI after unlock."""
        self._hide_lock_overlay()
        self._set_import_export_menu_state(tk.NORMAL)
        self.status_var.set("Сейф разблокирован")
        self.refresh_entries()

    def _apply_panic_ui(self) -> None:
        """Immediate UI response to panic mode activation."""
        # Hide all top-level windows
        for widget in self.root.winfo_children():
            if isinstance(widget, tk.Toplevel):
                try:
                    widget.destroy()
                except Exception:
                    pass

        self._apply_lock_ui()
        self.status_var.set("🚨 Паника — сейф заблокирован")

    # ---- lock overlay ----

    def _show_lock_overlay(self) -> None:
        """Display a full-window overlay that blocks access while locked."""
        if hasattr(self, "_lock_overlay") and self._lock_overlay:
            return  # Already shown

        overlay = tk.Toplevel(self.root)
        overlay.title("CryptoSafe — Заблокировано")
        overlay.attributes("-topmost", True)
        overlay.resizable(False, False)
        overlay.protocol("WM_DELETE_WINDOW", lambda: None)  # Prevent close

        # Size and position to cover the main window
        self.root.update_idletasks()
        x = self.root.winfo_x()
        y = self.root.winfo_y()
        w = self.root.winfo_width()
        h = self.root.winfo_height()
        overlay.geometry(f"{w}x{h}+{x}+{y}")

        # Content
        frame = ttk.Frame(overlay, padding=40)
        frame.pack(expand=True)

        ttk.Label(
            frame,
            text="🔒",
            font=("Arial", 64),
        ).pack(pady=(0, 16))

        ttk.Label(
            frame,
            text="CryptoSafe заблокирован",
            font=("Arial", 18, "bold"),
        ).pack()

        ttk.Label(
            frame,
            text="Введите мастер-пароль для продолжения",
            font=("Arial", 11),
            foreground="#555",
        ).pack(pady=(8, 24))

        from src.gui.widgets.password_entry import PasswordEntry
        pwd_entry = PasswordEntry(frame, show_generator=False)
        pwd_entry.pack(fill=tk.X, pady=(0, 12))
        pwd_entry.focus()

        status_var = tk.StringVar()
        ttk.Label(frame, textvariable=status_var, foreground="red").pack()

        def do_unlock(_event=None):
            pwd = pwd_entry.get()
            if not pwd:
                status_var.set("Введите пароль")
                return
            if self.auth_service and self.auth_service.login(pwd):
                # ВАЖНО: Сохраняем мастер-пароль после успешной разблокировки
                self.master_password = pwd
                print(f"[DEBUG] Мастер-пароль установлен после разблокировки: {bool(self.master_password)}")
                
                pwd_entry.clear()
                self._hide_lock_overlay()
                # Re-init audit logger with fresh password
                self._init_audit_logger(pwd)
                # Reset auto-lock timer
                if hasattr(self, "_auto_lock") and self._auto_lock:
                    self._auto_lock.unlock(pwd)
                self._apply_unlock_ui()
            else:
                pwd_entry.clear()
                status_var.set("Неверный пароль")

        pwd_entry.entry.bind("<Return>", do_unlock)
        ttk.Button(frame, text="Разблокировать", command=do_unlock).pack(pady=(8, 0))

        self._lock_overlay = overlay

    def _hide_lock_overlay(self) -> None:
        """Remove the lock overlay."""
        if hasattr(self, "_lock_overlay") and self._lock_overlay:
            try:
                self._lock_overlay.destroy()
            except Exception:
                pass
            self._lock_overlay = None

    def _prompt_unlock_after_activity(self) -> None:
        """If locked and user is active, bring the overlay to front."""
        if hasattr(self, "_lock_overlay") and self._lock_overlay:
            try:
                self._lock_overlay.lift()
                self._lock_overlay.focus_force()
            except Exception:
                pass

    # ---- public API ----

    def lock_vault(self) -> None:
        """Manually lock the vault (e.g. from menu or tray)."""
        if hasattr(self, "_auto_lock") and self._auto_lock:
            self._auto_lock.lock("manual")
        else:
            self._apply_lock_ui()

    def set_auto_lock_timeout(self, seconds: int) -> None:
        """Change the auto-lock idle timeout at runtime.

        Args:
            seconds: Idle seconds before auto-lock (60–28800).
        """
        if hasattr(self, "_auto_lock") and self._auto_lock:
            self._auto_lock.set_lock_timeout(seconds)

    def _shutdown_security(self) -> None:
        """Stop all Sprint 7 security services on application exit."""
        self._stop_security_tick()

        if hasattr(self, "_panic_mode") and self._panic_mode:
            try:
                self._panic_mode.unregister_hotkey()
            except Exception:
                pass

        if hasattr(self, "_auto_lock") and self._auto_lock:
            try:
                self._auto_lock.stop()
            except Exception:
                pass

        if hasattr(self, "_activity_monitor") and self._activity_monitor:
            try:
                self._activity_monitor.stop()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Sprint 7: System Tray (TRAY-1 … TRAY-4)
    # ------------------------------------------------------------------

    def _init_system_tray(self) -> None:
        """Create and start the system tray icon.

        Called once from ``setup_ui`` so the tray is available even before
        the user logs in.  The icon reflects the locked state at all times.
        """
        try:
            from src.gui.system_tray import SystemTray

            self._system_tray = SystemTray(
                root=self.root,
                on_show=self._tray_show_window,
                on_lock=self.lock_vault,
                on_unlock=self._tray_unlock,
                on_quick_search=self._tray_quick_search,
                on_settings=self.show_settings,
                on_clear_clipboard=self._clear_clipboard_from_tray,
                on_panic_mode=self._panic_mode_from_tray,
                on_exit=self.on_closing,
            )
            self._system_tray.start()

            # Minimise to tray instead of closing
            self.root.protocol("WM_DELETE_WINDOW", self.hide_to_tray)

        except Exception as exc:
            print(f"[SystemTray] Could not initialise: {exc}")

    def _on_window_close(self) -> None:
        """Intercept the window close button — minimise to tray if available."""
        if self._system_tray and self._system_tray.is_available():
            self.root.withdraw()  # Hide window, keep running in tray
            if self._system_tray:
                self._system_tray.show_notification(
                    "CryptoSafe",
                    "Приложение свёрнуто в трей. Нажмите на иконку для восстановления.",
                )
        else:
            self.on_closing()

    def _tray_show_window(self) -> None:
        """Restore the main window from the tray."""
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()

    def _tray_unlock(self) -> None:
        """Show the login dialog from the tray."""
        self._tray_show_window()
        if not self.is_vault_unlocked():
            self.show_login_dialog()

    def _tray_quick_search(self) -> None:
        """Open a quick-search popup from the tray."""
        self._tray_show_window()
        # Reuse the existing search bar — just focus it
        try:
            self.search_var.set("")
            # Find the search Entry widget and focus it
            for widget in self.root.winfo_children():
                if isinstance(widget, ttk.Frame):
                    for child in widget.winfo_children():
                        if isinstance(child, ttk.Entry):
                            child.focus_set()
                            break
        except Exception:
            pass

    def _clear_clipboard_from_tray(self):
        """Очистить буфер из трея"""
        if self.clipboard_service:
            self.clipboard_service.clear_clipboard("tray")

    def _panic_mode_from_tray(self):
        """Активировать Panic Mode из трея"""
        if self._panic_mode:
            self._panic_mode.activate("tray")

    def _update_tray_lock_state(self, locked: bool) -> None:
        """Sync the tray icon with the current lock state."""
        if self._system_tray:
            try:
                self._system_tray.set_locked(locked)
            except Exception:
                pass
