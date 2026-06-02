from __future__ import annotations

import os
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any, Dict, List, Optional


_FORMAT_EXTENSIONS = {
    ".json": "json",
    ".csv": "csv",
}

_FORMAT_LABELS = {
    "json": "CryptoSafe JSON (зашифрован)",
    "bitwarden": "Bitwarden JSON",
    "lastpass": "LastPass CSV",
    "csv": "CSV",
}

_CONFLICT_OPTIONS = [
    ("Пропустить (оставить существующую)", "skip"),
    ("Заменить (перезаписать существующую)", "replace"),
    ("Переименовать (добавить суффикс)", "rename"),
    ("Объединить (merge полей)", "merge"),
]


def _detect_format(file_path: str) -> str:
    path = Path(file_path)
    ext = path.suffix.lower()

    if ext == ".json":
        try:
            snippet = path.read_text(encoding="utf-8", errors="replace")[:2048]
            
            # First try to parse as JSON to check for cryptosafe_export flag
            import json as _json
            try:
                # Try to parse the snippet as JSON
                if not snippet.strip().endswith("}"):
                    # Try to complete the JSON if it's truncated
                    snippet_to_parse = snippet + "}"
                else:
                    snippet_to_parse = snippet
                
                data = _json.loads(snippet_to_parse)
                if isinstance(data, dict) and data.get("cryptosafe_export") is True:
                    return "json"
            except _json.JSONDecodeError:
                # If we can't parse as JSON, fall back to string detection
                pass
            
            # String-based detection for CryptoSafe JSON
            if '"cryptosafe_export": true' in snippet or "'cryptosafe_export': True" in snippet:
                return "json"
            
            # Bitwarden has "items" array and no cryptosafe flag
            if '"items"' in snippet and '"cryptosafe_export"' not in snippet:
                return "bitwarden"
                
            # Default to CryptoSafe JSON for .json files
            return "json"
        except OSError:
            pass
        return "json"  # default for .json

    if ext == ".csv":
        try:
            # Read first few lines to detect format
            content = path.read_text(encoding="utf-8", errors="replace")
            first_line = content.split("\n")[0].lower()
            
            print(f"[DEBUG] CSV первая строка: {first_line[:100]}")
            
            # Check if it starts with "ENCRYPTED:" marker
            if content.strip().startswith("ENCRYPTED:"):
                print("[DEBUG] Обнаружен зашифрованный LastPass CSV")
                return "lastpass"
            
            # LastPass CSV has specific columns
            # Check for LastPass-specific columns: grouping, extra, fav
            if "grouping" in first_line or "extra" in first_line or "fav" in first_line:
                print("[DEBUG] Обнаружен LastPass CSV по колонкам")
                return "lastpass"
            
            # Also check for typical LastPass column combination
            if "url" in first_line and "username" in first_line and "password" in first_line and "name" in first_line:
                # If it has name instead of title, it's likely LastPass
                if "name" in first_line and "title" not in first_line:
                    print("[DEBUG] Обнаружен LastPass CSV по комбинации колонок")
                    return "lastpass"
            
            print("[DEBUG] CSV определён как обычный CSV")
        except OSError as e:
            print(f"[DEBUG] Ошибка чтения CSV: {e}")
            pass
        return "csv"

    return "json"


class ImportDialog:

    def __init__(self, parent: tk.Widget, importer, entry_manager, master_password: Optional[str] = None) -> None:
        self.parent = parent
        self.importer = importer
        self.entry_manager = entry_manager
        self.master_password = master_password
        
        # Debug: проверяем получение мастер-пароля
        print(f"[DEBUG] ImportDialog.__init__: master_password получен = {bool(master_password)}")

        self._file_path: Optional[str] = None
        self._detected_format: Optional[str] = None
        self._preview_entries: List[Dict[str, Any]] = []

        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Импорт записей")
        self.dialog.geometry("750x700")
        self.dialog.resizable(True, True)
        self.dialog.transient(parent)
        self.dialog.grab_set()

        self._build_ui()

    def _build_ui(self) -> None:
        pad = {"padx": 14, "pady": 5}

        # --- File selection ---
        file_frame = ttk.LabelFrame(self.dialog, text="Файл импорта", padding=8)
        file_frame.pack(fill=tk.X, **pad)

        self._path_var = tk.StringVar()
        path_entry = ttk.Entry(file_frame, textvariable=self._path_var, state="readonly", width=48)
        path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(file_frame, text="Обзор…", command=self._browse_file).pack(side=tk.LEFT, padx=(6, 0))

        self._fmt_var = tk.StringVar(value="")
        self._fmt_label = ttk.Label(file_frame, textvariable=self._fmt_var, foreground="#555")
        self._fmt_label.pack(side=tk.LEFT, padx=(8, 0))

        # --- Password (JSON and LastPass) ---
        pwd_frame = ttk.LabelFrame(self.dialog, text="Пароль расшифровки ", padding=8)
        pwd_frame.pack(fill=tk.X, **pad)
        self._pwd_var = tk.StringVar()
        ttk.Entry(pwd_frame, textvariable=self._pwd_var, show="*", width=36).pack(anchor=tk.W)

        # --- Conflict resolution ---
        conf_frame = ttk.LabelFrame(self.dialog, text="Разрешение конфликтов", padding=8)
        conf_frame.pack(fill=tk.X, **pad)

        self._conflict_var = tk.StringVar(value="skip")
        for label, value in _CONFLICT_OPTIONS:
            ttk.Radiobutton(
                conf_frame, text=label, variable=self._conflict_var, value=value,
            ).pack(anchor=tk.W)

        # --- Preview table ---
        prev_frame = ttk.LabelFrame(self.dialog, text="Предварительный просмотр", padding=8)
        prev_frame.pack(fill=tk.BOTH, expand=True, **pad)

        cols = ("title", "username", "url", "status")
        self._tree = ttk.Treeview(prev_frame, columns=cols, show="headings", height=7)
        self._tree.heading("title", text="Название")
        self._tree.heading("username", text="Пользователь")
        self._tree.heading("url", text="URL")
        self._tree.heading("status", text="Статус")
        self._tree.column("title", width=160)
        self._tree.column("username", width=120)
        self._tree.column("url", width=140)
        self._tree.column("status", width=80, anchor="center")

        vsb = ttk.Scrollbar(prev_frame, orient=tk.VERTICAL, command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        self._tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        # --- Summary ---
        self._summary_var = tk.StringVar(value="Выберите файл для предварительного просмотра")
        ttk.Label(self.dialog, textvariable=self._summary_var, foreground="#333").pack(**pad)

        # --- Progress ---
        self._progress = ttk.Progressbar(self.dialog, mode="indeterminate")
        self._progress.pack(fill=tk.X, padx=14, pady=(0, 4))

        self._status_var = tk.StringVar(value="")
        ttk.Label(self.dialog, textvariable=self._status_var, foreground="#555").pack()

        # --- Buttons ---
        btn_frame = ttk.Frame(self.dialog)
        btn_frame.pack(fill=tk.X, padx=14, pady=8)
        ttk.Button(btn_frame, text="Отмена", command=self.dialog.destroy).pack(side=tk.RIGHT, padx=4)
        self._import_btn = ttk.Button(
            btn_frame, text="Импортировать", command=self._do_import, state=tk.DISABLED
        )
        self._import_btn.pack(side=tk.RIGHT)
        ttk.Button(btn_frame, text="Предпросмотр", command=self._do_preview).pack(side=tk.RIGHT, padx=4)

    def _browse_file(self) -> None:
        path = filedialog.askopenfilename(
            parent=self.dialog,
            filetypes=[
                ("Supported files", "*.json *.csv"),
                ("JSON files", "*.json"),
                ("CSV files", "*.csv"),
                ("All files", "*.*"),
            ],
            title="Выберите файл для импорта",
        )
        if not path:
            return
        self._file_path = path
        self._path_var.set(path)

        # Auto-detect format by content, not just extension
        fmt = _detect_format(path)
        self._detected_format = fmt
        print(f"[DEBUG] Определён формат файла: {fmt}")
        self._fmt_var.set(f"Формат: {_FORMAT_LABELS.get(fmt, fmt.upper())}")
        self._import_btn.configure(state=tk.NORMAL)
        self._do_preview()

    def _do_preview(self) -> None:
        if not self._file_path or not self._detected_format:
            return

        self._status_var.set("Загрузка предпросмотра…")
        self._progress.start(10)

        def run() -> None:
            try:
                result = self.importer.validate_import_file(
                    Path(self._file_path), self._detected_format
                )
                self.dialog.after(0, lambda: self._show_preview(result))
            except Exception as exc:
                self.dialog.after(0, lambda: self._preview_error(str(exc)))

        threading.Thread(target=run, daemon=True).start()

    def _show_preview(self, validation: Dict[str, Any]) -> None:
        self._progress.stop()
        self._status_var.set("")

        # Clear tree
        for row in self._tree.get_children():
            self._tree.delete(row)

        errors = validation.get("errors", [])
        warnings = validation.get("warnings", [])
        count = validation.get("entry_count") or 0

        if errors:
            self._summary_var.set(f"⚠ Ошибки валидации: {'; '.join(errors[:2])}")
            self._import_btn.configure(state=tk.DISABLED)
            return

        # Build existing title+username index for conflict detection
        existing: set = set()
        try:
            for e in self.entry_manager.get_all_entries():
                existing.add((e.get("title", "").lower(), e.get("username", "").lower()))
        except Exception:
            pass

        # Load entries for preview
        try:
            fmt = self._detected_format
            if fmt == "json":
                from src.core.import_export.formats.json_handler import JSONHandler
                content = Path(self._file_path).read_text(encoding="utf-8")
                envelope = JSONHandler.parse_envelope(content)
                # Can't decrypt without password — show metadata only
                count = envelope.get("metadata", {}).get("entry_count", 0)
                self._summary_var.set(
                    f"Записей в файле: {count}   |   Предпросмотр недоступен (зашифровано)"
                )
                return
            elif fmt == "csv":
                from src.core.import_export.formats.csv_handler import CSVHandler
                entries, _ = CSVHandler.import_file(self._file_path)
            elif fmt == "bitwarden":
                from src.core.import_export.formats.bitwarden_handler import BitwardenHandler
                entries, _ = BitwardenHandler.import_file(self._file_path)
            elif fmt == "lastpass":
                from src.core.import_export.formats.lastpass_handler import LastPassHandler
                # Check if file is encrypted
                try:
                    content = Path(self._file_path).read_text(encoding="utf-8")
                    if content.strip().startswith("ENCRYPTED:"):
                        print("[DEBUG] LastPass файл зашифрован, предпросмотр недоступен")
                        self._summary_var.set(
                            "🔒 Файл зашифрован   |   Предпросмотр недоступен (введите пароль и нажмите 'Импортировать')"
                        )
                        self._import_btn.configure(state=tk.NORMAL)
                        return
                except Exception as e:
                    print(f"[DEBUG] Ошибка проверки шифрования: {e}")
                    pass
                
                # Незашифрованный файл - показываем preview
                entries, _ = LastPassHandler.import_file(self._file_path)
            else:
                entries = []

            conflicts = 0
            for entry in entries[:200]:  # Show up to 200 rows
                title = entry.get("title", "")
                username = entry.get("username", "")
                url = entry.get("url", "")
                is_conflict = (title.lower(), username.lower()) in existing
                if is_conflict:
                    conflicts += 1
                status = "⚠ конфликт" if is_conflict else "✓ новая"
                tag = "conflict" if is_conflict else ""
                self._tree.insert("", tk.END, values=(title, username, url, status), tags=(tag,))

            self._tree.tag_configure("conflict", foreground="#c0392b")
            warn_str = f"   |   Предупреждений: {len(warnings)}" if warnings else ""
            self._summary_var.set(
                f"Записей: {len(entries)}   |   Конфликтов: {conflicts}{warn_str}"
            )
            self._import_btn.configure(state=tk.NORMAL)

        except Exception as exc:
            print(f"[DEBUG] Ошибка предпросмотра: {exc}")
            self._summary_var.set(f"⚠ Ошибка предпросмотра: {exc}")

    def _preview_error(self, message: str) -> None:
        self._progress.stop()
        self._status_var.set("")
        self._summary_var.set(f" {message}")
        self._import_btn.configure(state=tk.DISABLED)

    def _do_import(self) -> None:
        if not self._file_path or not self._detected_format:
            print("[DEBUG] _do_import: No file or format detected")
            return

        # Всегда проверяем мастер-пароль
        if not self.master_password:
            print("[DEBUG] _do_import: No master password")
            messagebox.showerror("Ошибка", "Мастер-пароль не установлен", parent=self.dialog)
            return

        fmt = self._detected_format
        strategy = self._conflict_var.get()
        
        print(f"[DEBUG] _do_import starting")
        print(f"[DEBUG] Format: {fmt}")
        print(f"[DEBUG] File path: {self._file_path}")
        print(f"[DEBUG] Strategy: {strategy}")

        # Для JSON и LastPass используем пароль из поля в диалоге
        file_password = None
        if fmt in ("json", "lastpass"):
            file_password = self._pwd_var.get() or None
            print(f"[DEBUG] Пароль файла для формата {fmt}: {bool(file_password)}")
            if file_password:
                print(f"[DEBUG] Длина пароля: {len(file_password)} символов")
            
            if not file_password:
                if not messagebox.askyesno(
                    "Пароль не указан",
                    "Пароль не введён. Попробовать импорт без расшифровки?",
                    parent=self.dialog,
                ):
                    print("[DEBUG] User cancelled import due to no password")
                    return

        self._import_btn.configure(state=tk.DISABLED)
        self._progress.start(10)
        self._status_var.set("Импорт…")

        def run() -> None:
            try:
                print(f"[DEBUG] run() thread started for format: {fmt}")
                if fmt == "json":
                    result = self.importer.import_json(
                        Path(self._file_path),
                        master_password=self.master_password,
                        file_password=file_password,
                        conflict_strategy=strategy,
                    )
                elif fmt == "csv":
                    result = self.importer.import_csv(
                        Path(self._file_path),
                        conflict_strategy=strategy,
                    )
                elif fmt == "bitwarden":
                    result = self.importer.import_bitwarden(
                        Path(self._file_path),
                        conflict_strategy=strategy,
                    )
                elif fmt == "lastpass":
                    print("[DEBUG] Calling importer.import_lastpass...")
                    result = self.importer.import_lastpass(
                        Path(self._file_path),
                        master_password=self.master_password,
                        file_password=file_password,
                        conflict_strategy=strategy,
                    )
                    print(f"[DEBUG] import_lastpass completed successfully")
                else:
                    raise ValueError(f"Unknown format: {fmt}")
                
                print(f"[DEBUG] Import completed, scheduling success callback")
                self.dialog.after(0, lambda: self._on_success(result))
            except Exception as exc:
                print(f"[DEBUG] Import failed with exception: {exc}")
                import traceback
                traceback.print_exc()
                self.dialog.after(0, lambda: self._on_error(str(exc)))

        threading.Thread(target=run, daemon=True).start()

    def _on_success(self, result) -> None:
        self._progress.stop()
        self._import_btn.configure(state=tk.NORMAL)
        self._status_var.set("")
        backup_note = "\nРезервная копия создана." if result.backup_created else ""
        messagebox.showinfo(
            "Импорт завершён",
            f"Всего записей: {result.total_entries}\n"
            f"Импортировано: {result.successful_imports}\n"
            f"Ошибок: {result.failed_imports}\n"
            f"Конфликтов: {result.conflict_count}"
            f"{backup_note}",
            parent=self.dialog,
        )
        self.dialog.destroy()

    def _on_error(self, message: str) -> None:
        self._progress.stop()
        self._import_btn.configure(state=tk.NORMAL)
        self._status_var.set("")
        messagebox.showerror("Ошибка импорта", message, parent=self.dialog)
