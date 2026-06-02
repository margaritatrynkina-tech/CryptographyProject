from __future__ import annotations

import threading
import tkinter as tk 
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any, Callable, Dict, List, Optional


_FORMATS = [
    ("Encrypted JSON (.json)", "json"),
    ("CSV — metadata only (.csv)", "csv"),
    ("Bitwarden JSON (.json)", "bitwarden"),
    ("LastPass CSV (.csv)", "lastpass"),  
]

_EXTENSIONS = {
    "json": [("JSON files", "*.json"), ("All files", "*.*")],
    "csv": [("CSV files", "*.csv"), ("All files", "*.*")],
    "bitwarden": [("JSON files", "*.json"), ("All files", "*.*")],
    "lastpass": [("CSV files", "*.csv"), ("All files", "*.*")],
}


class ExportDialog:
    def __init__(
        self,
        parent: tk.Widget,
        entry_manager,
        exporter,
        selected_ids: Optional[List[str]] = None,
        master_password: Optional[str] = None,
    ) -> None:
        self.parent = parent
        self.entry_manager = entry_manager
        self.exporter = exporter
        self.selected_ids = selected_ids or []
        self.master_password = master_password
        
        # Debug: проверяем получение мастер-пароля
        print(f"[DEBUG] ExportDialog.__init__: master_password получен = {bool(master_password)}")

        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Экспорт записей")
        self.dialog.geometry("520x520")
        self.dialog.resizable(False, False)
        self.dialog.transient(parent)
        self.dialog.grab_set()

        self._build_ui()
        self._update_preview()

    def _build_ui(self) -> None:
        pad = {"padx": 16, "pady": 6}

        # --- Format ---
        fmt_frame = ttk.LabelFrame(self.dialog, text="Формат экспорта", padding=8)
        fmt_frame.pack(fill=tk.X, **pad)

        self._fmt_var = tk.StringVar(value="json")
        for label, value in _FORMATS:
            ttk.Radiobutton(
                fmt_frame, text=label, variable=self._fmt_var, value=value,
                command=self._on_format_change,
            ).pack(anchor=tk.W)

        # --- Password (JSON and LastPass) ---
        self._pwd_frame = ttk.LabelFrame(self.dialog, text="Пароль шифрования", padding=8)
        self._pwd_frame.pack(fill=tk.X, **pad)
        self._pwd_var = tk.StringVar()
        ttk.Entry(self._pwd_frame, textvariable=self._pwd_var, show="*", width=36).pack(anchor=tk.W)

        # --- Compression options (JSON only) ---
        self._opts_frame = ttk.LabelFrame(self.dialog, text="Опции (только JSON)", padding=8)
        self._opts_frame.pack(fill=tk.X, **pad)

        self._gzip_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            self._opts_frame, text="GZIP-сжатие", variable=self._gzip_var,
        ).pack(anchor=tk.W)

        # --- Entry selection ---
        sel_frame = ttk.LabelFrame(self.dialog, text="Записи", padding=8)
        sel_frame.pack(fill=tk.X, **pad)

        self._sel_var = tk.StringVar(value="all")
        ttk.Radiobutton(
            sel_frame, text="Все записи", variable=self._sel_var,
            value="all", command=self._update_preview,
        ).pack(anchor=tk.W)
        ttk.Radiobutton(
            sel_frame, text=f"Выбранные ({len(self.selected_ids)})",
            variable=self._sel_var,
            value="selected", command=self._update_preview,
            state=tk.NORMAL if self.selected_ids else tk.DISABLED,
        ).pack(anchor=tk.W)

        # --- Preview ---
        prev_frame = ttk.LabelFrame(self.dialog, text="Предварительный просмотр", padding=8)
        prev_frame.pack(fill=tk.X, **pad)

        self._preview_var = tk.StringVar(value="")
        ttk.Label(prev_frame, textvariable=self._preview_var, foreground="#555").pack(anchor=tk.W)

        # --- Progress ---
        self._progress = ttk.Progressbar(self.dialog, mode="indeterminate")
        self._progress.pack(fill=tk.X, padx=16, pady=(0, 4))

        self._status_var = tk.StringVar(value="")
        ttk.Label(self.dialog, textvariable=self._status_var, foreground="#333").pack()

        # --- Buttons ---
        btn_frame = ttk.Frame(self.dialog)
        btn_frame.pack(fill=tk.X, padx=16, pady=10)
        ttk.Button(btn_frame, text="Отмена", command=self.dialog.destroy).pack(side=tk.RIGHT, padx=4)
        self._export_btn = ttk.Button(btn_frame, text="Экспортировать", command=self._do_export)
        self._export_btn.pack(side=tk.RIGHT)

    def _on_format_change(self) -> None:
        fmt = self._fmt_var.get()
        
        # Показываем/скрываем поле пароля для JSON и LastPass
        pwd_state = tk.NORMAL if fmt in ("json", "lastpass") else tk.DISABLED
        for child in self._pwd_frame.winfo_children():
            try:
                child.configure(state=pwd_state)
            except tk.TclError:
                pass
        
        # Показываем/скрываем опции сжатия только для JSON
        opts_state = tk.NORMAL if fmt == "json" else tk.DISABLED
        for child in self._opts_frame.winfo_children():
            try:
                child.configure(state=opts_state)
            except tk.TclError:
                pass
        
        self._update_preview()

    def _update_preview(self) -> None:
        try:
            if self._sel_var.get() == "selected" and self.selected_ids:
                count = len(self.selected_ids)
            else:
                entries = self.entry_manager.get_all_entries()
                count = len(entries)
            fmt = self._fmt_var.get()
            est_kb = count * (2 if fmt == "json" else 0.5)
            self._preview_var.set(
                f"Записей: {count}   |   Примерный размер: {est_kb:.0f} КБ"
            )
        except Exception:
            self._preview_var.set("Не удалось получить данные")

    def _do_export(self) -> None:
        fmt = self._fmt_var.get()
        
        # Debug: проверяем мастер-пароль перед экспортом
        print(f"[DEBUG] _do_export: self.master_password установлен = {bool(self.master_password)}")
        
        # Всегда проверяем мастер-пароль
        if not self.master_password:
            messagebox.showerror("Ошибка", "Мастер-пароль не установлен", parent=self.dialog)
            return

        # Для JSON и LastPass используем пароль из поля в диалоге
        export_password = None
        if fmt in ("json", "lastpass"):
            export_password = self._pwd_var.get() or None
            print(f"[DEBUG] Пароль экспорта для формата {fmt}: {bool(export_password)}")
            
            if not export_password:
                messagebox.showwarning(
                    "Отмена",
                    "Экспорт отменён: необходим пароль для шифрования",
                    parent=self.dialog,
                )
                return

        ext_list = _EXTENSIONS.get(fmt, [("All files", "*.*")])
        file_path = filedialog.asksaveasfilename(
            parent=self.dialog,
            filetypes=ext_list,
            defaultextension=ext_list[0][1].lstrip("*"),
            title="Сохранить экспорт как",
        )
        if not file_path:
            return

        entry_ids = self.selected_ids if self._sel_var.get() == "selected" else None
        opts: Dict[str, Any] = {
            "compression": self._gzip_var.get(),
        }

        self._export_btn.configure(state=tk.DISABLED)
        self._progress.start(10)
        self._status_var.set("Экспорт…")

        def run() -> None:
            try:
                result = self.exporter.export_vault(
                    entry_ids=entry_ids,
                    master_password=self.master_password,
                    export_password=export_password,
                    public_key=None,
                    format=fmt,
                    file_path=Path(file_path),
                    export_options=opts,
                )
                self.dialog.after(0, lambda: self._on_success(result))
            except Exception as exc:
                self.dialog.after(0, lambda: self._on_error(str(exc)))

        threading.Thread(target=run, daemon=True).start()

    def _on_success(self, result) -> None:
        self._progress.stop()
        self._export_btn.configure(state=tk.NORMAL)
        self._status_var.set("")
        messagebox.showinfo(
            "Экспорт завершён",
            f"Экспортировано записей: {result.entry_count}\n"
            f"Файл: {result.file_path}\n"
            f"SHA-256: {result.checksum[:16]}…",
            parent=self.dialog,
        )
        self.dialog.destroy()

    def _on_error(self, message: str) -> None:
        self._progress.stop()
        self._export_btn.configure(state=tk.NORMAL)
        self._status_var.set("")
        messagebox.showerror("Ошибка экспорта", message, parent=self.dialog)
