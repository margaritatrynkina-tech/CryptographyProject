"""Audit log viewer with logs, statistics, and export (GUI-1..3, EXP-4)."""
import json
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
from typing import Any, Callable, Dict, List, Optional


class AuditViewerWindow:
    PAGE_SIZE = 50

    def __init__(
        self,
        parent: tk.Tk,
        audit_logger,
        verify_callback: Callable[[], Dict[str, Any]],
        export_callback: Callable[..., None],
        on_entry_click: Optional[Callable[[str], None]] = None,
        schedule_export_callback: Optional[Callable[[str, str, str], None]] = None,
    ):
        self.parent = parent
        self.audit = audit_logger
        self.verify_callback = verify_callback
        self.export_callback = export_callback
        self.schedule_export_callback = schedule_export_callback
        self.on_entry_click = on_entry_click
        self._offset = 0
        self._rows: List[Dict[str, Any]] = []

        self.win = tk.Toplevel(parent)
        self.win.title("Журнал аудита")
        self.win.geometry("1050x700")
        self._build_ui()
        self.refresh()

    def _build_ui(self) -> None:
        notebook = ttk.Notebook(self.win)
        notebook.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        logs_tab = ttk.Frame(notebook)
        stats_tab = ttk.Frame(notebook)
        notebook.add(logs_tab, text="Журнал")
        notebook.add(stats_tab, text="Статистика")

        self._build_logs_tab(logs_tab)
        self._build_stats_tab(stats_tab)

    def _build_logs_tab(self, parent: ttk.Frame) -> None:
        filter_frame = ttk.Frame(parent)
        filter_frame.pack(fill=tk.X, pady=4)

        ttk.Label(filter_frame, text="Тип:").pack(side=tk.LEFT)
        self.event_type_var = tk.StringVar()
        ttk.Entry(filter_frame, textvariable=self.event_type_var, width=14).pack(side=tk.LEFT, padx=4)

        ttk.Label(filter_frame, text="Severity:").pack(side=tk.LEFT)
        self.severity_var = tk.StringVar()
        ttk.Combobox(
            filter_frame,
            textvariable=self.severity_var,
            values=["", "INFO", "WARN", "ERROR", "CRITICAL"],
            width=10,
        ).pack(side=tk.LEFT, padx=4)

        ttk.Label(filter_frame, text="Поиск:").pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        ttk.Entry(filter_frame, textvariable=self.search_var, width=16).pack(side=tk.LEFT, padx=4)

        ttk.Label(filter_frame, text="От:").pack(side=tk.LEFT, padx=(8, 0))
        self.date_from_var = tk.StringVar()
        ttk.Entry(filter_frame, textvariable=self.date_from_var, width=12).pack(side=tk.LEFT, padx=2)
        ttk.Label(filter_frame, text="До:").pack(side=tk.LEFT)
        self.date_to_var = tk.StringVar()
        ttk.Entry(filter_frame, textvariable=self.date_to_var, width=12).pack(side=tk.LEFT, padx=2)

        ttk.Button(filter_frame, text="Применить", command=self.refresh).pack(side=tk.LEFT, padx=4)
        ttk.Button(filter_frame, text="Целостность", command=self._verify).pack(side=tk.LEFT, padx=2)
        ttk.Button(filter_frame, text="JSON", command=lambda: self._export("json")).pack(side=tk.LEFT, padx=2)
        ttk.Button(filter_frame, text="CSV", command=lambda: self._export("csv")).pack(side=tk.LEFT, padx=2)
        ttk.Button(filter_frame, text="PDF", command=lambda: self._export("pdf")).pack(side=tk.LEFT, padx=2)
        if self.schedule_export_callback:
            ttk.Button(filter_frame, text="Расписание", command=self._schedule_export).pack(side=tk.LEFT, padx=2)

        paned = ttk.PanedWindow(parent, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True, pady=4)

        cols = ("seq", "timestamp", "event_type", "severity", "source", "entry_id")
        self.tree = ttk.Treeview(paned, columns=cols, show="headings", height=14)
        for c, w in zip(cols, (50, 170, 180, 70, 100, 100)):
            self.tree.heading(c, text=c)
            self.tree.column(c, width=w)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        paned.add(self.tree, weight=2)

        detail_frame = ttk.LabelFrame(paned, text="Детали")
        self.detail_text = tk.Text(detail_frame, height=10, wrap=tk.WORD)
        self.detail_text.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        paned.add(detail_frame, weight=1)

        nav = ttk.Frame(parent)
        nav.pack(fill=tk.X, pady=4)
        ttk.Button(nav, text="◀", command=self._prev_page).pack(side=tk.LEFT)
        ttk.Button(nav, text="▶", command=self._next_page).pack(side=tk.LEFT, padx=4)
        self.stats_var = tk.StringVar(value="")
        ttk.Label(nav, textvariable=self.stats_var).pack(side=tk.LEFT, padx=8)

    def _build_stats_tab(self, parent: ttk.Frame) -> None:
        ctrl = ttk.Frame(parent)
        ctrl.pack(fill=tk.X, pady=8)
        ttk.Label(ctrl, text="Период (дней):").pack(side=tk.LEFT)
        self.stats_days_var = tk.StringVar(value="7")
        ttk.Combobox(ctrl, textvariable=self.stats_days_var, values=["7", "30", "90"], width=6).pack(
            side=tk.LEFT, padx=4
        )
        ttk.Button(ctrl, text="Обновить", command=self._refresh_stats).pack(side=tk.LEFT, padx=4)

        self.stats_text = tk.Text(parent, height=8, wrap=tk.WORD)
        self.stats_text.pack(fill=tk.X, padx=8, pady=4)

        self.chart_canvas = tk.Canvas(parent, height=280, bg="white")
        self.chart_canvas.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        self._refresh_stats()

    def _refresh_stats(self) -> None:
        try:
            days = int(self.stats_days_var.get())
        except ValueError:
            days = 7
        stats = self.audit.get_statistics(days)
        self.stats_text.delete("1.0", tk.END)
        self.stats_text.insert(
            tk.END,
            f"Всего событий: {stats['total']}\n"
            f"Неудачные входы: {stats['failed_logins']}\n"
            f"Подозрительные: {stats['suspicious_events']}\n"
            f"Целостность (последняя): "
            f"{(self.audit.last_verify_result or {}).get('verified', 'n/a')}\n",
        )
        self._draw_chart(stats.get("by_event_type", {}))

    def _draw_chart(self, by_type: Dict[str, int]) -> None:
        self.chart_canvas.delete("all")
        if not by_type:
            self.chart_canvas.create_text(200, 100, text="Нет данных", fill="gray")
            return
        items = sorted(by_type.items(), key=lambda x: -x[1])[:12]
        max_val = max(v for _, v in items) or 1
        w = self.chart_canvas.winfo_width() or 800
        bar_w = max(30, (w - 80) // len(items))
        x0 = 40
        for i, (label, val) in enumerate(items):
            h = int(200 * val / max_val)
            x = x0 + i * (bar_w + 8)
            self.chart_canvas.create_rectangle(x, 240 - h, x + bar_w, 240, fill="#1565c0")
            self.chart_canvas.create_text(x + bar_w // 2, 250, text=str(val), font=("Segoe UI", 8))
            short = label[:10] + "…" if len(label) > 10 else label
            self.chart_canvas.create_text(x + bar_w // 2, 265, text=short, font=("Segoe UI", 7), angle=45)

    def refresh(self) -> None:
        et = self.event_type_var.get().strip() or None
        sev = self.severity_var.get().strip() or None
        search = self.search_var.get().strip() or None
        self._rows = self.audit.query_logs(
            event_type=et,
            severity=sev,
            search=search,
            limit=self.PAGE_SIZE,
            offset=self._offset,
        )
        self.tree.delete(*self.tree.get_children())
        for row in self._rows:
            self.tree.insert(
                "",
                tk.END,
                iid=str(row["sequence_number"]),
                values=(
                    row["sequence_number"],
                    row["timestamp"],
                    row["event_type"],
                    row["severity"],
                    row["source"],
                    row.get("entry_id") or "",
                ),
            )
        lv = self.audit.last_verify_result
        integrity = "OK" if lv and lv.get("verified") else "—"
        self.stats_var.set(
            f"Записей: {self.audit.count_logs()} | offset={self._offset} | "
            f"Integrity: {integrity}"
        )

    def _plain_entry_data(self, row: dict) -> str:
        if "entry_data_plain" in row:
            return row["entry_data_plain"]
        return self.audit._decrypt_entry_data(row["entry_data"])

    def _on_select(self, _event=None) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        seq = int(sel[0])
        row = next((r for r in self._rows if r["sequence_number"] == seq), None)
        if not row:
            return
        plain = self._plain_entry_data(row)
        try:
            entry = json.loads(plain)
        except json.JSONDecodeError:
            entry = {"raw": plain}
        sig_ok = self.audit.signer.verify(plain.encode("utf-8"), bytes.fromhex(row["signature"]))
        detail = {
            "verification": "valid" if sig_ok else "INVALID",
            "entry_hash": row["entry_hash"],
            "previous_hash": row["previous_hash"],
            "entry": entry,
        }
        self.detail_text.delete("1.0", tk.END)
        self.detail_text.insert(tk.END, json.dumps(detail, indent=2, ensure_ascii=False))
        if self.on_entry_click and row.get("entry_id"):
            self.on_entry_click(row["entry_id"])

    def _verify(self) -> None:
        result = self.verify_callback()
        msg = (
            f"Проверено: {result['total_entries']}\n"
            f"Валидных: {result['valid_entries']}\n"
            f"Целостность: {'OK' if result['verified'] else 'НАРУШЕНА'}"
        )
        if result["verified"]:
            messagebox.showinfo("Проверка", msg, parent=self.win)
        else:
            messagebox.showwarning("Проверка", msg, parent=self.win)

    def _export(self, fmt: str) -> None:
        pwd = simpledialog.askstring("Пароль", "Мастер-пароль:", show="*", parent=self.win)
        if pwd is None:
            return
        path = filedialog.asksaveasfilename(parent=self.win, defaultextension=f".{fmt}")
        if path:
            self.export_callback(
                fmt,
                path,
                pwd,
                self.date_from_var.get().strip() or None,
                self.date_to_var.get().strip() or None,
            )

    def _schedule_export(self) -> None:
        if not self.schedule_export_callback:
            return
        freq = simpledialog.askstring(
            "Расписание",
            "Частота: daily / weekly / monthly",
            parent=self.win,
        )
        if not freq:
            return
        path = filedialog.asksaveasfilename(parent=self.win, defaultextension=".json")
        if path and self.schedule_export_callback:
            pwd = simpledialog.askstring("Пароль", "Мастер-пароль:", show="*", parent=self.win)
            if pwd:
                self.schedule_export_callback(freq, path, pwd)

    def _prev_page(self) -> None:
        self._offset = max(0, self._offset - self.PAGE_SIZE)
        self.refresh()

    def _next_page(self) -> None:
        self._offset += self.PAGE_SIZE
        self.refresh()
