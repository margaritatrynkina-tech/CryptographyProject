
from __future__ import annotations

import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Any, Dict, List, Optional

from src.core.clipboard.clipboard_service import ClipboardService


class SharingDialog:

    def __init__(
        self,
        parent: tk.Widget,
        sharing_service,
        entry_id: str,
        entry_title: str = "",
        db_connection=None,
    ) -> None:
        self.parent = parent
        self.sharing_service = sharing_service
        self.entry_id = entry_id
        self.entry_title = entry_title
        self.db = db_connection

        self.dialog = tk.Toplevel(parent)
        self.dialog.title(f"Поделиться: {entry_title or entry_id}")
        self.dialog.geometry("680x600")
        self.dialog.resizable(False, True)
        self.dialog.transient(parent)
        self.dialog.grab_set()

        self._contacts: List[Dict[str, Any]] = self._load_contacts()
        self._build_ui()
        self._load_share_history()

    def _build_ui(self) -> None:
        pad = {"padx": 14, "pady": 5}

        nb = ttk.Notebook(self.dialog)
        nb.pack(fill=tk.BOTH, expand=True, padx=10, pady=8)

        # Tab 1: Create share
        create_tab = ttk.Frame(nb, padding=10)
        nb.add(create_tab, text="Создать ссылку")
        self._build_create_tab(create_tab)

        # Tab 2: QR code
        qr_tab = ttk.Frame(nb, padding=10)
        nb.add(qr_tab, text="QR код")
        self._build_qr_tab(qr_tab)

        # Tab 3: Share history
        history_tab = ttk.Frame(nb, padding=10)
        nb.add(history_tab, text="История шаринга")
        self._build_history_tab(history_tab)

        # Close button
        ttk.Button(self.dialog, text="Закрыть", command=self.dialog.destroy).pack(
            side=tk.RIGHT, padx=14, pady=8
        )

    def _build_create_tab(self, parent: ttk.Frame) -> None:
        # Recipient
        ttk.Label(parent, text="Получатель:").grid(row=0, column=0, sticky=tk.W, pady=4)
        self._recipient_var = tk.StringVar()

        contact_names = [f"{c['name']} <{c['identifier']}>" for c in self._contacts]
        if contact_names:
            self._recipient_combo = ttk.Combobox(
                parent, textvariable=self._recipient_var,
                values=contact_names, width=36,
            )
        else:
            self._recipient_combo = ttk.Entry(parent, textvariable=self._recipient_var, width=38)
        self._recipient_combo.grid(row=0, column=1, sticky=tk.W, padx=(8, 0), pady=4)

        # Encryption method
        ttk.Label(parent, text="Метод шифрования:").grid(row=1, column=0, sticky=tk.W, pady=4)
        self._enc_var = tk.StringVar(value="password")
        enc_frame = ttk.Frame(parent)
        enc_frame.grid(row=1, column=1, sticky=tk.W, padx=(8, 0))
        ttk.Radiobutton(enc_frame, text="Пароль", variable=self._enc_var,
                        value="password", command=self._on_enc_change).pack(side=tk.LEFT)
        ttk.Radiobutton(enc_frame, text="Публичный ключ", variable=self._enc_var,
                        value="public_key", command=self._on_enc_change).pack(side=tk.LEFT, padx=(10, 0))

        # Password field
        ttk.Label(parent, text="Пароль шаринга:").grid(row=2, column=0, sticky=tk.W, pady=4)
        self._share_pwd_var = tk.StringVar()
        self._share_pwd_entry = ttk.Entry(parent, textvariable=self._share_pwd_var, show="*", width=28)
        self._share_pwd_entry.grid(row=2, column=1, sticky=tk.W, padx=(8, 0), pady=4)

        # Permissions
        ttk.Label(parent, text="Права:").grid(row=3, column=0, sticky=tk.W, pady=4)
        self._readonly_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(parent, text="Только чтение (без пароля)", variable=self._readonly_var).grid(
            row=3, column=1, sticky=tk.W, padx=(8, 0), pady=4
        )

        # Expiration
        ttk.Label(parent, text="Срок действия (дней):").grid(row=4, column=0, sticky=tk.W, pady=4)
        self._expiry_var = tk.IntVar(value=7)
        ttk.Spinbox(parent, from_=1, to=30, textvariable=self._expiry_var, width=6).grid(
            row=4, column=1, sticky=tk.W, padx=(8, 0), pady=4
        )

        # Delivery method
        ttk.Label(parent, text="Способ доставки:").grid(row=5, column=0, sticky=tk.W, pady=4)
        self._delivery_var = tk.StringVar(value="file")
        del_frame = ttk.Frame(parent)
        del_frame.grid(row=5, column=1, sticky=tk.W, padx=(8, 0))
        ttk.Radiobutton(del_frame, text="Сохранить в файл", variable=self._delivery_var,
                        value="file").pack(side=tk.LEFT)
        ttk.Radiobutton(del_frame, text="Скопировать JSON", variable=self._delivery_var,
                        value="clipboard").pack(side=tk.LEFT, padx=(10, 0))

        # Status
        self._create_status_var = tk.StringVar(value="")
        ttk.Label(parent, textvariable=self._create_status_var, foreground="#555").grid(
            row=6, column=0, columnspan=2, pady=6
        )

        # Share button
        self._share_btn = ttk.Button(parent, text="Поделиться", command=self._do_share)
        self._share_btn.grid(row=7, column=1, sticky=tk.E, pady=8)

    def _build_qr_tab(self, parent: ttk.Frame) -> None:
        ttk.Label(
            parent,
            text="Сгенерируйте QR-код для обмена публичным ключом\nили для передачи пакета шаринга.",
            justify=tk.LEFT,
        ).pack(anchor=tk.W, pady=(0, 10))

        # Payload type selector
        type_frame = ttk.Frame(parent)
        type_frame.pack(fill=tk.X, pady=4)
        ttk.Label(type_frame, text="Тип данных:").pack(side=tk.LEFT)
        self._qr_type_var = tk.StringVar(value="public_key")
        ttk.Radiobutton(
            type_frame, text="Публичный ключ", variable=self._qr_type_var, value="public_key"
        ).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Radiobutton(
            type_frame, text="Пакет шаринга", variable=self._qr_type_var, value="share_package"
        ).pack(side=tk.LEFT, padx=(8, 0))

        # Share password for package QR
        pwd_frame = ttk.Frame(parent)
        pwd_frame.pack(fill=tk.X, pady=4)
        ttk.Label(pwd_frame, text="Пароль (для пакета):").pack(side=tk.LEFT)
        self._qr_pwd_var = tk.StringVar()
        ttk.Entry(pwd_frame, textvariable=self._qr_pwd_var, show="*", width=24).pack(
            side=tk.LEFT, padx=(8, 0)
        )

        # QR image display area
        self._qr_canvas = tk.Canvas(parent, width=300, height=300, bg="#f0f0f0", relief=tk.SUNKEN)
        self._qr_canvas.pack(pady=8)
        self._qr_canvas_text = self._qr_canvas.create_text(
            150, 150, text="Нажмите «Создать QR»", fill="#888", font=("Arial", 11)
        )

        # Info label
        self._qr_info_var = tk.StringVar(value="")
        ttk.Label(parent, textvariable=self._qr_info_var, foreground="#555").pack()

        # Buttons
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(pady=6)
        self._qr_gen_btn = ttk.Button(btn_frame, text="Создать QR", command=self._generate_qr)
        self._qr_gen_btn.pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text="Сохранить PNG…", command=self._save_qr_png).pack(
            side=tk.LEFT, padx=4
        )

        # Internal state
        self._qr_image = None          # PIL Image
        self._qr_tk_image = None       # PhotoImage kept alive

    def _generate_qr(self) -> None:
        self._qr_gen_btn.configure(state=tk.DISABLED)
        self._qr_info_var.set("Генерация…")

        payload_type = self._qr_type_var.get()
        password = self._qr_pwd_var.get() or None

        def run() -> None:
            try:
                from src.core.import_export.key_exchange import QRCodeService
                svc = QRCodeService(db_connection=self.db)

                if payload_type == "public_key":
                    # Generate a fresh RSA-2048 key pair and encode the public key
                    _, pub_pem = svc.generate_keypair("RSA-2048")
                    images = svc.export_public_key_qr(pub_pem)
                    info = f"Публичный ключ RSA-2048 | {len(images)} QR-код(ов)"
                else:
                    # Build a minimal share package payload for the QR
                    if not password:
                        raise ValueError("Введите пароль для пакета шаринга")
                    from src.core.import_export.models import EncryptionMethod
                    share_result = self.sharing_service.share_entry(
                        entry_id=self.entry_id,
                        recipient="qr_recipient",
                        permissions={"read_only": True},
                        expires_in_days=1,
                        encryption_method=EncryptionMethod.PASSWORD,
                        password=password,
                    )
                    import json
                    payload = json.dumps(share_result["package"], ensure_ascii=False)
                    images = svc.generate_qr_code(payload, payload_type="share_package")
                    info = f"Пакет шаринга | {len(images)} QR-код(ов)"

                self.dialog.after(0, lambda: self._show_qr(images[0], info))
            except Exception as exc:
                self.dialog.after(0, lambda: self._qr_error(str(exc)))

        import threading
        threading.Thread(target=run, daemon=True).start()

    def _show_qr(self, pil_image, info: str) -> None:
        self._qr_gen_btn.configure(state=tk.NORMAL)
        self._qr_info_var.set(info)
        self._qr_image = pil_image

        try:
            # Resize to fit canvas
            img_resized = pil_image.resize((290, 290))
            import tkinter.font  # noqa — ensure PIL PhotoImage works
            from PIL import ImageTk
            self._qr_tk_image = ImageTk.PhotoImage(img_resized)
            self._qr_canvas.delete("all")
            self._qr_canvas.create_image(150, 150, image=self._qr_tk_image)
        except Exception as exc:
            self._qr_canvas.itemconfigure(self._qr_canvas_text, text=f"Ошибка отображения:\n{exc}")

    def _qr_error(self, message: str) -> None:
        self._qr_gen_btn.configure(state=tk.NORMAL)
        self._qr_info_var.set(f"Ошибка: {message}")

    def _save_qr_png(self) -> None:
        if self._qr_image is None:
            messagebox.showinfo("Нет QR", "Сначала создайте QR-код", parent=self.dialog)
            return
        path = filedialog.asksaveasfilename(
            parent=self.dialog,
            defaultextension=".png",
            filetypes=[("PNG images", "*.png"), ("All files", "*.*")],
            title="Сохранить QR-код как PNG",
        )
        if path:
            try:
                self._qr_image.save(path)
                messagebox.showinfo("Сохранено", f"QR-код сохранён: {path}", parent=self.dialog)
            except Exception as exc:
                messagebox.showerror("Ошибка", str(exc), parent=self.dialog)

    def _build_history_tab(self, parent: ttk.Frame) -> None:
        cols = ("share_id", "recipient", "expires_at", "method")
        self._hist_tree = ttk.Treeview(parent, columns=cols, show="headings", height=10)
        self._hist_tree.heading("share_id", text="ID")
        self._hist_tree.heading("recipient", text="Получатель")
        self._hist_tree.heading("expires_at", text="Истекает")
        self._hist_tree.heading("method", text="Метод")
        self._hist_tree.column("share_id", width=80)
        self._hist_tree.column("recipient", width=160)
        self._hist_tree.column("expires_at", width=140)
        self._hist_tree.column("method", width=80)

        vsb = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self._hist_tree.yview)
        self._hist_tree.configure(yscrollcommand=vsb.set)
        self._hist_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        ttk.Button(parent, text="Отозвать выбранное", command=self._revoke_selected).pack(
            side=tk.BOTTOM, pady=6
        )

    def _on_enc_change(self) -> None:
        state = tk.NORMAL if self._enc_var.get() == "password" else tk.DISABLED
        self._share_pwd_entry.configure(state=state)

    def _do_share(self) -> None:
        recipient = self._recipient_var.get().strip()
        if not recipient:
            messagebox.showerror("Ошибка", "Укажите получателя", parent=self.dialog)
            return

        method = self._enc_var.get()
        password = self._share_pwd_var.get() or None
        if method == "password" and not password:
            messagebox.showerror("Ошибка", "Введите пароль шаринга", parent=self.dialog)
            return

        permissions = {
            "read_only": self._readonly_var.get(),
        }
        expires_in_days = self._expiry_var.get()

        self._share_btn.configure(state=tk.DISABLED)
        self._create_status_var.set("Создание пакета…")

        def run() -> None:
            try:
                from src.core.import_export.models import EncryptionMethod
                enc = EncryptionMethod(method)
                result = self.sharing_service.share_entry(
                    entry_id=self.entry_id,
                    recipient=recipient,
                    permissions=permissions,
                    expires_in_days=expires_in_days,
                    encryption_method=enc,
                    password=password,
                )
                self.dialog.after(0, lambda: self._on_share_success(result))
            except Exception as exc:
                self.dialog.after(0, lambda: self._on_share_error(str(exc)))

        threading.Thread(target=run, daemon=True).start()

    def _on_share_success(self, result: Dict[str, Any]) -> None:
        self._share_btn.configure(state=tk.NORMAL)
        self._create_status_var.set("")

        delivery = self._delivery_var.get()
        import json
        package_json = json.dumps(result["package"], indent=2, ensure_ascii=False)

        if delivery == "clipboard":
            try:
                # Use ClipboardService instead of Tkinter clipboard for auto-cleanup
                clipboard_service = ClipboardService()
                clipboard_service.copy_to_clipboard(package_json)
                messagebox.showinfo(
                    "Готово",
                    f"Пакет скопирован в буфер обмена.\nShare ID: {result['share_id']}\n"
                    f"Истекает: {result['expires_at']}\n"
                    f"Буфер будет автоматически очищен через 30 секунд.",
                    parent=self.dialog,
                )
            except Exception as exc:
                messagebox.showerror("Ошибка буфера", str(exc), parent=self.dialog)
        else:
            file_path = filedialog.asksaveasfilename(
                parent=self.dialog,
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
                title="Сохранить пакет шаринга",
            )
            if file_path:
                with open(file_path, "w", encoding="utf-8") as fh:
                    fh.write(package_json)
                messagebox.showinfo(
                    "Готово",
                    f"Пакет сохранён: {file_path}\nShare ID: {result['share_id']}",
                    parent=self.dialog,
                )

        self._load_share_history()

    def _on_share_error(self, message: str) -> None:
        self._share_btn.configure(state=tk.NORMAL)
        self._create_status_var.set("")
        messagebox.showerror("Ошибка шаринга", message, parent=self.dialog)

    def _revoke_selected(self) -> None:
        sel = self._hist_tree.selection()
        if not sel:
            messagebox.showinfo("Нет выбора", "Выберите запись для отзыва", parent=self.dialog)
            return
        share_id = self._hist_tree.item(sel[0])["values"][0]
        if messagebox.askyesno("Подтверждение", f"Отозвать шаринг {share_id}?", parent=self.dialog):
            ok = self.sharing_service.revoke_share(share_id)
            if ok:
                self._hist_tree.delete(sel[0])
                messagebox.showinfo("Готово", "Шаринг отозван", parent=self.dialog)
            else:
                messagebox.showerror("Ошибка", "Не удалось отозвать шаринг", parent=self.dialog)

    def _load_contacts(self) -> List[Dict[str, Any]]:
        if self.db is None:
            return []
        try:
            cursor = self.db.execute("SELECT * FROM contacts ORDER BY name")
            cols = [d[0] for d in cursor.description]
            return [dict(zip(cols, row)) for row in cursor.fetchall()]
        except Exception:
            return []

    def _load_share_history(self) -> None:
        for row in self._hist_tree.get_children():
            self._hist_tree.delete(row)
        if self.db is None:
            return
        try:
            cursor = self.db.execute(
                "SELECT shared_id, recipient_info, expires_at, encryption_method "
                "FROM shared_entries WHERE original_entry_id = ? ORDER BY shared_at DESC",
                (self.entry_id,),
            )
            for row in cursor.fetchall():
                self._hist_tree.insert("", tk.END, values=tuple(row))
        except Exception:
            pass
