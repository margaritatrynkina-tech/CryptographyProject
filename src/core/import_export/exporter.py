from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
import shutil
import tempfile
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from src.core.import_export.formats.json_handler import JSONHandler
from src.core.import_export.formats.csv_handler import CSVHandler
from src.core.import_export.formats.bitwarden_handler import BitwardenHandler
from src.core.import_export.formats.lastpass_handler import LastPassHandler
from src.core.import_export.models import ExportFormat, ExportMetadata, ExportResult

# Maximum file size for a single export (100 MB)
_MAX_EXPORT_BYTES = 100 * 1024 * 1024
# Streaming threshold: use chunked writes above this entry count
_STREAMING_THRESHOLD = 1_000


class VaultExporter:
    def __init__(self, entry_manager, encryption_service, audit_logger, config=None):
        self.entry_manager = entry_manager
        self.encryption_service = encryption_service
        self.audit_logger = audit_logger
        self.config = config or {}
    def export_vault(
        self,
        entry_ids: Optional[List[str]],
        master_password: str,
        export_password: Optional[str],
        public_key: Optional[bytes],
        format: Literal["json", "csv", "bitwarden", "lastpass"],
        file_path: Optional[Path] = None,
        export_options: Optional[Dict[str, Any]] = None,
    ) -> ExportResult:
        opts = export_options or {}
        start_time = time.monotonic()
        export_id = str(uuid.uuid4())

        # Resolve destination path
        if file_path is None:
            suffix = _format_suffix(format)
            tmp = tempfile.NamedTemporaryFile(
                suffix=suffix, delete=False, prefix="cryptosafe_export_"
            )
            tmp.close()
            file_path = Path(tmp.name)

        # Collect entries
        entries = self._collect_entries(entry_ids, opts)

        # Apply field exclusions
        exclude = opts.get("exclude_fields", [])
        if exclude:
            entries = [_strip_fields(e, exclude) for e in entries]

        tmp_path: Optional[Path] = None
        try:
            # Write to a temp file first, then move atomically
            tmp_fd, tmp_str = tempfile.mkstemp(
                suffix=_format_suffix(format), prefix="cs_exp_"
            )
            os.close(tmp_fd)
            tmp_path = Path(tmp_str)

            if format == "json":
                self._write_json(entries, tmp_path, export_password, public_key, opts, export_id)
            elif format == "csv":
                self._write_csv(entries, tmp_path)
            elif format == "bitwarden":
                self._write_bitwarden(entries, tmp_path)
            elif format == "lastpass":
                self._write_lastpass(entries, tmp_path, export_password)
            else:
                raise ValueError(f"Unsupported export format: '{format}'")

            # Integrity check
            checksum = _sha256_file(tmp_path)

            # Enforce size limit
            size = tmp_path.stat().st_size
            if size > _MAX_EXPORT_BYTES:
                raise ValueError(
                    f"Export file size {size} bytes exceeds the 100 MB limit"
                )

            # Move to final destination
            shutil.move(str(tmp_path), str(file_path))
            tmp_path = None  # moved — don't delete in finally

        finally:
            if tmp_path and tmp_path.exists():
                try:
                    tmp_path.unlink()
                except OSError:
                    pass

        duration = time.monotonic() - start_time

        # Audit log
        self._log_export(format, len(entries), str(file_path), checksum, export_id)

        return ExportResult(
            export_id=export_id,
            entry_count=len(entries),
            file_path=str(file_path),
            checksum=checksum,
            format=ExportFormat(format),
            duration_seconds=duration,
        )
    def _write_json(
        self,
        entries: List[Dict[str, Any]],
        path: Path,
        password: str,
        public_key: Optional[bytes],
        opts: Dict[str, Any],
        export_id: str,
    ) -> None:
        plaintext = JSONHandler.serialise_entries(entries)
        plaintext_hash = JSONHandler.compute_hash(plaintext)

        compress = opts.get("compression", False)
        if compress:
            plaintext = gzip.compress(plaintext, compresslevel=6)

        if public_key:
            enc_info, data_b64 = self._encrypt_with_public_key(plaintext, public_key)
        else:
            enc_info, data_b64 = self._encrypt_with_password_full(plaintext, password)

        if compress:
            enc_info["compressed"] = True

        metadata = ExportMetadata(
            format=ExportFormat.JSON,
            entry_count=len(entries),
            export_id=export_id,
        ).to_dict()

        envelope = JSONHandler.build_envelope(
            encrypted_data_b64=data_b64,
            metadata=metadata,
            encryption_info=enc_info,
            plaintext_hash=plaintext_hash,
        )

        path.write_text(envelope, encoding="utf-8")

    def _write_csv(self, entries: List[Dict[str, Any]], path: Path) -> None:
        if len(entries) > _STREAMING_THRESHOLD:
            # Streaming: write in batches to avoid large in-memory strings
            with open(str(path), "w", encoding="utf-8-sig", newline="") as fh:
                first_batch = entries[:100]
                fh.write(CSVHandler.export(first_batch, include_header=True))
                for i in range(100, len(entries), 100):
                    fh.write(CSVHandler.export(entries[i:i + 100], include_header=False))
        else:
            content = CSVHandler.export(entries)
            path.write_text(content, encoding="utf-8-sig")

    def _write_bitwarden(self, entries: List[Dict[str, Any]], path: Path) -> None:
        content = BitwardenHandler.export(entries)
        path.write_text(content, encoding="utf-8")

    def _write_lastpass(self, entries: List[Dict[str, Any]], path: Path, export_password: Optional[str]) -> None:
        content = LastPassHandler.export(entries, export_password)
        path.write_text(content, encoding="utf-8")

    def _collect_entries(
        self,
        entry_ids: Optional[List[str]],
        opts: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        if entry_ids is not None:
            entries = [
                e for eid in entry_ids
                if (e := self.entry_manager.get_entry(eid)) is not None
            ]
        else:
            entries = self.entry_manager.get_all_entries()

        # Tag filter
        filter_tags = opts.get("filter_tags")
        if filter_tags:
            tag_set = set(filter_tags)
            entries = [
                e for e in entries
                if _entry_tags(e) & tag_set
            ]

        # Date range filter
        date_from = opts.get("date_from")
        date_to = opts.get("date_to")
        if date_from or date_to:
            entries = _filter_by_date(entries, date_from, date_to)

        return entries

    @staticmethod
    def generate_export_salt() -> bytes:
        return os.urandom(16)

    @staticmethod
    def derive_export_key(
        password: str,
        salt: bytes,
        iterations: int = 100_000,
    ) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
        )
        return kdf.derive(password.encode("utf-8"))

    @staticmethod
    def clear_key_from_memory(key_bytes: bytearray) -> None:
        for i in range(len(key_bytes)):
            key_bytes[i] = 0


    def _encrypt_with_password_full(
        self, data: bytes, password: str
    ) -> tuple[Dict[str, Any], str]:
        salt = self.generate_export_salt()
        nonce = os.urandom(12)
        key = self.derive_export_key(password, salt)
        key_buf = bytearray(key)

        try:
            aesgcm = AESGCM(bytes(key_buf))
            ciphertext = aesgcm.encrypt(nonce, data, None)
        finally:
            self.clear_key_from_memory(key_buf)

        enc_info: Dict[str, Any] = {
            "method": "password",
            "algorithm": "AES-256-GCM",
            "kdf": "PBKDF2-HMAC-SHA256",
            "iterations": 100_000,
            "salt": base64.b64encode(salt).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
        }
        data_b64 = base64.b64encode(ciphertext).decode("ascii")
        return enc_info, data_b64

    def _encrypt_with_public_key(
        self, data: bytes, public_key: bytes
    ) -> tuple[Dict[str, Any], str]:
        sym_key = os.urandom(32)
        nonce = os.urandom(12)
        sym_buf = bytearray(sym_key)

        try:
            aesgcm = AESGCM(bytes(sym_buf))
            ciphertext = aesgcm.encrypt(nonce, data, None)
        finally:
            self.clear_key_from_memory(sym_buf)

        pub = serialization.load_pem_public_key(public_key)
        encrypted_key = pub.encrypt(
            sym_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        enc_info: Dict[str, Any] = {
            "method": "public_key",
            "algorithm": "RSA-OAEP+AES-256-GCM",
            "encrypted_key": base64.b64encode(encrypted_key).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
        }
        data_b64 = base64.b64encode(ciphertext).decode("ascii")
        return enc_info, data_b64


    def _log_export(
        self,
        format: str,
        entry_count: int,
        file_path: str,
        checksum: str,
        export_id: str,
    ) -> None:
        event = "AUDIT_EXPORT_CSV" if format == "csv" else "AUDIT_EXPORT"
        try:
            self.audit_logger.log_event(
                event_type=event,
                severity="INFO",
                source="vault_exporter",
                details={
                    "export_id": export_id,
                    "format": format,
                    "entry_count": entry_count,
                    "file_hash": checksum,
                },
            )
        except Exception:
            pass  # Audit failure must not abort the export



def _format_suffix(format: str) -> str:
    return {
        "json": ".json",
        "csv": ".csv",
        "bitwarden": ".json",
        "lastpass": ".csv",
    }.get(format, ".dat")


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(str(path), "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _strip_fields(entry: Dict[str, Any], exclude: List[str]) -> Dict[str, Any]:
    return {k: v for k, v in entry.items() if k not in exclude}


def _entry_tags(entry: Dict[str, Any]) -> set:
    tags = entry.get("tags", "")
    if isinstance(tags, list):
        return set(tags)
    if isinstance(tags, str) and tags:
        return {t.strip() for t in tags.split(",") if t.strip()}
    return set()


def _filter_by_date(
    entries: List[Dict[str, Any]],
    date_from: Optional[str],
    date_to: Optional[str],
) -> List[Dict[str, Any]]:
    result = []
    for e in entries:
        ts_str = e.get("updated_at") or e.get("created_at") or ""
        if not ts_str:
            result.append(e)
            continue
        ts = ts_str.rstrip("Z")
        if date_from and ts < date_from.rstrip("Z"):
            continue
        if date_to and ts > date_to.rstrip("Z"):
            continue
        result.append(e)
    return result
