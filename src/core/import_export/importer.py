from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
import re
import shutil
import tempfile
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from src.core.import_export.formats.json_handler import JSONHandler
from src.core.import_export.formats.csv_handler import CSVHandler
from src.core.import_export.formats.bitwarden_handler import BitwardenHandler
from src.core.import_export.formats.lastpass_handler import LastPassHandler
from src.core.import_export.models import (
    Conflict,
    ConflictResolution,
    ImportResult,
    ValidationError,
)

# 10 MB default file size limit (SEC-2)
_MAX_FILE_SIZE = 10 * 1024 * 1024

# Patterns that indicate malicious content (SEC-5)
_MALICIOUS_PATTERNS = [
    re.compile(r"<script", re.IGNORECASE),
    re.compile(r"javascript:", re.IGNORECASE),
    re.compile(r"\.\./"),          # path traversal
    re.compile(r"\.\.\\"),         # path traversal (Windows)
    re.compile(r"file://", re.IGNORECASE),
    re.compile(r"data:text/html", re.IGNORECASE),
]

# Checkpoint written every N entries
_CHECKPOINT_INTERVAL = 100


class VaultImporter:

    def __init__(self, entry_manager, encryption_service, audit_logger, db_manager=None):
        self.entry_manager = entry_manager
        self.encryption_service = encryption_service
        self.audit_logger = audit_logger
        self.db_manager = db_manager

    def import_json(
        self,
        file_path: Path,
        master_password: str,
        file_password: Optional[str] = None,
        conflict_strategy: str = "skip",
        private_key: Optional[bytes] = None,
    ) -> ImportResult:
        file_path = Path(file_path)
        self._check_file_exists(file_path)
        self._check_file_size(file_path)

        content = file_path.read_text(encoding="utf-8")
        envelope = JSONHandler.parse_envelope(content)

        enc_info = envelope["encryption"]
        data_b64 = envelope["data"]
        integrity = envelope.get("integrity", {})

        # Decrypt
        ciphertext = base64.b64decode(data_b64)
        method = enc_info.get("method", "password")

        if method == "password":
            if not file_password:
                raise ValueError("File password required to decrypt this export file")
            plaintext = self._decrypt_with_password(enc_info, ciphertext, file_password)
        elif method == "public_key":
            if not private_key:
                raise ValueError("Private key required to decrypt this export file")
            plaintext = self._decrypt_with_private_key(enc_info, ciphertext, private_key)
        elif method == "none":
            plaintext = ciphertext
        else:
            raise ValueError(f"Unknown encryption method: '{method}'")

        # Decompress if needed
        if enc_info.get("compressed"):
            plaintext = gzip.decompress(plaintext)

        # Verify integrity hash
        expected_hash = integrity.get("hash", "")
        if expected_hash and not JSONHandler.verify_hash(plaintext, expected_hash):
            raise ValueError(
                "Integrity check failed — the export file may have been tampered with"
            )

        entries = JSONHandler.deserialise_entries(plaintext)
        return self._import_entries(entries, conflict_strategy, source_format="json")

    def import_csv(
        self,
        file_path: Path,
        column_mapping: Optional[Dict[str, str]] = None,
        conflict_strategy: str = "skip",
    ) -> ImportResult:
        file_path = Path(file_path)
        self._check_file_exists(file_path)
        self._check_file_size(file_path)
        self._scan_for_malicious_content(file_path)

        entries, warnings = CSVHandler.import_file(str(file_path), column_mapping)
        result = self._import_entries(entries, conflict_strategy, source_format="csv")

        # Surface CSV parse warnings as validation errors
        for w in warnings:
            result.validation_errors.append(ValidationError(field="csv", message=w))

        return result

    def import_bitwarden(
        self,
        file_path: Path,
        conflict_strategy: str = "skip",
    ) -> ImportResult:
        file_path = Path(file_path)
        self._check_file_exists(file_path)
        self._check_file_size(file_path)

        entries, warnings = BitwardenHandler.import_file(str(file_path))
        result = self._import_entries(entries, conflict_strategy, source_format="bitwarden")
        for w in warnings:
            result.validation_errors.append(ValidationError(field="bitwarden", message=w))
        return result

    def import_lastpass(
        self,
        file_path: Path,
        master_password: str,
        file_password: Optional[str] = None,
        conflict_strategy: str = "skip",
    ) -> ImportResult:
        print(f"[DEBUG] VaultImporter.import_lastpass called")
        print(f"[DEBUG] file_path: {file_path}")
        print(f"[DEBUG] master_password: {bool(master_password)}")
        print(f"[DEBUG] file_password: {bool(file_password)}")
        print(f"[DEBUG] conflict_strategy: {conflict_strategy}")
        
        file_path = Path(file_path)
        self._check_file_exists(file_path)
        self._check_file_size(file_path)
        self._scan_for_malicious_content(file_path)

        print(f"[DEBUG] Calling LastPassHandler.import_file...")
        entries, warnings = LastPassHandler.import_file(str(file_path), file_password)
        print(f"[DEBUG] LastPassHandler.import_file returned {len(entries)} entries")
        
        print(f"[DEBUG] Calling _import_entries...")
        result = self._import_entries(entries, conflict_strategy, source_format="lastpass")
        print(f"[DEBUG] _import_entries completed: {result.successful_imports} successful, {result.failed_imports} failed")
        
        for w in warnings:
            result.validation_errors.append(ValidationError(field="lastpass", message=w))
        
        return result

    def validate_import_file(
        self,
        file_path: Path,
        format: Literal["json", "csv", "bitwarden", "lastpass"],
    ) -> Dict[str, Any]:
        file_path = Path(file_path)
        errors: List[str] = []
        warnings: List[str] = []
        entry_count: Optional[int] = None

        if not file_path.exists():
            return {
                "is_valid": False,
                "errors": [f"File not found: {file_path}"],
                "warnings": [],
                "entry_count": None,
                "detected_format": format,
            }

        size = file_path.stat().st_size
        if size > _MAX_FILE_SIZE:
            errors.append(
                f"File size {size:,} bytes exceeds the {_MAX_FILE_SIZE // 1024 // 1024} MB limit"
            )
            return {
                "is_valid": False,
                "errors": errors,
                "warnings": warnings,
                "entry_count": None,
                "detected_format": format,
            }

        if format == "json":
            try:
                content = file_path.read_text(encoding="utf-8")
                envelope = JSONHandler.parse_envelope(content)
                entry_count = envelope.get("metadata", {}).get("entry_count")
            except Exception as exc:
                errors.append(str(exc))

        elif format == "csv":
            is_valid, csv_errors = CSVHandler.validate(str(file_path))
            errors.extend(csv_errors)
            if is_valid:
                try:
                    entries, w = CSVHandler.import_file(str(file_path))
                    entry_count = len(entries)
                    warnings.extend(w)
                except Exception as exc:
                    warnings.append(f"Could not count entries: {exc}")

        elif format == "bitwarden":
            is_valid, bw_errors = BitwardenHandler.validate(str(file_path))
            errors.extend(bw_errors)
            if is_valid:
                try:
                    entries, w = BitwardenHandler.import_file(str(file_path))
                    entry_count = len(entries)
                    warnings.extend(w)
                except Exception as exc:
                    warnings.append(f"Could not count entries: {exc}")

        elif format == "lastpass":
            # Check if file is encrypted first
            try:
                content = file_path.read_text(encoding="utf-8")
                if content.strip().startswith("ENCRYPTED:"):
                    # Encrypted file is valid, but we can't count entries without password
                    print("[DEBUG] LastPass файл зашифрован, пропускаем детальную валидацию")
                    return {
                        "is_valid": True,
                        "errors": [],
                        "warnings": ["File is encrypted - password required for import"],
                        "entry_count": None,
                        "detected_format": format,
                    }
            except Exception:
                pass
            
            # Not encrypted - validate normally
            is_valid, lp_errors = LastPassHandler.validate(str(file_path))
            errors.extend(lp_errors)
            if is_valid:
                try:
                    entries, w = LastPassHandler.import_file(str(file_path))
                    entry_count = len(entries)
                    warnings.extend(w)
                except Exception as exc:
                    warnings.append(f"Could not count entries: {exc}")

        else:
            errors.append(f"Unknown format: '{format}'")

        return {
            "is_valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings,
            "entry_count": entry_count,
            "detected_format": format,
        }

    def create_backup(self) -> Path:
        if self.db_manager is None:
            raise IOError("No database manager available for backup")

        db_path = Path(self.db_manager.db_path)
        if not db_path.exists():
            raise IOError(f"Database file not found: {db_path}")

        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        backup_path = db_path.parent / f"vault_backup_{timestamp}.db"
        shutil.copy2(str(db_path), str(backup_path))
        return backup_path

    def resume_import(self, checkpoint_file: Path) -> ImportResult:
        checkpoint_file = Path(checkpoint_file)
        if not checkpoint_file.exists():
            raise FileNotFoundError(f"Checkpoint file not found: {checkpoint_file}")

        data = json.loads(checkpoint_file.read_text(encoding="utf-8"))
        remaining = data.get("remaining_entries", [])
        strategy = data.get("conflict_strategy", "skip")
        source_format = data.get("source_format", "json")

        if not remaining:
            return ImportResult(
                total_entries=0,
                successful_imports=0,
                failed_imports=0,
            )

        result = self._import_entries(remaining, strategy, source_format=source_format)

        # Clean up checkpoint on success
        try:
            checkpoint_file.unlink()
        except OSError:
            pass

        return result

    def _import_entries(
        self,
        entries: List[Dict[str, Any]],
        conflict_strategy: str,
        source_format: str = "json",
    ) -> ImportResult:
        start_time = time.monotonic()
        strategy = _parse_strategy(conflict_strategy)

        total = len(entries)
        successful = 0
        failed = 0
        conflicts: List[Conflict] = []
        validation_errors: List[ValidationError] = []
        backup_created = False

        # Create backup before any destructive operation
        if strategy in (ConflictResolution.REPLACE, ConflictResolution.MERGE):
            try:
                self.create_backup()
                backup_created = True
            except Exception:
                pass  # Non-fatal — proceed without backup

        # Load existing entries for conflict detection
        existing = self._load_existing_index()

        # Checkpoint state
        checkpoint_path: Optional[Path] = None
        remaining = list(entries)

        for idx, entry in enumerate(entries):
            # Write checkpoint every N entries
            if idx > 0 and idx % _CHECKPOINT_INTERVAL == 0:
                checkpoint_path = self._write_checkpoint(
                    remaining[idx:], conflict_strategy, source_format
                )

            try:
                entry_id = entry.get("id") or str(uuid.uuid4())
                title = entry.get("title", "").strip()
                username = entry.get("username", "").strip()

                if not title:
                    validation_errors.append(
                        ValidationError(
                            entry_id=entry_id,
                            field="title",
                            message="Entry has no title — skipped",
                        )
                    )
                    failed += 1
                    continue

                # Scan entry fields for malicious content
                mal_error = _scan_entry_fields(entry)
                if mal_error:
                    validation_errors.append(
                        ValidationError(
                            entry_id=entry_id,
                            field="content",
                            message=mal_error,
                        )
                    )
                    failed += 1
                    continue

                conflict_key = (title.lower(), username.lower())
                existing_id = existing.get(conflict_key)

                if existing_id:
                    conflict = Conflict(
                        imported_entry_id=entry_id,
                        existing_entry_id=existing_id,
                        conflict_type="duplicate_title_username",
                        resolution=strategy,
                    )
                    conflicts.append(conflict)

                    if strategy == ConflictResolution.SKIP:
                        continue
                    elif strategy == ConflictResolution.REPLACE:
                        entry["id"] = existing_id
                        self.entry_manager.update_entry(existing_id, entry)
                        successful += 1
                        continue
                    elif strategy == ConflictResolution.RENAME:
                        entry["title"] = _make_unique_title(title, existing)
                        entry["id"] = str(uuid.uuid4())
                    elif strategy == ConflictResolution.MERGE:
                        merged = self._merge_entries(
                            self.entry_manager.get_entry(existing_id), entry
                        )
                        self.entry_manager.update_entry(existing_id, merged)
                        successful += 1
                        existing[conflict_key] = existing_id
                        continue

                # New entry — assign fresh ID
                entry["id"] = entry.get("id") or str(uuid.uuid4())
                self.entry_manager.create_entry(entry)
                new_key = (entry.get("title", "").lower(), entry.get("username", "").lower())
                existing[new_key] = entry["id"]
                successful += 1

            except Exception as exc:
                failed += 1
                validation_errors.append(
                    ValidationError(
                        entry_id=entry.get("id", "unknown"),
                        field="import",
                        message=str(exc),
                    )
                )

        # Clean up checkpoint on completion
        if checkpoint_path and checkpoint_path.exists():
            try:
                checkpoint_path.unlink()
            except OSError:
                pass

        duration = time.monotonic() - start_time
        audit_log_id = self._log_import(source_format, total, successful, failed)

        return ImportResult(
            total_entries=total,
            successful_imports=successful,
            failed_imports=failed,
            conflicts=conflicts,
            validation_errors=validation_errors,
            backup_created=backup_created,
            audit_log_id=str(audit_log_id) if audit_log_id is not None else None,
            duration_seconds=duration,
        )

    def _decrypt_with_password(
        self, enc_info: Dict[str, Any], ciphertext: bytes, password: str
    ) -> bytes:
        salt = base64.b64decode(enc_info["salt"])
        nonce = base64.b64decode(enc_info["nonce"])
        iterations = enc_info.get("iterations", 100_000)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
        )
        key = kdf.derive(password.encode("utf-8"))
        key_buf = bytearray(key)

        try:
            aesgcm = AESGCM(bytes(key_buf))
            return aesgcm.decrypt(nonce, ciphertext, None)
        except Exception as exc:
            raise ValueError(
                "Decryption failed — wrong password or corrupted file"
            ) from exc
        finally:
            for i in range(len(key_buf)):
                key_buf[i] = 0

    def _decrypt_with_private_key(
        self, enc_info: Dict[str, Any], ciphertext: bytes, private_key: bytes
    ) -> bytes:
        encrypted_key = base64.b64decode(enc_info["encrypted_key"])
        nonce = base64.b64decode(enc_info["nonce"])

        priv = serialization.load_pem_private_key(private_key, password=None)
        sym_key = priv.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        sym_buf = bytearray(sym_key)
        try:
            aesgcm = AESGCM(bytes(sym_buf))
            return aesgcm.decrypt(nonce, ciphertext, None)
        except Exception as exc:
            raise ValueError("Decryption failed — wrong key or corrupted file") from exc
        finally:
            for i in range(len(sym_buf)):
                sym_buf[i] = 0

    def _check_file_exists(self, path: Path) -> None:
        if not path.exists():
            raise FileNotFoundError(f"Import file not found: {path}")

    def _check_file_size(self, path: Path) -> None:
        size = path.stat().st_size
        if size > _MAX_FILE_SIZE:
            raise ValueError(
                f"File size {size:,} bytes exceeds the "
                f"{_MAX_FILE_SIZE // 1024 // 1024} MB import limit"
            )

    def _scan_for_malicious_content(self, path: Path) -> None:
        try:
            text = path.read_bytes().decode("utf-8", errors="replace")
        except OSError:
            return
        for pattern in _MALICIOUS_PATTERNS:
            if pattern.search(text):
                raise ValueError(
                    f"Import file contains potentially malicious content "
                    f"(matched pattern: {pattern.pattern!r})"
                )

    def _load_existing_index(self) -> Dict[Tuple[str, str], str]:
        index: Dict[Tuple[str, str], str] = {}
        try:
            for entry in self.entry_manager.get_all_entries():
                key = (
                    entry.get("title", "").lower(),
                    entry.get("username", "").lower(),
                )
                index[key] = entry["id"]
        except Exception:
            pass
        return index

    @staticmethod
    def _merge_entries(
        existing: Optional[Dict[str, Any]],
        incoming: Dict[str, Any],
    ) -> Dict[str, Any]:
        if existing is None:
            return incoming
        merged = dict(existing)
        for key, value in incoming.items():
            if key in ("id", "created_at"):
                continue  # Preserve original identity and creation time
            if value and value != existing.get(key):
                merged[key] = value
        return merged

    def _write_checkpoint(
        self,
        remaining: List[Dict[str, Any]],
        conflict_strategy: str,
        source_format: str,
    ) -> Path:
        tmp_fd, tmp_path = tempfile.mkstemp(suffix=".checkpoint.json", prefix="cs_import_")
        try:
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as fh:
                json.dump(
                    {
                        "remaining_entries": remaining,
                        "conflict_strategy": conflict_strategy,
                        "source_format": source_format,
                        "written_at": datetime.utcnow().isoformat() + "Z",
                    },
                    fh,
                    ensure_ascii=False,
                )
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            return Path(tmp_path)
        return Path(tmp_path)

    def _log_import(
        self,
        source_format: str,
        total: int,
        successful: int,
        failed: int,
    ) -> Optional[int]:
        event = "AUDIT_IMPORT_CSV" if source_format == "csv" else "AUDIT_IMPORT"
        try:
            return self.audit_logger.log_event(
                event_type=event,
                severity="INFO",
                source="vault_importer",
                details={
                    "source_format": source_format,
                    "total_entries": total,
                    "successful": successful,
                    "failed": failed,
                },
            )
        except Exception:
            return None


def _parse_strategy(strategy: str) -> ConflictResolution:
    try:
        return ConflictResolution(strategy.lower())
    except ValueError:
        return ConflictResolution.SKIP


def _make_unique_title(
    title: str,
    existing_index: Dict[Tuple[str, str], str],
    username: str = "",
) -> str:
    counter = 1
    candidate = f"{title} (imported)"
    while (candidate.lower(), username.lower()) in existing_index:
        counter += 1
        candidate = f"{title} (imported {counter})"
    return candidate


def _scan_entry_fields(entry: Dict[str, Any]) -> Optional[str]:
    text_fields = ("title", "username", "url", "notes")
    for field in text_fields:
        value = str(entry.get(field, ""))
        for pattern in _MALICIOUS_PATTERNS:
            if pattern.search(value):
                return (
                    f"Field '{field}' contains potentially malicious content "
                    f"(matched: {pattern.pattern!r})"
                )
    return None
