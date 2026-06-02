"""
LastPass CSV format handler for CryptoSafe import/export.

Implements Task 8 requirements (EXP-1, IMP-1):
- Export: map CryptoSafe fields → LastPass CSV columns (with optional encryption)
- Import: parse LastPass CSV with columns:
    url, username, password, totp, extra, name, grouping, fav
- Handle LastPass-specific encoding and special characters (TEST-2)

LastPass CSV column reference:
  url, username, password, totp, extra, name, grouping, fav
"""

from __future__ import annotations

import base64
import csv
import io
import os
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


# LastPass canonical column order
_LP_FIELDNAMES = ["url", "username", "password", "totp", "extra", "name", "grouping", "fav"]

# Mapping from LastPass column → CryptoSafe vault field
_LP_TO_VAULT: Dict[str, str] = {
    "url": "url",
    "username": "username",
    "password": "password",
    "totp": "totp",
    "extra": "notes",
    "name": "title",
    "grouping": "tags",
    "fav": "favorite",
}

# Mapping from CryptoSafe vault field → LastPass column
_VAULT_TO_LP: Dict[str, str] = {v: k for k, v in _LP_TO_VAULT.items()}


class LastPassHandler:
    """Handles LastPass CSV export and import for CryptoSafe vault entries."""

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    @staticmethod
    def export(entries: List[Dict[str, Any]], password: Optional[str] = None) -> str:
        """Serialise CryptoSafe vault entries to LastPass CSV format.

        Args:
            entries: List of vault entry dicts (decrypted).
            password: Optional password for encrypting the CSV content.

        Returns:
            UTF-8 CSV string with LastPass column layout (optionally encrypted and base64-encoded).
        """
        output = io.StringIO()
        writer = csv.DictWriter(
            output,
            fieldnames=_LP_FIELDNAMES,
            quoting=csv.QUOTE_ALL,
            extrasaction="ignore",
        )
        writer.writeheader()

        for entry in entries:
            tags = entry.get("tags", "")
            if isinstance(tags, list):
                tags = ",".join(tags)

            row = {
                "url": entry.get("url", ""),
                "username": entry.get("username", ""),
                "password": entry.get("password", ""),
                "totp": entry.get("totp", ""),
                "extra": entry.get("notes", ""),
                "name": entry.get("title", ""),
                "grouping": tags,
                "fav": "1" if entry.get("favorite") else "0",
            }
            writer.writerow(row)

        csv_content = output.getvalue()
        
        # Encrypt if password provided
        if password:
            return LastPassHandler._encrypt_content(csv_content, password)
        
        return csv_content

    @staticmethod
    def export_to_file(entries: List[Dict[str, Any]], file_path: str) -> int:
        """Write LastPass CSV export to *file_path*.

        Args:
            entries: Vault entries to export.
            file_path: Destination file path.

        Returns:
            Number of entries written.
        """
        content = LastPassHandler.export(entries)
        with open(file_path, "w", encoding="utf-8", newline="") as fh:
            fh.write(content)
        return len(entries)

    # ------------------------------------------------------------------
    # Import
    # ------------------------------------------------------------------

    @staticmethod
    def import_file(file_path: str, password: Optional[str] = None) -> Tuple[List[Dict[str, Any]], List[str]]:
        """Parse a LastPass CSV export file.

        Args:
            file_path: Path to the LastPass ``.csv`` export file.
            password: Optional password for decrypting the file content.

        Returns:
            Tuple of ``(entries, warnings)``.

        Raises:
            FileNotFoundError: If *file_path* does not exist.
            ValueError: If the file cannot be parsed as LastPass CSV.
        """
        print(f"[DEBUG] LastPassHandler.import_file called")
        print(f"[DEBUG] File path: {file_path}")
        print(f"[DEBUG] Password provided: {bool(password)}")
        
        raw = _read_bytes(file_path)
        text = _decode(raw)
        
        print(f"[DEBUG] File content length: {len(text)} chars")
        print(f"[DEBUG] First 50 chars: {text[:50]}")
        
        # Try to decrypt if password provided and content looks encrypted
        if text.strip().startswith("ENCRYPTED:"):
            print("[DEBUG] Encrypted file detected")
            if password:
                print("[DEBUG] Attempting decryption...")
                try:
                    text = LastPassHandler._decrypt_content(text, password)
                    print(f"[DEBUG] Decryption successful, new length: {len(text)} chars")
                    print(f"[DEBUG] Decrypted first 100 chars: {text[:100]}")
                except Exception as exc:
                    print(f"[DEBUG] Decryption failed: {exc}")
                    raise
            else:
                print("[DEBUG] No password provided for encrypted file")
                raise ValueError("Password required to decrypt this LastPass CSV file")
        else:
            print("[DEBUG] File is not encrypted (no ENCRYPTED: prefix)")
        
        print("[DEBUG] Calling import_csv to parse content...")
        result = LastPassHandler.import_csv(text)
        print(f"[DEBUG] import_csv returned {len(result[0])} entries, {len(result[1])} warnings")
        return result

    @staticmethod
    def import_csv(content: str) -> Tuple[List[Dict[str, Any]], List[str]]:
        """Parse LastPass CSV from a string.

        Args:
            content: LastPass CSV text.

        Returns:
            Tuple of ``(entries, warnings)``.
        """
        print(f"[DEBUG] import_csv called with {len(content)} chars")
        
        if not content.strip():
            print("[DEBUG] Content is empty after strip()")
            return [], []

        reader = csv.DictReader(io.StringIO(content))
        if reader.fieldnames is None:
            print("[DEBUG] No fieldnames found in CSV")
            return [], ["LastPass CSV has no header row"]

        print(f"[DEBUG] CSV fieldnames: {reader.fieldnames}")
        
        # Normalise header names (LastPass sometimes uses different casing)
        normalised_fields = {f.strip().lower(): f for f in reader.fieldnames}
        print(f"[DEBUG] Normalised fields: {list(normalised_fields.keys())}")

        entries: List[Dict[str, Any]] = []
        warnings: List[str] = []
        now = datetime.utcnow().isoformat() + "Z"

        for line_num, row in enumerate(reader, start=2):
            # Normalise row keys
            norm_row = {k.strip().lower(): (v or "").strip() for k, v in row.items()}

            title = norm_row.get("name", "").strip()
            if not title:
                warnings.append(f"Line {line_num}: entry has no name/title, skipping")
                continue

            # Tags from grouping column
            grouping = norm_row.get("grouping", "")
            tags = [t.strip() for t in grouping.split(",") if t.strip()] if grouping else []

            entry: Dict[str, Any] = {
                "id": str(uuid.uuid4()),
                "title": title,
                "username": norm_row.get("username", ""),
                "password": norm_row.get("password", ""),
                "url": _clean_url(norm_row.get("url", "")),
                "notes": norm_row.get("extra", ""),
                "tags": tags,
                "totp": norm_row.get("totp", ""),
                "favorite": norm_row.get("fav", "0") == "1",
                "created_at": now,
                "updated_at": now,
            }
            entries.append(entry)

        print(f"[DEBUG] import_csv parsed {len(entries)} entries with {len(warnings)} warnings")
        return entries, warnings

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    @staticmethod
    def validate(file_path: str, password: Optional[str] = None) -> Tuple[bool, List[str]]:
        """Quick structural validation of a LastPass CSV file.

        Args:
            file_path: Path to the file.
            password: Optional password for decrypting encrypted files.

        Returns:
            Tuple of ``(is_valid, errors)``.
        """
        errors: List[str] = []
        try:
            raw = _read_bytes(file_path)
            text = _decode(raw)
            
            # Try to decrypt if password provided and content looks encrypted
            if password and text.strip().startswith("ENCRYPTED:"):
                try:
                    text = LastPassHandler._decrypt_content(text, password)
                except Exception as exc:
                    return False, [f"Cannot decrypt LastPass CSV: {exc}"]
            
            # Check if still encrypted (no password provided)
            if text.strip().startswith("ENCRYPTED:"):
                # Can't validate encrypted content without password
                return True, []  # Consider valid, will need password for actual import
            
            reader = csv.DictReader(io.StringIO(text))
            fieldnames = [f.strip().lower() for f in (reader.fieldnames or [])]
        except Exception as exc:
            return False, [f"Cannot read LastPass CSV: {exc}"]

        required = {"name", "username", "password"}
        missing = required - set(fieldnames)
        if missing:
            errors.append(
                f"Missing required LastPass columns: {', '.join(sorted(missing))}. "
                f"Found: {', '.join(sorted(fieldnames))}"
            )

        return len(errors) == 0, errors

    # ------------------------------------------------------------------
    # Encryption/Decryption
    # ------------------------------------------------------------------

    @staticmethod
    def _encrypt_content(content: str, password: str) -> str:
        """Encrypt CSV content with password using AES-256-GCM.
        
        Args:
            content: Plain CSV text
            password: Encryption password
            
        Returns:
            Encrypted content in format: ENCRYPTED:<salt>:<nonce>:<ciphertext_b64>
        """
        salt = os.urandom(16)
        nonce = os.urandom(12)
        
        # Derive key from password
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
        )
        key = kdf.derive(password.encode("utf-8"))
        
        # Encrypt
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, content.encode("utf-8"), None)
        
        # Format: ENCRYPTED:<salt_b64>:<nonce_b64>:<ciphertext_b64>
        salt_b64 = base64.b64encode(salt).decode("ascii")
        nonce_b64 = base64.b64encode(nonce).decode("ascii")
        cipher_b64 = base64.b64encode(ciphertext).decode("ascii")
        
        return f"ENCRYPTED:{salt_b64}:{nonce_b64}:{cipher_b64}"

    @staticmethod
    def _decrypt_content(encrypted_content: str, password: str) -> str:
        """Decrypt CSV content that was encrypted with _encrypt_content.
        
        Args:
            encrypted_content: Encrypted content in format ENCRYPTED:<salt>:<nonce>:<ciphertext_b64>
            password: Decryption password
            
        Returns:
            Decrypted CSV text
            
        Raises:
            ValueError: If decryption fails or format is invalid
        """
        if not encrypted_content.startswith("ENCRYPTED:"):
            raise ValueError("Content is not in encrypted format")
        
        parts = encrypted_content[10:].split(":", 2)  # Skip "ENCRYPTED:" prefix
        if len(parts) != 3:
            raise ValueError("Invalid encrypted content format")
        
        salt_b64, nonce_b64, cipher_b64 = parts
        
        try:
            salt = base64.b64decode(salt_b64)
            nonce = base64.b64decode(nonce_b64)
            ciphertext = base64.b64decode(cipher_b64)
        except Exception as exc:
            raise ValueError(f"Failed to decode encrypted content: {exc}")
        
        # Derive key from password
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
        )
        key = kdf.derive(password.encode("utf-8"))
        
        # Decrypt
        try:
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext.decode("utf-8")
        except Exception as exc:
            raise ValueError(f"Decryption failed — wrong password or corrupted file: {exc}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _read_bytes(file_path: str) -> bytes:
    with open(file_path, "rb") as fh:
        return fh.read()


def _decode(raw: bytes) -> str:
    """Detect and decode UTF-16, UTF-8-BOM, or UTF-8."""
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16")
    if raw[:3] == b"\xef\xbb\xbf":
        return raw[3:].decode("utf-8")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _clean_url(url: str) -> str:
    """Strip LastPass placeholder URLs like 'http://sn' (secure note marker)."""
    if url.lower() in ("http://sn", "https://sn", "sn"):
        return ""
    return url
