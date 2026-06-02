from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

from src.core.import_export.models import (
    Contact,
    EncryptionMethod,
    SharePackage,
)


class SharingService:


    DEFAULT_EXPIRY_DAYS = 7
    MIN_EXPIRY_DAYS = 1
    MAX_EXPIRY_DAYS = 30

    def __init__(
        self,
        db_connection,
        encryption_service,
        audit_logger,
        entry_manager,
    ) -> None:
        self.db = db_connection
        self.encryption_service = encryption_service
        self.audit_logger = audit_logger
        self.entry_manager = entry_manager

    def share_entry(
        self,
        entry_id: str,
        recipient: str,
        permissions: Dict[str, Any],
        expires_in_days: int = DEFAULT_EXPIRY_DAYS,
        encryption_method: EncryptionMethod = EncryptionMethod.PASSWORD,
        password: Optional[str] = None,
        recipient_public_key: Optional[bytes] = None,
    ) -> Dict[str, Any]:

        if expires_in_days < self.MIN_EXPIRY_DAYS or expires_in_days > self.MAX_EXPIRY_DAYS:
            raise ValueError(
                f"expires_in_days must be between {self.MIN_EXPIRY_DAYS} "
                f"and {self.MAX_EXPIRY_DAYS}"
            )

        entry = self._get_entry(entry_id)
        share_id = str(uuid.uuid4())
        expires_at = (
            datetime.utcnow() + timedelta(days=expires_in_days)
        ).isoformat() + "Z"

        filtered = self._filter_entry_for_sharing(entry, permissions)
        package = self._create_share_package(
            filtered,
            share_id,
            permissions,
            expires_at,
            encryption_method,
            password=password,
            recipient_public_key=recipient_public_key,
        )

        self._persist_share_record(
            share_id=share_id,
            entry_id=entry_id,
            recipient=recipient,
            permissions=permissions,
            expires_at=expires_at,
            encryption_method=encryption_method,
        )
        self._log_share_event(entry_id, recipient, share_id)

        return {
            "share_id": share_id,
            "package": package.to_dict(),
            "expires_at": expires_at,
            "permissions": permissions,
        }

    def import_shared_entry(
        self,
        package_dict: Dict[str, Any],
        password: Optional[str] = None,
        private_key: Optional[bytes] = None,
        save_to_vault: bool = True,
    ) -> Dict[str, Any]:

        package = SharePackage.from_dict(package_dict)
        self._verify_not_expired(package.expires_at)
        self._verify_integrity(package)

        entry_data = self._decrypt_package(package, password, private_key)

        saved = False
        if save_to_vault:
            self.entry_manager.add_entry(entry_data)
            saved = True

        return {"entry": entry_data, "saved": saved}

    def revoke_share(self, share_id: str) -> bool:

        try:
            self.db.execute(
                "UPDATE shared_entries SET expires_at = ? WHERE shared_id = ?",
                (datetime.utcnow().isoformat() + "Z", share_id),
            )
            return True
        except Exception:
            return False

    def _get_entry(self, entry_id: str) -> Dict[str, Any]:
        entry = self.entry_manager.get_entry(entry_id)
        if entry is None:
            raise KeyError(f"Entry '{entry_id}' not found in vault")
        return entry

    def _filter_entry_for_sharing(
        self,
        entry: Dict[str, Any],
        permissions: Dict[str, Any],
    ) -> Dict[str, Any]:

        allowed = {"title", "username", "url", "notes", "tags"}
        if not permissions.get("read_only", True):
            allowed.add("password")
        return {k: v for k, v in entry.items() if k in allowed}

    def _create_share_package(
        self,
        entry_data: Dict[str, Any],
        share_id: str,
        permissions: Dict[str, Any],
        expires_at: str,
        encryption_method: EncryptionMethod,
        password: Optional[str],
        recipient_public_key: Optional[bytes],
    ) -> SharePackage:
        plaintext = json.dumps(entry_data, ensure_ascii=False).encode("utf-8")

        if encryption_method == EncryptionMethod.PASSWORD:
            if not password:
                raise ValueError("password is required for PASSWORD encryption method")
            encrypted_b64 = self._encrypt_with_password(plaintext, password)
        elif encryption_method == EncryptionMethod.PUBLIC_KEY:
            if not recipient_public_key:
                raise ValueError(
                    "recipient_public_key is required for PUBLIC_KEY encryption method"
                )
            encrypted_b64 = self._encrypt_with_public_key(plaintext, recipient_public_key)
        else:
            raise ValueError(f"Unsupported encryption method: {encryption_method}")

        integrity = self._compute_integrity(encrypted_b64, share_id, expires_at)

        return SharePackage(
            share_id=share_id,
            entry_data=encrypted_b64,
            encryption_method=encryption_method,
            permissions=permissions,
            expires_at=expires_at,
            integrity=integrity,
        )

    def _encrypt_with_password(self, plaintext: bytes, password: str) -> str:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes

        salt = os.urandom(16)
        nonce = os.urandom(12)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
        )
        key = kdf.derive(password.encode("utf-8"))

        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        # Zero out key material
        key_buf = bytearray(key)
        for i in range(len(key_buf)):
            key_buf[i] = 0

        payload = {
            "method": "password",
            "salt": base64.b64encode(salt).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        }
        return base64.b64encode(
            json.dumps(payload).encode("utf-8")
        ).decode("ascii")

    def _encrypt_with_public_key(self, plaintext: bytes, public_key: bytes) -> str:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes, serialization

        sym_key = os.urandom(32)
        nonce = os.urandom(12)

        aesgcm = AESGCM(sym_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        pub = serialization.load_pem_public_key(public_key)
        encrypted_key = pub.encrypt(
            sym_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # Zero out symmetric key
        sym_buf = bytearray(sym_key)
        for i in range(len(sym_buf)):
            sym_buf[i] = 0

        payload = {
            "method": "public_key",
            "encrypted_key": base64.b64encode(encrypted_key).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        }
        return base64.b64encode(
            json.dumps(payload).encode("utf-8")
        ).decode("ascii")

    def _decrypt_package(
        self,
        package: SharePackage,
        password: Optional[str],
        private_key: Optional[bytes],
    ) -> Dict[str, Any]:
        raw = json.loads(base64.b64decode(package.entry_data).decode("utf-8"))
        method = raw.get("method")

        if method == "password":
            if not password:
                raise ValueError("Password required to decrypt this share package")
            plaintext = self._decrypt_password_payload(raw, password)
        elif method == "public_key":
            if not private_key:
                raise ValueError("Private key required to decrypt this share package")
            plaintext = self._decrypt_pubkey_payload(raw, private_key)
        else:
            raise ValueError(f"Unknown encryption method in package: {method}")

        return json.loads(plaintext.decode("utf-8"))

    def _decrypt_password_payload(self, raw: Dict, password: str) -> bytes:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes

        salt = base64.b64decode(raw["salt"])
        nonce = base64.b64decode(raw["nonce"])
        ciphertext = base64.b64decode(raw["ciphertext"])

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
        )
        key = kdf.derive(password.encode("utf-8"))
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)

    def _decrypt_pubkey_payload(self, raw: Dict, private_key: bytes) -> bytes:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes, serialization

        encrypted_key = base64.b64decode(raw["encrypted_key"])
        nonce = base64.b64decode(raw["nonce"])
        ciphertext = base64.b64decode(raw["ciphertext"])

        priv = serialization.load_pem_private_key(private_key, password=None)
        sym_key = priv.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        aesgcm = AESGCM(sym_key)
        return aesgcm.decrypt(nonce, ciphertext, None)

    def _compute_integrity(
        self, encrypted_b64: str, share_id: str, expires_at: str
    ) -> Dict[str, str]:

        secret = os.urandom(32)
        msg = f"{share_id}:{expires_at}:{encrypted_b64}".encode("utf-8")
        tag = hmac.new(secret, msg, hashlib.sha256).hexdigest()
        return {
            "hmac": tag,
            "secret": base64.b64encode(secret).decode("ascii"),
        }

    def _verify_integrity(self, package: SharePackage) -> None:

        if not package.integrity:
            return  # Packages without integrity data are accepted (legacy)
        secret = base64.b64decode(package.integrity["secret"])
        msg = (
            f"{package.share_id}:{package.expires_at}:{package.entry_data}"
        ).encode("utf-8")
        expected = hmac.new(secret, msg, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, package.integrity["hmac"]):
            raise ValueError("Share package integrity check failed — possible tampering")

    def _verify_not_expired(self, expires_at: str) -> None:
        expiry = datetime.fromisoformat(expires_at.rstrip("Z"))
        if datetime.utcnow() > expiry:
            raise ValueError("Share package has expired")

    def _persist_share_record(
        self,
        share_id: str,
        entry_id: str,
        recipient: str,
        permissions: Dict[str, Any],
        expires_at: str,
        encryption_method: EncryptionMethod,
    ) -> None:
        try:
            self.db.execute(
                """
                INSERT INTO shared_entries
                    (shared_id, original_entry_id, encryption_method,
                     recipient_info, permissions, shared_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    share_id,
                    entry_id,
                    encryption_method.value,
                    recipient,
                    json.dumps(permissions),
                    datetime.utcnow().isoformat() + "Z",
                    expires_at,
                ),
            )
        except Exception:
            pass  # Non-fatal: share still works without DB record

    def _log_share_event(
        self, entry_id: str, recipient: str, share_id: str
    ) -> None:
        try:
            self.audit_logger.log(
                event_type="AUDIT_SHARE",
                details={
                    "entry_id": entry_id,
                    "recipient": recipient,
                    "share_id": share_id,
                },
            )
        except Exception:
            pass


    def copy_share_link_to_clipboard(self, share_id: str) -> bool:
        try:
            # Get the share package from database
            cursor = self.db.execute(
                "SELECT * FROM shared_entries WHERE shared_id = ?",
                (share_id,)
            )
            row = cursor.fetchone()
            if not row:
                return False
                
            # Get the entry data
            entry = self._get_entry(row["original_entry_id"])
            permissions = json.loads(row["permissions"])
            
            # Recreate the share package
            package = self._create_share_package(
                entry_data=self._filter_entry_for_sharing(entry, permissions),
                share_id=share_id,
                permissions=permissions,
                expires_at=row["expires_at"],
                encryption_method=EncryptionMethod(row["encryption_method"]),
                password=None,  # Can't get original password
                recipient_public_key=None,
            )
            
            # Convert to JSON string
            package_json = json.dumps(package.to_dict(), indent=2, ensure_ascii=False)
            
            # Use ClipboardService to copy
            from src.core.clipboard.clipboard_service import ClipboardService
            clipboard_service = ClipboardService()
            clipboard_service.copy_to_clipboard(
                package_json,
                data_type="share_package",
                source_entry_id=row["original_entry_id"],
                auto_clear_seconds=30
            )
            
            return True
            
        except Exception as e:
            print(f"Error copying share to clipboard: {e}")
            return False

    def load_qr_from_clipboard_image(self) -> Optional[Dict[str, Any]]:
        try:
            # Check if clipboard contains an image
            import tkinter as tk
            root = tk.Tk()
            root.withdraw()
            
            try:
                # Try to get image from clipboard
                image = root.clipboard_get(type='image/png')
                if image:
                    # Save to temp file and decode
                    import tempfile
                    with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as tmp:
                        tmp.write(image)
                        tmp_path = tmp.name
                    
                    try:
                        from src.core.import_export.key_exchange import QRCodeService
                        svc = QRCodeService(db_connection=self.db)
                        chunk = svc.decode_qr_image(tmp_path)
                        
                        # If it's a single chunk, return it
                        if chunk.get("total") == 1:
                            return svc.decode_qr_chunks([chunk])
                        else:
                            # Multi-chunk QR - need all chunks
                            return {"chunk": chunk, "needs_more_chunks": True}
                    finally:
                        import os
                        os.unlink(tmp_path)
            except tk.TclError:
                # No image in clipboard
                pass
                
            return None
            
        except Exception as e:
            print(f"Error loading QR from clipboard: {e}")
            return None
