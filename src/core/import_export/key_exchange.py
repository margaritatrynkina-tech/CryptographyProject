from __future__ import annotations

import base64
import hashlib
import json
import os
import time
import zlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
try:
    import qrcode
    from qrcode.constants import ERROR_CORRECT_L
    _QRCODE_AVAILABLE = True
except ImportError:  # pragma: no cover
    _QRCODE_AVAILABLE = False

try:
    from PIL import Image
    _PIL_AVAILABLE = True
except ImportError:  # pragma: no cover
    _PIL_AVAILABLE = False

try:
    from pyzbar import pyzbar as _pyzbar
    _PYZBAR_AVAILABLE = True
except ImportError:  # pragma: no cover
    _PYZBAR_AVAILABLE = False

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.backends import default_backend

# Maximum bytes that fit in a single QR code at ERROR_CORRECT_L (binary mode)
_QR_MAX_BYTES = 2953
# Default QR code validity window in seconds
_QR_DEFAULT_TTL_SECONDS = 300  # 5 minutes


class QRCodeService:

    def __init__(
        self,
        db_connection=None,
        ttl_seconds: int = _QR_DEFAULT_TTL_SECONDS,
    ) -> None:
        self.db = db_connection
        self.ttl_seconds = ttl_seconds

    def generate_qr_code(
        self,
        data: Any,
        payload_type: str = "generic",
    ) -> List["Image.Image"]:

        if not _QRCODE_AVAILABLE or not _PIL_AVAILABLE:
            raise RuntimeError(
                "qrcode[pil] and Pillow are required for QR code generation. "
                "Install them with: pip install 'qrcode[pil]' Pillow"
            )

        raw = self._serialise_payload(data)
        compressed = zlib.compress(raw, level=9)

        nonce = base64.b64encode(os.urandom(16)).decode("ascii")
        expires_at = (
            datetime.utcnow() + timedelta(seconds=self.ttl_seconds)
        ).isoformat() + "Z"

        envelope = json.dumps(
            {
                "type": payload_type,
                "nonce": nonce,
                "expires_at": expires_at,
                "data": base64.b64encode(compressed).decode("ascii"),
            },
            separators=(",", ":"),
        ).encode("utf-8")

        chunks = self._split_into_chunks(envelope)
        total = len(chunks)
        images: List[Image.Image] = []

        for idx, chunk_bytes in enumerate(chunks, start=1):
            checksum = hashlib.sha256(chunk_bytes).hexdigest()[:8]
            chunk_envelope = json.dumps(
                {
                    "chunk": idx,
                    "total": total,
                    "data": base64.b64encode(chunk_bytes).decode("ascii"),
                    "checksum": checksum,
                },
                separators=(",", ":"),
            )
            qr = qrcode.QRCode(
                error_correction=ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(chunk_envelope)
            qr.make(fit=True)
            images.append(qr.make_image(fill_color="black", back_color="white"))

        return images
    def decode_qr_image(self, image_path: str) -> Dict[str, Any]:

        if not _PIL_AVAILABLE:
            raise RuntimeError("Pillow is required. Install with: pip install Pillow")
        if not _PYZBAR_AVAILABLE:
            raise RuntimeError(
                "pyzbar is required. Install with: pip install pyzbar"
            )

        img = Image.open(image_path)
        decoded_objects = _pyzbar.decode(img)

        if not decoded_objects:
            raise ValueError(f"No QR code found in image: {image_path}")

        raw_data = decoded_objects[0].data.decode("utf-8")
        try:
            return json.loads(raw_data)
        except json.JSONDecodeError as exc:
            raise ValueError(f"QR code contains invalid JSON: {exc}") from exc

    def decode_qr_chunks(self, chunks: List[Dict[str, Any]]) -> Any:

        if not chunks:
            raise ValueError("No chunks provided")

        # Validate and sort
        total = chunks[0].get("total", 1)
        if len(chunks) != total:
            raise ValueError(
                f"Expected {total} chunks but received {len(chunks)}"
            )

        sorted_chunks = sorted(chunks, key=lambda c: c["chunk"])

        # Verify checksums and reassemble
        parts: List[bytes] = []
        for chunk in sorted_chunks:
            chunk_bytes = base64.b64decode(chunk["data"])
            expected_checksum = hashlib.sha256(chunk_bytes).hexdigest()[:8]
            if chunk.get("checksum") != expected_checksum:
                raise ValueError(
                    f"Checksum mismatch on chunk {chunk['chunk']}"
                )
            parts.append(chunk_bytes)

        envelope_bytes = b"".join(parts)
        envelope = json.loads(envelope_bytes.decode("utf-8"))

        # Check expiry
        expires_at_str = envelope.get("expires_at", "")
        if expires_at_str:
            expires_at = datetime.fromisoformat(expires_at_str.rstrip("Z"))
            if datetime.utcnow() > expires_at:
                raise ValueError("QR code payload has expired")

        # Decompress and deserialise
        compressed = base64.b64decode(envelope["data"])
        raw = zlib.decompress(compressed)
        return self._deserialise_payload(raw)

    def generate_keypair(
        self,
        algorithm: str = "RSA-2048",
    ) -> Tuple[bytes, bytes]:

        if algorithm == "RSA-2048":
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend(),
            )
        elif algorithm == "ECC-P256":
            private_key = ec.generate_private_key(
                ec.SECP256R1(),
                backend=default_backend(),
            )
        else:
            raise ValueError(
                f"Unsupported algorithm '{algorithm}'. "
                "Choose 'RSA-2048' or 'ECC-P256'."
            )

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return private_pem, public_pem

    def export_public_key_qr(self, public_key_pem: bytes) -> List["Image.Image"]:

        return self.generate_qr_code(
            data=public_key_pem.decode("utf-8"),
            payload_type="public_key",
        )

    def compute_key_fingerprint(self, public_key_pem: bytes) -> str:

        pub = serialization.load_pem_public_key(public_key_pem)
        der = pub.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return hashlib.sha256(der).hexdigest()

    def store_contact_key(
        self,
        name: str,
        identifier: str,
        public_key_pem: bytes,
    ) -> str:

        if self.db is None:
            raise RuntimeError("No database connection available")

        import uuid as _uuid
        contact_id = str(_uuid.uuid4())
        fingerprint = self.compute_key_fingerprint(public_key_pem)
        now = datetime.utcnow().isoformat() + "Z"

        self.db.execute(
            """
            INSERT INTO contacts
                (contact_id, name, identifier, public_key, key_fingerprint,
                 last_used, created_at)
            VALUES (?, ?, ?, ?, ?, NULL, ?)
            """,
            (
                contact_id,
                name,
                identifier,
                public_key_pem.decode("utf-8"),
                fingerprint,
                now,
            ),
        )
        return contact_id

    def revoke_key(self, contact_id: str) -> bool:

        if self.db is None:
            return False
        try:
            cursor = self.db.execute(
                "DELETE FROM contacts WHERE contact_id = ?", (contact_id,)
            )
            return cursor.rowcount > 0
        except Exception:
            return False

    def rotate_key(self, contact_id: str, new_public_key_pem: bytes) -> bool:

        if self.db is None:
            return False
        try:
            new_fingerprint = self.compute_key_fingerprint(new_public_key_pem)
            cursor = self.db.execute(
                """
                UPDATE contacts
                SET public_key = ?, key_fingerprint = ?
                WHERE contact_id = ?
                """,
                (
                    new_public_key_pem.decode("utf-8"),
                    new_fingerprint,
                    contact_id,
                ),
            )
            return cursor.rowcount > 0
        except Exception:
            return False

    def get_contact(self, contact_id: str) -> Optional[Dict[str, Any]]:

        if self.db is None:
            return None
        cursor = self.db.execute(
            "SELECT * FROM contacts WHERE contact_id = ?", (contact_id,)
        )
        row = cursor.fetchone()
        if row is None:
            return None
        return dict(row)

    @staticmethod
    def _serialise_payload(data: Any) -> bytes:

        if isinstance(data, bytes):
            return data
        if isinstance(data, str):
            return data.encode("utf-8")
        return json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    @staticmethod
    def _deserialise_payload(raw: bytes) -> Any:

        try:
            return json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return raw

    @staticmethod
    def _split_into_chunks(data: bytes) -> List[bytes]:

        return [
            data[i: i + _QR_MAX_BYTES]
            for i in range(0, len(data), _QR_MAX_BYTES)
        ]
