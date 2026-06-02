"""
Native CryptoSafe encrypted JSON format handler.

Implements the low-level serialisation / deserialisation layer for the
CryptoSafe native JSON export format (FMT-1).  Encryption and decryption
are handled by the higher-level VaultExporter / VaultImporter; this
module is responsible only for the JSON schema.

Export envelope schema (version 1.0):
{
    "version": "1.0",
    "cryptosafe_export": true,
    "timestamp": "<ISO 8601>",
    "metadata": { <ExportMetadata dict> },
    "encryption": {
        "method": "password" | "public_key" | "none",
        "salt": "<base64>",          # password method only
        "nonce": "<base64>",
        "iterations": 100000         # password method only
    },
    "data": "<base64 ciphertext>",
    "integrity": {
        "hash": "<sha256 hex of plaintext>",
        "signature": "<base64 audit signature>"  # optional
    }
}
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, Dict, List, Optional


_SCHEMA_VERSION = "1.0"


class JSONHandler:
    """Serialises and deserialises the CryptoSafe native JSON export format.

    This class does **not** perform encryption — it only builds and parses
    the JSON envelope.  The ``data`` field is expected to already be
    base64-encoded ciphertext (or plaintext for ``method="none"``).
    """

    # ------------------------------------------------------------------
    # Building the export envelope
    # ------------------------------------------------------------------

    @staticmethod
    def build_envelope(
        encrypted_data_b64: str,
        metadata: Dict[str, Any],
        encryption_info: Dict[str, Any],
        plaintext_hash: Optional[str] = None,
        audit_signature: Optional[str] = None,
    ) -> str:
        """Construct the JSON export envelope string.

        Args:
            encrypted_data_b64: Base64-encoded ciphertext (or plaintext
                when ``encryption_info["method"] == "none"``).
            metadata: :class:`ExportMetadata` dict.
            encryption_info: Dict describing the encryption parameters.
                Must contain at least ``"method"``.
            plaintext_hash: SHA-256 hex digest of the unencrypted payload,
                used for integrity verification after decryption.
            audit_signature: Optional base64-encoded audit log signature.

        Returns:
            Pretty-printed JSON string.
        """
        envelope: Dict[str, Any] = {
            "version": _SCHEMA_VERSION,
            "cryptosafe_export": True,
            "timestamp": metadata.get("timestamp", ""),
            "metadata": metadata,
            "encryption": encryption_info,
            "data": encrypted_data_b64,
            "integrity": {
                "hash": plaintext_hash or "",
                "signature": audit_signature or "",
            },
        }
        return json.dumps(envelope, indent=2, ensure_ascii=False, sort_keys=False)

    # ------------------------------------------------------------------
    # Parsing the export envelope
    # ------------------------------------------------------------------

    @staticmethod
    def parse_envelope(content: str) -> Dict[str, Any]:
        """Parse and validate a CryptoSafe JSON export envelope.

        Args:
            content: Raw JSON string from an export file.

        Returns:
            The parsed envelope dict.

        Raises:
            ValueError: If the content is not valid JSON, is missing
                required fields, or has an unsupported schema version.
        """
        try:
            envelope = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON: {exc}") from exc

        if not isinstance(envelope, dict):
            raise ValueError("Export file root must be a JSON object")

        if not envelope.get("cryptosafe_export"):
            raise ValueError(
                "Not a CryptoSafe export file (missing 'cryptosafe_export' flag)"
            )

        version = envelope.get("version", "")
        if version != _SCHEMA_VERSION:
            raise ValueError(
                f"Unsupported export schema version '{version}'. "
                f"Expected '{_SCHEMA_VERSION}'."
            )

        for required in ("metadata", "encryption", "data", "integrity"):
            if required not in envelope:
                raise ValueError(f"Export envelope missing required field: '{required}'")

        return envelope

    # ------------------------------------------------------------------
    # Integrity helpers
    # ------------------------------------------------------------------

    @staticmethod
    def compute_hash(plaintext: bytes) -> str:
        """Return the SHA-256 hex digest of *plaintext*.

        Args:
            plaintext: Raw bytes of the unencrypted export payload.

        Returns:
            Lowercase hex string.
        """
        return hashlib.sha256(plaintext).hexdigest()

    @staticmethod
    def verify_hash(plaintext: bytes, expected_hash: str) -> bool:
        """Verify that *plaintext* matches *expected_hash*.

        Args:
            plaintext: Decrypted payload bytes.
            expected_hash: SHA-256 hex digest stored in the envelope.

        Returns:
            True if the hash matches, False otherwise.
        """
        if not expected_hash:
            return True  # No hash stored — skip verification
        actual = hashlib.sha256(plaintext).hexdigest()
        # Constant-time comparison to prevent timing attacks
        import hmac as _hmac
        return _hmac.compare_digest(actual, expected_hash.lower())

    # ------------------------------------------------------------------
    # Entry serialisation helpers
    # ------------------------------------------------------------------

    @staticmethod
    def serialise_entries(entries: List[Dict[str, Any]]) -> bytes:
        """Serialise a list of vault entries to compact JSON bytes.

        Args:
            entries: List of vault entry dicts.

        Returns:
            UTF-8 encoded JSON bytes.
        """
        return json.dumps(
            entries,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")

    @staticmethod
    def deserialise_entries(data: bytes) -> List[Dict[str, Any]]:
        """Deserialise vault entries from JSON bytes.

        Args:
            data: UTF-8 encoded JSON bytes (list of entry dicts).

        Returns:
            List of vault entry dicts.

        Raises:
            ValueError: If *data* is not a valid JSON list.
        """
        try:
            entries = json.loads(data.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError(f"Cannot deserialise entries: {exc}") from exc

        if not isinstance(entries, list):
            raise ValueError("Entries payload must be a JSON array")

        return entries

    # ------------------------------------------------------------------
    # Format detection
    # ------------------------------------------------------------------

    @staticmethod
    def is_cryptosafe_export(content: str) -> bool:
        """Return True if *content* looks like a CryptoSafe JSON export.

        Args:
            content: File content string (first few KB is sufficient).

        Returns:
            True if the ``cryptosafe_export`` flag is present.
        """
        try:
            data = json.loads(content)
            return bool(data.get("cryptosafe_export"))
        except (json.JSONDecodeError, AttributeError):
            return False
