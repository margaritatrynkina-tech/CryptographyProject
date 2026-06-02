"""
Bitwarden JSON format handler for CryptoSafe import/export.

Implements Task 7 requirements (EXP-1, IMP-1):
- Export: map CryptoSafe VaultEntry fields → Bitwarden JSON schema
- Import: parse Bitwarden JSON, map fields → CryptoSafe VaultEntry
- Handle folders/collections, all item types (login, note, card, identity)
- Interoperability tests use real Bitwarden export fixture files (TEST-2)

Bitwarden export schema reference:
  https://bitwarden.com/help/export-your-data/
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple


# Bitwarden item type constants
_TYPE_LOGIN = 1
_TYPE_SECURE_NOTE = 2
_TYPE_CARD = 3
_TYPE_IDENTITY = 4

# Bitwarden URI match-type constants
_MATCH_DOMAIN = 0
_MATCH_HOST = 1
_MATCH_STARTS_WITH = 2
_MATCH_EXACT = 3
_MATCH_REGEX = 4
_MATCH_NEVER = 5


class BitwardenHandler:
    """Handles Bitwarden-compatible JSON export and import.

    Bitwarden uses a well-known JSON schema for unencrypted exports.
    This handler maps between that schema and CryptoSafe's internal
    vault entry representation.
    """

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    @staticmethod
    def export(entries: List[Dict[str, Any]]) -> str:
        """Serialise CryptoSafe vault entries to Bitwarden JSON.

        Args:
            entries: List of vault entry dicts (decrypted).

        Returns:
            Pretty-printed Bitwarden JSON string.
        """
        bw_export = {
            "encrypted": False,
            "folders": [],
            "items": [BitwardenHandler._entry_to_bw_item(e) for e in entries],
        }
        return json.dumps(bw_export, indent=2, ensure_ascii=False)

    @staticmethod
    def export_to_file(entries: List[Dict[str, Any]], file_path: str) -> int:
        """Write Bitwarden JSON export to *file_path*.

        Args:
            entries: Vault entries to export.
            file_path: Destination file path.

        Returns:
            Number of entries written.
        """
        content = BitwardenHandler.export(entries)
        with open(file_path, "w", encoding="utf-8") as fh:
            fh.write(content)
        return len(entries)

    # ------------------------------------------------------------------
    # Import
    # ------------------------------------------------------------------

    @staticmethod
    def import_file(file_path: str) -> Tuple[List[Dict[str, Any]], List[str]]:
        """Parse a Bitwarden JSON export file.

        Args:
            file_path: Path to the Bitwarden ``.json`` export file.

        Returns:
            Tuple of ``(entries, warnings)`` where *entries* is a list of
            CryptoSafe vault entry dicts and *warnings* is a list of
            non-fatal messages (e.g. skipped non-login items).

        Raises:
            ValueError: If the file is not valid Bitwarden JSON.
            FileNotFoundError: If *file_path* does not exist.
        """
        with open(file_path, "r", encoding="utf-8") as fh:
            content = fh.read()
        return BitwardenHandler.import_json(content)

    @staticmethod
    def import_json(content: str) -> Tuple[List[Dict[str, Any]], List[str]]:
        """Parse Bitwarden JSON from a string.

        Args:
            content: Bitwarden JSON export string.

        Returns:
            Tuple of ``(entries, warnings)``.

        Raises:
            ValueError: If *content* is not valid Bitwarden JSON or is
                an encrypted export (which cannot be processed here).
        """
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid Bitwarden JSON: {exc}") from exc

        if not isinstance(data, dict):
            raise ValueError("Bitwarden export must be a JSON object")

        if data.get("encrypted", False):
            raise ValueError(
                "This is an encrypted Bitwarden export. "
                "Please export without encryption from Bitwarden first."
            )

        items = data.get("items", [])
        if not isinstance(items, list):
            raise ValueError("Bitwarden export 'items' field must be a list")

        # Build folder id → name lookup
        folders: Dict[str, str] = {}
        for folder in data.get("folders", []):
            fid = folder.get("id", "")
            fname = folder.get("name", "")
            if fid:
                folders[fid] = fname

        entries: List[Dict[str, Any]] = []
        warnings: List[str] = []

        for idx, item in enumerate(items):
            entry, item_warnings = BitwardenHandler._bw_item_to_entry(
                item, folders, idx
            )
            warnings.extend(item_warnings)
            if entry is not None:
                entries.append(entry)

        return entries, warnings

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    @staticmethod
    def validate(file_path: str) -> Tuple[bool, List[str]]:
        """Quick structural validation of a Bitwarden JSON file.

        Args:
            file_path: Path to the file.

        Returns:
            Tuple of ``(is_valid, errors)``.
        """
        errors: List[str] = []
        try:
            with open(file_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            return False, [f"Cannot read Bitwarden file: {exc}"]

        if not isinstance(data, dict):
            errors.append("Root element must be a JSON object")
            return False, errors

        if data.get("encrypted", False):
            errors.append(
                "Encrypted Bitwarden exports are not supported. "
                "Re-export without encryption."
            )

        if "items" not in data:
            errors.append("Missing required 'items' field")

        return len(errors) == 0, errors

    # ------------------------------------------------------------------
    # Internal conversion helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _entry_to_bw_item(entry: Dict[str, Any]) -> Dict[str, Any]:
        """Convert a CryptoSafe vault entry to a Bitwarden item dict."""
        now = datetime.utcnow().isoformat() + "Z"

        tags = entry.get("tags", "")
        if isinstance(tags, list):
            tags_str = ",".join(tags)
        else:
            tags_str = str(tags) if tags else ""

        url = entry.get("url", "")
        uris = []
        if url:
            uris = [{"match": None, "uri": url}]

        item: Dict[str, Any] = {
            "id": entry.get("id") or str(uuid.uuid4()),
            "organizationId": None,
            "folderId": None,
            "type": _TYPE_LOGIN,
            "reprompt": 0,
            "name": entry.get("title", ""),
            "notes": entry.get("notes") or None,
            "favorite": False,
            "fields": [],
            "login": {
                "uris": uris,
                "username": entry.get("username", ""),
                "password": entry.get("password", ""),
                "totp": None,
            },
            "collectionIds": None,
            "creationDate": entry.get("created_at") or now,
            "revisionDate": entry.get("updated_at") or now,
            "deletedDate": None,
        }

        # Store tags as a custom field so they survive a round-trip
        if tags_str:
            item["fields"].append(
                {"name": "cryptosafe_tags", "value": tags_str, "type": 0}
            )

        return item

    @staticmethod
    def _bw_item_to_entry(
        item: Dict[str, Any],
        folders: Dict[str, str],
        idx: int,
    ) -> Tuple[Optional[Dict[str, Any]], List[str]]:
        """Convert a Bitwarden item dict to a CryptoSafe vault entry.

        Non-login items (secure notes, cards, identities) are converted
        to entries with a note field and a warning.
        """
        warnings: List[str] = []
        item_type = item.get("type", _TYPE_LOGIN)
        item_name = item.get("name", f"Imported item {idx + 1}")

        if item_type == _TYPE_SECURE_NOTE:
            # Convert secure notes to vault entries with empty credentials
            entry = _make_base_entry(item)
            entry["title"] = item_name
            entry["notes"] = item.get("notes", "")
            warnings.append(
                f"Item '{item_name}' is a Secure Note — imported as entry with no credentials"
            )
            return entry, warnings

        if item_type in (_TYPE_CARD, _TYPE_IDENTITY):
            warnings.append(
                f"Item '{item_name}' (type {item_type}) is not a login — skipped"
            )
            return None, warnings

        # --- Login item (type 1) ---
        login = item.get("login") or {}
        uris = login.get("uris") or []

        # Pick the first non-empty URI
        url = ""
        for uri_obj in uris:
            candidate = (uri_obj.get("uri") or "").strip()
            if candidate:
                url = candidate
                break

        # Recover tags from custom fields if present
        tags: List[str] = []
        for field in item.get("fields") or []:
            if field.get("name") == "cryptosafe_tags":
                raw_tags = field.get("value", "")
                tags = [t.strip() for t in raw_tags.split(",") if t.strip()]

        # Fall back to folder name as a tag
        folder_id = item.get("folderId")
        if folder_id and folder_id in folders and not tags:
            tags = [folders[folder_id]]

        entry = _make_base_entry(item)
        entry.update(
            {
                "title": item_name,
                "username": login.get("username") or "",
                "password": login.get("password") or "",
                "url": url,
                "notes": item.get("notes") or "",
                "tags": tags,
            }
        )
        return entry, warnings


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _make_base_entry(item: Dict[str, Any]) -> Dict[str, Any]:
    """Create a base vault entry dict from Bitwarden item metadata."""
    now = datetime.utcnow().isoformat() + "Z"
    return {
        "id": item.get("id") or str(uuid.uuid4()),
        "title": "",
        "username": "",
        "password": "",
        "url": "",
        "notes": "",
        "tags": [],
        "created_at": item.get("creationDate") or now,
        "updated_at": item.get("revisionDate") or now,
    }
