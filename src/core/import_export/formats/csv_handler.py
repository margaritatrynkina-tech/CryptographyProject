"""
CSV format handler for CryptoSafe import/export.

Implements Tasks 8 & 9 requirements:
- Export: passwords always replaced with "[ENCRYPTED]" (SEC-1, FMT-3)
- Import: flexible column mapping, UTF-8/UTF-16 BOM detection, Excel and
  RFC 4180 dialect support, UUID4 IDs for new entries (IMP-1, EXP-1)

Property tests supported:
- P2: CSV export never contains actual passwords
- P7: CSV parse → format → parse produces equivalent data
"""

from __future__ import annotations

import codecs
import csv
import io
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

# Password column is always masked in CSV output (SEC-1)
_PASSWORD_PLACEHOLDER = "[ENCRYPTED]"

# Canonical column order for CryptoSafe CSV exports
_EXPORT_FIELDNAMES = [
    "title",
    "username",
    "password",
    "url",
    "notes",
    "tags",
    "created_at",
    "updated_at",
]

# Columns that must be present for a valid import
_REQUIRED_IMPORT_COLUMNS = {"title"}

# Default mapping: CSV column name → vault entry field
_DEFAULT_COLUMN_MAP: Dict[str, str] = {
    "title": "title",
    "name": "title",
    "username": "username",
    "user": "username",
    "login": "username",
    "email": "username",
    "password": "password",
    "pass": "password",
    "url": "url",
    "uri": "url",
    "website": "url",
    "notes": "notes",
    "comment": "notes",
    "extra": "notes",
    "tags": "tags",
    "group": "tags",
    "grouping": "tags",
    "created_at": "created_at",
    "updated_at": "updated_at",
}


class CSVHandler:
    """Handles CSV export and import for CryptoSafe vault entries.

    All export operations mask passwords with ``[ENCRYPTED]``.
    Import operations support flexible column mapping and multiple
    CSV dialects / encodings.
    """

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    @staticmethod
    def export(
        entries: List[Dict[str, Any]],
        include_header: bool = True,
        dialect: str = "excel",
    ) -> str:
        """Serialise vault entries to CSV.

        Passwords are **always** replaced with ``[ENCRYPTED]`` regardless
        of the entry data (P2 / SEC-1).

        Args:
            entries: List of vault entry dicts.
            include_header: Whether to write the header row.
            dialect: ``"excel"`` (default) or ``"unix"`` (RFC 4180).

        Returns:
            UTF-8 CSV string.
        """
        output = io.StringIO()
        writer = csv.DictWriter(
            output,
            fieldnames=_EXPORT_FIELDNAMES,
            dialect=dialect,
            quoting=csv.QUOTE_ALL,
            extrasaction="ignore",
        )

        if include_header:
            writer.writeheader()

        for entry in entries:
            tags = entry.get("tags", "")
            if isinstance(tags, list):
                tags = ",".join(tags)

            row = {
                "title": entry.get("title", ""),
                "username": entry.get("username", ""),
                "password": _PASSWORD_PLACEHOLDER,   # SEC-1: never export plaintext
                "url": entry.get("url", ""),
                "notes": entry.get("notes", ""),
                "tags": tags,
                "created_at": _fmt_timestamp(entry.get("created_at")),
                "updated_at": _fmt_timestamp(entry.get("updated_at")),
            }
            writer.writerow(row)

        return output.getvalue()

    @staticmethod
    def export_to_file(
        entries: List[Dict[str, Any]],
        file_path: str,
        encoding: str = "utf-8-sig",  # UTF-8 with BOM for Excel compatibility
        dialect: str = "excel",
    ) -> int:
        """Write CSV export directly to *file_path*.

        Args:
            entries: Vault entries to export.
            file_path: Destination file path.
            encoding: File encoding (default ``utf-8-sig`` for Excel BOM).
            dialect: CSV dialect.

        Returns:
            Number of entries written.
        """
        csv_text = CSVHandler.export(entries, dialect=dialect)
        with open(file_path, "w", encoding=encoding, newline="") as fh:
            fh.write(csv_text)
        return len(entries)

    # ------------------------------------------------------------------
    # Import
    # ------------------------------------------------------------------

    @staticmethod
    def import_file(
        file_path: str,
        column_mapping: Optional[Dict[str, str]] = None,
        encrypt_passwords: bool = True,
        session_key: Optional[bytes] = None,
    ) -> Tuple[List[Dict[str, Any]], List[str]]:
        """Parse a CSV file and return vault-ready entry dicts.

        Handles UTF-8, UTF-8-BOM, and UTF-16 encodings automatically.
        Supports Excel and RFC 4180 dialects via ``csv.Sniffer``.

        Args:
            file_path: Path to the CSV file.
            column_mapping: Optional override mapping ``{csv_col: vault_field}``.
                Falls back to :data:`_DEFAULT_COLUMN_MAP` for unmapped columns.
            encrypt_passwords: When True, passwords are stored as-is (the
                caller is responsible for encrypting with the session key).
            session_key: Unused here; reserved for future in-handler encryption.

        Returns:
            Tuple of ``(entries, warnings)`` where *entries* is a list of
            vault entry dicts and *warnings* is a list of non-fatal messages.
        """
        raw_bytes = _read_file_bytes(file_path)
        text, encoding = _decode_csv_bytes(raw_bytes)

        dialect = _sniff_dialect(text)
        reader = csv.DictReader(io.StringIO(text), dialect=dialect)

        if reader.fieldnames is None:
            return [], ["CSV file appears to be empty or has no header row"]

        effective_map = _build_column_map(reader.fieldnames, column_mapping)
        warnings: List[str] = []
        entries: List[Dict[str, Any]] = []

        for line_num, row in enumerate(reader, start=2):
            entry, row_warnings = _map_row_to_entry(row, effective_map, line_num)
            warnings.extend(row_warnings)
            if entry is not None:
                entries.append(entry)

        return entries, warnings

    @staticmethod
    def import_csv(
        content: str,
        column_mapping: Optional[Dict[str, str]] = None,
    ) -> Tuple[List[Dict[str, Any]], List[str]]:
        """Parse CSV from a string (in-memory variant of :meth:`import_file`).

        Args:
            content: CSV text.
            column_mapping: Optional column mapping override.

        Returns:
            Tuple of ``(entries, warnings)``.
        """
        if not content.strip():
            return [], []

        dialect = _sniff_dialect(content)
        reader = csv.DictReader(io.StringIO(content), dialect=dialect)

        if reader.fieldnames is None:
            return [], ["CSV content has no header row"]

        effective_map = _build_column_map(reader.fieldnames, column_mapping)
        warnings: List[str] = []
        entries: List[Dict[str, Any]] = []

        for line_num, row in enumerate(reader, start=2):
            entry, row_warnings = _map_row_to_entry(row, effective_map, line_num)
            warnings.extend(row_warnings)
            if entry is not None:
                entries.append(entry)

        return entries, warnings

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    @staticmethod
    def validate(file_path: str) -> Tuple[bool, List[str]]:
        """Quick structural validation of a CSV file before import.

        Args:
            file_path: Path to the CSV file.

        Returns:
            Tuple of ``(is_valid, errors)``.
        """
        errors: List[str] = []
        try:
            raw_bytes = _read_file_bytes(file_path)
            text, _ = _decode_csv_bytes(raw_bytes)
            dialect = _sniff_dialect(text)
            reader = csv.DictReader(io.StringIO(text), dialect=dialect)
            fieldnames = reader.fieldnames or []
        except Exception as exc:
            return False, [f"Cannot read CSV file: {exc}"]

        normalised = {f.strip().lower() for f in fieldnames}
        mapped_targets = set()
        for col in normalised:
            target = _DEFAULT_COLUMN_MAP.get(col)
            if target:
                mapped_targets.add(target)

        missing = _REQUIRED_IMPORT_COLUMNS - mapped_targets
        if missing:
            errors.append(
                f"Required column(s) not found or not mappable: {', '.join(sorted(missing))}. "
                f"Available columns: {', '.join(sorted(normalised))}"
            )

        return len(errors) == 0, errors


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _read_file_bytes(file_path: str) -> bytes:
    with open(file_path, "rb") as fh:
        return fh.read()


def _decode_csv_bytes(raw: bytes) -> Tuple[str, str]:
    """Detect encoding (UTF-16, UTF-8-BOM, UTF-8) and decode *raw*."""
    # UTF-16 BOM detection
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16"), "utf-16"
    # UTF-8 BOM
    if raw[:3] == b"\xef\xbb\xbf":
        return raw[3:].decode("utf-8"), "utf-8-sig"
    # Default UTF-8
    try:
        return raw.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        return raw.decode("latin-1"), "latin-1"


def _sniff_dialect(text: str) -> csv.Dialect:
    """Use csv.Sniffer to detect the CSV dialect; fall back to excel."""
    sample = text[:4096]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
        return dialect
    except csv.Error:
        return csv.excel


def _build_column_map(
    fieldnames: List[str],
    override: Optional[Dict[str, str]],
) -> Dict[str, str]:
    """Build a mapping from CSV column name → vault field name.

    Priority: explicit *override* > :data:`_DEFAULT_COLUMN_MAP` > identity.
    """
    result: Dict[str, str] = {}
    for col in fieldnames:
        key = col.strip().lower()
        if override and col in override:
            result[col] = override[col]
        elif override and key in override:
            result[col] = override[key]
        elif key in _DEFAULT_COLUMN_MAP:
            result[col] = _DEFAULT_COLUMN_MAP[key]
        # Unmapped columns are silently ignored
    return result


def _map_row_to_entry(
    row: Dict[str, Optional[str]],
    column_map: Dict[str, str],
    line_num: int,
) -> Tuple[Optional[Dict[str, Any]], List[str]]:
    """Convert a CSV row dict to a vault entry dict.

    Returns ``(None, warnings)`` if the row is entirely empty.
    """
    warnings: List[str] = []
    entry: Dict[str, Any] = {
        "id": str(uuid.uuid4()),
        "title": "",
        "username": "",
        "password": "",
        "url": "",
        "notes": "",
        "tags": [],
    }

    has_data = False
    for csv_col, vault_field in column_map.items():
        raw_value = (row.get(csv_col) or "").strip()
        if not raw_value:
            continue
        has_data = True

        if vault_field == "tags":
            # Tags may be comma-separated within the cell
            entry["tags"] = [t.strip() for t in raw_value.split(",") if t.strip()]
        elif vault_field in entry:
            entry[vault_field] = raw_value

    if not has_data:
        return None, []

    if not entry["title"]:
        warnings.append(f"Line {line_num}: entry has no title, skipping")
        return None, warnings

    # Timestamps
    now = datetime.utcnow().isoformat() + "Z"
    entry.setdefault("created_at", now)
    entry.setdefault("updated_at", now)

    return entry, warnings


def _fmt_timestamp(value: Any) -> str:
    """Return an ISO 8601 string for *value*, or empty string if absent."""
    if not value:
        return ""
    if isinstance(value, datetime):
        return value.isoformat() + "Z"
    return str(value)
