from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class ConflictResolution(str, Enum):

    SKIP = "skip"       # Keep existing entry, discard imported duplicate.
    REPLACE = "replace" # Overwrite existing entry with imported data.
    RENAME = "rename"   # Import entry under a modified title (adds suffix).
    MERGE = "merge"     # Merge non-conflicting fields from both entries.


class ExportFormat(str, Enum):

    JSON = "json"               # Native CryptoSafe encrypted JSON.
    CSV = "csv"                 # Generic CSV (passwords obfuscated).
    BITWARDEN = "bitwarden"     # Bitwarden-compatible JSON.
    LASTPASS = "lastpass"       # LastPass-compatible CSV.
    PDF = "pdf"                 # Read-only PDF report (export only).


class EncryptionMethod(str, Enum):

    PASSWORD = "password"           # AES-256-GCM with PBKDF2-derived key.
    PUBLIC_KEY = "public_key"       # RSA-OAEP / ECIES hybrid encryption.
    NONE = "none"                   # Plaintext (migration only, warns user).


@dataclass
class ValidationError:

    field: str
    message: str
    entry_id: Optional[str] = None

    def __str__(self) -> str:
        prefix = f"[{self.entry_id}] " if self.entry_id else ""
        return f"{prefix}{self.field}: {self.message}"


@dataclass
class ValidationResult:

    is_valid: bool
    errors: List[ValidationError] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    entry_count: Optional[int] = None
    detected_format: Optional[ExportFormat] = None


@dataclass
class Conflict:


    imported_entry_id: str
    existing_entry_id: str
    conflict_type: str
    resolution: Optional[ConflictResolution] = None



@dataclass
class ExportMetadata:

    format: ExportFormat
    entry_count: int
    export_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(
        default_factory=lambda: datetime.utcnow().isoformat() + "Z"
    )
    filter_criteria: Optional[Dict[str, Any]] = None
    audit_signature: Optional[str] = None
    public_key: Optional[str] = None
    app_version: str = "1.0"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "export_id": self.export_id,
            "timestamp": self.timestamp,
            "format": self.format.value,
            "entry_count": self.entry_count,
            "filter_criteria": self.filter_criteria,
            "audit_signature": self.audit_signature,
            "public_key": self.public_key,
            "app_version": self.app_version,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ExportMetadata":

        return cls(
            export_id=data.get("export_id", str(uuid.uuid4())),
            timestamp=data.get("timestamp", datetime.utcnow().isoformat() + "Z"),
            format=ExportFormat(data.get("format", "json")),
            entry_count=data.get("entry_count", 0),
            filter_criteria=data.get("filter_criteria"),
            audit_signature=data.get("audit_signature"),
            public_key=data.get("public_key"),
            app_version=data.get("app_version", "1.0"),
        )


@dataclass
class ExportResult:

    export_id: str
    entry_count: int
    file_path: str
    checksum: str
    format: ExportFormat
    duration_seconds: float = 0.0



@dataclass
class ImportResult:


    total_entries: int
    successful_imports: int
    failed_imports: int
    conflicts: List[Conflict] = field(default_factory=list)
    validation_errors: List[ValidationError] = field(default_factory=list)
    backup_created: bool = False
    audit_log_id: Optional[str] = None
    duration_seconds: float = 0.0

    @property
    def conflict_count(self) -> int:
        return len(self.conflicts)

    @property
    def error_count(self) -> int:
        return len(self.validation_errors)


@dataclass
class SharePackage:


    entry_data: str                          # base64-encoded ciphertext
    encryption_method: EncryptionMethod
    permissions: Dict[str, Any]
    expires_at: str
    share_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    sharer_info: Optional[str] = None
    created_at: str = field(
        default_factory=lambda: datetime.utcnow().isoformat() + "Z"
    )
    version: str = "1.0"
    integrity: Optional[Dict[str, str]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "share_id": self.share_id,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "permissions": self.permissions,
            "encryption_method": self.encryption_method.value,
            "entry_data": self.entry_data,
            "sharer_info": self.sharer_info,
            "integrity": self.integrity,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SharePackage":
        return cls(
            share_id=data.get("share_id", str(uuid.uuid4())),
            entry_data=data["entry_data"],
            encryption_method=EncryptionMethod(
                data.get("encryption_method", "password")
            ),
            permissions=data.get("permissions", {"read_only": True}),
            expires_at=data["expires_at"],
            sharer_info=data.get("sharer_info"),
            created_at=data.get("created_at", datetime.utcnow().isoformat() + "Z"),
            version=data.get("version", "1.0"),
            integrity=data.get("integrity"),
        )


@dataclass
class Contact:


    name: str
    identifier: str
    public_key: str                          # PEM-encoded
    key_fingerprint: str                     # SHA-256 hex of DER key
    contact_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    last_used: Optional[str] = None
    created_at: str = field(
        default_factory=lambda: datetime.utcnow().isoformat() + "Z"
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "contact_id": self.contact_id,
            "name": self.name,
            "identifier": self.identifier,
            "public_key": self.public_key,
            "key_fingerprint": self.key_fingerprint,
            "last_used": self.last_used,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Contact":
        return cls(
            contact_id=data.get("contact_id", str(uuid.uuid4())),
            name=data["name"],
            identifier=data["identifier"],
            public_key=data["public_key"],
            key_fingerprint=data["key_fingerprint"],
            last_used=data.get("last_used"),
            created_at=data.get("created_at", datetime.utcnow().isoformat() + "Z"),
        )
