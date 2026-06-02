# Implementation Plan

## Overview

Sprint 6 implementation plan for CryptoSafe Manager Import/Export functionality. Covers secure vault import/export, encrypted entry sharing, QR code key exchange, and Bitwarden/LastPass interoperability.

## Tasks

- [ ] 1. Create import/export module directory structure
  - Create `src/core/import_export/__init__.py`
  - Create `src/core/import_export/exporter.py` skeleton with `VaultExporter` class
  - Create `src/core/import_export/importer.py` skeleton with `VaultImporter` class
  - Create `src/core/import_export/sharing_service.py` skeleton with `SharingService` class
  - Create `src/core/import_export/key_exchange.py` skeleton with `QRCodeService` class
  - Create `src/core/import_export/formats/__init__.py`
  - Create `src/core/import_export/formats/json_handler.py` skeleton
  - Create `src/core/import_export/formats/csv_handler.py` skeleton
  - Create `src/core/import_export/formats/bitwarden_handler.py` skeleton
  - Create `src/core/import_export/formats/lastpass_handler.py` skeleton
  - **Requirement**: ARC-1

- [ ] 2. Create database schema extensions
  - Add `shared_entries` table migration to `src/database/db.py`: shared_id, original_entry_id, encryption_method, recipient_info, permissions, shared_at, expires_at
  - Add `import_export_history` table migration: operation_type, format, encryption_method, entry_count, file_size, checksum, verification_status, timestamp
  - Add `contacts` table migration: contact_id, name, identifier, public_key, key_fingerprint, last_used, created_at
  - Write migration function that creates all three tables if they don't exist
  - Write unit tests verifying table creation and schema
  - **Requirement**: DB-1, DB-2, DB-3

- [ ] 3. Define export/import data models
  - Create `src/core/import_export/models.py`
  - Implement `ExportMetadata` dataclass: export_id (UUID4), timestamp (ISO8601), format, entry_count, filter_criteria, audit_signature, public_key
  - Implement `ImportResult` dataclass: total_entries, successful_imports, failed_imports, conflicts, validation_errors, backup_created, audit_log_id
  - Implement `ConflictResolution` enum: SKIP, REPLACE, RENAME, MERGE
  - Implement `ValidationError` dataclass: field, message, entry_id
  - Implement `SharePackage` dataclass: share_id, entry_data, encryption_method, permissions, expires_at, sharer_info
  - Implement `Contact` dataclass: contact_id, name, identifier, public_key, key_fingerprint, last_used
  - Write unit tests for serialization/deserialization of all models
  - **Requirement**: ARC-1

- [ ] 4. Implement key separation architecture
  - Add `derive_export_key(password, salt, iterations=100000)` to `src/core/import_export/exporter.py` using PBKDF2-HMAC-SHA256
  - Ensure export key derivation is completely separate from master vault key derivation
  - Add `generate_export_salt()` helper returning `os.urandom(16)`
  - Add `clear_key_from_memory(key_bytes)` using `ctypes` or bytearray zeroing
  - Write security tests verifying export key != master key for same password
  - **Requirement**: ARC-2, SEC-3, SEC-4

- [ ] 5. Implement native encrypted JSON exporter
  - Implement `VaultExporter.export_vault(entry_ids, password, public_key, format)` in `exporter.py`
  - Implement `_encrypt_with_password(data, password)`: AES-256-GCM, random salt+nonce, PBKDF2 100k iterations
  - Implement `_encrypt_with_public_key(data, public_key)`: RSA-OAEP hybrid encryption
  - Output format: `{"version":"1.0","cryptosafe_export":true,"timestamp":"...","encryption":{...},"data":"base64...","integrity":{"hash":"sha256...","signature":"base64..."}}`
  - Add integrity hash using SHA-256 over sorted JSON
  - Log export to `import_export_history` table
  - Write property test: export then decrypt manually verifies data integrity
  - **Requirement**: EXP-2, FMT-1, SEC-1, SEC-3

- [ ] 6. Implement native encrypted JSON importer
  - Implement `VaultImporter.import_json(file_path, password, conflict_strategy)` in `importer.py`
  - Implement `_decrypt_with_password(package, password)`: reverse of export encryption
  - Implement `_decrypt_with_private_key(package, private_key)`: RSA-OAEP decryption
  - Validate integrity hash before decryption attempt
  - Re-encrypt entries with current session key after import
  - Log import to `import_export_history` table
  - Write property test: export → import round-trip preserves all entry fields (TEST-1)
  - **Requirement**: IMP-2, IMP-4, SEC-4

- [ ] 7. Implement Bitwarden JSON format support
  - Implement `BitwardenHandler.export(entries)` in `formats/bitwarden_handler.py`: map CryptoSafe fields to Bitwarden JSON schema
  - Implement `BitwardenHandler.import_file(file_path)`: parse Bitwarden JSON, map fields to CryptoSafe `VaultEntry`
  - Handle Bitwarden field mappings: `login.username`, `login.password`, `login.uris[0].uri`, `notes`, `name`
  - Handle Bitwarden folder structure and collections
  - Write interoperability tests using sample Bitwarden export fixture (TEST-2)
  - **Requirement**: EXP-1, IMP-1

- [ ] 8. Implement LastPass CSV format support
  - Implement `LastPassHandler.export(entries)` in `formats/lastpass_handler.py`: map to LastPass CSV columns
  - Implement `LastPassHandler.import_file(file_path)`: parse LastPass CSV with columns: url, username, password, totp, extra, name, grouping, fav
  - Handle LastPass-specific encoding and special characters
  - Write interoperability tests using sample LastPass export fixture (TEST-2)
  - **Requirement**: EXP-1, IMP-1

- [ ] 9. Implement CSV exporter and importer
  - Implement `CSVHandler.export(entries)` in `formats/csv_handler.py`: title, username, url, notes, tags, created_at, updated_at — password column always `[ENCRYPTED]`
  - Implement `CSVHandler.import_file(file_path, column_mapping)`: flexible column mapping, encrypt imported passwords with session key
  - Support UTF-8 and UTF-16 with BOM detection
  - Support Excel and RFC 4180 CSV dialects
  - Generate unique UUID4 IDs for imported entries
  - Write property test: CSV export never contains actual passwords (P2)
  - Write property test: CSV parse → format → parse produces equivalent data (P7)
  - **Requirement**: EXP-1, IMP-1, FMT-3, SEC-1

- [ ] 10. Implement import validation and conflict resolution
  - Implement `VaultImporter.validate_import_file(file_path, format)` returning `ValidationResult`
  - Implement `ConflictDetector.detect(existing_entries, imported_entries)` returning list of conflicts
  - Implement `ConflictResolver.resolve(conflicts, strategy)` for SKIP, REPLACE, RENAME, MERGE
  - Implement `VaultImporter.create_backup()` creating timestamped vault backup before destructive imports
  - Implement dry-run mode: preview changes without committing
  - Implement merge mode: add new entries, update existing
  - Implement replace mode: clear vault and import
  - Write property test: after any conflict resolution strategy, no duplicate (title+username) entries exist (P3)
  - **Requirement**: IMP-2, IMP-3, IMP-4

- [ ] 11. Implement import security measures
  - Add file size limit check (default 10MB, configurable) before processing
  - Add 30-second processing timeout using `threading.Timer`
  - Implement malicious content scanner: detect `<script>`, `javascript:`, path traversal patterns
  - Validate encryption header before attempting decryption
  - Clear all partially decrypted data on any failure using `finally` blocks
  - Write security tests: oversized file rejected, timeout enforced, malicious content blocked
  - **Requirement**: IMP-4, SEC-2, SEC-4, SEC-5, ERR-4

- [ ] 12. Implement export options and security
  - Add `export_options` parameter to `VaultExporter.export_vault`: field exclusions, encryption strength (128/256-bit), GZIP compression
  - Implement selective entry export: accept list of entry IDs, default to all
  - Implement tag-based and date-range filtering for batch export
  - Generate new random encryption key for each export (never reuse)
  - Delete temporary files in `finally` block after export completes
  - Write property test: filtered export result is always a subset of full vault (P4)
  - **Requirement**: ARC-3, EXP-3, EXP-4

- [ ] 13. Implement sharing service core
  - Implement `SharingService.share_entry(entry_id, recipient, permissions, expires_in_days)` in `sharing_service.py`
  - Create share record in `shared_entries` table
  - Implement `SharingService.import_shared_entry(package, password_or_key, save_to_vault)` for recipient workflow
  - Implement `SharingService.revoke_share(share_id)` marking share as expired
  - Support permissions: `{"read_only": True, "expiration": "2024-01-22T00:00:00Z"}`
  - Log all share events to audit system with recipient info
  - Write unit tests for full share → receive → save workflow
  - **Requirement**: SHR-1, SHR-2, SHR-3, SHR-4, INT-2

- [ ] 14. Implement sharing encryption methods
  - Implement `SharingService._encrypt_share_password(entry_data, password)`: AES-256-GCM, PBKDF2 100k iterations, random salt
  - Implement `SharingService._encrypt_share_pubkey(entry_data, public_key)`: RSA-OAEP/AES-256-GCM hybrid
  - Implement ECIES support for ECC P-256 keys
  - Implement ephemeral key exchange for forward secrecy
  - Add HMAC-SHA256 integrity tag to all share packages
  - Verify HMAC before any decryption attempt
  - Write cryptographic tests: tampered package rejected, correct key decrypts successfully (TEST-3)
  - **Requirement**: CRY-1, CRY-2, CRY-3, CRY-4

- [ ] 15. Implement share package format
  - Define share package structure in `models.py`: `{"version":"1.0","share_id":"...","created_at":"...","expires_at":"...","permissions":{...},"encryption":{...},"data":"base64...","integrity":{"hmac":"..."}}`
  - Include only selected entry fields based on permissions (exclude password if read-only)
  - Implement `SharePackage.serialize()` and `SharePackage.deserialize(data)`
  - Write format validation tests
  - **Requirement**: SHR-2, FMT-2

- [ ] 16. Implement QR code generation service
  - Implement `QRCodeService.generate_qr_code(data, payload_type)` in `key_exchange.py`
  - Use `qrcode` library with `ERROR_CORRECT_L` error correction
  - Implement chunking: split payloads >2953 bytes into numbered chunks with checksums
  - Add chunk metadata: `{"chunk":1,"total":3,"data":"base64...","checksum":"sha256[:8]"}`
  - Compress payload with `zlib` before encoding
  - Add nonce and timestamp to prevent replay attacks
  - QR code validity: 5 minutes default
  - Write unit tests: generate → decode round-trip preserves data (TEST-4)
  - **Requirement**: QR-1, QR-4

- [ ] 17. Implement QR code scanning and decoding
  - Implement `QRCodeService.decode_qr_image(image_path)` using `Pillow` + `pyzbar` or `opencv`
  - Implement `QRCodeService.decode_qr_chunks(chunks)`: validate checksums, sort by chunk number, reassemble, decompress
  - Handle malformed/invalid QR codes gracefully with descriptive errors
  - Validate payload integrity after reassembly
  - Write tests: valid QR decoded correctly, malformed QR returns error (TEST-4)
  - **Requirement**: QR-2

- [ ] 18. Implement public key exchange
  - Implement `QRCodeService.generate_keypair(algorithm)` supporting RSA-2048 and ECC P-256
  - Implement `QRCodeService.export_public_key_qr(public_key)` generating QR code of PEM-encoded public key
  - Store received public keys in `contacts` table with fingerprint (SHA-256 of key)
  - Implement `QRCodeService.revoke_key(contact_id)` and `rotate_key(contact_id, new_key)`
  - Write security tests: key fingerprint matches key, revoked key rejected
  - **Requirement**: QR-3

- [ ] 19. Integrate with vault system and audit logging
  - Wire `VaultExporter` to use `EntryManager.get_entries(ids)` for entry retrieval
  - Wire `VaultImporter` to use `EntryManager.add_entry()` and `EntryManager.update_entry()`
  - Add audit log calls: `AUDIT_EXPORT`, `AUDIT_EXPORT_CSV`, `AUDIT_IMPORT`, `AUDIT_IMPORT_CSV`, `AUDIT_SHARE`
  - Include entry count, format, file hash in audit entries
  - Write property test: every export/import operation produces exactly one audit log entry (P5)
  - **Requirement**: INT-1, INT-2

- [ ] 20. Integrate with clipboard system
  - Add `copy_share_link_to_clipboard(share_id)` in `sharing_service.py` using existing `ClipboardService`
  - Auto-clear clipboard after 30 seconds when share link is copied
  - Add `load_qr_from_clipboard_image()` helper for QR scanning via clipboard
  - Write integration tests for clipboard auto-clear behavior
  - **Requirement**: INT-3

- [ ] 21. Implement export dialog GUI
  - Create `src/gui/dialogs/export_dialog.py` with `ExportDialog(QDialog)`
  - Add format selection combo: Encrypted JSON, CSV, Bitwarden JSON, LastPass CSV
  - Add encryption settings panel: password field, strength selector (128/256-bit), GZIP checkbox
  - Add entry selection tree view with checkboxes (all entries or selected)
  - Add preview panel showing entry count and estimated file size
  - Connect to `VaultExporter` and show progress bar during export
  - **Requirement**: UI-1, EXP-3

- [ ] 22. Implement import dialog GUI
  - Create `src/gui/dialogs/import_dialog.py` with `ImportDialog(QDialog)`
  - Add file picker with format auto-detection on file selection
  - Add conflict resolution radio buttons: Skip, Replace, Rename, Merge
  - Add import mode selector: Merge, Replace, Dry-run
  - Add preview table showing entries to be imported with conflict indicators
  - Show summary: new entries, conflicts, validation errors before confirming
  - Connect to `VaultImporter` and show progress bar during import
  - **Requirement**: UI-2, IMP-3

- [ ] 23. Implement sharing dialog GUI
  - Create `src/gui/dialogs/sharing_dialog.py` with `SharingDialog(QDialog)`
  - Add recipient selector: dropdown from contacts table or manual entry
  - Add permission settings: read-only checkbox, expiration date picker (1-30 days)
  - Add delivery method tabs: QR Code, Save to File, Copy Link
  - Add share history table showing active shares with revoke buttons
  - Connect to `SharingService`
  - **Requirement**: UI-3

- [ ] 24. Implement QR code viewer GUI
  - Create `src/gui/dialogs/qr_viewer.py` with `QRViewer(QDialog)`
  - Display QR code image at minimum 300x300px using `QLabel` with `QPixmap`
  - Show payload type, creation time, and expiry countdown
  - Add "Copy to Clipboard" and "Save as PNG" buttons
  - Auto-refresh QR code display every 60 seconds for time-sensitive codes
  - Show warning when code is within 60 seconds of expiry
  - **Requirement**: UI-4

- [ ] 25. Add import/export menu items to main window
  - Add "Export..." and "Import..." items to File menu in `src/gui/main_window.py`
  - Add keyboard shortcuts: Ctrl+E for Export, Ctrl+I for Import
  - Disable both items when vault is locked; re-enable on unlock event
  - Connect Export to `ExportDialog`, Import to `ImportDialog`
  - Add "Share Entry..." to right-click context menu on entry list
  - Write GUI tests: menu items disabled when locked, enabled when unlocked
  - **Requirement**: UI-1, UI-2, UI-3

- [ ] 26. Implement performance optimizations
  - Implement streaming JSON export using `ijson` or chunked writes for >1000 entries
  - Implement batch database inserts (100 entries per transaction) in importer
  - Add progress callbacks every 10% or 100 entries during long operations
  - Implement memory limit: raise error if working memory exceeds 2x file size
  - Add operation timeout: 30s for import processing, 5min overall
  - Write performance benchmark: export 1000 entries <5s, import 1000 entries <10s (TEST-5)
  - Write performance benchmark: QR code generation for 1KB payload <100ms (TEST-5)
  - **Requirement**: PERF-1, PERF-2, PERF-3, PERF-4

- [ ] 27. Implement error handling and recovery
  - Add `try/finally` blocks in all export operations to clean up temp files
  - Implement `VaultImporter.resume_import(checkpoint_file)` for partial import recovery
  - Add checkpoint file written every 100 entries during import
  - Implement format detection fallback: if auto-detect fails, prompt user for manual selection
  - Add detailed error messages with entry ID and field name for validation failures
  - Write error handling tests: corrupted file, disk full simulation, timeout
  - **Requirement**: ERR-1, ERR-2, ERR-3, ERR-4

- [ ] 28. Write comprehensive test suite
  - Write TEST-1 round-trip tests: export to all formats → import back → verify all fields match
  - Write TEST-2 interoperability tests: import real Bitwarden/LastPass fixture files, verify field mapping
  - Write TEST-3 sharing security tests: tamper with share package bytes → verify HMAC rejection
  - Write TEST-4 QR code tests: generate QR with 1KB payload → decode → verify data integrity
  - Write TEST-5 performance tests: 1000-entry export/import timing and memory measurement
  - Write property tests P1-P10 using Hypothesis framework
  - **Requirement**: TEST-1, TEST-2, TEST-3, TEST-4, TEST-5

## Task Dependency Graph

```json
{
  "waves": [
    {
      "wave": 1,
      "tasks": ["1", "2", "3"]
    },
    {
      "wave": 2,
      "tasks": ["4", "5", "6", "7", "8", "9"]
    },
    {
      "wave": 3,
      "tasks": ["10", "11", "12", "13", "14", "15"]
    },
    {
      "wave": 4,
      "tasks": ["16", "17", "18", "19", "20"]
    },
    {
      "wave": 5,
      "tasks": ["21", "22", "23", "24", "25"]
    },
    {
      "wave": 6,
      "tasks": ["26", "27", "28"]
    }
  ]
}
```

## Notes

- New dependencies required: `qrcode[pil]`, `pyzbar`, `Pillow`, `cryptography` (already present)
- Three new DB tables: `shared_entries`, `import_export_history`, `contacts`
- Export keys must always be separate from master vault key (key separation)
- All exports encrypted by default; plaintext only as explicit migration option
- Performance targets: export 1000 entries <5s, import <10s, QR generation <100ms
- All 5 TZ test categories (TEST-1 to TEST-5) implemented in task 28
