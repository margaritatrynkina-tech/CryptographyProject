# Design Document

## Introduction

This document outlines the technical design for the Import/Export functionality in the CryptoSafe password manager. The design focuses on secure data serialization, encryption handling, audit trail integration, and user interface components for data migration operations.

## System Architecture

### Component Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    GUI Layer (MainWindow)                   │
├─────────────────────────────────────────────────────────────┤
│  Import/Export Dialogs → Progress Indicators → Notifications│
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                 Service Layer (Import/Export)               │
├─────────────────────────────────────────────────────────────┤
│  ExportService ──┐  ImportService ──┐  FormatValidators    │
│  JSONExporter    │  JSONImporter    │  CSVValidator        │
│  CSVExporter     │  CSVImporter     │  PDFGenerator        │
│  PDFExporter     │  ConflictResolver│  AuditLogger         │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                 Data Layer (Encryption/DB)                  │
├─────────────────────────────────────────────────────────────┤
│  EntryManager → EncryptionService → DatabaseManager        │
│  AuditLogSigner → KeyManager → VaultEncryption             │
└─────────────────────────────────────────────────────────────┘
```

### Key Components

1. **ExportService**: Orchestrates export operations across formats
2. **ImportService**: Manages import validation and data ingestion
3. **FormatHandlers**: JSON, CSV, and PDF specific serialization/deserialization
4. **ConflictResolver**: Handles duplicate detection and resolution strategies
5. **AuditIntegration**: Ensures all import/export operations are logged
6. **EncryptionBridge**: Manages key derivation and data encryption/decryption

## Data Models

### Export Metadata Schema
```python
class ExportMetadata:
    export_id: str  # UUID v4
    timestamp: datetime  # ISO 8601
    format: Literal["json", "csv", "pdf"]
    entry_count: int
    filter_criteria: Optional[Dict[str, Any]]  # For batch exports
    audit_signature: Optional[str]  # When audit trail is included
    public_key: Optional[str]  # For signature verification
```

### Import Result Schema
```python
class ImportResult:
    total_entries: int
    successful_imports: int
    failed_imports: int
    conflicts: List[Conflict]
    validation_errors: List[ValidationError]
    backup_created: bool
    audit_log_id: str
```

### Conflict Resolution Options
```python
class ConflictResolution:
    SKIP = "skip"      # Keep existing, discard imported
    REPLACE = "replace" # Replace existing with imported
    RENAME = "rename"   # Rename imported entry (add suffix)
    MERGE = "merge"     # Merge metadata where possible
```

## Interface Specifications

### ExportService Interface
```python
class ExportService:
    def export_json(
        self, 
        file_path: Path,
        password_confirmation: Callable[[], bool],
        filter_tags: Optional[List[str]] = None,
        date_range: Optional[Tuple[datetime, datetime]] = None
    ) -> ExportResult
    
    def export_csv(
        self,
        file_path: Path,
        password_confirmation: Callable[[], bool],
        include_passwords: bool = False  # Always False for security
    ) -> ExportResult
    
    def export_pdf(
        self,
        file_path: Path,
        password_confirmation: Callable[[], bool],
        report_title: str = "CryptoSafe Vault Report"
    ) -> ExportResult
```

### ImportService Interface
```python
class ImportService:
    def import_json(
        self,
        file_path: Path,
        original_password: Optional[str] = None,
        conflict_strategy: ConflictResolution = ConflictResolution.SKIP,
        validate_signatures: bool = True
    ) -> ImportResult
    
    def import_csv(
        self,
        file_path: Path,
        column_mapping: Optional[Dict[str, str]] = None,
        conflict_strategy: ConflictResolution = ConflictResolution.SKIP,
        validate_passwords: bool = True
    ) -> ImportResult
    
    def validate_import_file(
        self,
        file_path: Path,
        format: Literal["json", "csv"]
    ) -> ValidationResult
    
    def create_backup(self) -> Path
```

## Correctness Properties

Based on the prework analysis, the following property-based tests should be implemented:

### P1: JSON Round-Trip Property
**Property**: For all valid vault entries, exporting to JSON then importing should preserve all data (excluding transient fields like IDs and timestamps).

```python
def test_json_round_trip(vault_entries: List[VaultEntry]):
    # Export entries to JSON
    json_data = json_exporter.export(vault_entries)
    
    # Import the JSON data
    imported_entries = json_importer.import(json_data)
    
    # Compare essential fields (excluding IDs and timestamps)
    for original, imported in zip(vault_entries, imported_entries):
        assert original.title == imported.title
        assert original.username == imported.username
        assert original.password == imported.password
        assert original.url == imported.url
        assert original.notes == imported.notes
        assert set(original.tags) == set(imported.tags)
```

### P2: CSV Password Obfuscation Property
**Property**: For all vault entries, CSV export must never contain actual passwords in the output.

```python
def test_csv_password_obfuscation(vault_entries: List[VaultEntry]):
    # Export to CSV
    csv_data = csv_exporter.export(vault_entries, include_passwords=False)
    
    # Parse CSV
    reader = csv.DictReader(csv_data.splitlines())
    
    # Check that password column contains only "[ENCRYPTED]" or is empty
    for row in reader:
        password_field = row.get('password', '')
        assert password_field in ['[ENCRYPTED]', '']
        
        # Additional check: no actual password appears anywhere in CSV
        for entry in vault_entries:
            assert entry.password not in csv_data
```

### P3: Import Conflict Resolution Invariant
**Property**: After conflict resolution, the vault should not contain duplicate entries (same title and username).

```python
def test_conflict_resolution_invariant(
    existing_entries: List[VaultEntry],
    imported_entries: List[VaultEntry],
    strategy: ConflictResolution
):
    # Apply import with conflict resolution
    result = import_service.import_entries(
        imported_entries,
        conflict_strategy=strategy
    )
    
    # Get final vault state
    final_entries = entry_manager.get_all_entries()
    
    # Check for duplicates
    seen = set()
    for entry in final_entries:
        key = (entry.title.lower(), entry.username.lower())
        assert key not in seen, f"Duplicate entry found: {key}"
        seen.add(key)
```

### P4: Filtered Export Subset Property
**Property**: When exporting with filters, the exported data must be a subset of the full vault data.

```python
def test_filtered_export_subset(
    vault_entries: List[VaultEntry],
    filter_tags: List[str],
    date_range: Optional[Tuple[datetime, datetime]]
):
    # Apply filters manually
    filtered = [
        entry for entry in vault_entries
        if (not filter_tags or any(tag in entry.tags for tag in filter_tags))
        and (not date_range or date_range[0] <= entry.updated_at <= date_range[1])
    ]
    
    # Export with filters
    exported = export_service.export_json(
        filter_tags=filter_tags,
        date_range=date_range
    )
    
    # Parse exported data
    exported_entries = json_importer.import(exported)
    
    # Verify subset relationship
    exported_ids = {e.id for e in exported_entries}
    filtered_ids = {e.id for e in filtered}
    
    assert exported_ids == filtered_ids
```

### P5: Audit Log Integrity Property
**Property**: All import/export operations must generate corresponding audit log entries.

```python
def test_audit_log_integrity(vault_entries: List[VaultEntry]):
    # Get initial audit log count
    initial_count = audit_logger.get_entry_count()
    
    # Perform export operation
    export_service.export_json(vault_entries)
    
    # Check audit log was updated
    final_count = audit_logger.get_entry_count()
    assert final_count == initial_count + 1
    
    # Verify export event details
    last_event = audit_logger.get_latest_event()
    assert last_event.event_type == "AUDIT_EXPORT"
    assert last_event.entry_count == len(vault_entries)
```

### P6: Encryption Consistency Property
**Property**: Data encrypted for export should be decryptable with the correct key.

```python
def test_encryption_consistency(
    vault_entries: List[VaultEntry],
    encryption_key: bytes
):
    # Encrypt entries for export
    encrypted_data = []
    for entry in vault_entries:
        serialized = json.dumps(entry.to_dict())
        encrypted = encryption_service.encrypt(serialized, encryption_key)
        encrypted_data.append(encrypted)
    
    # Decrypt and verify
    for original, encrypted in zip(vault_entries, encrypted_data):
        decrypted = encryption_service.decrypt(encrypted, encryption_key)
        restored = VaultEntry.from_dict(json.loads(decrypted))
        
        # Compare essential fields
        assert original.title == restored.title
        assert original.username == restored.username
        assert original.password == restored.password
```

### P7: CSV Parser Round-Trip Property
**Property**: For all valid data, CSV parsing then formatting should produce equivalent CSV.

```python
def test_csv_parser_round_trip(csv_data: str):
    # Parse CSV
    entries = csv_parser.parse(csv_data)
    
    # Format back to CSV
    formatted_csv = csv_pretty_printer.format(entries)
    
    # Parse again
    re_parsed = csv_parser.parse(formatted_csv)
    
    # Compare entries (allowing for formatting differences)
    assert len(entries) == len(re_parsed)
    for e1, e2 in zip(entries, re_parsed):
        # Compare field by field, ignoring whitespace differences
        for field in ['title', 'username', 'url', 'notes']:
            assert e1[field].strip() == e2[field].strip()
```

### P8: Import Validation Property
**Property**: Invalid import data should always be rejected with appropriate error messages.

```python
def test_import_validation(invalid_data_sets: List[Tuple[str, Dict]]):
    for format_type, invalid_data in invalid_data_sets:
        result = import_service.validate_import_file(
            create_temp_file(invalid_data),
            format=format_type
        )
        
        assert not result.is_valid
        assert result.errors  # Should have at least one error
        assert all(isinstance(err, str) for err in result.errors)
```

### P9: Performance Scaling Property
**Property**: Export/import time should scale linearly with entry count within reasonable bounds.

```python
def test_performance_scaling(entry_sets: List[List[VaultEntry]]):
    timings = []
    
    for entries in entry_sets:
        start = time.time()
        export_service.export_json(entries)
        elapsed = time.time() - start
        
        timings.append((len(entries), elapsed))
    
    # Check that time increases linearly (allow some variance)
    # This is more of a benchmark than a strict property
    if len(timings) > 1:
        ratios = [t[1]/t[0] for t in timings]
        # Ratio should be relatively constant
        assert max(ratios) / min(ratios) < 3.0  # Allow 3x variance
```

### P10: Memory Safety Property
**Property**: Large exports should not cause memory exhaustion.

```python
def test_memory_safety(large_entry_set: List[VaultEntry]):
    # Monitor memory usage
    import psutil
    process = psutil.Process()
    
    initial_memory = process.memory_info().rss
    
    # Perform export with streaming
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        export_service.export_json(large_entry_set, file_path=Path(f.name))
    
    final_memory = process.memory_info().rss
    memory_increase = final_memory - initial_memory
    
    # Memory increase should be reasonable (< 100MB for 10k entries)
    assert memory_increase < 100 * 1024 * 1024  # 100MB
```

## Security Considerations

### Key Management
1. **Export Encryption**: Use session encryption key for data encryption in exports
2. **Password Confirmation**: Require master password re-entry for all export operations
3. **Key Derivation**: Use PBKDF2 with sufficient iterations for import decryption
4. **Key Isolation**: Never store decryption keys in export files

### Data Protection
1. **Password Obfuscation**: Never include plaintext passwords in CSV/PDF exports
2. **Audit Trail**: Include signatures in JSON exports for tamper detection
3. **Watermarking**: Add "CONFIDENTIAL" watermarks to PDF reports
4. **Access Control**: Disable import/export when vault is locked

### Validation and Sanitization
1. **Input Validation**: Strict validation of all imported data
2. **Path Traversal**: Prevent directory traversal in file paths
3. **Malformed Data**: Graceful handling of corrupted import files
4. **Size Limits**: Implement reasonable size limits for import files

## Error Handling

### Expected Error Conditions
1. **Invalid File Format**: Reject with specific format error message
2. **Decryption Failure**: Inform user of incorrect password
3. **Signature Validation Failure**: Warn user but allow override
4. **Disk Space Exhaustion**: Provide clear error and cleanup guidance
5. **Permission Denied**: Suggest running as administrator or checking permissions

### Recovery Strategies
1. **Automatic Backup**: Create vault backup before destructive imports
2. **Partial Import**: Allow successful entries when others fail
3. **Progress Persistence**: Resume interrupted operations where possible
4. **Transaction Rollback**: Rollback database changes on import failure

## Integration Points

### Existing Components
1. **EntryManager**: For retrieving and storing vault entries
2. **EncryptionService**: For data encryption/decryption operations
3. **AuditLogger**: For logging all import/export activities
4. **KeyManager**: For encryption key derivation and management
5. **DatabaseManager**: For batch database operations

### GUI Integration
1. **MainWindow**: Add import/export menu items and dialogs
2. **ProgressDialog**: Show operation progress with cancel option
3. **ConflictResolutionDialog**: Present conflict options to user
4. **FileDialogs**: Use native OS file pickers for path selection

## Testing Strategy

### Unit Tests
1. **Format Handlers**: Test JSON/CSV parsing and serialization
2. **Encryption Bridge**: Test encryption/decryption round-trips
3. **Validation Logic**: Test import validation rules
4. **Conflict Resolution**: Test duplicate detection and resolution

### Integration Tests
1. **End-to-End Export**: Full export workflow with UI interaction
2. **End-to-End Import**: Complete import with conflict resolution
3. **Audit Integration**: Verify audit logging for all operations
4. **Database Integration**: Test batch operations with real database

### Property-Based Tests
Implement all 10 correctness properties defined above using Hypothesis or similar PBT framework.

### Performance Tests
1. **Large Dataset Export**: Test with 10,000+ entries
2. **Memory Usage**: Monitor memory during streaming operations
3. **Concurrent Operations**: Test multiple simultaneous imports/exports

## Deployment Considerations

### Configuration
1. **Export Limits**: Configurable maximum export size
2. **Format Options**: Enable/disable specific export formats
3. **Security Settings**: Configurable password confirmation requirements
4. **Performance Tuning**: Batch size settings for database operations

### Compatibility
1. **Backward Compatibility**: Support import from older export formats
2. **Cross-Platform**: Ensure file operations work on Windows/macOS/Linux
3. **Character Encoding**: Support UTF-8/UTF-16 for international text
4. **CSV Dialects**: Handle Excel, LibreOffice, and standard CSV formats

## Monitoring and Metrics

### Key Metrics
1. **Export Success Rate**: Percentage of successful exports
2. **Import Success Rate**: Percentage of successful imports
3. **Operation Duration**: Average time for import/export operations
4. **Conflict Frequency**: How often conflicts occur during imports
5. **Audit Compliance**: Percentage of operations with proper audit logging

### Logging
1. **Operation Start/End**: Log beginning and completion of operations
2. **Error Details**: Detailed error logging for troubleshooting
3. **Performance Metrics**: Log operation duration and resource usage
4. **Security Events**: Log all security-relevant actions