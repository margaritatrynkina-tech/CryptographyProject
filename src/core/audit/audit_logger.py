import json
import re
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from src.core.audit.log_signer import AuditLogSigner
from src.core.audit.log_verifier import AuditLogVerifier
from src.core.audit.audit_encryption import AuditLogEncryption
from src.core.events import EventSystem, EventType


SENSITIVE_KEYS = frozenset({
    "password", "master_password", "secret", "key", "token",
    "encryption_key", "private_key", "seed", "credential",
})

REDACTED = "[REDACTED]"

EVENT_MAP = {
    EventType.USER_LOGGED_IN: ("AUTH_LOGIN_SUCCESS", "INFO"),
    EventType.USER_LOGGED_OUT: ("AUTH_LOGOUT", "INFO"),
    EventType.ENTRY_ADDED: ("VAULT_ENTRY_CREATE", "INFO"),
    EventType.ENTRY_UPDATED: ("VAULT_ENTRY_UPDATE", "INFO"),
    EventType.ENTRY_DELETED: ("VAULT_ENTRY_DELETE", "WARN"),
    EventType.CLIPBOARD_COPIED: ("CLIPBOARD_COPY", "INFO"),
    EventType.CLIPBOARD_CLEARED: ("CLIPBOARD_CLEAR", "INFO"),
    EventType.AUDIT_LOG_ENTRY: ("SECURITY_CLIPBOARD_MONITOR", "WARN"),
}


class AuditLogger:
    def __init__(
        self,
        db_connection: sqlite3.Connection,
        signer: AuditLogSigner,
        events: Optional[EventSystem] = None,
        user_id: str = "local_user",
        audit_encryption_key: Optional[bytes] = None,
        on_periodic_verify: Optional[Callable[[Dict[str, Any]], None]] = None,
        verify_interval_hours: float = 24.0,
    ):
        self.db = db_connection
        self.signer = signer
        self.verifier = AuditLogVerifier(signer)
        self._encrypter = AuditLogEncryption(audit_encryption_key)
        self.events = events
        self.user_id = user_id
        self._lock = threading.RLock()
        self._enabled = True
        self._degraded = False
        self._on_periodic_verify = on_periodic_verify
        self._periodic_timer: Optional[threading.Timer] = None
        self._verify_interval_hours = verify_interval_hours
        self._last_verify_result: Optional[Dict[str, Any]] = None
        self._ensure_genesis()
        self._store_public_key_once()
        if events:
            self._subscribe_events(events)
        self.start_periodic_verification()

    def start_periodic_verification(self) -> None:
        """VER-2: verify integrity every 24 hours (configurable)."""
        self._schedule_periodic_verify()

    def _schedule_periodic_verify(self) -> None:
        if self._periodic_timer:
            self._periodic_timer.cancel()
        interval = max(1.0, self._verify_interval_hours * 3600)
        self._periodic_timer = threading.Timer(interval, self._run_periodic_verify)
        self._periodic_timer.daemon = True
        self._periodic_timer.start()

    def _run_periodic_verify(self) -> None:
        try:
            result = self.verify_integrity(limit=1000)
            self._last_verify_result = result
            if self._on_periodic_verify:
                self._on_periodic_verify(result)
            if not result.get("verified"):
                self.log_event(
                    "AUDIT_INTEGRITY_FAILURE",
                    "CRITICAL",
                    "audit_logger",
                    {"result": result},
                )
        except Exception:
            pass
        finally:
            self._schedule_periodic_verify()

    def stop_periodic_verification(self) -> None:
        if self._periodic_timer:
            self._periodic_timer.cancel()
            self._periodic_timer = None

    def _decrypt_entry_data(self, stored: str) -> str:
        return self._encrypter.decrypt(stored)

    def _subscribe_events(self, events: EventSystem) -> None:
        for event_type in EVENT_MAP:
            events.subscribe(event_type, self._make_handler(event_type))

    def _make_handler(self, event_type: EventType) -> Callable:
        audit_type, severity = EVENT_MAP[event_type]

        def handler(data: Any) -> None:
            source = "event_system"
            details = data if isinstance(data, dict) else {"payload": data}
            entry_id = details.get("entry_id") or details.get("source_entry_id")
            self.log_event(
                audit_type,
                severity,
                source,
                details,
                entry_id=entry_id,
            )

        return handler

    def _ensure_genesis(self) -> None:
        cur = self.db.cursor()
        cur.execute("SELECT COUNT(*) FROM audit_log")
        if cur.fetchone()[0] == 0:
            self.log_event(
                "SYSTEM_GENESIS",
                "INFO",
                "audit_logger",
                {"message": "Audit log initialized"},
                user_id="system",
                sequence_override=0,
            )

    def _store_public_key_once(self) -> None:
        pub = self.signer.get_public_key_hex()
        if not pub:
            return
        cur = self.db.cursor()
        cur.execute(
            "INSERT OR IGNORE INTO audit_signing_keys (public_key_hex, algorithm) VALUES (?, ?)",
            (pub, self.signer.algorithm),
        )
        self.db.commit()

    @staticmethod
    def _sanitize_details(details: Dict[str, Any]) -> Dict[str, Any]:
        def _walk(obj: Any) -> Any:
            if isinstance(obj, dict):
                return {
                    k: REDACTED if k.lower() in SENSITIVE_KEYS else _walk(v)
                    for k, v in obj.items()
                }
            if isinstance(obj, list):
                return [_walk(i) for i in obj]
            if isinstance(obj, str):
                if re.search(r"(?i)(password|secret|key)\s*[:=]\s*\S+", obj):
                    return REDACTED
            return obj

        return _walk(details)

    def log_event(
        self,
        event_type: str,
        severity: str,
        source: str,
        details: Optional[Dict[str, Any]] = None,
        user_id: Optional[str] = None,
        entry_id: Optional[str] = None,
        sequence_override: Optional[int] = None,
    ) -> Optional[int]:
        if not self._enabled:
            return None

        with self._lock:
            try:
                return self._write_entry(
                    event_type,
                    severity,
                    source,
                    details or {},
                    user_id or self.user_id,
                    entry_id,
                    sequence_override,
                )
            except sqlite3.Error:
                self._degraded = True
                return None

    def _write_entry(
        self,
        event_type: str,
        severity: str,
        source: str,
        details: Dict[str, Any],
        user_id: str,
        entry_id: Optional[str],
        sequence_override: Optional[int],
    ) -> int:
        cur = self.db.cursor()
        cur.execute(
            "SELECT entry_hash FROM audit_log ORDER BY sequence_number DESC LIMIT 1"
        )
        row = cur.fetchone()
        previous_hash = row[0] if row else AuditLogSigner.GENESIS_HASH

        if sequence_override is not None:
            seq = sequence_override
        else:
            cur.execute("SELECT COALESCE(MAX(sequence_number), -1) + 1 FROM audit_log")
            seq = cur.fetchone()[0]

        entry = {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "event_type": event_type,
            "severity": severity,
            "user_id": user_id,
            "source": source,
            "details": self._sanitize_details(details),
            "sequence_number": seq,
            "previous_hash": previous_hash,
        }
        if entry_id:
            entry["entry_id"] = entry_id

        entry_json = json.dumps(entry, sort_keys=True, ensure_ascii=False)
        entry_hash = self.signer.compute_entry_hash(entry_json)
        signature = self.signer.sign(entry_json.encode("utf-8")).hex()
        stored_data = self._encrypter.encrypt(entry_json)

        cur.execute(
            """
            INSERT INTO audit_log
            (sequence_number, timestamp, event_type, severity, user_id, source,
             entry_id, previous_hash, entry_data, entry_hash, signature)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                seq,
                entry["timestamp"],
                event_type,
                severity,
                user_id,
                source,
                entry_id,
                previous_hash,
                stored_data,
                entry_hash,
                signature,
            ),
        )
        self.db.commit()
        return seq

    def verify_integrity(
        self, start_seq: int = 0, end_seq: Optional[int] = None, limit: Optional[int] = None
    ) -> Dict[str, Any]:
        decrypt_fn = self._decrypt_entry_data if self._encrypter.enabled else None
        return self.verifier.verify_connection(
            self.db, start_seq, end_seq, limit, decrypt_entry_data=decrypt_fn
        )

    @property
    def last_verify_result(self) -> Optional[Dict[str, Any]]:
        return self._last_verify_result

    def query_logs(
        self,
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        query = "SELECT * FROM audit_log WHERE 1=1"
        params: list = []
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if search:
            query += " AND (entry_data LIKE ? OR event_type LIKE ?)"
            params.extend([f"%{search}%", f"%{search}%"])
        query += " ORDER BY sequence_number DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        cur = self.db.cursor()
        cur.execute(query, params)
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    def count_logs(self, event_type: Optional[str] = None) -> int:
        cur = self.db.cursor()
        if event_type:
            cur.execute("SELECT COUNT(*) FROM audit_log WHERE event_type = ?", (event_type,))
        else:
            cur.execute("SELECT COUNT(*) FROM audit_log")
        return cur.fetchone()[0]

    def query_logs_by_date(
        self,
        date_from: Optional[str] = None,
        date_to: Optional[str] = None,
        limit: int = 10000,
    ) -> List[Dict[str, Any]]:
        query = "SELECT * FROM audit_log WHERE 1=1"
        params: list = []
        if date_from:
            query += " AND timestamp >= ?"
            params.append(date_from)
        if date_to:
            query += " AND timestamp <= ?"
            params.append(date_to)
        query += " ORDER BY sequence_number LIMIT ?"
        params.append(limit)
        cur = self.db.cursor()
        cur.execute(query, params)
        cols = [d[0] for d in cur.description]
        rows = [dict(zip(cols, row)) for row in cur.fetchall()]
        for row in rows:
            try:
                row["entry_data_plain"] = self._decrypt_entry_data(row["entry_data"])
            except Exception:
                row["entry_data_plain"] = row["entry_data"]
        return rows

    def get_statistics(self, days: int = 7) -> Dict[str, Any]:
        """GUI-3: event counts and security metrics for last N days."""
        cur = self.db.cursor()
        cur.execute(
            """
            SELECT event_type, severity, COUNT(*) as cnt
            FROM audit_log
            WHERE timestamp >= datetime('now', ?)
            GROUP BY event_type, severity
            """,
            (f"-{int(days)} days",),
        )
        by_type: Dict[str, int] = {}
        failed_logins = 0
        suspicious = 0
        for row in cur.fetchall():
            et, sev, cnt = row[0], row[1], row[2]
            by_type[et] = by_type.get(et, 0) + cnt
            if "LOGIN" in et and "FAIL" in et:
                failed_logins += cnt
            if "SECURITY" in et or sev in ("WARN", "CRITICAL"):
                suspicious += cnt
        return {
            "days": days,
            "by_event_type": by_type,
            "failed_logins": failed_logins,
            "suspicious_events": suspicious,
            "total": sum(by_type.values()),
        }

    def get_rows_for_export(
        self,
        start_seq: int = 0,
        end_seq: Optional[int] = None,
        date_from: Optional[str] = None,
        date_to: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        if date_from or date_to:
            return self.query_logs_by_date(date_from, date_to)
        query = "SELECT * FROM audit_log WHERE sequence_number >= ?"
        params: list = [start_seq]
        if end_seq is not None:
            query += " AND sequence_number <= ?"
            params.append(end_seq)
        query += " ORDER BY sequence_number"
        cur = self.db.cursor()
        cur.execute(query, params)
        cols = [d[0] for d in cur.description]
        rows = [dict(zip(cols, row)) for row in cur.fetchall()]
        for row in rows:
            try:
                row["entry_data"] = self._decrypt_entry_data(row["entry_data"])
            except Exception:
                pass
        return rows

    def attempt_sql_injection(self, payload: str) -> bool:
        blocked_patterns = ("';", "--", "DROP ", "UNION ", " OR 1=1")
        upper = payload.upper()
        for pat in blocked_patterns:
            if pat.upper() in upper or pat in payload:
                self.log_event(
                    "SECURITY_SQL_INJECTION_ATTEMPT",
                    "CRITICAL",
                    "audit_security",
                    {"payload_preview": payload[:80], "blocked": True},
                )
                return True
        return False

    @property
    def is_degraded(self) -> bool:
        return self._degraded

    def set_degraded(self, value: bool) -> None:
        self._degraded = value
