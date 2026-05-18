from typing import Any, Dict, List, Optional

from src.core.audit.log_signer import AuditLogSigner


class AuditLogVerifier:
    def __init__(self, signer: AuditLogSigner):
        self.signer = signer

    def verify_rows(
        self,
        rows: List[Dict[str, Any]],
        decrypt_entry_data: Optional[Any] = None,
    ) -> Dict[str, Any]:
        results: Dict[str, Any] = {
            "total_entries": len(rows),
            "valid_entries": 0,
            "invalid_entries": [],
            "chain_breaks": [],
            "verified": True,
        }
        previous_hash: Optional[str] = None

        for row in rows:
            seq = row["sequence_number"]
            entry_data = row["entry_data"]
            if decrypt_entry_data:
                entry_data = decrypt_entry_data(entry_data)
            signature_hex = row["signature"]
            entry_hash = row["entry_hash"]
            prev_hash = row["previous_hash"]

            try:
                signature = bytes.fromhex(signature_hex)
            except ValueError:
                results["invalid_entries"].append(
                    {"sequence": seq, "reason": "Invalid signature encoding"}
                )
                results["verified"] = False
                continue

            if not self.signer.verify(entry_data.encode("utf-8"), signature):
                results["invalid_entries"].append(
                    {"sequence": seq, "reason": "Invalid signature"}
                )
                results["verified"] = False
                continue

            computed = self.signer.compute_entry_hash(entry_data)
            if computed != entry_hash:
                results["invalid_entries"].append(
                    {"sequence": seq, "reason": "Hash mismatch"}
                )
                results["verified"] = False
                continue

            if previous_hash is not None and prev_hash != previous_hash:
                results["chain_breaks"].append(
                    {
                        "sequence": seq,
                        "expected": previous_hash,
                        "actual": prev_hash,
                    }
                )
                results["verified"] = False
                continue

            results["valid_entries"] += 1
            previous_hash = entry_hash

        return results

    def verify_connection(
        self,
        conn,
        start_seq: int = 0,
        end_seq: Optional[int] = None,
        limit: Optional[int] = None,
        decrypt_entry_data: Optional[Any] = None,
    ) -> Dict[str, Any]:
        query = """
            SELECT sequence_number, entry_data, signature, entry_hash, previous_hash
            FROM audit_log
            WHERE sequence_number >= ?
        """
        params: list = [start_seq]
        if end_seq is not None:
            query += " AND sequence_number <= ?"
            params.append(end_seq)
        query += " ORDER BY sequence_number"
        if limit is not None:
            query += f" LIMIT {int(limit)}"

        cur = conn.cursor()
        cur.execute(query, params)
        rows = [
            {
                "sequence_number": r[0],
                "entry_data": r[1],
                "signature": r[2],
                "entry_hash": r[3],
                "previous_hash": r[4],
            }
            for r in cur.fetchall()
        ]
        return self.verify_rows(rows, decrypt_entry_data=decrypt_entry_data)
