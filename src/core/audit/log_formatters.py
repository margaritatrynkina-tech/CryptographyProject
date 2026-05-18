import csv
import io
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


def export_logs(
    rows: List[Dict[str, Any]],
    fmt: str,
    output_path: str,
    signer_public_key_hex: str = "",
    metadata: Optional[Dict[str, Any]] = None,
    encrypt: bool = False,
    encryption_key: Optional[bytes] = None,
) -> str:
    fmt = fmt.lower()
    if fmt == "json":
        return _export_json(rows, output_path, signer_public_key_hex, metadata)
    if fmt == "csv":
        return _export_csv(rows, output_path)
    if fmt == "pdf":
        return _export_pdf(rows, output_path, metadata or {})
    raise ValueError(f"Unsupported export format: {fmt}")


def _export_json(
    rows: List[Dict[str, Any]],
    output_path: str,
    public_key_hex: str,
    metadata: Optional[Dict[str, Any]],
) -> str:
    payload = {
        "export_metadata": metadata
        or {
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "entry_count": len(rows),
        },
        "public_key_hex": public_key_hex,
        "algorithm": "Ed25519",
        "entries": rows,
    }
    Path(output_path).write_text(
        json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return output_path


def _export_csv(rows: List[Dict[str, Any]], output_path: str) -> str:
    fieldnames = [
        "sequence_number",
        "timestamp",
        "event_type",
        "severity",
        "user_id",
        "source",
        "entry_id",
        "entry_hash",
        "previous_hash",
    ]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fieldnames})
    return output_path


def _export_pdf(rows: List[Dict[str, Any]], output_path: str, metadata: Dict[str, Any]) -> str:
    lines = [
        "CryptoSafe Manager - Audit Log Report",
        f"Generated: {metadata.get('exported_at', datetime.now(timezone.utc).isoformat())}",
        f"Entries: {len(rows)}",
        "",
    ]
    for row in rows[:500]:
        lines.append(
            f"#{row.get('sequence_number')} {row.get('timestamp')} "
            f"{row.get('event_type')} [{row.get('severity')}]"
        )
    text = "\\n".join(lines)
    content = f"BT /F1 10 Tf 50 750 Td ({_pdf_escape(text[:3000])}) Tj ET"
    pdf = (
        f"%PDF-1.4\n"
        f"1 0 obj<< /Type /Catalog /Pages 2 0 R >>endobj\n"
        f"2 0 obj<< /Type /Pages /Kids [3 0 R] /Count 1 >>endobj\n"
        f"3 0 obj<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        f"/Contents 4 0 R /Resources<< /Font<< /F1 5 0 R >> >> >>endobj\n"
        f"4 0 obj<< /Length {len(content)} >>stream\n{content}\nendstream endobj\n"
        f"5 0 obj<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>endobj\n"
        f"xref\n0 6\n0000000000 65535 f \n"
        f"trailer<< /Size 6 /Root 1 0 R >>\nstartxref\n0\n%%EOF"
    )
    Path(output_path).write_bytes(pdf.encode("latin-1", errors="replace"))
    return output_path


def _pdf_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def import_signed_json(path: str) -> Dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))
