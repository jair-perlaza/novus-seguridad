#!/usr/bin/env python3
"""Exportacion SDL — JSON / CSV / ZIP / PDF con datos reales."""
from __future__ import annotations
import csv
import io
import json
import os
import zipfile
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
EXPORT_DIR = os.path.join(ROOT, "data", "sdl", "exports")


def _utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ensure_export_dir():
    os.makedirs(EXPORT_DIR, exist_ok=True)


def export_json(records: List[Dict[str, Any]], filename: Optional[str] = None) -> Dict[str, Any]:
    ensure_export_dir()
    name = filename or f"sdl_export_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
    path = os.path.join(EXPORT_DIR, name)
    payload = {"exported_at_utc": _utc(), "count": len(records), "invented": False, "records": records}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, default=str, indent=2)
    return {"ok": True, "format": "json", "path": path, "count": len(records)}


def export_csv(records: List[Dict[str, Any]], filename: Optional[str] = None) -> Dict[str, Any]:
    ensure_export_dir()
    name = filename or f"sdl_export_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.csv"
    path = os.path.join(EXPORT_DIR, name)
    fields = [
        "uuid", "version", "timestamp_utc", "engine", "record_type", "severity",
        "asset", "user_ref", "ioc", "cve", "mitre", "incident_id", "playbook_id",
        "sha256", "ed25519_sig", "malware", "ransomware", "apt",
    ]
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in records:
            w.writerow({k: r.get(k) for k in fields})
    return {"ok": True, "format": "csv", "path": path, "count": len(records)}


def export_zip(records: List[Dict[str, Any]], filename: Optional[str] = None) -> Dict[str, Any]:
    ensure_export_dir()
    j = export_json(records)
    c = export_csv(records)
    name = filename or f"sdl_export_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.zip"
    path = os.path.join(EXPORT_DIR, name)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(j["path"], arcname=os.path.basename(j["path"]))
        zf.write(c["path"], arcname=os.path.basename(c["path"]))
    return {"ok": True, "format": "zip", "path": path, "count": len(records)}


def export_pdf(records: List[Dict[str, Any]], filename: Optional[str] = None) -> Dict[str, Any]:
    ensure_export_dir()
    name = filename or f"sdl_export_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.pdf"
    path = os.path.join(EXPORT_DIR, name)
    try:
        from fpdf import FPDF
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(180, 8, "NOVUS Security Data Lake Export", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 8)
        pdf.multi_cell(180, 4, f"exported_at={_utc()} count={len(records)} invented=False")
        for r in records[:200]:
            line = f"{r.get('timestamp_utc')} | {r.get('engine')} | {r.get('record_type')} | {r.get('uuid')} | sha={str(r.get('sha256'))[:16]}"
            safe = line.encode("latin-1", "replace").decode("latin-1")
            pdf.multi_cell(180, 3.5, safe)
        if len(records) > 200:
            pdf.multi_cell(180, 4, f"... truncated {len(records)-200} records")
        pdf.output(path)
        return {"ok": True, "format": "pdf", "path": path, "count": len(records)}
    except Exception as exc:
        return {"ok": False, "format": "pdf", "error": str(exc)[:200]}
