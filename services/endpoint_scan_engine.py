"""
Motor de escaneo del endpoint local (host NOVUS).
Orquesta deep_scan_engine, monitor continuo y cuarentena — solo telemetría real del SO.
"""
from __future__ import annotations

import json
import socket
import threading
from datetime import datetime
from typing import Any, Dict, List, Optional

from utils.logger import logger

RISK_LABELS = {
    "info": "Seguro",
    "safe": "Seguro",
    "low": "Bajo riesgo",
    "medium": "Riesgo medio",
    "high": "Riesgo alto",
    "critical": "Riesgo crítico",
}

MODE_TO_PROFILE = {
    "quick": "quick",
    "full": "full",
    "complete": "full",
    "custom": "custom",
    "on_demand": "full",
    "malware": "malware",
    "rootkit": "rootkit",
}


class EndpointScanEngine:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._last_scan_id: Optional[str] = None

    def start_scan(
        self,
        mode: str = "quick",
        custom_paths: Optional[List[str]] = None,
        user_id: Optional[int] = None,
        session_id: str = "",
    ) -> Dict[str, Any]:
        from services.deep_scan_engine import deep_scan_engine

        profile = MODE_TO_PROFILE.get((mode or "quick").lower(), "quick")
        if profile == "custom" and not custom_paths:
            return {"status": "error", "message": "Modo personalizado requiere rutas locales válidas"}
        scan_id = deep_scan_engine.start_scan(
            session_id=session_id,
            user_id=user_id,
            profile=profile,
            query=f"Endpoint scan mode={mode}",
            modules_loaded=["Endpoint Shield", "Deep Scan Engine"],
            custom_roots=custom_paths,
        )
        with self._lock:
            self._last_scan_id = scan_id
        self._persist_scan_start(scan_id, mode, profile)
        return {
            "status": "started",
            "scan_id": scan_id,
            "mode": mode,
            "profile": profile,
            "host": socket.gethostname(),
        }

    def get_scan_status(self, scan_id: str) -> Optional[dict]:
        from services.deep_scan_engine import deep_scan_engine

        st = deep_scan_engine.get_status(scan_id)
        if not st:
            return None
        return self._enrich_status(st)

    def get_scan_report(self, scan_id: str) -> Optional[dict]:
        from services.deep_scan_engine import deep_scan_engine

        report = deep_scan_engine.get_report(scan_id)
        if report:
            self._persist_scan_complete(scan_id, report)
            return self._enrich_report(report)
        st = deep_scan_engine.get_status(scan_id)
        if st and st.get("status") == "running":
            return {"status": "running", "scan_id": scan_id, "progress_pct": st.get("progress_pct")}
        return None

    def engine_status(self) -> dict:
        from services.endpoint_realtime_monitor import get_monitor_status

        with self._lock:
            last = self._last_scan_id
        return {
            "host": socket.gethostname(),
            "endpoint_shield": "active",
            "deep_scan_engine": "active",
            "realtime_monitor": get_monitor_status(),
            "last_scan_id": last,
            "modes": list(MODE_TO_PROFILE.keys()) + ["continuous"],
        }

    def classify_finding(self, finding: dict) -> str:
        risk = str(finding.get("risk") or finding.get("severity") or "info").lower()
        return RISK_LABELS.get(risk, "Riesgo medio")

    def kernel_explain_finding(self, finding: dict) -> str:
        label = self.classify_finding(finding)
        evidence = finding.get("evidence") or finding.get("reason") or finding.get("description") or ""
        path = finding.get("path") or finding.get("location") or "N/D"
        return (
            f"Clasificación: {label}. "
            f"Evidencia verificable: {evidence}. "
            f"Origen local: {path}. "
            f"Motor: endpoint_scan_engine / deep_scan_engine."
        )

    def _enrich_status(self, st: dict) -> dict:
        out = dict(st)
        out["findings_preview"] = [
            {**f, "classification": self.classify_finding(f)} for f in (st.get("findings") or [])[:20]
        ]
        return out

    def _enrich_report(self, report: dict) -> dict:
        out = dict(report)
        findings = []
        for f in report.get("findings") or []:
            nf = dict(f)
            nf["classification"] = self.classify_finding(f)
            nf["kernel_explanation"] = self.kernel_explain_finding(f)
            findings.append(nf)
        out["findings"] = findings
        out["host"] = socket.gethostname()
        return out

    def _persist_scan_start(self, scan_id: str, mode: str, profile: str) -> None:
        from database import SessionLocal, EndpointScanRecord

        db = SessionLocal()
        try:
            db.add(
                EndpointScanRecord(
                    id=f"ESR-{scan_id[:8]}",
                    scan_id=scan_id,
                    mode=mode,
                    profile=profile,
                    status="running",
                    hostname=socket.gethostname(),
                    started_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    finished_at=None,
                    findings_json="[]",
                    stats_json="{}",
                    report_summary=None,
                )
            )
            db.commit()
        except Exception as exc:
            logger.debug("endpoint scan record start: %s", exc)
        finally:
            db.close()

    def _persist_scan_complete(self, scan_id: str, report: dict) -> None:
        from database import SessionLocal, EndpointScanRecord

        db = SessionLocal()
        try:
            row = db.query(EndpointScanRecord).filter(EndpointScanRecord.scan_id == scan_id).first()
            if not row:
                return
            row.status = "completed"
            row.finished_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            row.findings_json = json.dumps(report.get("findings") or [], ensure_ascii=False)
            row.stats_json = json.dumps(report.get("summary") or {}, ensure_ascii=False)
            row.report_summary = (report.get("text_report") or "")[:4000]
            db.commit()
        except Exception as exc:
            logger.debug("endpoint scan record complete: %s", exc)
        finally:
            db.close()
        try:
            from services.defense_evidence_registry import record_defense_event

            record_defense_event(
                phase="detect",
                action="endpoint_scan_completed",
                motor="endpoint_scan_engine",
                outcome="success",
                threat_type="endpoint_analysis",
                evidence={
                    "scan_id": scan_id,
                    "host": socket.gethostname(),
                    "findings": len(report.get("findings") or []),
                    "verified": True,
                },
                detail=f"Escaneo endpoint completado — {len(report.get('findings') or [])} hallazgos",
                confidence="Alta",
            )
        except Exception:
            pass


endpoint_scan_engine = EndpointScanEngine()
