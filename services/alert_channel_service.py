"""
Canales de alerta — efectos reales de whatsapp_alerts y email_reports.
"""
from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from utils.logger import logger

ALERTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "alerts")
WHATSAPP_QUEUE = os.path.join(ALERTS_DIR, "whatsapp_queue.json")


def _ensure_dir():
    os.makedirs(ALERTS_DIR, exist_ok=True)


def _load_queue() -> List[dict]:
    _ensure_dir()
    if not os.path.exists(WHATSAPP_QUEUE):
        return []
    try:
        with open(WHATSAPP_QUEUE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def _save_queue(items: List[dict]) -> None:
    _ensure_dir()
    with open(WHATSAPP_QUEUE, "w", encoding="utf-8") as f:
        json.dump(items[-100:], f, indent=2, ensure_ascii=False)


def dispatch_threat_alerts(threats: List[dict], suspicious_processes: List[dict]) -> None:
    """Enruta alertas críticas/altas al administrador principal (CEO) — único destino externo."""
    from services.config_service import whatsapp_alerts_enabled

    if not whatsapp_alerts_enabled():
        return

    from services.network_event_log import network_event_log

    candidates = []
    for t in threats or []:
        sev = str(t.get("severity") or "").lower()
        if sev in ("critical", "critico", "crítico", "high", "alto", "alta"):
            candidates.append(f"[{t.get('type', 'amenaza').upper()}] Severidad {t.get('severity')}")

    for p in (suspicious_processes or [])[:5]:
        candidates.append(f"[PROC] {p.get('name', 'proceso')} PID {p.get('pid', '?')}")

    if not candidates:
        return

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    body_lines = [f"Alertas NOVUS — {ts}", ""]
    for msg in candidates:
        full = f"Alerta CEO: {msg}"
        network_event_log.record(full, level="alert")
        body_lines.append(msg)
        queue = _load_queue()
        queue.append({"time": ts, "message": msg, "channel": "ceo_email", "status": "routed"})
        _save_queue(queue)

    try:
        from services.email_delivery_service import send_to_ceo

        send_to_ceo(
            subject=f"[NOVUS] {len(candidates)} alerta(s) de seguridad",
            body="\n".join(body_lines),
            category="threat_alert",
        )
    except Exception as exc:
        logger.debug("CEO threat alert email: %s", exc)

    try:
        from database import SessionLocal, Log
        db = SessionLocal()
        try:
            db.add(Log(
                evento="ceo_security_alert",
                detalle=f"{len(candidates)} alerta(s) enviadas al CEO — {ts}",
                fecha=ts,
            ))
            db.commit()
        finally:
            db.close()
    except Exception as exc:
        logger.debug("ceo alert log: %s", exc)


def maybe_generate_daily_email_report(user_email: Optional[str] = None) -> Optional[dict]:
    """Genera informe diario si email_reports está habilitado."""
    from services.config_service import email_reports_enabled

    if not email_reports_enabled():
        return None

    try:
        from services.enterprise_report_service import build_enterprise_report
        from services.network_event_log import network_event_log

        report = build_enterprise_report(
            sections=["general", "vulnerabilidades"],
            user_email=user_email,
        )
        from services.report_pdf_service import generate_pdf
        pdf_path = generate_pdf(report)

        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        network_event_log.record(
            f"Reporte diario generado: {report['id']} — enviado al administrador principal",
            level="info",
        )
        try:
            from services.email_delivery_service import send_to_ceo

            attachments = []
            if pdf_path and os.path.isfile(pdf_path):
                with open(pdf_path, "rb") as pf:
                    attachments.append({
                        "filename": os.path.basename(pdf_path),
                        "content": pf.read(),
                    })
            send_to_ceo(
                subject=f"[NOVUS] Reporte diario {report['id']}",
                body=(
                    f"Informe diario NOVUS\nID: {report['id']}\n"
                    f"Generado: {ts}\n"
                    f"Origen: platform_metrics / enterprise_report_service\n"
                    f"Solicitante sesión: {user_email or 'sistema'}"
                ),
                attachments=attachments or None,
                category="daily_report",
            )
        except Exception as mail_exc:
            logger.debug("CEO daily report email: %s", mail_exc)
        try:
            from database import SessionLocal, Log
            db = SessionLocal()
            try:
                db.add(Log(
                    evento="email_daily_report",
                    detalle=f"Informe {report['id']} generado para canal email",
                    fecha=ts,
                ))
                db.commit()
            finally:
                db.close()
        except Exception:
            pass
        return {"report_id": report["id"], "generated_at": ts}
    except Exception as exc:
        logger.error("daily email report: %s", exc)
        return None


def get_whatsapp_queue(limit: int = 10) -> List[dict]:
    return _load_queue()[:limit]
