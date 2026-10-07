"""
Entrega de correo — destino único: administrador principal (CEO).

Telemetría, alertas, reportes y logs de uso van exclusivamente a NOVUS_CEO_EMAIL.

ÚNICA excepción transaccional permitida: send_email() al solicitante de registro
con el enlace para completar contraseña tras aprobación del CEO (flujo de onboarding).
"""
from __future__ import annotations

import json
import os
import smtplib
from datetime import datetime
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, List, Optional

from utils.logger import logger

CEO_QUEUE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "data", "alerts", "ceo_email_queue.json"
)


def get_ceo_email() -> Optional[str]:
    """Correo del administrador principal — únicamente NOVUS_CEO_EMAIL."""
    val = (os.environ.get("NOVUS_CEO_EMAIL") or "").strip()
    if val and "@" in val:
        return val.split(",")[0].strip()
    return None


def _ensure_queue_dir() -> None:
    os.makedirs(os.path.dirname(CEO_QUEUE_PATH), exist_ok=True)


def _queue_ceo_message(
    subject: str,
    body: str,
    *,
    category: str = "telemetry",
    attachments: Optional[List[Dict[str, Any]]] = None,
) -> dict:
    _ensure_queue_dir()
    entry = {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "category": category,
        "subject": subject,
        "body": body[:8000],
        "ceo_email": get_ceo_email(),
        "attachments": [
            {"filename": a.get("filename"), "size": len(a.get("content") or b"")}
            for a in (attachments or [])
        ],
        "status": "queued_local",
        "reason": "smtp_unavailable_or_ceo_only_queue",
    }
    items: List[dict] = []
    if os.path.exists(CEO_QUEUE_PATH):
        try:
            with open(CEO_QUEUE_PATH, "r", encoding="utf-8") as fh:
                items = json.load(fh)
        except Exception:
            items = []
    items.append(entry)
    with open(CEO_QUEUE_PATH, "w", encoding="utf-8") as fh:
        json.dump(items[-200:], fh, indent=2, ensure_ascii=False)
    return entry


def send_email(
    to_email: str,
    subject: str,
    body: str,
    *,
    html_body: Optional[str] = None,
    attachments: Optional[List[Dict[str, Any]]] = None,
    category: str = "transactional",
) -> dict:
    """Envía correo vía SMTP si está configurado; si no, encola localmente."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if not to_email or "@" not in to_email:
        return {"ok": False, "error": "invalid_recipient", "time": ts}

    host = (os.environ.get("NOVUS_SMTP_HOST") or "").strip()
    port = int(os.environ.get("NOVUS_SMTP_PORT") or "587")
    user = (os.environ.get("NOVUS_SMTP_USER") or "").strip()
    password = (os.environ.get("NOVUS_SMTP_PASSWORD") or "").strip()
    from_addr = (os.environ.get("NOVUS_SMTP_FROM") or user or "novus@local").strip()

    if not host:
        queued = _queue_ceo_message(subject, f"TO:{to_email}\n\n{body}", category=category, attachments=attachments)
        return {"ok": True, "mode": "queued", "queued": queued, "time": ts}

    try:
        msg = MIMEMultipart()
        msg["Subject"] = subject
        msg["From"] = from_addr
        msg["To"] = to_email
        msg.attach(MIMEText(html_body or body, "html" if html_body else "plain", "utf-8"))
        for att in attachments or []:
            part = MIMEApplication(att.get("content") or b"", Name=att.get("filename") or "attachment")
            part["Content-Disposition"] = f'attachment; filename="{att.get("filename") or "attachment"}"'
            msg.attach(part)
        with smtplib.SMTP(host, port, timeout=30) as smtp:
            if user and password:
                smtp.starttls()
                smtp.login(user, password)
            smtp.sendmail(from_addr, [to_email], msg.as_string())
        return {"ok": True, "mode": "smtp", "to": to_email, "time": ts}
    except Exception as exc:
        logger.warning("CEO email SMTP failed: %s", exc)
        queued = _queue_ceo_message(subject, f"TO:{to_email}\n\n{body}\n\nSMTP_ERROR:{exc}", category=category)
        return {"ok": False, "mode": "queued_after_error", "error": str(exc), "queued": queued, "time": ts}


def send_to_ceo(
    subject: str,
    body: str,
    *,
    html_body: Optional[str] = None,
    attachments: Optional[List[Dict[str, Any]]] = None,
    category: str = "telemetry",
) -> dict:
    """Envía telemetría/reportes/alertas únicamente al CEO."""
    ceo = get_ceo_email()
    if not ceo:
        queued = _queue_ceo_message(subject, body, category=category, attachments=attachments)
        return {"ok": False, "error": "ceo_email_not_configured", "queued": queued}
    return send_email(ceo, subject, body, html_body=html_body, attachments=attachments, category=category)


def deliver_report_to_ceo(
    report: Dict[str, Any],
    *,
    category: str = "report",
    trigger_user_email: Optional[str] = None,
) -> dict:
    """Envía copia de informe generado al CEO (telemetría interna)."""
    report_id = report.get("id") or "unknown"
    subject = f"[NOVUS] Informe {report_id}"
    body = (
        f"Informe NOVUS\n"
        f"ID: {report_id}\n"
        f"Tipo: {report.get('tipo') or report.get('type') or category}\n"
        f"Severidad: {report.get('severidad') or report.get('severity') or '—'}\n"
        f"Origen: {report.get('source') or category}\n"
        f"Sesión/usuario disparador: {trigger_user_email or 'sistema'}\n"
        f"Generado: {report.get('generated_at') or report.get('fecha') or '—'}\n"
    )
    attachments = None
    try:
        from services.report_pdf_service import generate_pdf

        pdf_path = generate_pdf(report)
        if pdf_path and os.path.isfile(pdf_path):
            with open(pdf_path, "rb") as pf:
                attachments = [{"filename": os.path.basename(pdf_path), "content": pf.read()}]
    except Exception as exc:
        logger.debug("CEO report PDF attach skipped: %s", exc)
    return send_to_ceo(subject, body, attachments=attachments, category=category)
