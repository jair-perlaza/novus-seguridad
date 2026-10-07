"""
Gmail email analysis — parses real messages via Gmail API and classifies threats.
Uses security_engine.inspect_email_integrity for phishing heuristics.
"""
import base64
import json
import os
import re
import threading
import time
from datetime import datetime
from email.utils import parseaddr
from urllib.parse import urlparse

from utils.logger import logger

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ANALYSES_DIR = os.path.join(BASE_DIR, "data", "gmail", "analyses")

CLASSIFICATIONS = (
    "Seguro", "Sospechoso", "Malicioso", "Spam", "Phishing",
    "Ingeniería social", "Fraude", "Desconocido",
)

SUSPICIOUS_EXTENSIONS = {".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".msi", ".hta"}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz"}
MACRO_MIMES = {
    "application/vnd.ms-excel", "application/vnd.ms-powerpoint",
    "application/vnd.openxmlformats-officedocument",
    "application/msword",
}

_sync_running = False
_sync_lock = threading.Lock()
_processed_ids = {}


def _analyses_path(user_id):
    path = os.path.join(ANALYSES_DIR, str(user_id))
    os.makedirs(path, exist_ok=True)
    return path


def _save_analysis(user_id, record):
    folder = _analyses_path(user_id)
    fname = f"{record['message_id']}.json"
    with open(os.path.join(folder, fname), "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2, ensure_ascii=False)
    return record


def _load_history(user_id, limit=50):
    folder = _analyses_path(user_id)
    if not os.path.isdir(folder):
        return []
    files = sorted(
        [os.path.join(folder, f) for f in os.listdir(folder) if f.endswith(".json")],
        key=os.path.getmtime,
        reverse=True,
    )
    records = []
    for fp in files[:limit]:
        try:
            with open(fp, "r", encoding="utf-8") as f:
                records.append(json.load(f))
        except Exception:
            continue
    return records


def get_stats(user_id):
    history = _load_history(user_id, limit=500)
    stats = {
        "total_analyzed": len(history),
        "safe": 0, "suspicious": 0, "malicious": 0,
        "last_analysis": None, "protection_status": "inactive",
    }
    for r in history:
        c = r.get("classification", "")
        if c == "Seguro":
            stats["safe"] += 1
        elif c in ("Sospechoso", "Spam", "Desconocido"):
            stats["suspicious"] += 1
        elif c in ("Malicioso", "Phishing", "Ingeniería social", "Fraude"):
            stats["malicious"] += 1
    if history:
        stats["last_analysis"] = history[0].get("analyzed_at")
    from services.gmail_oauth_service import get_connection_status
    if get_connection_status(user_id).get("connected"):
        stats["protection_status"] = "active"
    return stats


def _decode_body(payload):
    text_parts = []
    html_parts = []

    def walk(part):
        mime = part.get("mimeType", "")
        body = part.get("body", {})
        data = body.get("data")
        if data:
            raw = base64.urlsafe_b64decode(data + "==").decode("utf-8", errors="replace")
            if "html" in mime:
                html_parts.append(raw)
            else:
                text_parts.append(raw)
        for sub in part.get("parts") or []:
            walk(sub)

    walk(payload)
    return "\n".join(text_parts), "\n".join(html_parts)


def _extract_urls(text, html):
    combined = (text or "") + " " + (html or "")
    return list(set(re.findall(r'https?://[^\s<>"\']+', combined, re.I)))


def _parse_auth_headers(headers):
    auth = {"spf": None, "dkim": None, "dmarc": None}
    for h in headers:
        name = h.get("name", "").lower()
        val = h.get("value", "")
        if name == "received-spf":
            auth["spf"] = val
        elif name == "authentication-results":
            if "dkim=pass" in val.lower():
                auth["dkim"] = "pass"
            elif "dkim=fail" in val.lower():
                auth["dkim"] = "fail"
            if "dmarc=pass" in val.lower():
                auth["dmarc"] = "pass"
            elif "dmarc=fail" in val.lower():
                auth["dmarc"] = "fail"
    return auth


def _classify(risk_score, findings, auth):
    findings_lower = " ".join(findings).lower()
    if risk_score >= 0.75 or "phishing" in findings_lower:
        return "Phishing"
    if risk_score >= 0.65:
        return "Malicioso"
    if any(k in findings_lower for k in ("urgencia", "transferencia", "suplantación", "look-alike")):
        return "Ingeniería social"
    if any(k in findings_lower for k in ("fraude", "typosquat")):
        return "Fraude"
    if auth.get("spf") and "fail" in str(auth["spf"]).lower():
        return "Sospechoso"
    if auth.get("dkim") == "fail" or auth.get("dmarc") == "fail":
        return "Sospechoso"
    if risk_score >= 0.35:
        return "Sospechoso"
    if risk_score <= 0.15 and auth.get("dkim") == "pass":
        return "Seguro"
    if risk_score <= 0.2:
        return "Seguro"
    return "Desconocido"


def analyze_message(user_id, msg, service=None):
    """Analyze a Gmail API message resource."""
    headers = {h["name"].lower(): h["value"] for h in msg.get("payload", {}).get("headers", [])}
    sender_raw = headers.get("from", "")
    _, sender_email = parseaddr(sender_raw)
    sender_domain = sender_email.split("@")[-1] if "@" in sender_email else ""

    text_body, html_body = _decode_body(msg.get("payload", {}))
    auth = _parse_auth_headers(msg.get("payload", {}).get("headers", []))
    urls = _extract_urls(text_body, html_body)

    attachments = []
    def walk_attachments(part):
        filename = part.get("filename")
        if filename:
            attachments.append({
                "filename": filename,
                "mimeType": part.get("mimeType"),
                "size": part.get("body", {}).get("size", 0),
            })
        for sub in part.get("parts") or []:
            walk_attachments(sub)
    walk_attachments(msg.get("payload", {}))

    findings = []
    risk = 0.0

    if auth.get("spf") and "fail" in str(auth["spf"]).lower():
        risk += 0.25
        findings.append("SPF falló en autenticación del remitente.")
    if auth.get("dkim") == "fail":
        risk += 0.30
        findings.append("DKIM no válido.")
    if auth.get("dmarc") == "fail":
        risk += 0.35
        findings.append("DMARC no cumple política del dominio.")

    for url in urls:
        host = urlparse(url).netloc.lower()
        if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", host):
            risk += 0.20
            findings.append(f"URL con IP directa: {url[:80]}")
        if len(host) > 40:
            risk += 0.10
            findings.append(f"Dominio URL inusualmente largo: {host[:50]}")

    for att in attachments:
        ext = os.path.splitext(att["filename"])[1].lower()
        mime = (att.get("mimeType") or "").lower()
        if ext in SUSPICIOUS_EXTENSIONS:
            risk += 0.40
            findings.append(f"Adjunto ejecutable sospechoso: {att['filename']}")
        if ext in ARCHIVE_EXTENSIONS:
            risk += 0.15
            findings.append(f"Archivo comprimido adjunto: {att['filename']}")
        if any(m in mime for m in MACRO_MIMES) and ext in (".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptm"):
            risk += 0.25
            findings.append(f"Posible macro en documento Office: {att['filename']}")

    phishing_keywords = [
        r"urgente", r"acción requerida", r"verificar cuenta", r"contraseña",
        r"transferencia", r"haz clic aquí", r"premio", r"factura pendiente",
    ]
    content = (text_body + " " + html_body).lower()
    for pat in phishing_keywords:
        if re.search(pat, content, re.I):
            risk += 0.12
            findings.append(f"Indicador de ingeniería social: '{pat}'.")

    if html_body and len(re.findall(r"<a\s", html_body, re.I)) > 5:
        risk += 0.10
        findings.append("HTML con múltiples enlaces embebidos.")

    try:
        from services.novus_security_integration import novus_security
        meta = {
            "sender": sender_email,
            "sender_domain": sender_domain,
            "domain_age_days": None,
            "is_digitally_signed": auth.get("dkim") == "pass",
        }
        shield = novus_security.security_engine.inspect_email_integrity(meta, text_body or html_body)
        if shield.get("findings"):
            findings.extend(shield["findings"])
        score_str = shield.get("risk_score", "0%").replace("%", "")
        try:
            risk = max(risk, float(score_str) / 100.0)
        except ValueError:
            pass
    except Exception as exc:
        logger.debug(f"security_engine integration: {exc}")

    risk = min(risk, 1.0)
    classification = _classify(risk, findings, auth)

    record = {
        "message_id": msg.get("id"),
        "thread_id": msg.get("threadId"),
        "subject": headers.get("subject", "(sin asunto)"),
        "sender": sender_email,
        "sender_display": sender_raw,
        "domain": sender_domain,
        "analyzed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "classification": classification,
        "risk_score": round(risk * 100, 1),
        "authentication": auth,
        "urls_found": urls[:20],
        "attachments": attachments,
        "findings": findings,
        "technical_summary": (
            f"Clasificación: {classification}. Riesgo {round(risk*100)}%. "
            + (findings[0] if findings else "Sin indicadores críticos detectados.")
        ),
        "suggested_actions": _suggest_actions(classification, risk, sender_email, sender_domain),
    }
    saved = _save_analysis(user_id, record)
    _ingest_mail_shield(user_id, saved)
    return saved


def _ingest_mail_shield(user_id, record):
    try:
        from services.mail_shield_service import ingest_analysis_record
        ingest_analysis_record(user_id, "google_workspace", record, auto_action=True)
    except Exception as exc:
        logger.debug("mail_shield ingest: %s", exc)


def _suggest_actions(classification, risk, sender, domain):
    actions = [{"id": "report", "label": "Generar informe técnico", "requires_confirmation": False}]
    if risk >= 0.4:
        actions.extend([
            {"id": "quarantine", "label": "Mover a cuarentena", "requires_confirmation": True},
            {"id": "spam", "label": "Mover a spam", "requires_confirmation": True},
            {"id": "mark_suspicious", "label": "Marcar como sospechoso", "requires_confirmation": True},
            {"id": "block_sender", "label": "Bloquear remitente", "requires_confirmation": True},
            {"id": "block_domain", "label": "Bloquear dominio", "requires_confirmation": True},
            {"id": "alert", "label": "Crear alerta NOVUS", "requires_confirmation": True},
        ])
    return actions


def sync_new_messages(user_id):
    from services.gmail_oauth_service import load_credentials, save_meta, is_oauth_configured

    if not is_oauth_configured():
        return {"status": "error", "message": "OAuth no configurado", "analyzed": 0}

    creds = load_credentials(user_id)
    if not creds:
        return {"status": "error", "message": "Gmail no conectado", "analyzed": 0}

    try:
        from googleapiclient.discovery import build
        service = build("gmail", "v1", credentials=creds, cache_discovery=False)

        profile = service.users().getProfile(userId="me").execute()
        save_meta(user_id, email=profile.get("emailAddress"), last_sync=datetime.now().isoformat())

        result = service.users().messages().list(userId="me", q="is:unread newer_than:7d", maxResults=15).execute()
        messages = result.get("messages", [])
        analyzed = []

        for item in messages:
            mid = item["id"]
            cache_key = f"{user_id}:{mid}"
            if cache_key in _processed_ids:
                continue
            full = service.users().messages().get(userId="me", id=mid, format="full").execute()
            record = analyze_message(user_id, full, service)
            analyzed.append(record)
            _processed_ids[cache_key] = True

        return {"status": "success", "analyzed": len(analyzed), "records": analyzed}
    except Exception as exc:
        logger.error(f"Gmail sync error: {exc}", exc_info=True)
        return {"status": "error", "message": str(exc), "analyzed": 0}


def execute_action(user_id, action_id, message_id, confirmed=False):
    if not confirmed:
        return {
            "status": "confirm_required",
            "message": "Esta acción modifica su buzón. Confirme explícitamente para continuar.",
        }

    from services.gmail_oauth_service import load_credentials
    creds = load_credentials(user_id)
    if not creds:
        return {"status": "error", "message": "Gmail no conectado"}

    try:
        from googleapiclient.discovery import build
        service = build("gmail", "v1", credentials=creds, cache_discovery=False)

        if action_id == "quarantine":
            _modify_labels(service, message_id, add=["NOVUS-Quarantine"], remove=["INBOX"])
        elif action_id == "spam":
            service.users().messages().trash(userId="me", id=message_id).execute()
        elif action_id == "mark_suspicious":
            _modify_labels(service, message_id, add=["NOVUS-Sospechoso"])
        elif action_id == "block_sender":
            return {"status": "pending", "message": "Fuente real todavía no implementada — configure filtro en Gmail API."}
        elif action_id == "block_domain":
            return {"status": "pending", "message": "Fuente real todavía no implementada — bloqueo de dominio requiere Gmail API."}
        elif action_id == "alert":
            _create_novus_alert(user_id, message_id)
        elif action_id == "report":
            return {"status": "success", "message": "Informe disponible en historial de análisis."}
        else:
            return {"status": "error", "message": f"Acción desconocida: {action_id}"}

        return {"status": "success", "message": f"Acción '{action_id}' ejecutada correctamente."}
    except Exception as exc:
        return {"status": "error", "message": str(exc)}


def _modify_labels(service, message_id, add=None, remove=None):
    body = {}
    if add:
        body["addLabelIds"] = add
    if remove:
        body["removeLabelIds"] = remove
    service.users().messages().modify(userId="me", id=message_id, body=body).execute()


def _create_novus_alert(user_id, message_id):
    folder = _analyses_path(user_id)
    fp = os.path.join(folder, f"{message_id}.json")
    if os.path.isfile(fp):
        with open(fp, "r", encoding="utf-8") as f:
            record = json.load(f)
        alert_path = os.path.join(BASE_DIR, "data", "gmail", "alerts.jsonl")
        os.makedirs(os.path.dirname(alert_path), exist_ok=True)
        with open(alert_path, "a", encoding="utf-8") as f:
            f.write(json.dumps({"user_id": user_id, **record}, ensure_ascii=False) + "\n")


def get_history(user_id, limit=30):
    return _load_history(user_id, limit)


def start_background_gmail_sync(interval=120):
    global _sync_running
    with _sync_lock:
        if _sync_running:
            return
        _sync_running = True

    def loop():
        from services.gmail_oauth_service import GMAIL_DATA_DIR, is_oauth_configured
        while True:
            try:
                if is_oauth_configured() and os.path.isdir(GMAIL_DATA_DIR):
                    for uid in os.listdir(GMAIL_DATA_DIR):
                        token = os.path.join(GMAIL_DATA_DIR, uid, "token.json")
                        if os.path.isfile(token):
                            sync_new_messages(int(uid) if uid.isdigit() else uid)
            except Exception as exc:
                logger.debug(f"Gmail background sync: {exc}")
            time.sleep(interval)

    t = threading.Thread(target=loop, daemon=True, name="GmailSync")
    t.start()
    logger.info("Gmail background sync started")
