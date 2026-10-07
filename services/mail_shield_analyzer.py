"""Análisis de correo Mail Shield — reutiliza motores verificables."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List

from services.gmail_analyzer_service import analyze_message as gmail_analyze_message


def analyze_gmail_message(user_id, msg, service=None) -> Dict[str, Any]:
    record = gmail_analyze_message(user_id, msg, service=service)
    record["provider"] = "google_workspace"
    return record


def analyze_graph_message(msg: Dict[str, Any]) -> Dict[str, Any]:
    """Análisis heurístico sobre payload Microsoft Graph (sin inventar contenido)."""
    subject = msg.get("subject") or "(sin asunto)"
    sender = (msg.get("from") or {}).get("emailAddress") or {}
    sender_email = sender.get("address") or ""
    domain = sender_email.split("@")[-1] if "@" in sender_email else ""
    body = msg.get("body") or {}
    content = body.get("content") or ""
    risk = 0.0
    findings: List[str] = []

    auth = {
        "spf": None,
        "dkim": None,
        "dmarc": None,
        "reply_to_mismatch": False,
        "note": "Graph expone internetMessageHeaders en vista detallada — solicite $select=internetMessageHeaders para SPF/DKIM/DMARC completos.",
    }
    for h in msg.get("internetMessageHeaders") or []:
        name = (h.get("name") or "").lower()
        val = h.get("value") or ""
        if name == "received-spf":
            auth["spf"] = val
        elif name == "authentication-results":
            vl = val.lower()
            if "dkim=pass" in vl:
                auth["dkim"] = "pass"
            elif "dkim=fail" in vl:
                auth["dkim"] = "fail"
            if "dmarc=pass" in vl:
                auth["dmarc"] = "pass"
            elif "dmarc=fail" in vl:
                auth["dmarc"] = "fail"
    reply_to = ""
    for h in msg.get("internetMessageHeaders") or []:
        if (h.get("name") or "").lower() == "reply-to":
            reply_to = (h.get("value") or "").lower()
            break
    if reply_to and sender_email and "@" in reply_to:
        rt_dom = reply_to.split("@")[-1].strip("> ")
        if rt_dom and domain and rt_dom != domain.lower():
            auth["reply_to_mismatch"] = True

    import re
    urls = list(set(re.findall(r"https?://[^\s<>\"']+", content, re.I)))
    for url in urls[:10]:
        try:
            from services.web_shield_analyzer import analyze_url
            from services.mail_shield_config import load_mail_shield_config
            cfg = load_mail_shield_config()
            link = analyze_url(url, whitelist=cfg.get("whitelist_domains"), blacklist=cfg.get("blacklist_domains"))
            if link.get("risk_score", 0) >= 45:
                risk = max(risk, link["risk_score"] / 100.0)
                findings.append(f"Enlace de riesgo ({link['risk_score']}): {url[:120]}")
        except Exception:
            pass

    if auth.get("reply_to_mismatch"):
        risk += 0.35
        findings.append("Reply-To distinto del dominio del remitente (posible BEC).")
    if auth.get("spf") and "fail" in str(auth["spf"]).lower():
        risk += 0.25
        findings.append("SPF falló (internetMessageHeaders).")
    if auth.get("dkim") == "fail":
        risk += 0.30
        findings.append("DKIM fail en authentication-results.")
    if auth.get("dmarc") == "fail":
        risk += 0.35
        findings.append("DMARC fail en authentication-results.")

    if "urgent" in content.lower() or "transfer" in content.lower():
        risk += 0.15
        findings.append("Indicador BEC/urgencia en cuerpo del mensaje.")

    risk = min(1.0, risk)
    classification = "Phishing" if risk >= 0.75 else ("Malicioso" if risk >= 0.55 else ("Sospechoso" if risk >= 0.35 else "Seguro"))

    return {
        "message_id": msg.get("id"),
        "provider": "microsoft365",
        "subject": subject,
        "sender": sender_email,
        "domain": domain,
        "analyzed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "classification": classification,
        "risk_score": round(risk * 100, 1),
        "authentication": auth,
        "urls_found": urls[:20],
        "attachments": [],
        "findings": findings,
        "technical_summary": findings[0] if findings else "Sin indicadores críticos en vista Graph resumida.",
    }
