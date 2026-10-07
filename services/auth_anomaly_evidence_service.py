"""
Evidencia verificable de anomalías de autenticación — única fuente para brute_force / spraying.
Solo cuenta eventos LOGIN_FAILED (Log) y AuthAccessEvent fallidos dentro de una ventana temporal.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

from utils.ip_validation import is_documentation_ip

DEFAULT_WINDOW_HOURS = 24
MIN_BRUTE_FORCE_ATTEMPTS = 5
MIN_SPRAY_IPS = 4
MIN_STUFFING_EMAILS = 8


def _parse_log_row(det: str) -> Tuple[str, str]:
    email, ip = "unknown", "unknown"
    for part in (det or "").split():
        if part.startswith("email="):
            email = part.split("=", 1)[1]
        elif part.startswith("ip="):
            ip = part.split("=", 1)[1]
    return email, ip


def _is_lab_ip(ip: str) -> bool:
    value = (ip or "").strip().lower()
    return (
        not value
        or value == "unknown"
        or value in ("127.0.0.1", "::1", "localhost")
        or value.startswith("127.")
    )


def _is_lab_email(email: str) -> bool:
    value = (email or "").strip().lower()
    return value.endswith("@example.com") or value.endswith("@novus.local")


def _cutoff_str(hours: int) -> str:
    return (datetime.now() - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")


def ip_has_recent_login_failures(db, ip: str, window_hours: int = DEFAULT_WINDOW_HOURS) -> bool:
    """True si la IP tiene al menos un LOGIN_FAILED verificable en la ventana."""
    from database import Log

    if not ip or _is_lab_ip(ip) or is_documentation_ip(ip):
        return False
    cutoff = _cutoff_str(window_hours)
    rows = (
        db.query(Log)
        .filter(Log.evento == "LOGIN_FAILED", Log.fecha >= cutoff)
        .order_by(Log.id.desc())
        .limit(500)
        .all()
    )
    for row in rows:
        det = row.detalle or ""
        if "[EXCLUIDO: IP RFC 5737" in det:
            continue
        _, row_ip = _parse_log_row(det)
        if row_ip == ip:
            return True
    try:
        from database import AuthAccessEvent

        since = cutoff
        cnt = (
            db.query(AuthAccessEvent)
            .filter(
                AuthAccessEvent.success.is_(False),
                AuthAccessEvent.timestamp >= since,
                AuthAccessEvent.ip_address == ip,
            )
            .count()
        )
        return cnt > 0
    except Exception:
        return False


def collect_auth_failure_evidence(db, window_hours: int = DEFAULT_WINDOW_HOURS) -> Dict[str, Dict[str, Any]]:
    """
    Agrupa fallos de login por IP con trazabilidad (IDs de log, ventana, timestamps).
    """
    from database import Log

    cutoff = _cutoff_str(window_hours)
    rows = (
        db.query(Log)
        .filter(Log.evento == "LOGIN_FAILED", Log.fecha >= cutoff)
        .order_by(Log.id.desc())
        .limit(500)
        .all()
    )

    by_ip: Dict[str, Dict[str, Any]] = {}
    all_emails: Set[str] = set()

    for row in rows:
        det = row.detalle or ""
        if "[EXCLUIDO: IP RFC 5737" in det:
            continue
        email, ip = _parse_log_row(det)
        if is_documentation_ip(ip) or _is_lab_ip(ip) or _is_lab_email(email):
            continue
        all_emails.add(email)
        if ip == "unknown":
            continue
        bucket = by_ip.setdefault(
            ip,
            {
                "log_row_ids": [],
                "emails": set(),
                "first_event_at": row.fecha,
                "last_event_at": row.fecha,
            },
        )
        bucket["log_row_ids"].append(row.id)
        bucket["emails"].add(email)
        if row.fecha and row.fecha < bucket["first_event_at"]:
            bucket["first_event_at"] = row.fecha
        if row.fecha and row.fecha > bucket["last_event_at"]:
            bucket["last_event_at"] = row.fecha

    for ip, bucket in by_ip.items():
        bucket["attempts"] = len(bucket["log_row_ids"])
        bucket["emails"] = sorted(bucket["emails"])

    return by_ip


def build_verified_auth_threats(db, window_hours: int = DEFAULT_WINDOW_HOURS) -> List[dict]:
    """Genera amenazas auth solo con evidencia en ventana y trazabilidad completa."""
    by_ip = collect_auth_failure_evidence(db, window_hours)
    threats: List[dict] = []
    ts_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for ip, ev in by_ip.items():
        attempts = ev.get("attempts") or 0
        if attempts < MIN_BRUTE_FORCE_ATTEMPTS:
            continue
        log_ids = ev.get("log_row_ids") or []
        last_at = ev.get("last_event_at") or ts_now
        first_at = ev.get("first_event_at") or last_at
        details = {
            "verified": True,
            "evidence": (
                f"{attempts} intentos LOGIN_FAILED verificables desde {ip} "
                f"(ventana {window_hours}h, logs {log_ids[:8]}{'…' if len(log_ids) > 8 else ''})"
            ),
            "ip": ip,
            "attempts": attempts,
            "source": "auth_access_audit",
            "motor": "auth_protection_service",
            "event_type": "brute_force",
            "log_row_ids": log_ids,
            "window_hours": window_hours,
            "first_event_at": first_at,
            "last_event_at": last_at,
            "timestamp": last_at,
            "confidence": "Alta",
            "investigation_status": "En investigación",
        }
        threats.append({
            "type": "brute_force",
            "severity": "high",
            "source": "auth_access_audit",
            "details": details,
        })

    # password spraying: misma cuenta, múltiples IP en ventana
    by_email: Dict[str, Set[str]] = {}
    for ip, ev in by_ip.items():
        for email in ev.get("emails") or []:
            if email == "unknown" or _is_lab_email(email):
                continue
            by_email.setdefault(email, set()).add(ip)

    for email, ips in by_email.items():
        if len(ips) < MIN_SPRAY_IPS:
            continue
        threats.append({
            "type": "password_spraying",
            "severity": "medium",
            "source": "auth_access_audit",
            "details": {
                "verified": True,
                "evidence": f"Cuenta {email}: intentos desde {len(ips)} IP(s) en {window_hours}h",
                "email": email,
                "unique_ips": len(ips),
                "source": "auth_access_audit",
                "motor": "auth_protection_service",
                "event_type": "password_spraying",
                "window_hours": window_hours,
                "timestamp": ts_now,
                "last_event_at": ts_now,
                "confidence": "Media",
                "investigation_status": "En investigación",
            },
        })

    if len(all_emails := {e for ev in by_ip.values() for e in (ev.get("emails") or []) if e != "unknown"}) >= MIN_STUFFING_EMAILS:
        total_attempts = sum(ev.get("attempts") or 0 for ev in by_ip.values())
        if total_attempts >= 10:
            threats.append({
                "type": "credential_stuffing",
                "severity": "medium",
                "source": "auth_access_audit",
                "details": {
                    "verified": True,
                    "evidence": (
                        f"{len(all_emails)} cuentas distintas, {total_attempts} fallos "
                        f"en ventana {window_hours}h"
                    ),
                    "unique_emails": len(all_emails),
                    "source": "auth_access_audit",
                    "motor": "auth_protection_service",
                    "event_type": "credential_stuffing",
                    "window_hours": window_hours,
                    "timestamp": ts_now,
                    "last_event_at": ts_now,
                    "confidence": "Media",
                    "investigation_status": "En investigación",
                },
            })

    return threats


def auth_details_pass_gate(details: dict) -> Tuple[bool, str]:
    """Exige trazabilidad mínima para amenazas basadas en auth."""
    if not isinstance(details, dict) or details.get("verified") is not True:
        return False, "auth sin verified"
    src = str(details.get("source") or "")
    event_type = str(details.get("event_type") or "").lower()

    if src == "audit_logs" and not details.get("log_row_ids"):
        return False, "auth legacy sin log_row_ids"

    last_at = details.get("last_event_at") or details.get("timestamp")
    if not last_at:
        return False, "auth sin last_event_at"
    try:
        dt = datetime.strptime(str(last_at)[:19], "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return False, "timestamp auth inválido"
    window = int(details.get("window_hours") or DEFAULT_WINDOW_HOURS)
    if datetime.now() - dt > timedelta(hours=window + 1):
        return False, "evidencia auth fuera de ventana"

    if event_type == "brute_force" or details.get("ip"):
        if not details.get("log_row_ids"):
            return False, "brute_force sin log_row_ids"
        if (details.get("attempts") or 0) < MIN_BRUTE_FORCE_ATTEMPTS:
            return False, "intentos insuficientes en ventana"

    return True, ""
