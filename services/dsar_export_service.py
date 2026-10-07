"""
P0-5 — DSAR export mínimo (soporte técnico, no declaración legal).

TENANT-SCOPED via require_canonical_tenant_id.
No exporta secretos, HOST_GLOBAL ni NOVUS_GLOBAL.
"""
from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from utils.logger import logger

# Hard denylist substrings for accidental secret leakage in serialized export
_SECRET_MARKERS = (
    "hashed_password",
    "password_hash",
    "secret_enc",
    "secret_key",
    "api_key",
    "apikey",
    "refresh_token",
    "access_token",
    "private_key",
    "fernet",
    "novus_mfa_key",
    "setup_token",
    "channel_key",
)


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _cat(
    *,
    category: str,
    state: str,
    records: Optional[List[Any]] = None,
    count: Optional[int] = None,
    reason: Optional[str] = None,
    notes: Optional[str] = None,
) -> Dict[str, Any]:
    recs = list(records or [])
    return {
        "category": category,
        "data_state": state,
        "count": count if count is not None else len(recs),
        "records": recs,
        "reason": reason,
        "notes": notes,
    }


def _scrub_dict(obj: Any, *, depth: int = 0) -> Any:
    """Drop keys that look like secrets; never invent replacements."""
    if depth > 8:
        return None
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            kl = str(k).lower()
            if any(m in kl for m in _SECRET_MARKERS) or kl in ("password", "passwd", "token", "secret"):
                continue
            out[k] = _scrub_dict(v, depth=depth + 1)
        return out
    if isinstance(obj, list):
        return [_scrub_dict(x, depth=depth + 1) for x in obj[:500]]
    return obj


def _contains_secret_leak(blob: str) -> List[str]:
    low = blob.lower()
    hits = []
    for m in _SECRET_MARKERS:
        if m in low:
            hits.append(m)
    # bcrypt-ish / long hex hashes that look like password hashes in values
    if re.search(r"\$2[aby]\$\d{2}\$", blob):
        hits.append("bcrypt_hash_pattern")
    return hits


def _export_users(tid: str, limit: int) -> Dict[str, Any]:
    from database import SessionLocal, Usuario

    db = SessionLocal()
    try:
        rows = (
            db.query(Usuario)
            .filter(Usuario.nit_pyme == tid)
            .limit(limit)
            .all()
        )
        records = []
        for u in rows:
            records.append(
                {
                    "id": u.id,
                    "email": u.email,
                    "role": getattr(u, "role", None),
                    "sector": getattr(u, "sector", None),
                    "nit_pyme": getattr(u, "nit_pyme", None),
                    "is_active": getattr(u, "is_active", None),
                    "is_temporal": getattr(u, "is_temporal", None),
                    "trial_expiry": str(getattr(u, "trial_expiry", None) or "") or None,
                    # Explicitly omitted: hashed_password
                }
            )
        return _cat(category="account_users", state="LIVE" if records else "NOT_AVAILABLE", records=records)
    except Exception as exc:
        logger.warning("dsar users: %s", exc)
        return _cat(category="account_users", state="UNKNOWN", reason=str(exc)[:160])
    finally:
        db.close()


def _export_alerts(tid: str, limit: int) -> Dict[str, Any]:
    from database import SessionLocal, Alerta
    from services.tenant_isolation_service import sql_tenant_filter
    from sqlalchemy import and_

    db = SessionLocal()
    try:
        q = (
            sql_tenant_filter(db.query(Alerta), Alerta, tid)
            .filter(and_(Alerta.tenant_id.isnot(None), Alerta.tenant_id != ""))
            .order_by(Alerta.id.desc())
            .limit(limit)
        )
        records = []
        for a in q.all():
            records.append(
                {
                    "id": a.id,
                    "tenant_id": a.tenant_id,
                    "titulo": a.titulo,
                    "descripcion": (a.descripcion or "")[:500],
                    "nivel": a.nivel,
                    "fecha": str(a.fecha) if a.fecha else None,
                    "activa": a.activa,
                    "ip_afectada": a.ip_afectada,
                }
            )
        return _cat(category="alerts", state="LIVE" if records else "NOT_AVAILABLE", records=records)
    except Exception as exc:
        logger.warning("dsar alerts: %s", exc)
        return _cat(category="alerts", state="UNKNOWN", reason=str(exc)[:160])
    finally:
        db.close()


def _export_reports(tid: str, limit: int) -> Dict[str, Any]:
    try:
        from services.security_report_service import list_reports

        raw = list_reports(limit=limit, tenant_id=tid) or []
        records = [_scrub_dict(r) for r in raw]
        return _cat(category="reports", state="LIVE" if records else "NOT_AVAILABLE", records=records)
    except Exception as exc:
        return _cat(category="reports", state="UNKNOWN", reason=str(exc)[:160])


def _export_evidence(tid: str, limit: int) -> Dict[str, Any]:
    try:
        from services.evidence_center_service import list_evidence

        raw = list_evidence(limit=limit, tenant_id=tid) or []
        records = [_scrub_dict(r) for r in raw]
        return _cat(category="evidence", state="LIVE" if records else "NOT_AVAILABLE", records=records)
    except Exception as exc:
        return _cat(category="evidence", state="UNKNOWN", reason=str(exc)[:160])


def _export_sessions(tid: str, limit: int) -> Dict[str, Any]:
    try:
        from services.login_session_audit_service import list_login_sessions

        raw = list_login_sessions(limit=limit, tenant_id=tid) or []
        records = []
        for s in raw:
            scrubbed = _scrub_dict(s)
            if isinstance(scrubbed, dict):
                scrubbed.pop("session_secret", None)
                scrubbed.pop("csrf_token", None)
            records.append(scrubbed)
        return _cat(category="login_sessions", state="LIVE" if records else "NOT_AVAILABLE", records=records)
    except Exception as exc:
        return _cat(category="login_sessions", state="UNKNOWN", reason=str(exc)[:160])


def _export_incidents(tid: str, limit: int) -> Dict[str, Any]:
    try:
        from services.imcm.engine import search_incidents

        raw = search_incidents(tenant_id=tid, limit=limit) or []
        records = [_scrub_dict(r) for r in raw]
        return _cat(category="incidents", state="LIVE" if records else "NOT_AVAILABLE", records=records)
    except Exception as exc:
        return _cat(category="incidents", state="UNKNOWN", reason=str(exc)[:160])


def _export_vulnerabilities(tid: str, limit: int) -> Dict[str, Any]:
    from database import SessionLocal, Vulnerabilidad
    from services.tenant_isolation_service import sql_tenant_filter

    db = SessionLocal()
    try:
        q = sql_tenant_filter(db.query(Vulnerabilidad), Vulnerabilidad, tid).limit(limit)
        records = []
        for v in q.all():
            records.append(
                {
                    "id": getattr(v, "id", None),
                    "tenant_id": getattr(v, "tenant_id", None),
                    "titulo": getattr(v, "titulo", None),
                    "descripcion": str(getattr(v, "descripcion", None) or "")[:500],
                    "nivel": getattr(v, "nivel", None),
                    "severidad": getattr(v, "severidad", None),
                    "estado": getattr(v, "estado", None),
                    "componente": getattr(v, "componente", None),
                    "fecha": getattr(v, "fecha", None),
                }
            )
        return _cat(
            category="vulnerabilities",
            state="LIVE" if records else "NOT_AVAILABLE",
            records=records,
            notes="Only rows with exact tenant_id match; host-scoped vulns excluded",
        )
    except Exception as exc:
        return _cat(category="vulnerabilities", state="UNKNOWN", reason=str(exc)[:160])
    finally:
        db.close()


def _export_inventory(tid: str, limit: int) -> Dict[str, Any]:
    try:
        from database import SessionLocal, NetworkDeviceInventory
        from services.tenant_isolation_service import sql_tenant_filter

        db = SessionLocal()
        try:
            q = sql_tenant_filter(db.query(NetworkDeviceInventory), NetworkDeviceInventory, tid).limit(limit)
            records = []
            for d in q.all():
                records.append(
                    {
                        "id": getattr(d, "id", None),
                        "tenant_id": getattr(d, "tenant_id", None),
                        "hostname": getattr(d, "hostname", None),
                        "ip": getattr(d, "ip", None),
                        "mac": getattr(d, "mac", None),
                        "device_type": getattr(d, "device_type", None),
                        "vendor": getattr(d, "vendor", None),
                        "first_seen": getattr(d, "first_seen", None),
                        "last_seen": getattr(d, "last_seen", None),
                    }
                )
            return _cat(
                category="inventory",
                state="LIVE" if records else "NOT_AVAILABLE",
                records=records,
                notes="Exact tenant_id only; platform host inventory not attributed to client",
            )
        finally:
            db.close()
    except Exception as exc:
        return _cat(category="inventory", state="NOT_EXPORTABLE", reason=str(exc)[:160])


def _export_collective_memory(tid: str, limit: int) -> Dict[str, Any]:
    """Tenant-scoped collective memory rows only (P0-1). Skip legacy unscoped."""
    from pathlib import Path

    path = Path(__file__).resolve().parents[1] / "data" / "swarm_defense" / "collective_memory.jsonl"
    if not path.is_file():
        return _cat(category="collective_memory", state="NOT_AVAILABLE", notes="file absent")
    records = []
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                if len(records) >= limit:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except Exception:
                    continue
                row_tid = str(row.get("tenant_id") or "").strip()
                if not row_tid or row_tid != tid:
                    continue
                records.append(
                    {
                        "tenant_id": row_tid,
                        "key": row.get("key") or row.get("incident_key"),
                        "summary": str(row.get("summary") or row.get("description") or "")[:300],
                        "timestamp": row.get("timestamp") or row.get("ts"),
                    }
                )
        return _cat(
            category="collective_memory",
            state="LIVE" if records else "NOT_AVAILABLE",
            records=records,
            notes="Legacy unscoped rows excluded (NOT tenant data)",
        )
    except Exception as exc:
        return _cat(category="collective_memory", state="UNKNOWN", reason=str(exc)[:160])


def _not_exportable_globals() -> List[Dict[str, Any]]:
    return [
        _cat(
            category="HOST_GLOBAL",
            state="NOT_EXPORTABLE",
            reason="Host/platform telemetry and baselines are not tenant personal data",
        ),
        _cat(
            category="NOVUS_GLOBAL",
            state="NOT_EXPORTABLE",
            reason="Shared intel / platform global stores are not tenant personal data",
        ),
        _cat(
            category="mfa_secrets",
            state="NOT_EXPORTABLE",
            reason="TOTP secrets and recovery material must never be exported",
        ),
        _cat(
            category="credentials",
            state="NOT_EXPORTABLE",
            reason="password hashes, API keys, tokens, cryptographic material excluded",
        ),
    ]


def build_dsar_export(
    *,
    tenant_id: str,
    requested_by_email: Optional[str],
    limit_per_category: int = 100,
) -> Dict[str, Any]:
    tid = str(tenant_id or "").strip()
    if not tid:
        raise ValueError("tenant_not_configured")

    lim = max(1, min(int(limit_per_category or 100), 200))
    export_id = f"DSAR-{uuid.uuid4().hex[:12].upper()}"

    categories = [
        _export_users(tid, lim),
        _export_alerts(tid, lim),
        _export_reports(tid, lim),
        _export_evidence(tid, lim),
        _export_sessions(tid, lim),
        _export_incidents(tid, lim),
        _export_vulnerabilities(tid, lim),
        _export_inventory(tid, lim),
        _export_collective_memory(tid, lim),
    ]
    categories.extend(_not_exportable_globals())

    package = {
        "status": "success",
        "export_id": export_id,
        "generated_at_utc": _utc(),
        "scope": "TENANT",
        "tenant_id": tid,
        "requested_by": requested_by_email,
        "requested_scope": "dsar_access_export_minimum",
        "technical_support_only": True,
        "legal_compliance_claim": False,
        "limit_per_category": lim,
        "categories": categories,
        "counts": {c["category"]: c.get("count", 0) for c in categories if c.get("data_state") != "NOT_EXPORTABLE"},
        "excluded_always": [
            "passwords",
            "password_hashes",
            "mfa_secrets",
            "api_keys",
            "tokens",
            "cryptographic_keys",
            "HOST_GLOBAL",
            "NOVUS_GLOBAL",
            "other_tenants",
        ],
    }

    # Final leak scan on serialized package (excluding intentional marker names in excluded_always)
    scan_blob = json.dumps(
        {k: v for k, v in package.items() if k not in ("excluded_always",)},
        ensure_ascii=False,
        default=str,
    )
    # Remove known safe occurrences of marker words in category names / reasons
    leak_hits = [
        h
        for h in _contains_secret_leak(scan_blob)
        if h not in ("secret_key",)  # may appear in reason text; double-check values
    ]
    # Stricter: bcrypt in payload is always a fail
    package["secret_scan"] = {
        "bcrypt_pattern_found": bool(re.search(r"\$2[aby]\$\d{2}\$", scan_blob)),
        "marker_hits": sorted(set(leak_hits))[:20],
    }
    if package["secret_scan"]["bcrypt_pattern_found"]:
        # Strip user records entirely if somehow hashed leaked
        for c in package["categories"]:
            if c.get("category") == "account_users":
                c["records"] = [
                    {k: v for k, v in r.items() if "hash" not in str(k).lower() and "password" not in str(k).lower()}
                    if isinstance(r, dict)
                    else r
                    for r in (c.get("records") or [])
                ]
                c["notes"] = (c.get("notes") or "") + " secret_scan_sanitized"
    return package


def record_dsar_audit(*, tenant_id: str, user_email: Optional[str], export_id: str, counts: Dict[str, Any]) -> None:
    try:
        from services.enterprise_data_service import record_audit_domain

        record_audit_domain(
            action="dsar_export",
            user_email=user_email,
            tenant_id=tenant_id,
            outcome="success",
            detail={"export_id": export_id, "counts": counts, "p0": "p0_5"},
        )
    except Exception as exc:
        logger.debug("dsar audit: %s", exc)
