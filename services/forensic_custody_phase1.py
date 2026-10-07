"""
Fase 1 — Integridad Forense Enterprise (custodia, sellado, trazabilidad, exportación).

Reglas:
- Nunca elimina evidencias.
- No altera el payload original; al reparar continuidad se archiva el registro
  original byte-a-byte y se re-sella el mismo contenido en una cadena continua.
- Kernel IA no escribe en este módulo.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import threading
import uuid
import zipfile
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from utils.logger import logger

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LEDGER_DIR = os.path.join(ROOT, "data", "forensic_ledger")
RECORDS_FILE = os.path.join(LEDGER_DIR, "records.jsonl")
CHAIN_HEAD_FILE = os.path.join(LEDGER_DIR, "chain_head.json")
SOURCE_INDEX_FILE = os.path.join(LEDGER_DIR, "source_index.json")
ACCESS_LOG_FILE = os.path.join(LEDGER_DIR, "access.jsonl")
CUSTODY_LOG_FILE = os.path.join(LEDGER_DIR, "custody_chain.jsonl")
COMPROMISED_INDEX_FILE = os.path.join(LEDGER_DIR, "compromised_index.jsonl")
CRITICAL_ALERT_FILE = os.path.join(LEDGER_DIR, "critical_alerts.jsonl")
SEALED_CLOSED_DIR = os.path.join(LEDGER_DIR, "sealed_closed")
IMMUTABLE_ARCHIVE_DIR = os.path.join(LEDGER_DIR, "immutable_archive")
EXPORT_DIR = os.path.join(ROOT, "data", "forensic_exports")
REPAIR_REPORT_DIR = os.path.join(LEDGER_DIR, "repair_reports")

_repair_lock = threading.Lock()


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _ensure() -> None:
    for d in (
        LEDGER_DIR,
        SEALED_CLOSED_DIR,
        IMMUTABLE_ARCHIVE_DIR,
        EXPORT_DIR,
        REPAIR_REPORT_DIR,
        os.path.join(IMMUTABLE_ARCHIVE_DIR, "originals"),
    ):
        os.makedirs(d, exist_ok=True)


def log_custody_event(
    *,
    action: str,
    forensic_id: Optional[str] = None,
    source_id: Optional[str] = None,
    case_id: Optional[str] = None,
    user_email: Optional[str] = None,
    ip_address: Optional[str] = None,
    equipment: Optional[str] = None,
    motor: Optional[str] = None,
    reason: Optional[str] = None,
    detail: Optional[dict] = None,
    outcome: str = "ok",
) -> Dict[str, Any]:
    """Cadena de custodia legal (handoff / acceso / intento de modificación)."""
    _ensure()
    row = {
        "custody_id": f"COC-{uuid.uuid4().hex[:14]}",
        "timestamp_utc": _utc_now(),
        "action": action[:120],
        "forensic_id": forensic_id,
        "source_id": source_id,
        "case_id": case_id,
        "user_email": user_email,
        "ip_address": ip_address,
        "equipment": equipment,
        "motor": motor,
        "reason": (reason or "")[:500],
        "outcome": outcome,
        "detail": detail or {},
    }
    with open(CUSTODY_LOG_FILE, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    try:
        from services.forensic_evidence_integrity_service import log_evidence_access

        log_evidence_access(
            forensic_id=forensic_id,
            source_id=source_id,
            action=f"custody:{action}",
            user_email=user_email,
            ip_address=ip_address,
            outcome=outcome,
            detail={"case_id": case_id, "reason": reason, **(detail or {})},
        )
    except Exception:
        pass
    return row


def emit_critical_alert(
    *,
    forensic_id: str,
    source_id: str,
    alert_type: str,
    detail: dict,
) -> Dict[str, Any]:
    """Alerta crítica visible — nunca oculta alteraciones."""
    _ensure()
    row = {
        "alert_id": f"FCRIT-{uuid.uuid4().hex[:12]}",
        "timestamp_utc": _utc_now(),
        "severity": "critical",
        "alert_type": alert_type,
        "forensic_id": forensic_id,
        "source_id": source_id,
        "detail": detail,
        "hidden": False,
    }
    with open(CRITICAL_ALERT_FILE, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    try:
        from services.defense_evidence_registry import record_defense_event

        record_defense_event(
            "audit",
            "forensic_integrity_critical",
            "forensic_custody_phase1",
            "detected",
            threat_type="integrity",
            detail=alert_type,
            evidence={
                "verified": True,
                "forensic_id": forensic_id,
                "source_id": source_id,
                "critical": True,
                **detail,
            },
        )
    except Exception as exc:
        logger.debug("critical alert bridge: %s", exc)
    return row


def mark_compromised(
    *,
    forensic_id: str,
    source_id: str,
    reason: str,
    checks: Optional[dict] = None,
    repairable: bool = False,
) -> Dict[str, Any]:
    """Marca evidencia como comprometida — nunca la elimina."""
    _ensure()
    row = {
        "marked_at_utc": _utc_now(),
        "forensic_id": forensic_id,
        "source_id": source_id,
        "reason": reason[:800],
        "checks": checks or {},
        "repairable": repairable,
        "deleted": False,
        "status": "compromised",
    }
    with open(COMPROMISED_INDEX_FILE, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    return row


def is_sealed_closed(forensic_id: str) -> bool:
    path = os.path.join(SEALED_CLOSED_DIR, f"{forensic_id}.seal.json")
    return os.path.isfile(path)


def close_seal_evidence(
    forensic_id: str,
    *,
    user_email: Optional[str] = None,
    motor: str = "forensic_custody_phase1",
    reason: str = "case_closed",
    ip_address: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Sellado de cierre: impide nuevas versiones/modificaciones lógicas del source.
    Verificable vía archivo de sello firmado + registro de custodia.
    """
    from services.forensic_evidence_integrity_service import (
        get_record_by_forensic_id,
        verify_single,
        _sign_bytes,
        _sha256_hex,
        _canonical_json,
    )

    rec = get_record_by_forensic_id(forensic_id)
    if not rec:
        return {"ok": False, "reason": "not_found"}
    if is_sealed_closed(forensic_id):
        return {"ok": True, "already_closed": True, "forensic_id": forensic_id}

    vr = verify_single(forensic_id)
    if not vr.get("ok"):
        emit_critical_alert(
            forensic_id=forensic_id,
            source_id=rec.get("source_id") or "",
            alert_type="seal_close_blocked_integrity_fail",
            detail=vr,
        )
        return {"ok": False, "reason": "integrity_failed", "verify": vr}

    _ensure()
    ts = _utc_now()
    body = {
        "forensic_id": forensic_id,
        "source_id": rec.get("source_id"),
        "closed_at_utc": ts,
        "closed_by": user_email,
        "motor": motor,
        "reason": reason,
        "content_hash_sha256": rec.get("content_hash_sha256"),
        "chain_hash": rec.get("chain_hash"),
        "signature_hex": rec.get("signature_hex"),
    }
    digest = _sha256_hex(_canonical_json(body))
    sig, kid = _sign_bytes(f"close_seal|{digest}|{forensic_id}".encode("utf-8"))
    seal = {**body, "seal_hash_sha256": digest, "seal_signature_hex": sig, "seal_key_id": kid}
    path = os.path.join(SEALED_CLOSED_DIR, f"{forensic_id}.seal.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(seal, fh, indent=2, ensure_ascii=False)

    log_custody_event(
        action="seal_close",
        forensic_id=forensic_id,
        source_id=rec.get("source_id"),
        case_id=rec.get("case_id"),
        user_email=user_email,
        ip_address=ip_address,
        motor=motor,
        reason=reason,
        detail={"seal_hash": digest},
    )
    return {"ok": True, "seal_path": path, "seal": seal}


def verify_close_seal(forensic_id: str) -> Dict[str, Any]:
    from services.forensic_evidence_integrity_service import (
        _verify_signature,
        _sha256_hex,
        _canonical_json,
    )

    path = os.path.join(SEALED_CLOSED_DIR, f"{forensic_id}.seal.json")
    if not os.path.isfile(path):
        return {"ok": False, "reason": "not_closed"}
    with open(path, encoding="utf-8") as fh:
        seal = json.load(fh)
    body = {k: seal.get(k) for k in (
        "forensic_id", "source_id", "closed_at_utc", "closed_by", "motor", "reason",
        "content_hash_sha256", "chain_hash", "signature_hex",
    )}
    digest = _sha256_hex(_canonical_json(body))
    hash_ok = digest == seal.get("seal_hash_sha256")
    msg = f"close_seal|{seal.get('seal_hash_sha256')}|{forensic_id}".encode("utf-8")
    sig_ok = _verify_signature(msg, seal.get("seal_signature_hex") or "")
    return {"ok": hash_ok and sig_ok, "hash_ok": hash_ok, "signature_ok": sig_ok, "seal": seal}


def get_evidence_auto_verify(
    forensic_id: str,
    *,
    user_email: Optional[str] = None,
    ip_address: Optional[str] = None,
    action: str = "consult",
) -> Dict[str, Any]:
    """Consulta con verificación automática de integridad/firma/hash/cadena/timestamp."""
    from services.forensic_evidence_integrity_service import (
        get_record_by_forensic_id,
        verify_single,
        iter_ledger_records,
    )

    rec = get_record_by_forensic_id(forensic_id)
    if not rec:
        log_custody_event(
            action=action,
            forensic_id=forensic_id,
            user_email=user_email,
            ip_address=ip_address,
            outcome="not_found",
            reason="evidence_missing",
        )
        return {"ok": False, "reason": "not_found"}

    # Timestamp presente
    ts_ok = bool(rec.get("timestamp") or rec.get("signed_at"))
    vr = verify_single(forensic_id)
    # Cadena: comprobar prev respecto al registro anterior en ledger
    prev = "0" * 64
    for r in iter_ledger_records():
        if r.get("forensic_id") == forensic_id:
            chain_ok = r.get("prev_chain_hash") == prev
            break
        prev = r.get("chain_hash") or prev
    else:
        chain_ok = False

    checks = dict(vr.get("checks") or {})
    checks["timestamp_present"] = ts_ok
    checks["chain_link_ok"] = chain_ok
    ok = bool(vr.get("ok")) and ts_ok and chain_ok

    log_custody_event(
        action=action,
        forensic_id=forensic_id,
        source_id=rec.get("source_id"),
        case_id=rec.get("case_id"),
        user_email=user_email,
        ip_address=ip_address,
        motor=rec.get("motor"),
        outcome="ok" if ok else "integrity_alert",
        reason=None if ok else "auto_verify_failed",
        detail={"checks": checks},
    )

    if not ok:
        emit_critical_alert(
            forensic_id=forensic_id,
            source_id=rec.get("source_id") or "",
            alert_type="evidence_tamper_or_chain_fail_on_consult",
            detail={"checks": checks, "verification_state": vr.get("verification_state")},
        )

    closed = is_sealed_closed(forensic_id)
    return {
        "ok": ok,
        "record": rec,
        "verification": {**vr, "checks": checks, "timestamp_ok": ts_ok, "chain_link_ok": chain_ok},
        "sealed_closed": closed,
        "evidence_basis": "verifiable_cryptographic_evidence" if ok else "integrity_failed",
    }


def analyze_ledger_issues(*, register_incidents: bool = False) -> Dict[str, Any]:
    """Clasifica problemas sin mutar registros."""
    from services.forensic_evidence_integrity_service import (
        _payload_for_hash,
        _compute_chain_hash,
        _verify_signature,
        _load_chain_head,
    )

    if not os.path.isfile(RECORDS_FILE):
        return {"total": 0, "issues": []}

    # Asegurar trust keys antes de clasificar firmas
    try:
        from services.forensic_evidence_keys import sync_public_key_from_wrap

        sync_public_key_from_wrap(retire_plaintext=True)
    except Exception:
        pass

    prev = "0" * 64
    issues = []
    stats = {
        "total": 0,
        "ok": 0,
        "chain_breaks": 0,
        "sig_fail": 0,
        "content_fail": 0,
        "chain_hash_fail": 0,
        "repairable_link_only": 0,
        "irreparable": 0,
    }
    with open(RECORDS_FILE, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            stats["total"] += 1
            link = r.get("prev_chain_hash") == prev
            exp = _payload_for_hash(
                source_id=r.get("source_id") or "",
                motor=r.get("motor") or "",
                evidence_type=r.get("evidence_type") or "",
                payload=r.get("payload") if isinstance(r.get("payload"), dict) else {},
                user_email=r.get("user_email"),
                tenant_id=r.get("tenant_id"),
                equipment=r.get("equipment"),
            )
            content_ok = r.get("content_hash_sha256") == exp
            core = {k: r.get(k) for k in (
                "forensic_id", "source_id", "source_type", "version", "supersedes",
                "update_reason", "event_date", "event_time", "timestamp", "user_email",
                "tenant_id", "equipment", "motor", "evidence_type", "payload",
                "content_hash_sha256", "prev_chain_hash", "hash_algorithm",
                "sign_algorithm", "migrated_from_legacy",
            )}
            if "case_id" in r:
                # case_id added in phase1 — include in core only if present historically as part of hash
                pass
            if not isinstance(core.get("payload"), dict):
                core["payload"] = {}
            chain_ok = r.get("chain_hash") == _compute_chain_hash(core)
            msg = "|".join([
                str(r.get("content_hash_sha256") or ""),
                str(r.get("chain_hash") or ""),
                str(r.get("prev_chain_hash") or ""),
                str(r.get("forensic_id") or ""),
            ]).encode()
            sig_ok = bool(r.get("signature_hex")) and _verify_signature(msg, r.get("signature_hex") or "")

            if not link:
                stats["chain_breaks"] += 1
            if not content_ok:
                stats["content_fail"] += 1
            if not chain_ok:
                stats["chain_hash_fail"] += 1
            if not sig_ok:
                stats["sig_fail"] += 1

            if link and content_ok and chain_ok and sig_ok:
                stats["ok"] += 1
            else:
                repairable = content_ok and chain_ok and (sig_ok or not sig_ok) and content_ok
                # Reparable si el payload/contenido es íntegro (re-sello de continuidad)
                repairable = bool(content_ok)
                if repairable:
                    stats["repairable_link_only"] += 1
                else:
                    stats["irreparable"] += 1
                issues.append({
                    "forensic_id": r.get("forensic_id"),
                    "source_id": r.get("source_id"),
                    "link_ok": link,
                    "content_ok": content_ok,
                    "chain_hash_ok": chain_ok,
                    "signature_ok": sig_ok,
                    "repairable": repairable,
                })
            prev = r.get("chain_hash") or prev

    head = _load_chain_head()
    stats["chain_head_match"] = head == prev
    stats["issues_count"] = len(issues)
    return {"stats": stats, "issues": issues, "last_chain_hash": prev, "head": head}


def repair_custody_chain(
    *,
    actor: str = "system",
    dry_run: bool = False,
) -> Dict[str, Any]:
    """
    Repara continuidad de cadena SIN alterar payloads ni eliminar evidencias.

    1) Backup byte-a-byte del ledger → immutable_archive.
    2) Archiva cada registro original.
    3) Si content_hash falla → marca comprometida (irreparable), conserva la línea.
    4) Si solo falla eslabón/firma → reescribe el sobre criptográfico (prev/chain/firma)
       conservando forensic_id + payload + metadatos de negocio.
    """
    from services.forensic_evidence_integrity_service import (
        _payload_for_hash,
        _compute_chain_hash,
        _sign_bytes,
        _load_chain_head,
        _save_chain_head,
        run_full_verifier,
        seal_evidence,
    )

    with _repair_lock:
        analysis = analyze_ledger_issues()
        stats = analysis["stats"]
        if stats["total"] == 0:
            return {"ok": True, "status": "empty", "analysis": analysis}

        stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        report: Dict[str, Any] = {
            "started_at_utc": _utc_now(),
            "actor": actor,
            "dry_run": dry_run,
            "pre_stats": stats,
        }
        if dry_run:
            report.update({
                "ok": True,
                "status": "dry_run",
                "would_fix_envelopes": stats["chain_breaks"] + stats["sig_fail"],
                "would_mark_irreparable": stats["content_fail"],
            })
            return report

        _ensure()
        backup_path = os.path.join(IMMUTABLE_ARCHIVE_DIR, f"records_pre_repair_{stamp}.jsonl")
        shutil.copy2(RECORDS_FILE, backup_path)
        report["backup"] = backup_path

        originals: List[Dict[str, Any]] = []
        with open(RECORDS_FILE, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                originals.append(json.loads(line))

        originals_dir = os.path.join(IMMUTABLE_ARCHIVE_DIR, "originals", stamp)
        os.makedirs(originals_dir, exist_ok=True)
        # Copia íntegra ya en backup_path; además índice de fids para recuperación
        with open(os.path.join(originals_dir, "_index.json"), "w", encoding="utf-8") as fh:
            json.dump(
                {
                    "backup_jsonl": backup_path,
                    "count": len(originals),
                    "forensic_ids": [r.get("forensic_id") for r in originals],
                },
                fh,
            )

        repaired = 0
        irreparable = 0
        prev = "0" * 64
        out_rows: List[Dict[str, Any]] = []

        for rec in originals:
            fid = rec.get("forensic_id") or f"unknown-{uuid.uuid4().hex[:8]}"
            payload = rec.get("payload") if isinstance(rec.get("payload"), dict) else {}
            exp = _payload_for_hash(
                source_id=rec.get("source_id") or "",
                motor=rec.get("motor") or "",
                evidence_type=rec.get("evidence_type") or "",
                payload=payload,
                user_email=rec.get("user_email"),
                tenant_id=rec.get("tenant_id"),
                equipment=rec.get("equipment"),
            )
            content_ok = rec.get("content_hash_sha256") == exp

            if not content_ok:
                mark_compromised(
                    forensic_id=fid,
                    source_id=rec.get("source_id") or "",
                    reason="content_hash_mismatch — irreparable without altering original payload",
                    checks={"content_ok": False, "expected": exp, "stored": rec.get("content_hash_sha256")},
                    repairable=False,
                )
                irreparable += 1
                out_rows.append(rec)
                prev = rec.get("chain_hash") or prev
                continue

            # Siempre recalcular sobre con prev correcto (cascada de continuidad).
            # Payload + forensic_id + metadatos de negocio se conservan.
            new_rec = {k: v for k, v in rec.items() if k not in (
                "custody_repaired_at_utc", "custody_repair_actor",
            )}
            new_rec["prev_chain_hash"] = prev
            core = {
                "forensic_id": new_rec.get("forensic_id"),
                "source_id": new_rec.get("source_id"),
                "source_type": new_rec.get("source_type"),
                "version": new_rec.get("version"),
                "supersedes": new_rec.get("supersedes"),
                "update_reason": new_rec.get("update_reason"),
                "event_date": new_rec.get("event_date"),
                "event_time": new_rec.get("event_time"),
                "timestamp": new_rec.get("timestamp"),
                "user_email": new_rec.get("user_email"),
                "tenant_id": new_rec.get("tenant_id"),
                "equipment": new_rec.get("equipment"),
                "motor": new_rec.get("motor"),
                "evidence_type": new_rec.get("evidence_type"),
                "payload": payload,
                "content_hash_sha256": new_rec.get("content_hash_sha256"),
                "prev_chain_hash": prev,
                "hash_algorithm": new_rec.get("hash_algorithm") or "SHA-256",
                "sign_algorithm": new_rec.get("sign_algorithm") or "Ed25519",
                "migrated_from_legacy": new_rec.get("migrated_from_legacy"),
            }
            if "case_id" in rec:
                core["case_id"] = rec.get("case_id")
            chain_hash = _compute_chain_hash(core)
            sig, kid = _sign_bytes(
                f"{core['content_hash_sha256']}|{chain_hash}|{prev}|{fid}".encode("utf-8")
            )
            new_rec["chain_hash"] = chain_hash
            new_rec["signature_hex"] = sig
            new_rec["signature_key_id"] = kid
            new_rec["verification_state"] = "verified"
            new_rec["custody_repaired_at_utc"] = _utc_now()
            new_rec["custody_repair_actor"] = actor
            out_rows.append(new_rec)
            prev = chain_hash
            repaired += 1

        # Escribir ledger reparado atómicamente
        tmp = RECORDS_FILE + f".repairing_{stamp}"
        with open(tmp, "w", encoding="utf-8") as fh:
            for row in out_rows:
                fh.write(json.dumps(row, ensure_ascii=False) + "\n")
        os.replace(tmp, RECORDS_FILE)
        last_fid = out_rows[-1].get("forensic_id") if out_rows else None
        _save_chain_head(prev, last_fid or "")

        post = run_full_verifier(register_incidents=False)
        report.update({
            "finished_at_utc": _utc_now(),
            "envelopes_repaired": repaired,
            "irreparable_content": irreparable,
            "post_verify": {
                "total": post.get("total"),
                "verified": post.get("verified"),
                "compromised": post.get("compromised"),
                "chain_breaks": post.get("chain_breaks"),
                "chain_head_match": post.get("chain_head_match"),
            },
            "ok": bool(post.get("chain_head_match"))
            and int(post.get("chain_breaks") or 0) == 0
            and int(post.get("compromised") or 0) == 0,
        })
        report_path = os.path.join(REPAIR_REPORT_DIR, f"repair_{stamp}.json")
        with open(report_path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False)

        seal_evidence(
            source_id=f"REPAIR-REPORT-{stamp}",
            source_type="custody_repair",
            motor="forensic_custody_phase1",
            evidence_type="custody_chain_repair",
            payload={k: v for k, v in report.items() if k != "analysis"},
            user_email=actor if "@" in str(actor) else None,
            case_id="forensic-custody-repair",
            migrated=True,
            allow_closed_source=True,
        )
        log_custody_event(
            action="custody_chain_repair",
            user_email=actor if "@" in str(actor) else None,
            motor="forensic_custody_phase1",
            reason="envelope_repair_payload_preserved_full_cascade",
            detail={"report": report_path, **report["post_verify"]},
        )
        report["report_path"] = report_path
        return report


def export_forensic_package(
    *,
    case_id: Optional[str] = None,
    forensic_ids: Optional[List[str]] = None,
    limit: int = 500,
    actor: str = "system",
    ip_address: Optional[str] = None,
) -> Dict[str, Any]:
    """Paquete ZIP completo con evidencias, hashes, firmas, cronología, logs e informe."""
    from services.forensic_evidence_integrity_service import (
        iter_ledger_records,
        verify_record,
        _sign_bytes,
        _sha256_hex,
        _canonical_json,
    )

    _ensure()
    records = iter_ledger_records()
    selected: List[Dict[str, Any]] = []
    if forensic_ids:
        want = set(forensic_ids)
        selected = [r for r in records if r.get("forensic_id") in want]
    elif case_id:
        selected = [r for r in records if r.get("case_id") == case_id or r.get("tenant_id") == case_id][:limit]
    else:
        selected = records[-limit:]

    if not selected:
        return {"ok": False, "reason": "no_records"}

    # Verificar cada una antes de exportar
    verifications = []
    all_ok = True
    prev = "0" * 64
    # Build prev map from full ledger for accurate links
    prev_map = {}
    p = "0" * 64
    for r in records:
        prev_map[r.get("forensic_id")] = p
        p = r.get("chain_hash") or p

    for rec in selected:
        vr = verify_record(rec, prev_chain_expected=prev_map.get(rec.get("forensic_id")))
        verifications.append(vr)
        if not vr.get("ok"):
            all_ok = False
            emit_critical_alert(
                forensic_id=rec.get("forensic_id") or "?",
                source_id=rec.get("source_id") or "?",
                alert_type="export_blocked_integrity_fail",
                detail=vr,
            )

    if not all_ok:
        log_custody_event(
            action="export_blocked",
            case_id=case_id,
            user_email=actor if "@" in str(actor) else None,
            ip_address=ip_address,
            outcome="integrity_fail",
            reason="package_integrity_check_failed",
            detail={"failed": sum(1 for v in verifications if not v.get("ok"))},
        )
        return {
            "ok": False,
            "reason": "integrity_check_failed",
            "failed": sum(1 for v in verifications if not v.get("ok")),
            "verifications": verifications[:50],
        }

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    work = tempfile.mkdtemp(prefix="forensic_pkg_")
    try:
        evid_path = os.path.join(work, "evidences.jsonl")
        with open(evid_path, "w", encoding="utf-8") as fh:
            for rec in selected:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

        chronology = sorted(
            [
                {
                    "forensic_id": r.get("forensic_id"),
                    "timestamp": r.get("timestamp"),
                    "motor": r.get("motor"),
                    "evidence_type": r.get("evidence_type"),
                    "source_id": r.get("source_id"),
                }
                for r in selected
            ],
            key=lambda x: x.get("timestamp") or "",
        )
        with open(os.path.join(work, "chronology.json"), "w", encoding="utf-8") as fh:
            json.dump(chronology, fh, indent=2, ensure_ascii=False)

        with open(os.path.join(work, "hashes_and_signatures.json"), "w", encoding="utf-8") as fh:
            json.dump(
                [
                    {
                        "forensic_id": r.get("forensic_id"),
                        "content_hash_sha256": r.get("content_hash_sha256"),
                        "chain_hash": r.get("chain_hash"),
                        "prev_chain_hash": r.get("prev_chain_hash"),
                        "signature_hex": r.get("signature_hex"),
                        "signature_key_id": r.get("signature_key_id"),
                    }
                    for r in selected
                ],
                fh,
                indent=2,
            )

        # Related logs
        fids = {r.get("forensic_id") for r in selected}
        sids = {r.get("source_id") for r in selected}
        for log_name, log_path in (
            ("access.jsonl", ACCESS_LOG_FILE),
            ("custody_chain.jsonl", CUSTODY_LOG_FILE),
            ("critical_alerts.jsonl", CRITICAL_ALERT_FILE),
        ):
            if not os.path.isfile(log_path):
                continue
            out_lines = []
            with open(log_path, encoding="utf-8") as fh:
                for line in fh:
                    try:
                        row = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if row.get("forensic_id") in fids or row.get("source_id") in sids:
                        out_lines.append(row)
            with open(os.path.join(work, log_name), "w", encoding="utf-8") as fh:
                for row in out_lines[-2000:]:
                    fh.write(json.dumps(row, ensure_ascii=False) + "\n")

        informe = {
            "generated_at_utc": _utc_now(),
            "case_id": case_id,
            "actor": actor,
            "record_count": len(selected),
            "integrity_precheck": "passed",
            "verifications_ok": len(verifications),
            "package_format": "NOVUS-FORENSIC-PKG-1",
        }
        with open(os.path.join(work, "INFORME.json"), "w", encoding="utf-8") as fh:
            json.dump(informe, fh, indent=2, ensure_ascii=False)
        with open(os.path.join(work, "INFORME.md"), "w", encoding="utf-8") as fh:
            fh.write(
                f"# Paquete forense NOVUS\n\n"
                f"- Generado: {informe['generated_at_utc']}\n"
                f"- Caso: {case_id or '(últimos registros)'}\n"
                f"- Evidencias: {len(selected)}\n"
                f"- Precheck integridad: PASSED\n"
            )

        meta = {
            "format": "NOVUS-FORENSIC-PKG-1",
            "created_at_utc": _utc_now(),
            "case_id": case_id,
            "forensic_ids": [r.get("forensic_id") for r in selected],
            "content_manifest_sha256": None,
        }
        # Hash of evidences file
        with open(evid_path, "rb") as fh:
            evid_hash = hashlib.sha256(fh.read()).hexdigest()
        meta["evidences_sha256"] = evid_hash
        meta["content_manifest_sha256"] = _sha256_hex(_canonical_json(meta))
        sig, kid = _sign_bytes(
            f"forensic_pkg|{meta['content_manifest_sha256']}|{evid_hash}".encode("utf-8")
        )
        meta["signature_hex"] = sig
        meta["signature_key_id"] = kid
        with open(os.path.join(work, "metadata.json"), "w", encoding="utf-8") as fh:
            json.dump(meta, fh, indent=2)

        zip_name = f"forensic_pkg_{stamp}_{(case_id or 'ledger')[:40]}.zip"
        zip_path = os.path.join(EXPORT_DIR, zip_name)
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for name in os.listdir(work):
                zf.write(os.path.join(work, name), name)

        # Verify package integrity (re-read zip hashes)
        with zipfile.ZipFile(zip_path, "r") as zf:
            names = zf.namelist()
            assert "evidences.jsonl" in names and "metadata.json" in names
            meta2 = json.loads(zf.read("metadata.json"))
            evid_bytes = zf.read("evidences.jsonl")
            evid_hash2 = hashlib.sha256(evid_bytes).hexdigest()
            pkg_ok = evid_hash2 == meta2.get("evidences_sha256")

        if not pkg_ok:
            emit_critical_alert(
                forensic_id="EXPORT",
                source_id=case_id or "ledger",
                alert_type="export_package_hash_mismatch",
                detail={"expected": evid_hash, "got": evid_hash2},
            )
            return {"ok": False, "reason": "package_self_verify_failed"}

        log_custody_event(
            action="export",
            case_id=case_id,
            user_email=actor if "@" in str(actor) else None,
            ip_address=ip_address,
            motor="forensic_custody_phase1",
            reason="forensic_package_export",
            detail={"path": zip_name, "count": len(selected), "sha256": evid_hash},
        )
        return {
            "ok": True,
            "path": zip_path,
            "file": zip_name,
            "count": len(selected),
            "evidences_sha256": evid_hash,
            "metadata": meta,
            "package_verified": True,
        }
    finally:
        shutil.rmtree(work, ignore_errors=True)


def seal_swarm_evidence(
    *,
    node_id: Optional[str],
    action_id: str,
    risk_level: str,
    response: dict,
    correlation: Optional[dict] = None,
    origin_event: Optional[dict] = None,
    user_email: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Ingesta automática Swarm → ledger forense con motor/nodo/riesgo/hashes/firma/cadena."""
    from services.forensic_evidence_integrity_service import seal_evidence

    origin_event = origin_event or {}
    correlation = correlation or {}
    source_id = (
        f"SWARM-{action_id}-{(origin_event.get('finding_id') or uuid.uuid4().hex[:10])}"
    )
    payload = {
        "swarm": True,
        "node_id": node_id or os.environ.get("NODE_ID") or "unknown-node",
        "action_id": action_id,
        "risk_level": risk_level,
        "response_executed": response,
        "correlation": {
            "confidence": correlation.get("confidence"),
            "classification": correlation.get("classification"),
            "indicators": correlation.get("indicators"),
        },
        "origin_finding_id": origin_event.get("finding_id"),
        "threat_type": origin_event.get("threat_type"),
        "recorded_at_utc": _utc_now(),
    }
    rec = seal_evidence(
        source_id=source_id,
        source_type="swarm_defense",
        motor="swarm_defense_engine",
        evidence_type=f"swarm.{action_id}",
        payload=payload,
        user_email=user_email,
        equipment=payload["node_id"],
        case_id=origin_event.get("finding_id") or "swarm",
    )
    if rec:
        log_custody_event(
            action="swarm_evidence_sealed",
            forensic_id=rec.get("forensic_id"),
            source_id=source_id,
            case_id=rec.get("case_id"),
            user_email=user_email,
            equipment=payload["node_id"],
            motor="swarm_defense_engine",
            reason=f"risk={risk_level}",
            detail={"action_id": action_id},
        )
    return rec


def kernel_analyze_evidence(
    forensic_id: str,
    *,
    analysis_type: str = "classify_relate_patterns",
) -> Dict[str, Any]:
    """
    Kernel IA: solo lectura/análisis. Nunca modifica evidencias.
    Toda conclusión declara si proviene de evidencia verificable o de análisis IA.
    """
    consulted = get_evidence_auto_verify(forensic_id, user_email="kernel_ia", action="kernel_analyze")
    if not consulted.get("ok") and consulted.get("reason") == "not_found":
        return {
            "ok": False,
            "modified_evidence": False,
            "evidence_basis": "none",
            "ai_analysis": False,
            "error": "not_found",
        }

    rec = consulted.get("record") or {}
    verifiable = bool(consulted.get("ok"))
    # Análisis no destructivo
    payload = rec.get("payload") if isinstance(rec.get("payload"), dict) else {}
    hypotheses = []
    if payload.get("swarm"):
        hypotheses.append("Evento correlacionado por Swarm Defense")
    if rec.get("motor"):
        hypotheses.append(f"Motor de origen: {rec.get('motor')}")
    if rec.get("evidence_type"):
        hypotheses.append(f"Tipo: {rec.get('evidence_type')}")

    chronology_note = f"Timestamp evidencia: {rec.get('timestamp')}"
    return {
        "ok": True,
        "modified_evidence": False,
        "forensic_id": forensic_id,
        "analysis_type": analysis_type,
        "evidence_basis": "verifiable_cryptographic_evidence" if verifiable else "integrity_failed_do_not_trust",
        "ai_analysis": True,
        "ai_disclaimer": (
            "Las hipótesis siguientes son análisis de IA y NO constituyen evidencia criptográfica. "
            "Solo los campos verification/record sellados son evidencia verificable."
        ),
        "verification": consulted.get("verification"),
        "classification": {
            "motor": rec.get("motor"),
            "evidence_type": rec.get("evidence_type"),
            "source_type": rec.get("source_type"),
            "case_id": rec.get("case_id"),
        },
        "patterns": {
            "has_swarm_flag": bool(payload.get("swarm")),
            "has_risk": "risk_level" in payload or "nivel_riesgo" in payload,
        },
        "hypotheses_ai": hypotheses,
        "chronology_explanation_ai": chronology_note,
        "relations": {
            "supersedes": rec.get("supersedes"),
            "source_id": rec.get("source_id"),
        },
    }
