"""
Sistema forense de integridad e inmutabilidad de evidencias NOVUS.

Capa append-only sobre evidencias reales ya registradas por motores NOVUS.
No sustituye defense_registry ni platform_evidences — los sella criptográficamente.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from utils.logger import logger

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LEDGER_DIR = os.path.join(ROOT, "data", "forensic_ledger")
RECORDS_FILE = os.path.join(LEDGER_DIR, "records.jsonl")
CHAIN_HEAD_FILE = os.path.join(LEDGER_DIR, "chain_head.json")
SOURCE_INDEX_FILE = os.path.join(LEDGER_DIR, "source_index.json")
# Sidecar O(1): forensic_id → byte offset in records.jsonl (NOT part of hash chain).
FID_OFFSET_INDEX_FILE = os.path.join(LEDGER_DIR, "fid_offset_index.json")
ACCESS_LOG_FILE = os.path.join(LEDGER_DIR, "access.jsonl")
INTEGRITY_INCIDENTS_FILE = os.path.join(LEDGER_DIR, "integrity_incidents.jsonl")
MIGRATION_CURSOR_FILE = os.path.join(LEDGER_DIR, "migration_cursor.json")

HASH_ALGORITHM = "SHA-256"
SIGN_ALGORITHM = "Ed25519"
COMPROMISED_LABEL = "Integridad comprometida"
SEALED_CLOSED_DIR = os.path.join(LEDGER_DIR, "sealed_closed")
COMPROMISED_INDEX_FILE = os.path.join(LEDGER_DIR, "compromised_index.jsonl")
CUSTODY_LOG_FILE = os.path.join(LEDGER_DIR, "custody_chain.jsonl")
IMMUTABLE_ARCHIVE_DIR = os.path.join(LEDGER_DIR, "immutable_archive")
LEDGER_LOCK_FILE = os.path.join(LEDGER_DIR, ".ledger.write.lock")

_lock = threading.Lock()
CRITICAL_ALERT_FILE = os.path.join(LEDGER_DIR, "critical_alerts.jsonl")
_fid_offset_cache: Optional[Dict[str, int]] = None


class _LedgerFileLock:
    """Bloqueo exclusivo de proceso para evitar chain_breaks por sellado concurrente."""

    def __init__(self, path: str):
        self.path = path
        self._fh = None

    def __enter__(self):
        _ensure_dirs()
        self._fh = open(self.path, "a+b")
        try:
            if os.name == "nt":
                import msvcrt

                self._fh.seek(0)
                if self._fh.read(1) == b"":
                    self._fh.write(b"0")
                    self._fh.flush()
                self._fh.seek(0)
                msvcrt.locking(self._fh.fileno(), msvcrt.LK_LOCK, 1)
            else:
                import fcntl

                fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX)
        except Exception as exc:
            logger.debug("ledger file lock fallback to threading lock: %s", exc)
        return self

    def __exit__(self, *args):
        try:
            if self._fh and os.name == "nt":
                import msvcrt

                self._fh.seek(0)
                msvcrt.locking(self._fh.fileno(), msvcrt.LK_UNLCK, 1)
            elif self._fh:
                import fcntl

                fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
        except Exception:
            pass
        try:
            if self._fh:
                self._fh.close()
        except Exception:
            pass
        return False


def _now_parts() -> Tuple[str, str, str]:
    # Compat: nuevas evidencias usan UTC vía seal_evidence; helpers locales conservan firma
    return _utc_parts()


def _ensure_dirs() -> None:
    os.makedirs(LEDGER_DIR, exist_ok=True)


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)


def _sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _payload_for_hash(
    *,
    source_id: str,
    motor: str,
    evidence_type: str,
    payload: dict,
    user_email: Optional[str],
    tenant_id: Optional[str],
    equipment: Optional[str],
) -> str:
    body = {
        "source_id": source_id,
        "motor": motor,
        "evidence_type": evidence_type,
        "user_email": user_email,
        "tenant_id": tenant_id,
        "equipment": equipment,
        "payload": payload,
    }
    return _sha256_hex(_canonical_json(body))


def _load_chain_head() -> str:
    _ensure_dirs()
    if not os.path.isfile(CHAIN_HEAD_FILE):
        return "0" * 64
    try:
        with open(CHAIN_HEAD_FILE, encoding="utf-8") as fh:
            data = json.load(fh)
        return data.get("chain_hash") or ("0" * 64)
    except Exception:
        return "0" * 64


def _save_chain_head(chain_hash: str, forensic_id: str) -> None:
    with open(CHAIN_HEAD_FILE, "w", encoding="utf-8") as fh:
        json.dump({
            "chain_hash": chain_hash,
            "last_forensic_id": forensic_id,
            "updated_at": _now_parts()[0],
        }, fh, indent=2)


def _load_source_index() -> Dict[str, str]:
    _ensure_dirs()
    if not os.path.isfile(SOURCE_INDEX_FILE):
        return {}
    try:
        with open(SOURCE_INDEX_FILE, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


def _save_source_index(index: Dict[str, str]) -> None:
    with open(SOURCE_INDEX_FILE, "w", encoding="utf-8") as fh:
        json.dump(index, fh, indent=2, ensure_ascii=False)


def _load_fid_offset_index() -> Dict[str, int]:
    """Load forensic_id → byte-offset map (derived metadata; not chain material)."""
    global _fid_offset_cache
    if _fid_offset_cache is not None:
        return _fid_offset_cache
    _ensure_dirs()
    if not os.path.isfile(FID_OFFSET_INDEX_FILE):
        _fid_offset_cache = {}
        return _fid_offset_cache
    try:
        with open(FID_OFFSET_INDEX_FILE, encoding="utf-8") as fh:
            raw = json.load(fh)
        _fid_offset_cache = {str(k): int(v) for k, v in (raw or {}).items()}
    except Exception:
        _fid_offset_cache = {}
    return _fid_offset_cache


def _save_fid_offset_index(index: Dict[str, int]) -> None:
    global _fid_offset_cache
    _fid_offset_cache = dict(index)
    _ensure_dirs()
    with open(FID_OFFSET_INDEX_FILE, "w", encoding="utf-8") as fh:
        json.dump(_fid_offset_cache, fh, ensure_ascii=False)


def _rebuild_fid_offset_index() -> Dict[str, int]:
    """Rare O(n) rebuild — only when sidecar missing/corrupt. Does not alter records."""
    index: Dict[str, int] = {}
    if not os.path.isfile(RECORDS_FILE):
        _save_fid_offset_index(index)
        return index
    with open(RECORDS_FILE, "rb") as fh:
        while True:
            offset = fh.tell()
            line = fh.readline()
            if not line:
                break
            s = line.strip()
            if not s:
                continue
            try:
                row = json.loads(s.decode("utf-8"))
                fid = row.get("forensic_id")
                if fid:
                    index[str(fid)] = offset
            except Exception:
                continue
    _save_fid_offset_index(index)
    return index


def _append_record_jsonl(record: Dict[str, Any]) -> int:
    """Append one record in binary mode; return starting byte offset."""
    _ensure_dirs()
    raw = (json.dumps(record, ensure_ascii=False) + "\n").encode("utf-8")
    with open(RECORDS_FILE, "ab") as fh:
        offset = fh.tell()
        fh.write(raw)
    return offset


def _read_record_at_offset(offset: int) -> Optional[Dict[str, Any]]:
    if not os.path.isfile(RECORDS_FILE):
        return None
    try:
        with open(RECORDS_FILE, "rb") as fh:
            fh.seek(int(offset))
            line = fh.readline()
        if not line:
            return None
        return json.loads(line.decode("utf-8"))
    except Exception:
        return None


def _sign_bytes(message: bytes) -> Tuple[str, str]:
    from services.forensic_evidence_keys import load_signing_keypair

    private_key, key_id = load_signing_keypair()
    sig = private_key.sign(message)
    return sig.hex(), key_id


def _verify_signature(message: bytes, signature_hex: str) -> bool:
    try:
        from services.forensic_evidence_keys import load_trusted_public_keys

        sig = bytes.fromhex(signature_hex)
        for _name, pub in load_trusted_public_keys():
            try:
                pub.verify(sig, message)
                return True
            except Exception:
                continue
        return False
    except Exception:
        return False


def _utc_parts() -> Tuple[str, str, str]:
    """Timestamp UTC canónico para nuevas evidencias."""
    from datetime import timezone

    now = datetime.now(timezone.utc)
    ts = now.strftime("%Y-%m-%d %H:%M:%S UTC")
    return ts, now.strftime("%Y-%m-%d"), now.strftime("%H:%M:%S")


def _host_equipment() -> str:
    try:
        import socket

        return socket.gethostname()
    except Exception:
        return "unknown-host"


def _compute_chain_hash(record_core: dict) -> str:
    return _sha256_hex(_canonical_json(record_core))


def seal_evidence(
    *,
    source_id: str,
    source_type: str,
    motor: str,
    evidence_type: str,
    payload: dict,
    user_email: Optional[str] = None,
    tenant_id: Optional[str] = None,
    equipment: Optional[str] = None,
    supersedes: Optional[str] = None,
    version: int = 1,
    update_reason: Optional[str] = None,
    migrated: bool = False,
    case_id: Optional[str] = None,
    allow_closed_source: bool = False,
) -> Optional[Dict[str, Any]]:
    """
    Append-only: sella evidencia con hash, firma y eslabón de cadena.
    Campos enterprise: SHA-256, Ed25519, prev_chain_hash, timestamp UTC,
    forensic_id, case_id, user_email, equipment.
    Si source_id ya sellado (misma versión lógica), no duplica salvo supersedes.
    """
    if not source_id or not motor:
        return None
    if not isinstance(payload, dict):
        payload = {"raw": payload}

    equipment = equipment or _host_equipment()
    case_id = case_id or tenant_id

    with _lock:
        with _LedgerFileLock(LEDGER_LOCK_FILE):
            index = _load_source_index()
            if not supersedes and source_id in index and not migrated:
                return get_record_by_forensic_id(index[source_id])

            # Impedir modificación lógica de evidencias con sello de cierre
            if not allow_closed_source and source_id in index:
                try:
                    from services.forensic_custody_phase1 import is_sealed_closed

                    prev_fid = index.get(source_id)
                    if prev_fid and is_sealed_closed(prev_fid) and not supersedes:
                        try:
                            from services.forensic_custody_phase1 import (
                                log_custody_event,
                                emit_critical_alert,
                            )

                            log_custody_event(
                                action="modify_blocked_sealed",
                                forensic_id=prev_fid,
                                source_id=source_id,
                                user_email=user_email,
                                motor=motor,
                                reason="sealed_closed",
                                outcome="denied",
                            )
                            emit_critical_alert(
                                forensic_id=prev_fid,
                                source_id=source_id,
                                alert_type="attempt_modify_sealed_evidence",
                                detail={"motor": motor, "user": user_email},
                            )
                        except Exception:
                            pass
                        return None
                except Exception:
                    pass

            ts, fecha, hora = _utc_parts()
            forensic_id = f"FEV-{uuid.uuid4().hex[:14]}"
            content_hash = _payload_for_hash(
                source_id=source_id,
                motor=motor,
                evidence_type=evidence_type,
                payload=payload,
                user_email=user_email,
                tenant_id=tenant_id,
                equipment=equipment,
            )
            prev_chain_hash = _load_chain_head()

            record_core = {
                "forensic_id": forensic_id,
                "source_id": source_id,
                "source_type": source_type,
                "version": version,
                "supersedes": supersedes,
                "update_reason": update_reason,
                "event_date": fecha,
                "event_time": hora,
                "timestamp": ts,
                "user_email": user_email,
                "tenant_id": tenant_id,
                "case_id": case_id,
                "equipment": equipment,
                "motor": motor,
                "evidence_type": evidence_type,
                "payload": payload,
                "content_hash_sha256": content_hash,
                "prev_chain_hash": prev_chain_hash,
                "hash_algorithm": HASH_ALGORITHM,
                "sign_algorithm": SIGN_ALGORITHM,
                "migrated_from_legacy": migrated,
            }
            chain_hash = _compute_chain_hash(record_core)
            sign_message = f"{content_hash}|{chain_hash}|{prev_chain_hash}|{forensic_id}".encode("utf-8")
            signature_hex, key_id = _sign_bytes(sign_message)
            signed_at = ts

            record = {
                **record_core,
                "chain_hash": chain_hash,
                "signature_hex": signature_hex,
                "signature_key_id": key_id,
                "signed_at": signed_at,
                "verification_state": "verified",
            }

            _ensure_dirs()
            offset = _append_record_jsonl(record)
            fid_index = _load_fid_offset_index()
            fid_index[forensic_id] = offset
            _save_fid_offset_index(fid_index)
            _save_chain_head(chain_hash, forensic_id)
            index[source_id] = forensic_id
            _save_source_index(index)

    return record


def append_evidence_version(
    *,
    source_id: str,
    motor: str,
    evidence_type: str,
    payload: dict,
    user_email: Optional[str],
    tenant_id: Optional[str],
    equipment: Optional[str],
    reason: str,
) -> Optional[Dict[str, Any]]:
    """Nueva versión inmutable — nunca sobrescribe el registro anterior."""
    index = _load_source_index()
    prev_fid = index.get(source_id)
    prev_record = get_record_by_forensic_id(prev_fid) if prev_fid else None
    version = int((prev_record or {}).get("version") or 0) + 1
    return seal_evidence(
        source_id=source_id,
        source_type=(prev_record or {}).get("source_type") or "versioned",
        motor=motor,
        evidence_type=evidence_type,
        payload=payload,
        user_email=user_email,
        tenant_id=tenant_id,
        equipment=equipment,
        supersedes=prev_fid,
        version=version,
        update_reason=reason[:500],
    )


def log_evidence_access(
    *,
    forensic_id: Optional[str],
    source_id: Optional[str],
    action: str,
    user_email: Optional[str] = None,
    ip_address: Optional[str] = None,
    outcome: str = "ok",
    detail: Optional[dict] = None,
) -> None:
    ts, fecha, hora = _now_parts()
    row = {
        "timestamp": ts,
        "event_date": fecha,
        "event_time": hora,
        "forensic_id": forensic_id,
        "source_id": source_id,
        "action": action[:120],
        "user_email": user_email,
        "ip_address": ip_address,
        "outcome": outcome,
        "detail": detail or {},
    }
    _ensure_dirs()
    with open(ACCESS_LOG_FILE, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, ensure_ascii=False) + "\n")


def _register_integrity_incident(
    *,
    forensic_id: str,
    source_id: str,
    incident_type: str,
    detail: dict,
) -> None:
    ts, _, _ = _now_parts()
    row = {
        "id": f"FINT-{uuid.uuid4().hex[:12]}",
        "timestamp": ts,
        "forensic_id": forensic_id,
        "source_id": source_id,
        "incident_type": incident_type,
        "detail": detail,
    }
    _ensure_dirs()
    with open(INTEGRITY_INCIDENTS_FILE, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    try:
        from services.defense_evidence_registry import _forensic_alert
        import services.defense_evidence_registry as _dr

        if not _forensic_alert:
            _dr._forensic_alert = True
            try:
                from services.defense_evidence_registry import record_defense_event

                record_defense_event(
                    "audit",
                    "forensic_integrity_compromised",
                    "forensic_evidence_integrity_service",
                    "detected",
                    threat_type="integrity",
                    detail=incident_type,
                    evidence={
                        "verified": True,
                        "forensic_id": forensic_id,
                        "source_id": source_id,
                        **detail,
                    },
                )
            finally:
                _dr._forensic_alert = False
    except Exception as exc:
        logger.debug("forensic integrity alert bridge: %s", exc)


def verify_record(
    record: Dict[str, Any],
    *,
    prev_chain_expected: Optional[str] = None,
    register_incident: bool = True,
) -> Dict[str, Any]:
    """Verificación real: hash, firma, eslabón previo."""
    fid = record.get("forensic_id")
    sid = record.get("source_id")
    checks = {
        "content_hash_ok": False,
        "signature_ok": False,
        "chain_link_ok": False,
        "chain_hash_ok": False,
    }
    expected_content = _payload_for_hash(
        source_id=sid or "",
        motor=record.get("motor") or "",
        evidence_type=record.get("evidence_type") or "",
        payload=record.get("payload") if isinstance(record.get("payload"), dict) else {},
        user_email=record.get("user_email"),
        tenant_id=record.get("tenant_id"),
        equipment=record.get("equipment"),
    )
    stored_hash = record.get("content_hash_sha256")
    checks["content_hash_ok"] = stored_hash == expected_content

    record_core = {
        "forensic_id": record.get("forensic_id"),
        "source_id": record.get("source_id"),
        "source_type": record.get("source_type"),
        "version": record.get("version"),
        "supersedes": record.get("supersedes"),
        "update_reason": record.get("update_reason"),
        "event_date": record.get("event_date"),
        "event_time": record.get("event_time"),
        "timestamp": record.get("timestamp"),
        "user_email": record.get("user_email"),
        "tenant_id": record.get("tenant_id"),
        "equipment": record.get("equipment"),
        "motor": record.get("motor"),
        "evidence_type": record.get("evidence_type"),
        "payload": record.get("payload") if isinstance(record.get("payload"), dict) else {},
        "content_hash_sha256": record.get("content_hash_sha256"),
        "prev_chain_hash": record.get("prev_chain_hash"),
        "hash_algorithm": record.get("hash_algorithm"),
        "sign_algorithm": record.get("sign_algorithm"),
        "migrated_from_legacy": record.get("migrated_from_legacy"),
    }
    # Compat: case_id solo entra al core si existía al sellar (no romper ledger histórico)
    if "case_id" in record:
        record_core["case_id"] = record.get("case_id")
    expected_chain = _compute_chain_hash(record_core)
    checks["chain_hash_ok"] = record.get("chain_hash") == expected_chain

    if prev_chain_expected is not None:
        checks["chain_link_ok"] = (record.get("prev_chain_hash") == prev_chain_expected)
    else:
        checks["chain_link_ok"] = True

    sign_message = (
        f"{stored_hash}|{record.get('chain_hash')}|{record.get('prev_chain_hash')}|{fid}"
    ).encode("utf-8")
    sig = record.get("signature_hex") or ""
    checks["signature_ok"] = bool(sig) and _verify_signature(sign_message, sig)

    ok = all(checks.values())
    state = "verified" if ok else COMPROMISED_LABEL
    if not ok and register_incident:
        _register_integrity_incident(
            forensic_id=fid or "unknown",
            source_id=sid or "unknown",
            incident_type="verification_failed",
            detail={"checks": checks, "stored_hash": stored_hash, "expected_hash": expected_content},
        )
    return {
        "forensic_id": fid,
        "source_id": sid,
        "verification_state": state,
        "checks": checks,
        "ok": ok,
    }


def iter_ledger_records() -> List[Dict[str, Any]]:
    if not os.path.isfile(RECORDS_FILE):
        return []
    rows: List[Dict[str, Any]] = []
    with open(RECORDS_FILE, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def get_record_by_forensic_id(forensic_id: Optional[str]) -> Optional[Dict[str, Any]]:
    """O(1) seek via fid_offset_index; rebuild sidecar once if miss. No full-scan hot path."""
    if not forensic_id:
        return None
    fid = str(forensic_id)
    index = _load_fid_offset_index()
    offset = index.get(fid)
    if offset is None:
        # Sidecar cold / stale — rebuild once (rare).
        index = _rebuild_fid_offset_index()
        offset = index.get(fid)
        if offset is None:
            return None
    row = _read_record_at_offset(offset)
    if row and row.get("forensic_id") == fid:
        return row
    # Offset stale (manual edit / truncation) — rebuild and retry once.
    index = _rebuild_fid_offset_index()
    offset = index.get(fid)
    if offset is None:
        return None
    row = _read_record_at_offset(offset)
    if row and row.get("forensic_id") == fid:
        return row
    return None


def verify_single(forensic_id: str) -> Dict[str, Any]:
    records = iter_ledger_records()
    prev_hash = "0" * 64
    target = None
    prev_for_target = "0" * 64
    for rec in records:
        if rec.get("forensic_id") == forensic_id:
            target = rec
            prev_for_target = prev_hash
            break
        prev_hash = rec.get("chain_hash") or prev_hash
    if not target:
        return {"ok": False, "error": "not_found", "forensic_id": forensic_id}
    return verify_record(target, prev_chain_expected=prev_for_target)


def run_full_verifier(*, ledger_path: Optional[str] = None, register_incidents: bool = False) -> Dict[str, Any]:
    """Recorre el ledger real — sin simulaciones."""
    global RECORDS_FILE
    original = RECORDS_FILE
    if ledger_path:
        RECORDS_FILE = ledger_path
    try:
        records = iter_ledger_records()
        if not records:
            return {
                "total": 0,
                "verified": 0,
                "compromised": 0,
                "chain_breaks": 0,
                "results": [],
                "message": "Sin registros forenses sellados aún.",
            }
        prev_hash = "0" * 64
        verified = 0
        compromised = 0
        chain_breaks = 0
        results = []
        for rec in records:
            link_ok = rec.get("prev_chain_hash") == prev_hash
            if not link_ok:
                chain_breaks += 1
                if register_incidents:
                    _register_integrity_incident(
                        forensic_id=rec.get("forensic_id") or "?",
                        source_id=rec.get("source_id") or "?",
                        incident_type="chain_break",
                        detail={"expected_prev": prev_hash, "got": rec.get("prev_chain_hash")},
                    )
            vr = verify_record(
                rec,
                prev_chain_expected=prev_hash if link_ok else None,
                register_incident=register_incidents,
            )
            if not link_ok:
                vr["ok"] = False
                vr["verification_state"] = COMPROMISED_LABEL
                vr["checks"]["chain_link_ok"] = False
            results.append(vr)
            if vr.get("ok"):
                verified += 1
            else:
                compromised += 1
            prev_hash = rec.get("chain_hash") or prev_hash
        head = _load_chain_head()
        head_ok = prev_hash == head if records else True
        if not head_ok:
            chain_breaks += 1
        return {
            "total": len(records),
            "verified": verified,
            "compromised": compromised,
            "chain_breaks": chain_breaks,
            "chain_head_match": head_ok,
            "hash_algorithm": HASH_ALGORITHM,
            "sign_algorithm": SIGN_ALGORITHM,
            "results": results[-100:],
        }
    finally:
        RECORDS_FILE = original


def hook_seal_defense_entry(entry: Dict[str, Any]) -> None:
    if not entry or entry.get("status") == "skipped":
        return
    try:
        from services.tenant_scope_service import get_platform_tenant_id

        seal_evidence(
            source_id=entry.get("id") or f"DEF-unknown-{uuid.uuid4().hex[:8]}",
            source_type="defense_registry",
            motor=entry.get("motor") or "unknown",
            evidence_type=entry.get("action") or entry.get("phase") or "defense_event",
            payload={
                "phase": entry.get("phase"),
                "action": entry.get("action"),
                "outcome": entry.get("outcome"),
                "threat_type": entry.get("threat_type"),
                "evidence": entry.get("evidence") or {},
                "detail": entry.get("detail"),
                "finding_id": entry.get("finding_id"),
            },
            user_email=entry.get("user_email"),
            tenant_id=get_platform_tenant_id(),
            equipment=None,
        )
    except Exception as exc:
        logger.debug("hook_seal_defense_entry: %s", exc)


def hook_seal_platform_evidence(out: Dict[str, Any], evidence: Optional[dict]) -> None:
    if not out or out.get("status") in ("skipped", "error"):
        return
    eid = out.get("id")
    if not eid:
        return
    try:
        from services.tenant_scope_service import get_platform_tenant_id

        seal_evidence(
            source_id=eid,
            source_type="platform_evidence",
            motor=out.get("motor") or "evidence_center",
            evidence_type=out.get("categoria") or "evidence",
            payload={
                "descripcion": out.get("descripcion"),
                "evidence": evidence or {},
                "nivel_riesgo": out.get("nivel_riesgo"),
                "estado": out.get("estado"),
                "accion_ejecutada": out.get("accion_ejecutada"),
            },
            user_email=None,
            tenant_id=get_platform_tenant_id(),
            equipment=None,
        )
    except Exception as exc:
        logger.debug("hook_seal_platform_evidence: %s", exc)


def build_export_integrity_manifest(report: dict, export_path: Optional[str] = None) -> Dict[str, Any]:
    """Hash global y metadatos de firma para exportaciones."""
    from services.forensic_evidence_keys import ensure_forensic_signing_key

    ts, _, _ = _now_parts()
    body = _canonical_json(report)
    content_hash = _sha256_hex(body)
    manifest = {
        "generated_at": ts,
        "report_id": report.get("id"),
        "content_hash_sha256": content_hash,
        "hash_algorithm": HASH_ALGORITHM,
        "sign_algorithm": SIGN_ALGORITHM,
        "signature_key_id": ensure_forensic_signing_key(),
    }
    if export_path and os.path.isfile(export_path):
        try:
            with open(export_path, "rb") as fh:
                file_hash = hashlib.sha256(fh.read()).hexdigest()
            manifest["export_file_sha256"] = file_hash
        except OSError:
            pass
    sign_msg = f"export|{content_hash}|{manifest.get('export_file_sha256','')}|{report.get('id')}".encode()
    sig, kid = _sign_bytes(sign_msg)
    manifest["signature_hex"] = sig
    manifest["signature_key_id"] = kid
    manifest["integrity_verified_at_generation"] = True
    related = []
    for ref in (report.get("technical_details") or [])[:50]:
        rid = ref.get("id") if isinstance(ref, dict) else None
        if rid:
            idx = _load_source_index()
            if rid in idx:
                related.append({"source_id": rid, "forensic_id": idx[rid]})
    manifest["sealed_evidence_refs"] = related
    try:
        from services.forensic_pcap_capture_service import get_pcap_manifest_for_report

        pcap_refs = get_pcap_manifest_for_report(report)
        if pcap_refs:
            manifest["forensic_pcap_captures"] = pcap_refs
            manifest["pcap_disclaimer"] = (
                "Las capturas listan metadatos y hashes; no implican interpretación del contenido del tráfico."
            )
    except Exception:
        pass
    manifest["global_bundle_hash_sha256"] = _sha256_hex(_canonical_json({
        "report_hash": content_hash,
        "file_hash": manifest.get("export_file_sha256"),
        "refs": related,
    }))
    return manifest


def migrate_defense_registry_batch(*, max_lines: int = 2000) -> Dict[str, Any]:
    """Migra eventos legacy DEF-* al ledger forense (idempotente)."""
    from services.defense_evidence_registry import EVENTS_FILE

    cursor = {"line": 0}
    if os.path.isfile(MIGRATION_CURSOR_FILE):
        try:
            with open(MIGRATION_CURSOR_FILE, encoding="utf-8") as fh:
                cursor = json.load(fh)
        except Exception:
            pass
    start = int(cursor.get("line") or 0)
    index = _load_source_index()
    sealed = 0
    skipped = 0
    processed = 0
    if not os.path.isfile(EVENTS_FILE):
        return {"sealed": 0, "skipped": 0, "message": "no defense registry"}
    with open(EVENTS_FILE, encoding="utf-8") as fh:
        for i, line in enumerate(fh):
            if i < start:
                continue
            if processed >= max_lines:
                break
            line = line.strip()
            if not line:
                continue
            processed += 1
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                skipped += 1
                continue
            sid = entry.get("id")
            if not sid or sid in index:
                skipped += 1
                continue
            if seal_evidence(
                source_id=sid,
                source_type="defense_registry",
                motor=entry.get("motor") or "unknown",
                evidence_type=entry.get("action") or "defense_event",
                payload={
                    "phase": entry.get("phase"),
                    "action": entry.get("action"),
                    "outcome": entry.get("outcome"),
                    "threat_type": entry.get("threat_type"),
                    "evidence": entry.get("evidence") or {},
                    "detail": entry.get("detail"),
                },
                user_email=entry.get("user_email"),
                tenant_id=None,
                equipment=None,
                migrated=True,
            ):
                sealed += 1
    new_line = start + processed
    with open(MIGRATION_CURSOR_FILE, "w", encoding="utf-8") as fh:
        json.dump({"line": new_line, "updated_at": _now_parts()[0]}, fh)
    return {"sealed": sealed, "skipped": skipped, "cursor_line": new_line, "processed": processed}


def get_system_summary() -> Dict[str, Any]:
    records = iter_ledger_records()
    return {
        "ledger_path": RECORDS_FILE,
        "record_count": len(records),
        "hash_algorithm": HASH_ALGORITHM,
        "sign_algorithm": SIGN_ALGORITHM,
        "chain_head": _load_chain_head(),
        "compromised_label": COMPROMISED_LABEL,
    }
