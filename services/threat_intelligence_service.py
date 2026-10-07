"""
NOVUS Threat Intelligence Center — Base de conocimiento de casos.

Convierte hallazgos reales (vulnerabilidades, incidentes, amenazas) en expedientes
técnicos con evidencia, timeline, correlación y lecciones aprendidas.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import socket
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from database import (
    Alerta,
    InteligenciaCaso,
    InteligenciaPropuesta,
    InteligenciaTimeline,
    SessionLocal,
    Usuario,
)
from utils.logger import logger

INTEL_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "intelligence")

SEVERITY_ORDER = {"CRITICO": 4, "CRÍTICO": 4, "CRITICAL": 4, "ALTO": 3, "HIGH": 3,
                  "MEDIO": 2, "MEDIUM": 2, "BAJO": 1, "LOW": 1, "INFO": 0}


def _ensure_dirs():
    os.makedirs(INTEL_DIR, exist_ok=True)


def _json_load(raw: Optional[str], default=None):
    if default is None:
        default = []
    if not raw:
        return default
    try:
        return json.loads(raw)
    except Exception:
        return default


def _json_dump(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=2)


def _normalize_risk(raw: str) -> str:
    v = str(raw or "").upper()
    if any(x in v for x in ("CRIT", "CRÍT")):
        return "CRITICO"
    if "HIGH" in v or "ALTO" in v or "ALTA" in v:
        return "ALTO"
    if "MED" in v:
        return "MEDIO"
    if "LOW" in v or "BAJO" in v:
        return "BAJO"
    return "MEDIO"


def _host_context() -> dict:
    return {
        "equipo": socket.gethostname(),
        "sistema_operativo": f"{platform.system()} {platform.release()}".strip(),
    }


def _user_context(user_email: Optional[str] = None, user_id: Optional[int] = None) -> dict:
    ctx = _host_context()
    ctx["usuario"] = user_email or "sistema"
    ctx["empresa"] = "Sin datos disponibles"
    ctx["sector"] = "Sin datos disponibles"
    if not user_email:
        return ctx
    db = SessionLocal()
    try:
        u = db.query(Usuario).filter(Usuario.email == user_email).first()
        if u:
            ctx["sector"] = u.sector or ctx["sector"]
            ctx["empresa"] = u.nit_pyme or u.email.split("@")[-1]
    finally:
        db.close()
    return ctx


def _next_case_id(db) -> str:
    today = datetime.now().strftime("%Y%m%d")
    prefix = f"CASO-{today}-"
    rows = db.query(InteligenciaCaso.id).filter(InteligenciaCaso.id.like(f"{prefix}%")).all()
    seq = len(rows) + 1
    return f"{prefix}{seq:04d}"


def _build_keywords(case: dict) -> str:
    parts = [
        case.get("id", ""),
        case.get("tipo", ""),
        case.get("nivel_riesgo", ""),
        case.get("estado", ""),
        case.get("empresa", ""),
        case.get("usuario", ""),
        case.get("equipo", ""),
        case.get("sector", ""),
        case.get("source_ref", ""),
        case.get("correlacion_grupo", ""),
    ]
    ev = case.get("evidencia") or {}
    for key in ("ips", "macs", "puertos", "procesos", "hashes", "dominios"):
        for item in ev.get(key) or []:
            parts.append(str(item))
    for m in case.get("motores") or []:
        parts.append(str(m))
    for h in case.get("hallazgos") or []:
        if isinstance(h, dict):
            parts.extend([str(h.get("nombre", "")), str(h.get("id", ""))])
        else:
            parts.append(str(h))
    return " ".join(p for p in parts if p).lower()


def _extract_evidence(finding: dict, collected: Optional[dict] = None) -> dict:
    """Extrae evidencia real — nunca inventada."""
    ev: Dict[str, Any] = {
        "ips": [], "macs": [], "puertos": [], "procesos": [], "servicios": [],
        "archivos": [], "hashes": [], "logs": [], "conexiones": [], "eventos": [],
        "reglas": [], "indicadores": [], "reportes": [],
    }
    collected = collected or {}
    fid = str(finding.get("id") or finding.get("finding_id") or "")

    ip = finding.get("ip")
    if ip:
        ev["ips"].append(ip)

    if "PROC" in fid.upper():
        ev["procesos"].append({
            "pid": finding.get("pid"),
            "nombre": finding.get("nombre") or finding.get("name"),
            "descripcion": finding.get("descripcion") or finding.get("command_line"),
        })
    if "PORT" in fid.upper():
        port = finding.get("port") or re.search(r"PORT-(\d+)", fid, re.I)
        port_num = port.group(1) if hasattr(port, "group") else port
        ev["puertos"].append({"port": port_num, "descripcion": finding.get("descripcion", "")})

    sec = collected.get("security") or {}
    for sp in sec.get("suspicious_processes") or []:
        ev["procesos"].append({
            "pid": sp.get("pid"), "nombre": sp.get("name"),
            "descripcion": sp.get("description") or sp.get("command_line"),
        })
    for p in collected.get("processes") or []:
        if isinstance(p, dict):
            ev["procesos"].append({"pid": p.get("pid"), "nombre": p.get("name"), "cpu": p.get("cpu_percent")})

    net = collected.get("network") or {}
    for n in net.get("nodes") or []:
        if n.get("ip"):
            ev["ips"].append(n["ip"])
        if n.get("mac"):
            ev["macs"].append(n["mac"])

    conn = collected.get("connections") or {}
    samples = conn.get("samples") or conn.get("connections") or []
    for c in (samples if isinstance(samples, list) else [])[:20]:
        if isinstance(c, dict):
            ev["conexiones"].append(c)

    for port in (collected.get("firewall") or {}).get("open_ports") or sec.get("open_ports") or []:
        ev["puertos"].append(port)

    siem = collected.get("siem") or {}
    for log in (siem.get("audit_logs") or [])[:15]:
        ev["logs"].append(log)
    for evn in (siem.get("network_events") or [])[:15]:
        ev["eventos"].append(evn)

    if finding.get("hash"):
        ev["hashes"].append(finding["hash"])

    # Dedupe lists
    for k in ev:
        if isinstance(ev[k], list) and ev[k] and isinstance(ev[k][0], dict):
            seen = set()
            unique = []
            for item in ev[k]:
                key = json.dumps(item, sort_keys=True, default=str)
                if key not in seen:
                    seen.add(key)
                    unique.append(item)
            ev[k] = unique
        elif isinstance(ev[k], list):
            ev[k] = list(dict.fromkeys(str(x) for x in ev[k] if x))
    return ev


def _infer_tipo(finding: dict) -> str:
    fid = str(finding.get("id") or "").upper()
    tipo = str(finding.get("tipo") or finding.get("type") or "").lower()
    if "incident" in tipo or fid.startswith("INC") or fid.startswith("RT-"):
        return "incidente"
    if "malware" in tipo or "virus" in tipo:
        return "ataque"
    if "PROC" in fid or finding.get("suspicious"):
        return "comportamiento_sospechoso"
    if "vuln" in tipo or "PORT" in fid or finding.get("fuente"):
        return "vulnerabilidad"
    if finding.get("threat_type"):
        return "amenaza"
    return "hallazgo_seguridad"


def _generate_lessons(finding: dict, tipo: str, motores: List[str], acciones: List[str]) -> dict:
    nombre = finding.get("nombre") or finding.get("name") or finding.get("titulo") or "Hallazgo detectado"
    return {
        "que_ocurrio": f"NOVUS detectó: {nombre}. Tipo clasificado: {tipo}.",
        "como_ocurrio": finding.get("descripcion") or finding.get("details") or "Evidencia registrada por motores de telemetría.",
        "que_permitio": "Superficie de exposición identificada en el equipo monitorizado (datos de motores reales).",
        "respuesta_novus": f"Motores activados: {', '.join(motores[:6]) or 'N/D'}. Acciones: {', '.join(acciones[:4]) or 'Detección y documentación'}.",
        "mejoras_recomendadas": "Revisar políticas de hardening, parches pendientes y reglas de detección asociadas al tipo de hallazgo.",
    }


def _generate_proposals(tipo: str, finding: dict) -> List[str]:
    props = []
    fid = str(finding.get("id") or "")
    if tipo == "comportamiento_sospechoso" or "PROC" in fid:
        props.append("Este caso podría mejorar la detección de procesos con comportamiento atípico en el motor XDR.")
    if tipo == "vulnerabilidad" or "PORT" in fid:
        props.append("Este caso podría mejorar la correlación de puertos expuestos con servicios no autorizados.")
    if tipo == "incidente":
        props.append("Este caso podría mejorar la correlación automática entre alertas SIEM e incidentes.")
    if tipo == "amenaza" or tipo == "ataque":
        props.append("Este caso podría mejorar la detección temprana de amenazas en runtime.")
    if not props:
        props.append(f"Este caso ({tipo}) podría enriquecer las reglas de detección del sector afectado.")
    return props


def _correlation_group(finding: dict, tipo: str, ip: Optional[str]) -> str:
    seed = f"{tipo}|{ip or ''}|{finding.get('nombre') or finding.get('name') or ''}"
    h = hashlib.sha256(seed.encode()).hexdigest()[:8]
    return f"GRP-{datetime.now().strftime('%Y%m%d')}-{h}"


class ThreatIntelligenceService:
    """Centro de Inteligencia NOVUS — casos, correlación, búsqueda, exportación."""

    def _find_existing(
        self, db, source_ref: str, tipo: str, ip: Optional[str]
    ) -> Optional[InteligenciaCaso]:
        if source_ref:
            row = db.query(InteligenciaCaso).filter(InteligenciaCaso.source_ref == source_ref).first()
            if row:
                return row
        if ip:
            cutoff = (datetime.now() - timedelta(hours=24)).strftime("%Y-%m-%d")
            candidates = (
                db.query(InteligenciaCaso)
                .filter(InteligenciaCaso.tipo == tipo, InteligenciaCaso.fecha >= cutoff)
                .all()
            )
            for c in candidates:
                ev = _json_load(c.evidencia_json, {})
                if ip in (ev.get("ips") or []):
                    return c
        return None

    def create_or_update_case(
        self,
        finding: dict,
        context: Optional[dict] = None,
        collected: Optional[dict] = None,
        motores: Optional[List[str]] = None,
        acciones: Optional[List[str]] = None,
        reglas: Optional[List[str]] = None,
        elapsed_sec: Optional[float] = None,
        timeline_events: Optional[List[dict]] = None,
    ) -> dict:
        """Crea expediente o correlaciona con caso existente."""
        _ensure_dirs()
        context = {**_user_context(context.get("usuario") if context else None), **(context or {})}
        finding = dict(finding or {})
        tipo = _infer_tipo(finding)
        source_ref = str(finding.get("id") or finding.get("finding_id") or "")
        ip = finding.get("ip")
        motores = list(motores or [])
        acciones = list(acciones or [])
        reglas = list(reglas or [])
        evidencia = _extract_evidence(finding, collected)
        hallazgos = [finding] if finding else []
        now = datetime.now()
        fecha = now.strftime("%Y-%m-%d")
        hora = now.strftime("%H:%M:%S")

        db = SessionLocal()
        try:
            existing = self._find_existing(db, source_ref, tipo, ip)
            if existing:
                caso_id = existing.id
                ev_old = _json_load(existing.evidencia_json, {})
                for k, v in evidencia.items():
                    if isinstance(v, list):
                        merged = ev_old.get(k, []) + v
                        if merged and isinstance(merged[0], dict):
                            seen = {json.dumps(x, sort_keys=True, default=str) for x in merged}
                            ev_old[k] = [json.loads(s) for s in seen]
                        else:
                            ev_old[k] = list(dict.fromkeys(str(x) for x in merged if x))
                motores_old = _json_load(existing.motores_json, [])
                motores = list(dict.fromkeys(motores_old + motores))
                hall_old = _json_load(existing.hallazgos_json, [])
                if finding and finding not in hall_old:
                    hall_old.append(finding)
                hallazgos = hall_old
                evidencia = ev_old
                existing.estado = "correlacionado"
                existing.updated_at = now.strftime("%Y-%m-%d %H:%M:%S")
                existing.motores_json = _json_dump(motores)
                existing.hallazgos_json = _json_dump(hallazgos)
                existing.evidencia_json = _json_dump(evidencia)
                if elapsed_sec:
                    existing.tiempo_respuesta_sec = str(elapsed_sec)
                case_dict_upd = self._row_to_dict(existing)
                case_dict_upd["evidencia"] = evidencia
                case_dict_upd["motores"] = motores
                case_dict_upd["hallazgos"] = hallazgos
                existing.keywords = _build_keywords(case_dict_upd)
                row = existing
            else:
                caso_id = _next_case_id(db)
                grupo = _correlation_group(finding, tipo, ip)
                lessons = _generate_lessons(finding, tipo, motores, acciones)
                recs = finding.get("recomendaciones") or []
                if not recs and finding.get("descripcion"):
                    recs = [f"Investigar: {finding.get('descripcion')[:200]}"]
                case_dict = {
                    "id": caso_id,
                    "fecha": fecha,
                    "hora": hora,
                    "empresa": context.get("empresa"),
                    "usuario": context.get("usuario"),
                    "equipo": context.get("equipo"),
                    "sistema_operativo": context.get("sistema_operativo"),
                    "sector": context.get("sector"),
                    "tipo": tipo,
                    "nivel_riesgo": _normalize_risk(
                        finding.get("riesgo") or finding.get("severidad") or finding.get("gravedad") or finding.get("severity")
                    ),
                    "estado": "abierto",
                    "evidencia": evidencia,
                    "motores": motores,
                    "hallazgos": hallazgos,
                    "reglas": reglas,
                    "acciones": acciones,
                    "tiempo_respuesta_sec": str(elapsed_sec) if elapsed_sec else None,
                    "resultado": "Detectado y documentado por NOVUS Threat Intelligence Center",
                    "recomendaciones": recs,
                    "lecciones_aprendidas": lessons,
                    "correlacion_grupo": grupo,
                    "source_ref": source_ref or None,
                }
                case_dict["keywords"] = _build_keywords(case_dict)
                row = InteligenciaCaso(
                    id=caso_id,
                    fecha=fecha,
                    hora=hora,
                    empresa=case_dict["empresa"],
                    usuario=case_dict["usuario"],
                    equipo=case_dict["equipo"],
                    sistema_operativo=case_dict["sistema_operativo"],
                    sector=case_dict["sector"],
                    tipo=tipo,
                    nivel_riesgo=case_dict["nivel_riesgo"],
                    estado="abierto",
                    evidencia_json=_json_dump(evidencia),
                    motores_json=_json_dump(motores),
                    hallazgos_json=_json_dump(hallazgos),
                    reglas_json=_json_dump(reglas),
                    acciones_json=_json_dump(acciones),
                    tiempo_respuesta_sec=case_dict["tiempo_respuesta_sec"],
                    resultado=case_dict["resultado"],
                    recomendaciones_json=_json_dump(recs),
                    lecciones_json=_json_dump(lessons),
                    correlacion_grupo=grupo,
                    source_ref=source_ref or None,
                    keywords=case_dict["keywords"],
                    created_at=now.strftime("%Y-%m-%d %H:%M:%S"),
                    updated_at=now.strftime("%Y-%m-%d %H:%M:%S"),
                )
                db.add(row)
                for prop in _generate_proposals(tipo, finding):
                    db.add(InteligenciaPropuesta(
                        caso_id=caso_id,
                        propuesta=prop,
                        estado="pendiente",
                        fecha=now.strftime("%Y-%m-%d %H:%M:%S"),
                    ))

            # Timeline
            events = timeline_events or [{
                "timestamp": f"{fecha} {hora}",
                "evento": "Detección NOVUS",
                "detalle": finding.get("descripcion") or finding.get("nombre") or source_ref or tipo,
            }]
            max_ord = db.query(InteligenciaTimeline).filter(
                InteligenciaTimeline.caso_id == caso_id
            ).count()
            for i, ev in enumerate(events):
                db.add(InteligenciaTimeline(
                    caso_id=caso_id,
                    timestamp=ev.get("timestamp", f"{fecha} {hora}"),
                    evento=ev.get("evento", "Evento"),
                    detalle=ev.get("detalle", ""),
                    orden=max_ord + i,
                ))

            db.commit()
            return self.get_case(caso_id)
        except Exception as exc:
            db.rollback()
            logger.error(f"ThreatIntel create_case: {exc}", exc_info=True)
            raise
        finally:
            db.close()

    def get_case(self, case_id: str) -> Optional[dict]:
        db = SessionLocal()
        try:
            row = db.query(InteligenciaCaso).filter(InteligenciaCaso.id == case_id).first()
            if not row:
                return None
            timeline = (
                db.query(InteligenciaTimeline)
                .filter(InteligenciaTimeline.caso_id == case_id)
                .order_by(InteligenciaTimeline.orden)
                .all()
            )
            propuestas = (
                db.query(InteligenciaPropuesta)
                .filter(InteligenciaPropuesta.caso_id == case_id)
                .all()
            )
            return self._row_to_dict(row, timeline, propuestas)
        finally:
            db.close()

    def _row_to_dict(self, row, timeline=None, propuestas=None) -> dict:
        return {
            "id": row.id,
            "fecha": row.fecha,
            "hora": row.hora,
            "empresa": row.empresa,
            "usuario": row.usuario,
            "equipo": row.equipo,
            "sistema_operativo": row.sistema_operativo,
            "sector": row.sector,
            "tipo": row.tipo,
            "nivel_riesgo": row.nivel_riesgo,
            "estado": row.estado,
            "evidencia": _json_load(row.evidencia_json, {}),
            "motores": _json_load(row.motores_json, []),
            "hallazgos": _json_load(row.hallazgos_json, []),
            "reglas": _json_load(row.reglas_json, []),
            "acciones": _json_load(row.acciones_json, []),
            "tiempo_respuesta_sec": row.tiempo_respuesta_sec,
            "resultado": row.resultado,
            "recomendaciones": _json_load(row.recomendaciones_json, []),
            "lecciones_aprendidas": _json_load(row.lecciones_json, {}),
            "correlacion_grupo": row.correlacion_grupo,
            "source_ref": row.source_ref,
            "timeline": [
                {"timestamp": t.timestamp, "evento": t.evento, "detalle": t.detalle}
                for t in (timeline or [])
            ],
            "propuestas_mejora": [
                {"id": p.id, "propuesta": p.propuesta, "estado": p.estado, "fecha": p.fecha}
                for p in (propuestas or [])
            ],
            "created_at": row.created_at,
            "updated_at": row.updated_at,
        }

    def list_cases(self, limit: int = 100) -> List[dict]:
        db = SessionLocal()
        try:
            rows = (
                db.query(InteligenciaCaso)
                .order_by(InteligenciaCaso.created_at.desc())
                .limit(limit)
                .all()
            )
            return [self._row_to_dict(r) for r in rows]
        finally:
            db.close()

    def search_cases(self, filters: dict) -> List[dict]:
        db = SessionLocal()
        try:
            q = db.query(InteligenciaCaso)
            if filters.get("fecha"):
                q = q.filter(InteligenciaCaso.fecha == filters["fecha"])
            if filters.get("empresa"):
                q = q.filter(InteligenciaCaso.empresa.ilike(f"%{filters['empresa']}%"))
            if filters.get("usuario"):
                q = q.filter(InteligenciaCaso.usuario.ilike(f"%{filters['usuario']}%"))
            if filters.get("equipo"):
                q = q.filter(InteligenciaCaso.equipo.ilike(f"%{filters['equipo']}%"))
            if filters.get("tipo"):
                q = q.filter(InteligenciaCaso.tipo == filters["tipo"])
            if filters.get("nivel"):
                q = q.filter(InteligenciaCaso.nivel_riesgo == filters["nivel"].upper())
            if filters.get("estado"):
                q = q.filter(InteligenciaCaso.estado == filters["estado"])
            if filters.get("keyword"):
                kw = f"%{filters['keyword'].lower()}%"
                q = q.filter(InteligenciaCaso.keywords.ilike(kw))
            if filters.get("motor"):
                q = q.filter(InteligenciaCaso.motores_json.ilike(f"%{filters['motor']}%"))
            if filters.get("ip"):
                q = q.filter(InteligenciaCaso.evidencia_json.ilike(f"%{filters['ip']}%"))
            if filters.get("puerto"):
                q = q.filter(InteligenciaCaso.evidencia_json.ilike(f"%{filters['puerto']}%"))
            if filters.get("hash"):
                q = q.filter(InteligenciaCaso.evidencia_json.ilike(f"%{filters['hash']}%"))
            if filters.get("proceso"):
                q = q.filter(InteligenciaCaso.evidencia_json.ilike(f"%{filters['proceso']}%"))
            if filters.get("dominio"):
                q = q.filter(InteligenciaCaso.evidencia_json.ilike(f"%{filters['dominio']}%"))
            rows = q.order_by(InteligenciaCaso.created_at.desc()).limit(200).all()
            return [self._row_to_dict(r) for r in rows]
        finally:
            db.close()

    def sync_from_real_sources(
        self,
        user_email: Optional[str] = None,
        user_id: Optional[int] = None,
    ) -> dict:
        """Importa hallazgos reales actuales del equipo a casos de inteligencia."""
        created = 0
        updated = 0
        ctx = _user_context(user_email, user_id)
        motores = ["novus_security_integration", "security_engine"]

        try:
            from services.novus_security_integration import novus_security
            novus_security.detect_threats_realtime(force=True)
            cache = novus_security._threat_cache or {}
            motores.extend(["security.threats", "security.vulnerabilities"])

            for v in cache.get("vulnerabilities") or []:
                before = self._count_cases()
                self.create_or_update_case(v, context=ctx, motores=motores)
                after = self._count_cases()
                if after > before:
                    created += 1
                else:
                    updated += 1

            for sp in cache.get("suspicious_processes") or []:
                finding = {
                    "id": f"PROC-{sp.get('pid')}",
                    "nombre": sp.get("name"),
                    "descripcion": sp.get("description") or sp.get("command_line"),
                    "riesgo": "ALTO",
                    "ip": "local",
                }
                before = self._count_cases()
                self.create_or_update_case(finding, context=ctx, motores=motores + ["advanced_detector.processes"])
                if self._count_cases() > before:
                    created += 1
                else:
                    updated += 1

            for port in cache.get("open_ports") or []:
                finding = {
                    "id": f"PORT-{port.get('port')}",
                    "nombre": f"Puerto {port.get('port')}",
                    "descripcion": port.get("description", ""),
                    "riesgo": "MEDIO",
                    "ip": port.get("target_ip", "local"),
                    "port": port.get("port"),
                }
                before = self._count_cases()
                self.create_or_update_case(finding, context=ctx, motores=motores)
                if self._count_cases() > before:
                    created += 1
                else:
                    updated += 1
        except Exception as exc:
            logger.error(f"sync security cache: {exc}")

        db = SessionLocal()
        try:
            from services.alert_reconciliation_service import RESOLVED_LEVEL
            for alerta in db.query(Alerta).order_by(Alerta.id.desc()).limit(20).all():
                if alerta.nivel == RESOLVED_LEVEL:
                    continue
                titulo_lower = (alerta.titulo or "").lower()
                if "high_entropy" in titulo_lower:
                    continue
                finding = {
                    "id": f"INC-{alerta.id:04d}",
                    "nombre": alerta.titulo,
                    "descripcion": alerta.descripcion,
                    "riesgo": alerta.nivel,
                    "ip": alerta.ip_afectada or "local",
                    "tipo": "incidente",
                }
                before = self._count_cases()
                self.create_or_update_case(
                    finding, context=ctx, motores=motores + ["incidents.manager"],
                    timeline_events=[{
                        "timestamp": alerta.fecha or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "evento": "Alerta registrada",
                        "detalle": alerta.titulo,
                    }],
                )
                if self._count_cases() > before:
                    created += 1
                else:
                    updated += 1
        finally:
            db.close()

        try:
            from services.playbook_service import list_executions
            for ex in list_executions(limit=30):
                finding = {
                    "id": f"PBX-{ex.get('id', '')}",
                    "nombre": f"Playbook: {ex.get('playbook_nombre', ex.get('playbook_id'))}",
                    "descripcion": ex.get("resultado") or "",
                    "riesgo": "ALTO" if ex.get("nivel_exito") == "Alto" else "MEDIO",
                    "tipo": "playbook",
                }
                before = self._count_cases()
                self.create_or_update_case(
                    finding,
                    context=ctx,
                    motores=["playbook_service"] + (ex.get("motores") or []),
                    acciones=ex.get("acciones") or [],
                    elapsed_sec=ex.get("duracion_seg"),
                    timeline_events=[{
                        "timestamp": ex.get("fecha", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                        "evento": "Playbook ejecutado",
                        "detalle": f"{ex.get('estado')} — {ex.get('nivel_exito')} — {ex.get('duracion_seg')}s",
                    }],
                )
                if self._count_cases() > before:
                    created += 1
                else:
                    updated += 1
        except Exception as exc:
            logger.debug("sync playbooks to intel: %s", exc)

        return {"created": created, "updated": updated, "total": self._count_cases()}

    def _count_cases(self) -> int:
        db = SessionLocal()
        try:
            return db.query(InteligenciaCaso).count()
        finally:
            db.close()

    def ingest_kernel_operation(
        self,
        message: str,
        plan_intent: str,
        engines: List[str],
        collected: dict,
        user_email: Optional[str],
        elapsed_sec: Optional[float] = None,
        decisions: Optional[List[str]] = None,
    ):
        """Integración con Kernel IA — crea casos desde operación SOC completada."""
        ctx = _user_context(user_email)
        vulns = collected.get("vulnerabilities") or []
        sec = collected.get("security") or {}
        sus = sec.get("suspicious_processes") or []
        findings = list(vulns)
        for sp in sus:
            findings.append({
                "id": f"PROC-{sp.get('pid')}",
                "nombre": sp.get("name"),
                "descripcion": sp.get("description"),
                "riesgo": "ALTO",
            })
        if not findings and collected.get("capabilities_executed"):
            findings.append({
                "id": f"KERNEL-{plan_intent}",
                "nombre": f"Análisis Kernel: {plan_intent}",
                "descripcion": message[:300],
                "riesgo": collected.get("risk_level") or "MEDIO",
            })
        timeline = [
            {"timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "evento": "Consulta Kernel IA", "detalle": message[:200]},
            {"timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "evento": "Motores ejecutados", "detalle": ", ".join(engines[:8])},
        ]
        if decisions:
            timeline.append({
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "evento": "Decisiones SOC",
                "detalle": "; ".join(decisions[:3]),
            })
        for f in findings[:10]:
            try:
                self.create_or_update_case(
                    f,
                    context=ctx,
                    collected=collected,
                    motores=engines,
                    acciones=decisions or [],
                    reglas=[f"intent:{plan_intent}"],
                    elapsed_sec=elapsed_sec,
                    timeline_events=timeline,
                )
            except Exception as exc:
                logger.warning(f"Kernel TI ingest: {exc}")

    def ingest_runtime_threat(self, entry: dict):
        """Integración XDR — amenaza en tiempo real con clasificación de cobertura."""
        from services.threat_coverage_service import threat_coverage

        finding = {
            "id": f"RT-{entry.get('threat_type', 'TH')}-{entry.get('time', '')}".replace(" ", ""),
            "nombre": entry.get("threat_type"),
            "descripcion": str(entry.get("details", "")),
            "riesgo": entry.get("severity", "MEDIO"),
            "threat_type": entry.get("threat_type"),
            "tipo": "amenaza",
            "verified": entry.get("verified"),
            "evidence": entry.get("evidence") or entry.get("details"),
        }
        category_id, _ = threat_coverage.classify_finding(finding)
        if not threat_coverage.has_sufficient_evidence(finding, category_id):
            logger.debug("TI ingest skipped — insufficient evidence for %s", category_id)
            return

        cat = threat_coverage.get_category(category_id or "") or {}
        finding["coverage_category"] = category_id
        finding["coverage_label"] = cat.get("label")

        self.create_or_update_case(
            finding,
            context=_user_context(),
            motores=["security.threats", "novus_security_integration", "threat_coverage_service"],
            timeline_events=[{
                "timestamp": datetime.now().strftime(f"%Y-%m-%d {entry.get('time', '%H:%M:%S')}"),
                "evento": f"Amenaza runtime: {entry.get('threat_type')} [{category_id}]",
                "detalle": str(entry.get("details", ""))[:300],
            }],
        )

    def stats(self) -> dict:
        db = SessionLocal()
        try:
            total = db.query(InteligenciaCaso).count()
            abiertos = db.query(InteligenciaCaso).filter(InteligenciaCaso.estado == "abierto").count()
            criticos = db.query(InteligenciaCaso).filter(InteligenciaCaso.nivel_riesgo == "CRITICO").count()
            propuestas = db.query(InteligenciaPropuesta).filter(InteligenciaPropuesta.estado == "pendiente").count()
            return {"total": total, "abiertos": abiertos, "criticos": criticos, "propuestas_pendientes": propuestas}
        finally:
            db.close()

    def get_operational_dashboard(self, user_email: Optional[str] = None) -> dict:
        from services.intel_operational_service import get_operational_dashboard
        return get_operational_dashboard(user_email)

    def answer_kernel_query(self, question: str, user_email: Optional[str] = None) -> Optional[str]:
        from services.intel_operational_service import answer_kernel_query
        return answer_kernel_query(question, user_email)

    def _has_pending_incidents(self) -> bool:
        db = SessionLocal()
        try:
            open_incidents = (
                db.query(InteligenciaCaso)
                .filter(
                    InteligenciaCaso.estado.in_(["abierto", "correlacionado"]),
                    InteligenciaCaso.tipo.in_(["incidente", "amenaza"]),
                )
                .count()
            )
            if open_incidents:
                return True
            from services.alert_reconciliation_service import RESOLVED_LEVEL
            pending_alerts = (
                db.query(Alerta)
                .filter(Alerta.nivel != RESOLVED_LEVEL)
                .count()
            )
            if pending_alerts:
                return True
        finally:
            db.close()
        try:
            from services.novus_security_integration import novus_security
            for threat in novus_security.security_engine.threat_registry or []:
                if threat.get("verified") and (threat.get("evidence") or threat.get("indicators")):
                    return True
        except Exception:
            pass
        return False

    def clean_processed_state(
        self,
        user_email: Optional[str] = None,
        user_id: Optional[int] = None,
    ) -> dict:
        """Limpieza operativa del Centro de Inteligencia — solo si no hay incidentes pendientes."""
        if self._has_pending_incidents():
            return {
                "status": "blocked",
                "message": "No es posible limpiar porque existen incidentes pendientes.",
            }

        from services.network_event_log import network_event_log

        events_removed = network_event_log.purge_processed()
        closed = 0
        db = SessionLocal()
        try:
            rows = (
                db.query(InteligenciaCaso)
                .filter(InteligenciaCaso.estado.in_(["abierto", "correlacionado", "pendiente"]))
                .all()
            )
            for row in rows:
                resultado = (row.resultado or "").lower()
                tipo = row.tipo or ""
                if tipo == "playbook" and "exitoso" in resultado:
                    row.estado = "cerrado"
                    row.updated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    closed += 1
                elif any(k in resultado for k in ("resuelto", "remediación", "remediacion", "mitigado", "cerrado")):
                    row.estado = "cerrado"
                    row.updated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    closed += 1
            db.commit()
        finally:
            db.close()

        sync_result = self.sync_from_real_sources(user_email=user_email, user_id=user_id)

        priority = None
        try:
            from services.dashboard_priority_service import get_current_priority
            priority = get_current_priority(user_email)
        except Exception as exc:
            logger.debug("clean intel priority refresh: %s", exc)

        return {
            "status": "success",
            "message": "Centro de Inteligencia actualizado correctamente.",
            "events_removed": events_removed,
            "cases_closed": closed,
            "sync": sync_result,
            "priority": priority,
        }


threat_intelligence = ThreatIntelligenceService()
