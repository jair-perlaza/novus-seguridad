"""
Catálogo de Action Packs — ejecución solo con RBAC + confirmación + auditoría.
Acciones no cableadas a motores reales se declaran explícitamente (no se simulan).
"""
from __future__ import annotations

from typing import Any, Dict, Optional, Sequence

from services.kernel_enterprise_v2.audit import record_action_audit
from services.kernel_enterprise_v2.base import ActionResult, BaseActionPack
from services.kernel_enterprise_v2.registry import PackRegistry
from services.rbac_service import (
    ADMIN_ROLES,
    ROLE_ANALYST,
    ROLE_CLIENT,
    ROLE_COMPANY_ADMIN,
    ROLE_SUPER_ADMIN,
    SOC_ROLES,
    normalize_role,
)


def _role_allowed(user_role: Optional[str], allowed: Sequence[str]) -> bool:
    role = normalize_role(user_role)
    return role in set(allowed)


class DeclarativeActionPack(BaseActionPack):
    def __init__(
        self,
        action_id: str,
        label: str,
        category: str,
        keywords: Sequence[str],
        description: str,
        allowed_roles: Sequence[str],
        *,
        capability_id: Optional[str] = None,
        requires_confirm: bool = True,
        version: str = "1.0.0",
        handler_key: Optional[str] = None,
    ):
        self.action_id = action_id
        self.label = label
        self.category = category
        self.keywords = tuple(keywords)
        self.description = description
        self.allowed_roles = tuple(allowed_roles)
        self.capability_id = capability_id
        self.requires_confirm = requires_confirm
        self.version = version
        self.handler_key = handler_key

    def is_wired(self) -> bool:
        return bool(self.capability_id or self.handler_key)

    def execute(
        self,
        *,
        user_email: Optional[str],
        user_role: Optional[str],
        params: Optional[dict] = None,
        confirmed: bool = False,
        reason: str = "",
    ) -> ActionResult:
        params = params or {}

        if not _role_allowed(user_role, self.allowed_roles):
            msg = (
                f"Acción «{self.label}» denegada por RBAC. "
                f"Rol actual: {normalize_role(user_role)}. "
                f"Roles permitidos: {', '.join(self.allowed_roles)}."
            )
            audit_id = record_action_audit(
                action_id=self.action_id,
                user_email=user_email,
                user_role=user_role,
                reason=reason,
                status="denied",
                result_message=msg,
                params=params,
            )
            return ActionResult(self.action_id, False, "denied", msg, audit_id=audit_id)

        if self.requires_confirm and not confirmed:
            msg = (
                f"Acción «{self.label}» requiere confirmación explícita del operador "
                f"(mínimo privilegio). Motive la acción y confirme."
            )
            audit_id = record_action_audit(
                action_id=self.action_id,
                user_email=user_email,
                user_role=user_role,
                reason=reason,
                status="needs_confirm",
                result_message=msg,
                params=params,
            )
            return ActionResult(self.action_id, False, "needs_confirm", msg, audit_id=audit_id)

        if not self.is_wired():
            msg = (
                f"Acción «{self.label}» está registrada en Kernel Enterprise V2 "
                f"pero aún no está cableada a un motor NOVUS real. "
                f"No se simula la ejecución. Motivo: capability/handler ausente."
            )
            audit_id = record_action_audit(
                action_id=self.action_id,
                user_email=user_email,
                user_role=user_role,
                reason=reason,
                status="not_wired",
                result_message=msg,
                params=params,
            )
            return ActionResult(self.action_id, False, "not_wired", msg, audit_id=audit_id)

        try:
            evidence, details = _dispatch(self, params, user_email)
            msg = f"Acción «{self.label}» ejecutada contra motor real. Motivo: {reason or 'n/d'}."
            audit_id = record_action_audit(
                action_id=self.action_id,
                user_email=user_email,
                user_role=user_role,
                reason=reason,
                status="executed",
                result_message=msg,
                params=params,
                evidence=evidence,
            )
            return ActionResult(
                self.action_id,
                True,
                "executed",
                msg,
                audit_id=audit_id,
                evidence=evidence,
                details=details,
            )
        except Exception as exc:
            msg = f"Acción «{self.label}» falló: {exc}. Kernel IA no oculta el error."
            audit_id = record_action_audit(
                action_id=self.action_id,
                user_email=user_email,
                user_role=user_role,
                reason=reason,
                status="error",
                result_message=msg,
                params=params,
            )
            return ActionResult(self.action_id, False, "error", msg, audit_id=audit_id)


def _dispatch(pack: DeclarativeActionPack, params: dict, user_email: Optional[str]):
    """Despacha a capacidades/servicios reales. Sin stubs falsos."""
    if pack.handler_key == "playbook_execute":
        from services.playbook_service import execute_playbook

        playbook_id = params.get("playbook_id")
        if not playbook_id:
            raise ValueError("Falta parámetro playbook_id")
        result = execute_playbook(playbook_id, user_email=user_email or "kernel_enterprise_v2")
        return {"playbook_id": playbook_id}, {"result": result}

    if pack.handler_key == "compliance_evaluate":
        from services.compliance_center_service import build_profile, evaluate_controls

        sector = params.get("sector_id", "general")
        country = params.get("country", "CO")
        profile = build_profile(sector_id=sector, country=country)
        evaluation = evaluate_controls(profile=profile)
        return {"sector_id": sector, "country": country}, {
            "score": evaluation.get("score"),
            "counts": evaluation.get("counts"),
            "controls": len(evaluation.get("controls") or []),
        }

    if pack.handler_key == "generate_report":
        # Solo vía capability real
        from services.ai_capability_registry import capability_registry

        data, module = capability_registry._run_capability("reports.manager", None, True)
        return {"module": module}, {"data_preview": _preview(data)}

    if pack.capability_id:
        from services.ai_capability_registry import capability_registry

        data, module = capability_registry._run_capability(pack.capability_id, None, True)
        return {"capability": pack.capability_id, "module": module}, {"data_preview": _preview(data)}

    raise RuntimeError("Sin despachador — estado inconsistente (debería ser not_wired)")


def _preview(data: Any) -> Any:
    if data is None:
        return None
    if isinstance(data, dict):
        return {"keys": list(data.keys())[:30], "truncated": True}
    if isinstance(data, list):
        return {"count": len(data), "sample": data[:5], "truncated": True}
    return str(data)[:500]


# roles helpers
_SOC = SOC_ROLES
_ADMIN = ADMIN_ROLES
_ALL_OPS = SOC_ROLES + (ROLE_CLIENT,)  # lecturas amplias no — acciones ops = SOC
_READ_SCAN = SOC_ROLES  # escaneos = SOC mínimo

_ACTION_SPECS = [
    # Filesystem — no cableadas (transparencia)
    ("fs.create_folder", "Crear carpetas", "filesystem", ["crear carpeta", "mkdir"], "Crear carpeta en host", _ADMIN, None, True, None),
    ("fs.delete_folder", "Eliminar carpetas", "filesystem", ["eliminar carpeta", "rmdir"], "Eliminar carpeta", _ADMIN, None, True, None),
    ("fs.move_file", "Mover archivos", "filesystem", ["mover archivo", "move file"], "Mover archivo", _ADMIN, None, True, None),
    ("fs.copy_file", "Copiar archivos", "filesystem", ["copiar archivo", "copy file"], "Copiar archivo", _ADMIN, None, True, None),
    ("fs.rename_file", "Renombrar archivos", "filesystem", ["renombrar archivo", "rename"], "Renombrar archivo", _ADMIN, None, True, None),
    # Reportes / casos
    ("report.create", "Crear reportes", "reporting", ["crear reporte", "generar reporte"], "Crear/consultar reportes", _SOC, "reports.manager", False, "generate_report"),
    ("report.pdf", "Generar PDFs", "reporting", ["generar pdf", "exportar pdf"], "Generar PDF de reporte", _SOC, "reports.manager", True, "generate_report"),
    ("evidence.create", "Generar evidencias", "forensic", ["generar evidencia", "crear evidencia"], "Registrar evidencia de defensa", _SOC, None, True, None),
    ("case.create", "Crear casos", "cases", ["crear caso", "abrir caso"], "Crear caso de estudio/incidente", (ROLE_SUPER_ADMIN,), None, True, None),
    ("case.close", "Cerrar casos", "cases", ["cerrar caso"], "Cerrar caso", (ROLE_SUPER_ADMIN,), None, True, None),
    # Escaneos cableados a capabilities reales
    ("scan.endpoint", "Escanear equipos", "scan", ["escanear equipo", "escanear endpoint"], "Escaneo endpoint en vivo", _READ_SCAN, "endpoints.live", False, None),
    ("scan.disk", "Escanear discos", "scan", ["escanear disco", "escanear discos"], "Métricas/disco vía system metrics", _READ_SCAN, "system.metrics", False, None),
    ("scan.processes", "Escanear procesos", "scan", ["escanear procesos", "listar procesos"], "Escáner de procesos", _READ_SCAN, "process.scanner", False, None),
    ("scan.memory", "Escanear memoria", "scan", ["escanear memoria", "ram"], "Métricas de memoria", _READ_SCAN, "system.metrics", False, None),
    ("scan.services", "Escanear servicios", "scan", ["escanear servicios"], "Servicios vía detector avanzado / procesos", _READ_SCAN, "advanced_detector.processes", False, None),
    ("scan.registry", "Escanear registro", "scan", ["escanear registro", "registry"], "Registro Windows — no cableado a motor dedicado", _ADMIN, None, True, None),
    ("scan.scheduled_tasks", "Escanear tareas programadas", "scan", ["tareas programadas", "scheduled tasks"], "Tareas programadas — no cableado", _ADMIN, None, True, None),
    ("scan.autostart", "Escanear inicio automático", "scan", ["inicio automático", "autostart", "run key"], "Inicio automático — no cableado", _ADMIN, None, True, None),
    ("scan.network", "Escanear red", "scan", ["escanear red", "scan network", "arp"], "Escáner de red ARP", _READ_SCAN, "network.scanner", False, None),
    ("scan.devices", "Escanear dispositivos", "scan", ["escanear dispositivos", "inventario dispositivos"], "Dispositivos vía red/endpoints", _READ_SCAN, "network.scanner", False, None),
    ("scan.printers", "Escanear impresoras", "scan", ["escanear impresoras"], "Impresoras — no cableado", _READ_SCAN, None, True, None),
    ("scan.usb", "Escanear USB", "scan", ["escanear usb", "dispositivos usb"], "USB — no cableado", _ADMIN, None, True, None),
    ("scan.certificates", "Escanear certificados", "scan", ["escanear certificados", "certificados ssl"], "Certificados — no cableado", _ADMIN, None, True, None),
    ("scan.logs", "Escanear logs", "scan", ["escanear logs", "revisar logs"], "Logs SIEM si existen", _READ_SCAN, "siem.logs", False, None),
    ("scan.events", "Escanear eventos", "scan", ["escanear eventos", "eventos de red"], "Eventos de red", _READ_SCAN, "network.events", False, None),
    ("scan.ports", "Escanear puertos", "scan", ["escanear puertos", "port scan"], "Puertos / firewall local", _READ_SCAN, "advanced_detector.ports", False, None),
    ("scan.dns", "Escanear DNS", "scan", ["escanear dns"], "DNS — no cableado a motor dedicado", _READ_SCAN, None, True, None),
    ("scan.dhcp", "Escanear DHCP", "scan", ["escanear dhcp"], "DHCP — no cableado", _READ_SCAN, None, True, None),
    ("scan.gateway", "Escanear Gateway", "scan", ["escanear gateway", "gateway"], "Gateway vía topología/red", _READ_SCAN, "network.scanner", False, None),
    ("scan.traffic", "Escanear tráfico", "scan", ["escanear tráfico", "traffic"], "Estadísticas de tráfico", _READ_SCAN, "traffic.stats", False, None),
    ("scan.vulnerabilities", "Escanear vulnerabilidades", "scan", ["escanear vulnerabilidades", "scan vulns"], "Motor de vulnerabilidades", _READ_SCAN, "security.vulnerabilities", False, None),
    ("scan.applications", "Escanear aplicaciones", "scan", ["escanear aplicaciones", "software instalado"], "Aplicaciones — deep scan si disponible", _READ_SCAN, "deep_scan.engine", True, None),
    ("scan.obsolete_software", "Escanear software obsoleto", "scan", ["software obsoleto", "eol"], "Software obsoleto vía vulnerabilidades", _READ_SCAN, "security.vulnerabilities", False, None),
    ("scan.permissions", "Escanear permisos", "scan", ["escanear permisos", "acl"], "Permisos — no cableado", _ADMIN, None, True, None),
    ("scan.policies", "Escanear políticas", "scan", ["escanear políticas", "gpo"], "Políticas — no cableado", _ADMIN, None, True, None),
    # Automatización
    ("auto.isolate_host", "Aislar equipos", "automation", ["aislar equipo", "isolate host"], "Aislamiento — requiere motor de remediación dedicado", _ADMIN, None, True, None),
    ("auto.block_ip", "Bloquear IP", "automation", ["bloquear ip", "block ip"], "Bloqueo IP — centro de bloqueos / remediación", _ADMIN, None, True, None),
    ("auto.block_domain", "Bloquear dominios", "automation", ["bloquear dominio", "block domain"], "Bloqueo de dominio — no cableado directo", _ADMIN, None, True, None),
    ("auto.block_process", "Bloquear procesos", "automation", ["bloquear proceso"], "Bloqueo de proceso — confirmación Kernel existente", _ADMIN, None, True, None),
    ("auto.kill_malicious", "Finalizar procesos maliciosos", "automation", ["matar proceso", "kill process", "finalizar proceso"], "Terminación — vía flujo Kernel confirmado (no bypass)", _ADMIN, None, True, None),
    ("auto.restart_service", "Reiniciar servicios", "automation", ["reiniciar servicio"], "Reinicio de servicio — no cableado", _ADMIN, None, True, None),
    ("auto.stop_service", "Detener servicios", "automation", ["detener servicio", "stop service"], "Detener servicio — no cableado", _ADMIN, None, True, None),
    ("auto.start_service", "Iniciar servicios", "automation", ["iniciar servicio", "start service"], "Iniciar servicio — no cableado", _ADMIN, None, True, None),
    ("auto.schedule_task", "Programar tareas", "automation", ["programar tarea"], "Programar tarea — no cableado", _ADMIN, None, True, None),
    ("auto.backup", "Crear respaldos", "automation", ["crear respaldo", "backup"], "Respaldo — no cableado", _ADMIN, None, True, None),
    ("auto.report", "Generar informes automáticamente", "automation", ["informe automático", "auto report"], "Informe vía gestor de reportes", _SOC, "reports.manager", True, "generate_report"),
    ("auto.evidence", "Crear evidencias (auto)", "automation", ["evidencia automática"], "Evidencia — defense_coordinator (requiere wiring específico)", _SOC, None, True, None),
    ("auto.notify_admins", "Notificar administradores", "automation", ["notificar admin", "alertar administradores"], "Notificación — no cableado a canal externo", _SOC, None, True, None),
    ("auto.escalate", "Escalar incidentes", "automation", ["escalar incidente", "escalamiento"], "Escalamiento — playbooks", _SOC, None, True, "playbook_execute"),
    ("auto.playbook", "Ejecutar playbook", "automation", ["ejecutar playbook", "run playbook"], "Ejecutar playbook real", _SOC, "playbooks.manager", True, "playbook_execute"),
    ("compliance.evaluate", "Evaluar cumplimiento", "compliance", ["evaluar compliance", "auditar cumplimiento"], "Evaluación Compliance Center", _SOC, None, False, "compliance_evaluate"),
    ("scan.deep", "Deep Scan integral", "scan", ["deep scan", "escaneo profundo"], "Motor Deep Scan", _READ_SCAN, "deep_scan.engine", True, None),
    ("scan.malware", "Escanear malware", "scan", ["escanear malware", "antimalware"], "Detector antimalware", _READ_SCAN, "advanced_detector.malware", False, None),
    ("scan.threats", "Escanear amenazas XDR", "scan", ["escanear amenazas", "xdr scan"], "Motor XDR / amenazas", _READ_SCAN, "security.threats", False, None),
]


def register_all_action_packs(registry: PackRegistry) -> int:
    count = 0
    for spec in _ACTION_SPECS:
        (
            action_id,
            label,
            category,
            keywords,
            description,
            roles,
            capability_id,
            requires_confirm,
            handler_key,
        ) = spec
        # Si capability no existe en catálogo, no fingir wiring salvo handler_key
        cap = capability_id
        if cap:
            try:
                from services.ai_capability_registry import capability_registry

                if cap not in capability_registry.CAPABILITY_CATALOG and not handler_key:
                    cap = None
            except Exception:
                pass
        registry.register_action(
            DeclarativeActionPack(
                action_id=action_id,
                label=label,
                category=category,
                keywords=keywords,
                description=description,
                allowed_roles=roles,
                capability_id=cap,
                requires_confirm=requires_confirm,
                handler_key=handler_key,
            )
        )
        count += 1
    return count
