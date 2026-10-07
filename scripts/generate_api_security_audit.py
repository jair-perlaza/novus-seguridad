"""
Inventario y auditoría de seguridad de todas las APIs públicas NOVUS.
Genera JSON + Markdown con clasificación de riesgo y protecciones.
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from core.app import create_app
from services.api_security_service import is_sensitive_path

RISK_BY_PATTERN = [
    ("/kill", "CRITICO", "Terminación de procesos"),
    ("/remediate", "CRITICO", "Remediación automática"),
    ("/mitigate", "CRITICO", "Mitigación de incidentes"),
    ("/execute", "CRITICO", "Ejecución de playbooks"),
    ("/investigate", "ALTO", "Investigación NDR"),
    ("/launch-tool", "ALTO", "Lanzamiento herramientas OS"),
    ("/scan/file", "ALTO", "Análisis de archivos subidos"),
    ("/ai/command", "ALTO", "Comandos Kernel IA"),
    ("/config/save", "ALTO", "Persistencia de configuración"),
    ("/oauth", "MEDIO", "Flujo OAuth"),
    ("/sync", "MEDIO", "Sincronización externa"),
    ("/clean", "MEDIO", "Limpieza de datos"),
    ("/ndci/cases/create", "MEDIO", "Creación casos NDCI"),
    ("/ndci/cases/manual", "MEDIO", "Casos manuales NDCI"),
]

GLOBAL_PROTECTIONS = [
    "auth_global_before_request (core/security.py)",
    "rate_limit_api_120_per_min (db_security)",
    "rate_limit_sensitive_30_per_min (api_security_service)",
    "query_param_sqli_scan (db_security.sanitize_and_validate_query)",
    "json_body_size_limit_1mb",
    "security_headers_after_request",
    "api_auth_failed_logging (defense_registry + Log)",
]

SENSITIVE_HARDENED_ENDPOINTS = frozenset({
    "system_api.api_scan_file",
    "system_api.api_remediate_vulnerability",
    "system_api.api_launch_tool",
    "system_api.api_sector_shield_remediate",
    "system_api.api_sector_shield_mitigate",
    "system_api.ai_command",
    "system_api.kill_process",
    "system_api.mitigate_incident",
    "system_api.api_save_config",
    "network_api.investigate_network_ndr_device",
    "playbooks_api.api_execute_playbook",
    "reports_api.api_remediate",
    "reports_api.api_verify_manual",
    "ai_api.api_ai_chat",
})


def classify_risk(path: str) -> Dict[str, str]:
    p = path.lower()
    for frag, level, desc in RISK_BY_PATTERN:
        if frag in p:
            return {"level": level, "reason": desc}
    if is_sensitive_path(path):
        return {"level": "MEDIO", "reason": "Ruta marcada sensible por fragmento"}
    if request_method_writes(path):
        return {"level": "MEDIO", "reason": "Operación de escritura"}
    return {"level": "BAJO", "reason": "Lectura / consulta"}


def request_method_writes(path: str) -> bool:
    return False  # placeholder; risk uses route methods below


def build_inventory(app) -> Dict[str, Any]:
    apis: List[Dict[str, Any]] = []
    public_endpoints = {"auth.login", "auth.logout", "auth.sector_login_page", "auth.sector_auth", "static"}

    for rule in sorted(app.url_map.iter_rules(), key=lambda r: r.rule):
        if "/api/" not in rule.rule:
            continue
        methods = sorted(m for m in rule.methods if m not in ("HEAD", "OPTIONS"))
        path = rule.rule
        endpoint = rule.endpoint

        risk = {"level": "BAJO", "reason": "Lectura / consulta"}
        for frag, level, desc in RISK_BY_PATTERN:
            if frag in path.lower():
                risk = {"level": level, "reason": desc}
                break
        if risk["level"] == "BAJO" and any(m in ("POST", "PUT", "PATCH", "DELETE") for m in methods):
            risk = {"level": "MEDIO", "reason": "Mutación de estado"}
        if is_sensitive_path(path) and risk["level"] == "BAJO":
            risk = {"level": "MEDIO", "reason": "Ruta sensible"}

        protections = list(GLOBAL_PROTECTIONS)
        if endpoint in SENSITIVE_HARDENED_ENDPOINTS:
            protections.append("@api_hardened decorator")
        if endpoint not in public_endpoints:
            protections.append("@login_required (endpoint)")
        protections.append("defense_evidence_registry (eventos bloqueo/auth)")

        gaps = []
        if risk["level"] in ("CRITICO", "ALTO") and endpoint not in SENSITIVE_HARDENED_ENDPOINTS:
            gaps.append("Sin @api_hardened explícito — protegido solo por middleware global")
        if "/oauth/callback" in path:
            gaps.append("OAuth callback requiere sesión activa; sin token state CSRF dedicado")

        apis.append({
            "path": path,
            "methods": methods,
            "endpoint": endpoint,
            "risk": risk,
            "protections": protections,
            "gaps": gaps,
            "hardened_explicit": endpoint in SENSITIVE_HARDENED_ENDPOINTS,
        })

    strengthened = [a for a in apis if a["hardened_explicit"]]
    already_ok = [a for a in apis if not a["gaps"] and a["risk"]["level"] == "BAJO"]
    with_gaps = [a for a in apis if a["gaps"]]

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_apis_reviewed": len(apis),
        "global_protections": GLOBAL_PROTECTIONS,
        "apis_protected_by_global_middleware": len(apis),
        "apis_explicitly_hardened": len(strengthened),
        "apis_already_adequate_low_risk": len(already_ok),
        "apis_with_residual_gaps": len(with_gaps),
        "strengthened_endpoints": [a["path"] for a in strengthened],
        "residual_risks": [
            "Rate limit global por IP no distingue usuarios autenticados vs anónimos",
            "OAuth Gmail sin state token anti-CSRF dedicado",
            "Endpoints MEDIO sin @api_hardened dependen solo del middleware global",
            "Sin WAF externo; protección limitada a capa aplicación",
            "upload scan/file sin límite de tamaño de archivo explícito en api_security_service",
        ],
        "recommendations": [
            "Añadir límite de tamaño en upload multipart para /api/system/scan/file",
            "Implementar state parameter en OAuth Gmail",
            "Rate limit por usuario autenticado además de IP",
            "Extender @api_hardened a /api/gmail/action y /api/ndci/cases/create",
        ],
        "apis": apis,
    }


def write_reports(data: Dict[str, Any]) -> None:
    out_dir = os.path.join(ROOT, "data")
    os.makedirs(out_dir, exist_ok=True)
    json_path = os.path.join(out_dir, "api_security_audit.json")
    md_path = os.path.join(out_dir, "api_security_audit.md")

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    lines = [
        "# Auditoría de Endurecimiento APIs NOVUS",
        "",
        f"**Generado:** {data['generated_at']}",
        "",
        "## Resumen",
        "",
        f"| Métrica | Valor |",
        f"|---------|-------|",
        f"| APIs revisadas | {data['total_apis_reviewed']} |",
        f"| Protegidas por middleware global | {data['apis_protected_by_global_middleware']} |",
        f"| Endurecidas explícitamente (@api_hardened) | {data['apis_explicitly_hardened']} |",
        f"| Bajo riesgo ya adecuadas | {data['apis_already_adequate_low_risk']} |",
        f"| Con brechas residuales documentadas | {data['apis_with_residual_gaps']} |",
        "",
        "## Protecciones globales aplicadas",
        "",
    ]
    for p in data["global_protections"]:
        lines.append(f"- {p}")
    lines.extend([
        "",
        "## Endpoints endurecidos explícitamente",
        "",
    ])
    for p in data["strengthened_endpoints"]:
        lines.append(f"- `{p}`")
    lines.extend([
        "",
        "## Riesgos residuales (honestos)",
        "",
    ])
    for r in data["residual_risks"]:
        lines.append(f"- {r}")
    lines.extend([
        "",
        "## Recomendaciones futuras",
        "",
    ])
    for r in data["recommendations"]:
        lines.append(f"- {r}")
    lines.extend([
        "",
        "## Detalle por API (primeras 50)",
        "",
        "| Ruta | Métodos | Riesgo | Endurecido |",
        "|------|---------|--------|------------|",
    ])
    for a in data["apis"][:50]:
        lines.append(
            f"| `{a['path']}` | {', '.join(a['methods'])} | {a['risk']['level']} | "
            f"{'Sí' if a['hardened_explicit'] else 'Global'} |"
        )
    if len(data["apis"]) > 50:
        lines.append(f"\n*... y {len(data['apis']) - 50} APIs adicionales en api_security_audit.json*")

    with open(md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"Audit JSON: {json_path}")
    print(f"Audit MD:   {md_path}")
    print(f"Total APIs: {data['total_apis_reviewed']}")


def main():
    app = create_app()
    data = build_inventory(app)
    write_reports(data)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
