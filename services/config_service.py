"""
Central security configuration for NOVUS.
Loads/saves security_config.json and exposes scan intensity settings.
"""
import json
import os
from typing import Any, Dict

CONFIG_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config")
CONFIG_FILE = os.path.join(CONFIG_DIR, "security_config.json")

DEFAULT_CONFIG: Dict[str, Any] = {
    "pentest_mode": "estandar",
    "whatsapp_alerts": True,
    "email_reports": False,
    "sector_activo": None,
    "auto_remediation": False,
}

PENTEST_LIMITS = {
    "pasivo": {"process_limit": 5, "port_limit": 5, "port_range": (1, 100), "run_pkg_scan": False},
    "estandar": {"process_limit": 10, "port_limit": 10, "port_range": (1, 1000), "run_pkg_scan": True},
    "agresivo": {"process_limit": 20, "port_limit": 20, "port_range": (1, 5000), "run_pkg_scan": True},
}

PENTEST_LABELS = {
    "pasivo": "Pasivo — escaneo mínimo (5 proc / 5 puertos)",
    "estandar": "Estándar — balance recomendado (10 proc / 10 puertos)",
    "agresivo": "Agresivo — escaneo profundo (20 proc / 5000 puertos)",
}


def load_config() -> Dict[str, Any]:
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            merged = {**DEFAULT_CONFIG, **data}
            return merged
        except Exception:
            pass
    return dict(DEFAULT_CONFIG)


def save_config(data: Dict[str, Any]) -> Dict[str, Any]:
    """Persiste cambios fusionando con claves existentes (perfiles sector, shield, etc.)."""
    os.makedirs(CONFIG_DIR, exist_ok=True)
    current: Dict[str, Any] = {}
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as handle:
                current = json.load(handle)
        except Exception:
            current = {}

    updates = {
        "pentest_mode": data.get("pentest_mode", current.get("pentest_mode", DEFAULT_CONFIG["pentest_mode"])),
        "whatsapp_alerts": bool(data.get("whatsapp_alerts", current.get("whatsapp_alerts", DEFAULT_CONFIG["whatsapp_alerts"]))),
        "email_reports": bool(data.get("email_reports", current.get("email_reports", DEFAULT_CONFIG["email_reports"]))),
        "sector_activo": data.get("sector_activo", current.get("sector_activo")),
    }
    if "auto_remediation" in data:
        updates["auto_remediation"] = bool(data.get("auto_remediation"))

    current.update(updates)
    with open(CONFIG_FILE, "w", encoding="utf-8") as handle:
        json.dump(current, handle, indent=2, ensure_ascii=False)
    return {**DEFAULT_CONFIG, **current}


def get_pentest_mode() -> str:
    mode = (load_config().get("pentest_mode") or "estandar").lower()
    return mode if mode in PENTEST_LIMITS else "estandar"


def get_pentest_limits() -> Dict[str, Any]:
    return dict(PENTEST_LIMITS[get_pentest_mode()])


def whatsapp_alerts_enabled() -> bool:
    return bool(load_config().get("whatsapp_alerts", True))


def email_reports_enabled() -> bool:
    return bool(load_config().get("email_reports", False))


def auto_remediation_enabled() -> bool:
    return bool(load_config().get("auto_remediation", False))


def get_config_effects() -> Dict[str, str]:
    cfg = load_config()
    return {
        "pentest_mode": "Aplicado inmediatamente en el próximo escaneo de vulnerabilidades.",
        "sector_activo": "Aplicado inmediatamente al escudo sectorial y perfil del Kernel IA.",
        "whatsapp_alerts": (
            "Activo — alertas críticas se enrutan al canal WhatsApp (cola + eventos + log)."
            if cfg.get("whatsapp_alerts") else
            "Inactivo — no se encolan alertas WhatsApp."
        ),
        "email_reports": (
            "Activo — al sincronizar reportes se genera informe diario automático."
            if cfg.get("email_reports") else
            "Inactivo — no se generan reportes diarios automáticos."
        ),
    }


def get_config_summary_for_kernel() -> str:
    cfg = load_config()
    limits = get_pentest_limits()
    return (
        f"Configuración activa NOVUS:\n"
        f"• Sector: {cfg.get('sector_activo') or 'Sin sector'}\n"
        f"• Pentest: {cfg.get('pentest_mode')} — {PENTEST_LABELS.get(cfg.get('pentest_mode', 'estandar'), '')}\n"
        f"• Límites escaneo: {limits.get('process_limit')} procesos, {limits.get('port_limit')} puertos\n"
        f"• WhatsApp gerencia: {'Activado' if cfg.get('whatsapp_alerts') else 'Desactivado'}\n"
        f"• Reporte email diario: {'Activado' if cfg.get('email_reports') else 'Desactivado'}\n"
        f"• Remediación automática Kernel: {'Activada' if cfg.get('auto_remediation') else 'Desactivada'}"
    )


def answer_kernel_query(question: str) -> str | None:
    q = (question or "").lower()
    triggers = (
        "configuración", "configuracion", "config ", "pentest", "sector activo",
        "whatsapp", "email report", "intensidad", "qué modo", "que modo",
    )
    if not any(k in q for k in triggers):
        return None
    summary = get_config_summary_for_kernel()
    effects = get_config_effects()
    if "whatsapp" in q:
        return f"WhatsApp alertas: {effects['whatsapp_alerts']}"
    if "email" in q or "reporte diario" in q:
        return f"Reporte email: {effects['email_reports']}"
    if "pentest" in q or "intensidad" in q:
        cfg = load_config()
        lim = get_pentest_limits()
        return (
            f"Modo pentest: {cfg.get('pentest_mode')}. "
            f"Límites: {lim.get('process_limit')} procesos, {lim.get('port_limit')} puertos. "
            f"{effects['pentest_mode']}"
        )
    return summary
