"""
Puntuación de protección calculada — cada check es binario y verificable en runtime.
No se fijan porcentajes manualmente.
"""
from __future__ import annotations

from typing import Any, Callable, Dict, List, Tuple

Check = Tuple[str, Callable[[], bool], str]


def _checks() -> List[Check]:
    checks: List[Check] = []

    def add(name: str, fn: Callable[[], bool], evidence: str):
        checks.append((name, fn, evidence))

    add("cryptovault_aes_gcm", lambda: _cryptovault_ok(), "crypto_vault.py verify_health")
    add("auth_protection_config", lambda: _auth_cfg_ok(), "auth_protection_config.py")
    add("hostile_hardening_csrf", lambda: _hostile_flag("csrf_protection_enabled"), "hostile_hardening.json")
    add("hostile_ip_lists", lambda: _hostile_lists(), "hostile_hardening ip_whitelist/blacklist")
    add("http_abuse_guard", lambda: _import_ok("services.http_abuse_guard"), "http_abuse_guard.py")
    add("malware_behavior_engine", lambda: _import_ok("services.malware_behavior_engine"), "malware_behavior_engine.py")
    add("network_baseline_module", lambda: _import_ok("services.network_baseline_service"), "network_baseline_service.py")
    add("sensitive_ops_audit", lambda: _import_ok("services.sensitive_operations_audit"), "sensitive_operations_audit.py")
    add("defense_registry", lambda: _defense_registry_ok(), "defense_evidence_registry.py")
    add("web_shield_engine", lambda: _web_shield_ok(), "web_shield_engine.get_engine_status")
    add("rate_limit_db_layer", lambda: _db_security_ok(), "database.db_security.check_rate_limit")
    add("session_cookie_secure_config", lambda: _session_secure(), "core/config SESSION_COOKIE_SECURE")
    add("virustotal_optional", lambda: _vt_configured(), "VIRUSTOTAL_API_KEY env (opcional)")
    add("mail_oauth_connected", lambda: _mail_oauth(), "mail_shield_service (opcional)")
    add("ndr_baseline_file", lambda: _baseline_exists(), "data/network_baseline/lan_baseline.json")
    return checks


def _import_ok(module: str) -> bool:
    try:
        __import__(module)
        return True
    except Exception:
        return False


def _cryptovault_ok() -> bool:
    try:
        from crypto_vault import CryptoVault
        return CryptoVault().verify_health().get("aes_gcm_roundtrip") is True
    except Exception:
        return False


def _auth_cfg_ok() -> bool:
    try:
        from services.auth_protection_config import get_auth_protection_config
        c = get_auth_protection_config()
        return c.get("block_attempt", 0) >= 5
    except Exception:
        return False


def _hostile_flag(key: str) -> bool:
    try:
        from services.hostile_hardening_config import get_hostile_hardening_config
        return bool(get_hostile_hardening_config().get(key))
    except Exception:
        return False


def _hostile_lists() -> bool:
    try:
        from services.hostile_hardening_config import get_hostile_hardening_config
        c = get_hostile_hardening_config()
        return isinstance(c.get("ip_blacklist"), list) and isinstance(c.get("ip_whitelist"), list)
    except Exception:
        return False


def _defense_registry_ok() -> bool:
    try:
        from services.defense_evidence_registry import get_registry_summary
        s = get_registry_summary()
        return isinstance(s, dict)
    except Exception:
        return False


def _web_shield_ok() -> bool:
    try:
        from services.web_shield_engine import get_engine_status
        st = get_engine_status()
        return st.get("engine") == "novus_web_shield"
    except Exception:
        return False


def _session_secure() -> bool:
    try:
        from core.config import get_config
        return bool(get_config().SESSION_COOKIE_SECURE or get_config().BEHIND_PROXY)
    except Exception:
        return False


def _vt_configured() -> bool:
    import os
    return bool(os.environ.get("VIRUSTOTAL_API_KEY", "").strip())


def _mail_oauth() -> bool:
    try:
        from services.mail_shield_service import get_integration_status
        return bool(get_integration_status(None).get("any_connected"))
    except Exception:
        return False


def _baseline_exists() -> bool:
    import os
    p = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "network_baseline", "lan_baseline.json")
    return os.path.isfile(p)


def _db_security_ok() -> bool:
    try:
        from database import db_security
        r = db_security.check_rate_limit("__health__", max_requests=9999, window_seconds=60)
        return isinstance(r, dict)
    except Exception:
        return False


def compute_protection_score() -> Dict[str, Any]:
    results = []
    passed = 0
    optional_pass = 0
    optional_total = 0
    for name, fn, evidence in _checks():
        optional = name in ("virustotal_optional", "mail_oauth_connected", "ndr_baseline_file")
        try:
            ok = bool(fn())
        except Exception:
            ok = False
        if optional:
            optional_total += 1
            if ok:
                optional_pass += 1
        else:
            if ok:
                passed += 1
        results.append({"check": name, "passed": ok, "evidence": evidence, "optional": optional})
    core_total = sum(1 for r in results if not r["optional"])
    core_pct = round(100.0 * passed / core_total, 2) if core_total else 0.0
    all_total = len(results)
    all_pass = passed + optional_pass
    overall_pct = round(100.0 * all_pass / all_total, 2) if all_total else 0.0
    return {
        "core_protection_percent": core_pct,
        "overall_protection_percent": overall_pct,
        "core_passed": passed,
        "core_total": core_total,
        "checks": results,
        "method": "binary_verifiable_checks",
        "ddos_volumetric_mitigation": False,
        "note": "overall incluye checks opcionales (VT, OAuth correo, baseline LAN)",
    }
