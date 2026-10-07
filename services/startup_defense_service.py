"""
Inicialización de motores de defensa al arranque de NOVUS.
Activa detección, standby sectorial, verificación de cifrado y registro de evidencia.
"""
from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Any, Dict

from utils.logger import logger

BOOT_REPORT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "data", "defense_boot_report.json"
)

ALL_SECTORS = ("fintech", "logistica", "aplicaciones_moviles", "otros")


def _verify_cryptovault() -> Dict[str, Any]:
    result: Dict[str, Any] = {"motor": "cryptovault", "status": "unknown"}
    try:
        from crypto_vault import CryptoVault

        vault = CryptoVault()
        sample = "NOVUS-encryption-health-check"
        token = vault.proteger(sample)
        recovered = vault.desproteger(token)
        roundtrip_ok = recovered == sample
        health = vault.verify_health()
        result.update({
            "status": "success" if roundtrip_ok else "failed",
            "aes_gcm_roundtrip": roundtrip_ok,
            "aes_key_wrapped": health.get("aes_key_wrapped"),
            "aes_plaintext_retired": health.get("aes_plaintext_retired"),
            "ecc_private_wrapped": health.get("ecc_private_wrapped"),
            "active_kid": health.get("active_kid"),
            "key_versions": health.get("key_versions"),
            "legacy_ciphertext_roundtrip": health.get("legacy_ciphertext_roundtrip"),
            "key_wrap": health.get("key_wrap"),
            "tls_status": health.get("tls_status"),
        })
        from services.defense_coordinator import defense_coordinator

        defense_coordinator.record_detection(
            "cryptovault",
            "encryption_health_check",
            result,
            phase="audit",
            outcome="success" if roundtrip_ok else "failed",
            threat_type="encryption",
            detail="Verificación AES-256-GCM + key wrap al arranque",
            confidence="Alta" if roundtrip_ok else "Baja",
        )
    except Exception as exc:
        result.update({"status": "failed", "error": str(exc)})
    return result


def _verify_data_integrity() -> Dict[str, Any]:
    try:
        from services.data_integrity_service import verify_critical_artifacts

        out = verify_critical_artifacts()
        out["status"] = "success" if out.get("ok") else "failed"
        return out
    except Exception as exc:
        return {"status": "failed", "error": str(exc)}


def _bootstrap_sector_baselines() -> Dict[str, Any]:
    """Configura módulos activos/standby por sector sin desactivar ningún motor."""
    try:
        from services.adaptive_sector_protection_engine import (
            PROTECTION_MODULES,
            SECTOR_PRIORITY,
            bootstrap_sector_baselines,
        )

        return bootstrap_sector_baselines()
    except Exception as exc:
        logger.debug("sector bootstrap: %s", exc)
        return {"status": "failed", "error": str(exc)}


def _run_uce_detection() -> Dict[str, Any]:
    try:
        from services.universal_compatibility_engine import uce

        infra = uce.detect_infrastructure(user_email=None, persist=True)
        from services.defense_coordinator import defense_coordinator

        defense_coordinator.record_detection(
            "universal_compatibility_engine",
            "infra_detect_boot",
            {
                "technologies_count": infra.get("technologies_count", 0),
                "compatible_modules": (infra.get("compatible_modules") or [])[:12],
                "sector_key": infra.get("sector_key"),
            },
            phase="audit",
            outcome="success",
            detail=f"UCE: {infra.get('technologies_count', 0)} tecnologías detectadas",
            confidence="Alta" if infra.get("technologies_count", 0) >= 1 else "Media",
        )
        return {"status": "success", **infra}
    except Exception as exc:
        return {"status": "failed", "error": str(exc)}


def _maybe_aes_key_rotation() -> Dict[str, Any]:
    """Rotación AES solo si hostile_hardening aes_key_max_age_days > 0."""
    try:
        from services.hostile_hardening_config import get_hostile_hardening_config
        from services.cryptovault_key_rotation import maybe_rotate_on_schedule

        days = int(get_hostile_hardening_config().get("aes_key_max_age_days") or 0)
        return maybe_rotate_on_schedule(max_age_days=days)
    except Exception as exc:
        return {"status": "failed", "error": str(exc)}


def _verify_defense_registry() -> Dict[str, Any]:
    try:
        from services.defense_evidence_registry import get_registry_summary

        summary = get_registry_summary()
        return {"status": "success", "summary": summary}
    except Exception as exc:
        return {"status": "failed", "error": str(exc)}


def initialize_defense_stack() -> Dict[str, Any]:
    """Ejecutar una vez al arranque — no bloquea el servidor."""
    report: Dict[str, Any] = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "sectors": list(ALL_SECTORS),
        "components": {},
    }

    report["components"]["cryptovault"] = _verify_cryptovault()
    report["components"]["aes_key_rotation"] = _maybe_aes_key_rotation()
    report["components"]["data_integrity"] = _verify_data_integrity()
    report["components"]["uce"] = _run_uce_detection()
    report["components"]["sector_baselines"] = _bootstrap_sector_baselines()
    report["components"]["defense_registry"] = _verify_defense_registry()

    motors_ok = sum(
        1 for c in report["components"].values()
        if isinstance(c, dict) and c.get("status") in ("success", "ok")
    )
    report["motors_verified"] = motors_ok
    report["status"] = "ready" if motors_ok >= 3 else "degraded"

    try:
        os.makedirs(os.path.dirname(BOOT_REPORT_PATH), exist_ok=True)
        with open(BOOT_REPORT_PATH, "w", encoding="utf-8") as fh:
            json.dump(report, fh, ensure_ascii=False, indent=2)
    except Exception as exc:
        logger.debug("boot report write: %s", exc)

    try:
        from services.defense_coordinator import defense_coordinator

        defense_coordinator.notify_kernel_incident(
            "startup_defense_service",
            "DEFENSE_STACK_BOOT",
            f"Motores verificados al arranque: {motors_ok}/4 componentes — estado {report['status']}",
            severity="info",
            evidence={"components": list(report["components"].keys())},
        )
    except Exception:
        pass

    cv = report["components"].get("cryptovault", {}).get("status")
    uce_st = report["components"].get("uce", {}).get("status")
    sec_st = report["components"].get("sector_baselines", {}).get("status")
    reg_st = report["components"].get("defense_registry", {}).get("status")
    logger.info(
        f"Defense stack boot: cryptovault={cv} uce={uce_st} sectors={sec_st} registry={reg_st}"
    )
    return report
