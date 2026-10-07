"""Orquestación de defensa de dispositivos — delega a AIE/NDR; no ejecuta firewall directo."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from utils.logger import logger

_ATTACK_THRESHOLD_RECOMMEND = 3
_controller: Optional["NOVUSDefenseController"] = None


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_json(raw, default=None):
    if default is None:
        default = {}
    if not raw:
        return default
    try:
        return json.loads(raw)
    except Exception:
        return default


class NOVUSDefenseController:
    """
    Facade sobre inventario AIE, historial device_connection_monitor y acciones admin.
    No ejecuta iptables/netsh; aislamiento = estado inventario + recomendación.
    """

    def on_radar_device_found(
        self,
        ip: str,
        mac: str,
        hostname: str = "",
        ttl: Optional[int] = None,
        vendor: str = "",
    ) -> Dict[str, Any]:
        """Invocado cuando el radar ARP/NDR detecta un equipo."""
        from services.network_device_defense.device_classifier import (
            classify_device_from_node,
            classification_evidence,
        )

        node = {
            "ip": ip,
            "mac": mac,
            "name": hostname,
            "hostname": hostname,
            "vendor": vendor,
            "ttl": ttl,
        }
        dtype = classify_device_from_node(node)
        node["device_type"] = dtype

        try:
            from services.asset_intelligence_engine import sync_asset_from_node
            sync_asset_from_node(node)
        except Exception as exc:
            logger.debug("defense_controller sync_asset: %s", exc)

        device = self._load_device(mac)
        evidence = classification_evidence(node)
        return {
            "mac": (mac or "").upper(),
            "ip": ip,
            "hostname": hostname or device.get("hostname") or "NO DISPONIBLE",
            "vendor": vendor or device.get("vendor") or "NO DISPONIBLE",
            "device_type": dtype,
            "status": device.get("status") or "CONNECTED",
            "connection_count": device.get("connection_count") or device.get("times_seen") or 0,
            "attack_count": device.get("attack_count") or 0,
            "is_isolated": device.get("is_isolated") or False,
            "first_seen": device.get("first_seen") or "NO DISPONIBLE",
            "last_seen": device.get("last_seen") or _utc_now(),
            "executes_actions": False,
            "evidence": evidence,
            "verified": bool(mac and ip),
            "invented": False,
        }

    def on_radar_device_lost(self, mac: str) -> Dict[str, Any]:
        """Marca desconexión — el historial persistente lo gestiona device_connection_monitor."""
        device = self._load_device(mac)
        return {
            "mac": (mac or "").upper(),
            "status": "DISCONNECTED",
            "previous_ip": device.get("ip") or "NO DISPONIBLE",
            "executes_actions": False,
            "note": "Historial persistente vía device_connection_monitor.process_scan_presence",
            "verified": bool(mac),
            "invented": False,
        }

    def register_attack(
        self,
        mac: str,
        attack_details: str,
        *,
        auto_isolate: bool = False,
    ) -> Dict[str, Any]:
        """
        Registra señal de ataque asociada a MAC en learning_json AIE.
        auto_isolate se ignora para ejecución directa — solo recomienda aislamiento.
        """
        mac_key = (mac or "").lower()
        if not mac_key:
            return {"status": "error", "message": "MAC requerida", "executes_actions": False}

        total = self._increment_attack_count(mac_key, attack_details)
        recommend = total >= _ATTACK_THRESHOLD_RECOMMEND or auto_isolate
        result: Dict[str, Any] = {
            "status": "recorded",
            "mac": mac_key.upper(),
            "attack_count": total,
            "attack_details": attack_details,
            "recommend_isolation": recommend,
            "executes_actions": False,
            "verified": True,
            "invented": False,
        }
        if recommend:
            result["recommendation"] = "RECOMMEND_ISOLATE"
            if total >= _ATTACK_THRESHOLD_RECOMMEND:
                result["reason"] = (
                    f"Umbral de señales alcanzado ({total}>={_ATTACK_THRESHOLD_RECOMMEND}) — "
                    "requiere acción administrativa o aprobación Swarm"
                )
            else:
                result["reason"] = (
                    "Señal registrada con solicitud de aislamiento — "
                    "requiere acción administrativa o aprobación Swarm"
                )

        try:
            from services.ai_kernel_event_engine.event_engine import analyze_security_event

            device = self._load_device(mac_key) or {}
            result["kernel_analysis"] = analyze_security_event(
                "DEVICE_ATTACK_ACCUMULATION",
                {
                    "mac": mac_key,
                    "ip": device.get("ip"),
                    "device_type": device.get("device_type"),
                    "attack_count": total,
                    "details": attack_details,
                },
            )
        except Exception as exc:
            logger.debug("kernel_analysis register_attack: %s", exc)

        return result

    def isolate_device(
        self,
        mac: str,
        *,
        admin_request: bool = False,
        user_email: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Aislamiento de inventario vía AIE cuando admin_request=True.
        Sin admin_request solo devuelve recomendación (no bloquea red).
        """
        mac_key = (mac or "").lower()
        device = self._load_device(mac_key)
        if not device:
            return {
                "status": "ERROR",
                "message": "Dispositivo no encontrado en inventario AIE",
                "executes_actions": False,
                "executes_network_block": False,
                "verified": False,
                "invented": False,
            }

        if not admin_request:
            return {
                "status": "RECOMMENDATION",
                "message": (
                    f"Se recomienda marcar {mac_key.upper()} como aislado en inventario AIE. "
                    "Use POST /api/network/assets/<mac>/action con action=isolate."
                ),
                "device": device,
                "recommendation": "RECOMMEND_ISOLATE",
                "executes_actions": False,
                "executes_network_block": False,
                "verified": True,
                "invented": False,
            }

        from services.asset_intelligence_engine import apply_admin_action

        action_result = apply_admin_action(
            mac_key,
            "isolate",
            user_email=user_email,
            notes=notes or "Aislamiento solicitado vía NOVUSDefenseController",
        )
        success = action_result.get("status") == "success"
        updated = self._load_device(mac_key) or device
        return {
            "status": "SUCCESS" if success else "ERROR",
            "message": action_result.get("message") or (
                f"Equipo {mac_key.upper()} marcado aislado en inventario AIE."
                if success else "No se pudo aplicar acción administrativa"
            ),
            "device": updated,
            "aie_result": action_result,
            "executes_actions": success,
            "executes_network_block": False,
            "verified": success,
            "invented": False,
        }

    def release_device(
        self,
        mac: str,
        *,
        admin_request: bool = False,
        user_email: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Restaura estado en inventario — approve corporativo, sin reglas OS."""
        mac_key = (mac or "").lower()
        device = self._load_device(mac_key)
        if not device:
            return {
                "status": "ERROR",
                "message": "Dispositivo no encontrado",
                "executes_actions": False,
                "executes_network_block": False,
            }

        if not admin_request:
            return {
                "status": "RECOMMENDATION",
                "message": "Use acción administrativa approve/corporate para restaurar acceso en inventario.",
                "device": device,
                "executes_actions": False,
                "executes_network_block": False,
            }

        from services.asset_intelligence_engine import apply_admin_action

        action_result = apply_admin_action(
            mac_key,
            "approve",
            user_email=user_email,
            notes="Restauración solicitada vía NOVUSDefenseController",
        )
        success = action_result.get("status") == "success"
        updated = self._load_device(mac_key) or device
        return {
            "status": "SUCCESS" if success else "ERROR",
            "message": action_result.get("message"),
            "device": updated,
            "aie_result": action_result,
            "executes_actions": success,
            "executes_network_block": False,
        }

    def _load_device(self, mac: str) -> Optional[Dict[str, Any]]:
        mac_key = (mac or "").lower()
        if not mac_key:
            return None
        try:
            from database import SessionLocal, NetworkDeviceInventory

            db = SessionLocal()
            try:
                record = db.query(NetworkDeviceInventory).filter(
                    NetworkDeviceInventory.mac == mac_key
                ).first()
                if not record:
                    return None
                learning = _parse_json(record.learning_json, {})
                attack_count = int(learning.get("attack_count") or 0)
                status = "ISOLATED" if (record.asset_status or "") == "aislado" else "CONNECTED"
                return {
                    "mac": (record.mac or mac_key).upper(),
                    "ip": record.ip,
                    "hostname": record.hostname,
                    "vendor": record.vendor,
                    "device_type": record.device_type,
                    "status": status,
                    "first_seen": record.first_seen,
                    "last_seen": record.last_seen,
                    "connection_count": record.times_seen or 0,
                    "attack_count": attack_count,
                    "is_isolated": status == "ISOLATED",
                    "asset_status": record.asset_status,
                    "trust_score": record.trust_score,
                }
            finally:
                db.close()
        except Exception as exc:
            logger.debug("defense_controller _load_device: %s", exc)
            return None

    def _increment_attack_count(self, mac: str, attack_details: str) -> int:
        try:
            from database import SessionLocal, NetworkDeviceInventory

            db = SessionLocal()
            try:
                record = db.query(NetworkDeviceInventory).filter(
                    NetworkDeviceInventory.mac == mac
                ).first()
                if not record:
                    return 0
                learning = _parse_json(record.learning_json, {})
                attacks = learning.setdefault("attack_events", [])
                attacks.append({"at": _utc_now(), "detail": attack_details[:500]})
                attacks = attacks[-50:]
                learning["attack_events"] = attacks
                learning["attack_count"] = int(learning.get("attack_count") or 0) + 1
                record.learning_json = json.dumps(learning, ensure_ascii=False)
                db.commit()
                return int(learning["attack_count"])
            except Exception as exc:
                db.rollback()
                logger.debug("increment_attack_count: %s", exc)
                return 0
            finally:
                db.close()
        except Exception:
            return 0


def get_defense_controller() -> NOVUSDefenseController:
    global _controller
    if _controller is None:
        _controller = NOVUSDefenseController()
    return _controller
