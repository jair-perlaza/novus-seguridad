"""
Memoria operativa del Kernel IA — aprendizaje sin modificar código ni reglas de seguridad.

Registra preferencias, consultas frecuentes y patrones de uso por usuario.
"""
from __future__ import annotations

import json
import os
from collections import Counter
from datetime import datetime
from typing import Any, Dict, List, Optional

from utils.logger import logger

MEMORY_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "kernel_memory")
OPS_LOG = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "kernel_operations.jsonl")


def _user_key(user_id: Optional[int], user_email: Optional[str] = None) -> str:
    if user_id:
        return f"user_{user_id}"
    if user_email:
        return f"email_{user_email.replace('@', '_at_')}"
    return "anonymous"


def _load_profile(key: str) -> dict:
    os.makedirs(MEMORY_DIR, exist_ok=True)
    path = os.path.join(MEMORY_DIR, f"{key}.json")
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {
        "query_counts": {},
        "intent_counts": {},
        "engine_counts": {},
        "action_counts": {},
        "modules_used": {},
        "scan_profiles": {},
        "tech_level": "intermedio",
        "visualization": "detallado",
        "authorized_automations": [],
        "last_interaction": None,
        "total_interactions": 0,
    }


def _save_profile(key: str, profile: dict):
    os.makedirs(MEMORY_DIR, exist_ok=True)
    path = os.path.join(MEMORY_DIR, f"{key}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(profile, f, indent=2, ensure_ascii=False)


class KernelMemory:
    """Aprendizaje operativo — preferencias y historial de operaciones."""

    def get_preferences(self, user_id: Optional[int] = None, user_email: Optional[str] = None) -> dict:
        key = _user_key(user_id, user_email)
        profile = _load_profile(key)
        top_queries = sorted(profile.get("query_counts", {}).items(), key=lambda x: -x[1])[:5]
        top_intents = sorted(profile.get("intent_counts", {}).items(), key=lambda x: -x[1])[:5]
        top_engines = sorted(profile.get("engine_counts", {}).items(), key=lambda x: -x[1])[:8]
        return {
            "user_key": key,
            "tech_level": profile.get("tech_level", "intermedio"),
            "visualization": profile.get("visualization", "detallado"),
            "sector_key": profile.get("sector_key"),
            "sector_label": profile.get("sector_label"),
            "frequent_queries": [q for q, _ in top_queries],
            "frequent_intents": [i for i, _ in top_intents],
            "frequent_engines": [e for e, _ in top_engines],
            "frequent_scans": sorted(
                profile.get("scan_profiles", {}).items(), key=lambda x: -x[1]
            )[:3],
            "total_interactions": profile.get("total_interactions", 0),
        }

    def record_interaction(
        self,
        user_id: Optional[int],
        user_email: Optional[str],
        message: str,
        intent_id: str,
        engines: List[str],
        request_type: str,
        profile: Optional[str] = None,
    ):
        key = _user_key(user_id, user_email)
        profile_data = _load_profile(key)
        profile_data["total_interactions"] = profile_data.get("total_interactions", 0) + 1
        profile_data["last_interaction"] = datetime.now().isoformat()

        q_norm = message.strip().lower()[:80]
        profile_data.setdefault("query_counts", {})[q_norm] = profile_data["query_counts"].get(q_norm, 0) + 1
        profile_data.setdefault("intent_counts", {})[intent_id] = profile_data["intent_counts"].get(intent_id, 0) + 1
        for eng in engines:
            profile_data.setdefault("engine_counts", {})[eng] = profile_data["engine_counts"].get(eng, 0) + 1
        if profile:
            profile_data.setdefault("scan_profiles", {})[profile] = profile_data["scan_profiles"].get(profile, 0) + 1

        # Inferir nivel técnico por complejidad de consultas
        tech_signals = sum(1 for w in ["cve", "xdr", "siem", "arp", "rootkit", "exploit", "remediar"] if w in q_norm)
        if tech_signals >= 2:
            profile_data["tech_level"] = "avanzado"
        elif tech_signals == 0 and profile_data["total_interactions"] > 10:
            profile_data.setdefault("tech_level", "intermedio")

        _save_profile(key, profile_data)

    def log_operation(self, record: dict):
        """Registro persistente de operaciones del Kernel."""
        os.makedirs(os.path.dirname(OPS_LOG), exist_ok=True)
        record["timestamp"] = datetime.now().isoformat()
        try:
            with open(OPS_LOG, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
        except Exception as exc:
            logger.warning(f"Kernel operation log failed: {exc}")

    def personalization_hint(self, user_id: Optional[int], user_email: Optional[str] = None) -> Optional[str]:
        prefs = self.get_preferences(user_id, user_email)
        if not prefs.get("frequent_scans"):
            return None
        scan, count = prefs["frequent_scans"][0]
        if count >= 3:
            return f"Escaneo frecuente detectado: perfil «{scan}» ({count} veces)."
        return None


kernel_memory = KernelMemory()
