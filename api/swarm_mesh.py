#!/usr/bin/env python3
"""
API Swarm Mesh Enterprise — identidad, trust, ingest, status.
Ingest es el endpoint peer (autenticación por firma Ed25519 del sobre, no sesión web).
"""
from __future__ import annotations

from flask import Blueprint, jsonify, request, session

swarm_mesh_api_bp = Blueprint("swarm_mesh_api", __name__, url_prefix="/api/swarm-mesh")


def _require_login() -> bool:
    from services.enterprise_api_auth import enterprise_api_authenticated
    return enterprise_api_authenticated()


def _actor() -> str:
    return session.get("user_email") or session.get("email") or "operator"


@swarm_mesh_api_bp.route("/identity", methods=["GET"])
def mesh_identity():
    """Público para discovery entre peers (solo PEM pública + fingerprint)."""
    from services.swarm_defense.mesh import node_identity

    info = node_identity.ensure_node_identity()
    return jsonify(
        {
            "ok": True,
            "node_id": info.get("node_id"),
            "fingerprint": info.get("fingerprint"),
            "algorithm": "Ed25519",
            "public_pem": node_identity.public_pem_for(),
        }
    )


@swarm_mesh_api_bp.route("/status", methods=["GET"])
def mesh_status_route():
    if not _require_login():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.swarm_defense.mesh import mesh_status

    return jsonify(mesh_status())


@swarm_mesh_api_bp.route("/trust", methods=["GET"])
def mesh_trust_list():
    if not _require_login():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.swarm_defense.mesh import trust_registry

    return jsonify(trust_registry.trust_status())


@swarm_mesh_api_bp.route("/trust", methods=["POST"])
def mesh_trust_add():
    if not _require_login():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    body = request.get_json(silent=True) or {}
    from services.swarm_defense.mesh import channel_keys, trust_registry

    peer_id = str(body.get("peer_id") or "").strip()
    public_pem = str(body.get("public_pem") or "").strip()
    base_url = str(body.get("base_url") or "").strip()
    channel_b64 = body.get("channel_key_b64")
    if base_url:
        from services.web_security_auth_enterprise.ssrf_guard import is_url_safe

        safe, reason = is_url_safe(base_url)
        if not safe:
            return jsonify({
                "ok": False,
                "error": "ssrf_blocked",
                "reason": reason,
                "message": "base_url apunta a destino no permitido",
            }), 400
    res = trust_registry.trust_peer(
        peer_id=peer_id,
        public_pem=public_pem,
        base_url=base_url,
        label=str(body.get("label") or peer_id),
        actor=_actor(),
    )
    if not res.get("ok"):
        return jsonify(res), 400
    if channel_b64:
        channel_keys.import_channel_key_b64(peer_id, str(channel_b64))
    else:
        channel_keys.get_or_create_channel_key(peer_id)
        res["channel_key_b64"] = channel_keys.export_channel_key_b64(peer_id)
        res["note"] = "Entregar channel_key_b64 al peer de forma segura (out-of-band) y POST /trust allí"
    return jsonify(res)


@swarm_mesh_api_bp.route("/trust/revoke", methods=["POST"])
def mesh_trust_revoke():
    if not _require_login():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    body = request.get_json(silent=True) or {}
    from services.swarm_defense.mesh import trust_registry

    peer_id = str(body.get("peer_id") or "").strip()
    if not peer_id:
        return jsonify({"ok": False, "error": "peer_id_required"}), 400
    return jsonify(
        trust_registry.revoke_peer(peer_id=peer_id, reason=str(body.get("reason") or ""), actor=_actor())
    )


@swarm_mesh_api_bp.route("/ingest", methods=["POST"])
def mesh_ingest():
    """
    Endpoint peer: valida firma/cifrado/trust/replay/poisoning.
    No requiere sesión web — la autenticación es criptográfica del sobre.
    """
    body = request.get_json(silent=True) or {}
    if not isinstance(body, dict) or not body.get("meta") or not body.get("ciphertext_b64"):
        return jsonify({"ok": False, "error": "envelope_required"}), 400
    from services.swarm_defense.mesh import ingest_envelope

    result = ingest_envelope(body)
    code = 200 if result.get("ok") else 403
    return jsonify(result), code


@swarm_mesh_api_bp.route("/intel", methods=["GET"])
def mesh_intel():
    if not _require_login():
        return jsonify({"ok": False, "error": "auth_required"}), 401
    from services.swarm_defense.mesh import intel_store

    return jsonify({"ok": True, "stats": intel_store.stats(), "recent_inbound": intel_store.recent("inbound", 20)})
