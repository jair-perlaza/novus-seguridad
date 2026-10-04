"""
API — NOVUS Threat Intelligence Center
"""
from flask import Blueprint, jsonify, request, send_file
from flask_login import login_required, current_user

from services.report_pdf_service import generate_case_pdf
from services.threat_intelligence_service import threat_intelligence
from utils.logger import logger

threat_intel_api_bp = Blueprint("threat_intel_api", __name__, url_prefix="/api/threat-intel")


@threat_intel_api_bp.route("/cases", methods=["GET"])
@login_required
def api_list_cases():
    try:
        limit = int(request.args.get("limit", 100))
        cases = threat_intelligence.list_cases(limit=limit)
        stats = threat_intelligence.stats()
        return jsonify({"status": "success", "cases": cases, "count": len(cases), "stats": stats})
    except Exception as exc:
        logger.error(f"TI list cases: {exc}", exc_info=True)
        return jsonify({"status": "error", "message": str(exc)}), 500


@threat_intel_api_bp.route("/cases/<case_id>", methods=["GET"])
@login_required
def api_get_case(case_id):
    case = threat_intelligence.get_case(case_id)
    if not case:
        return jsonify({"status": "error", "message": "Caso no encontrado"}), 404
    return jsonify({"status": "success", "case": case})


@threat_intel_api_bp.route("/search", methods=["GET"])
@login_required
def api_search_cases():
    try:
        filters = {
            "fecha": request.args.get("fecha"),
            "empresa": request.args.get("empresa"),
            "usuario": request.args.get("usuario"),
            "equipo": request.args.get("equipo"),
            "tipo": request.args.get("tipo"),
            "nivel": request.args.get("nivel"),
            "estado": request.args.get("estado"),
            "motor": request.args.get("motor"),
            "proceso": request.args.get("proceso"),
            "ip": request.args.get("ip"),
            "puerto": request.args.get("puerto"),
            "hash": request.args.get("hash"),
            "dominio": request.args.get("dominio"),
            "keyword": request.args.get("q") or request.args.get("keyword"),
        }
        filters = {k: v for k, v in filters.items() if v}
        cases = threat_intelligence.search_cases(filters)
        return jsonify({"status": "success", "cases": cases, "count": len(cases), "filters": filters})
    except Exception as exc:
        logger.error(f"TI search: {exc}", exc_info=True)
        return jsonify({"status": "error", "message": str(exc)}), 500


@threat_intel_api_bp.route("/sync", methods=["POST"])
@login_required
def api_sync_cases():
    try:
        result = threat_intelligence.sync_from_real_sources(
            user_email=getattr(current_user, "email", None),
            user_id=getattr(current_user, "id", None),
        )
        try:
            from services.performance_cache import invalidate
            invalidate()
        except Exception:
            pass
        return jsonify({"status": "success", **result})
    except Exception as exc:
        logger.error(f"TI sync: {exc}", exc_info=True)
        return jsonify({"status": "error", "message": str(exc)}), 500


@threat_intel_api_bp.route("/cases/<case_id>/pdf", methods=["GET"])
@login_required
def api_case_pdf(case_id):
    case = threat_intelligence.get_case(case_id)
    if not case:
        return jsonify({"status": "error", "message": "Caso no encontrado"}), 404
    try:
        path = generate_case_pdf(case)
        return send_file(path, as_attachment=True, download_name=f"{case_id}.pdf")
    except Exception as exc:
        logger.error(f"TI PDF: {exc}", exc_info=True)
        return jsonify({"status": "error", "message": str(exc)}), 500


@threat_intel_api_bp.route("/stats", methods=["GET"])
@login_required
def api_stats():
    return jsonify({"status": "success", "stats": threat_intelligence.stats()})


@threat_intel_api_bp.route("/dashboard", methods=["GET"])
@login_required
def api_operational_dashboard():
    try:
        dash = threat_intelligence.get_operational_dashboard(
            user_email=getattr(current_user, "email", None),
        )
        return jsonify(dash)
    except Exception as exc:
        logger.error(f"TI dashboard: {exc}", exc_info=True)
        return jsonify({"status": "error", "message": str(exc)}), 500


@threat_intel_api_bp.route("/timeline", methods=["GET"])
@login_required
def api_timeline():
    try:
        from services.intel_operational_service import collect_operational_data, build_global_timeline
        limit = min(int(request.args.get("limit", 60)), 200)
        data = collect_operational_data(getattr(current_user, "email", None))
        return jsonify({
            "status": "success",
            "timeline": build_global_timeline(data, limit=limit),
            "count": len(build_global_timeline(data, limit=limit)),
        })
    except Exception as exc:
        logger.error(f"TI timeline: {exc}", exc_info=True)
        return jsonify({"status": "error", "message": str(exc)}), 500


@threat_intel_api_bp.route("/recommendations", methods=["GET"])
@login_required
def api_recommendations():
    try:
        from services.intel_operational_service import collect_operational_data, build_recommendations
        data = collect_operational_data(getattr(current_user, "email", None))
        recs = build_recommendations(data, getattr(current_user, "email", None))
        return jsonify({"status": "success", "recommendations": recs, "count": len(recs)})
    except Exception as exc:
        logger.error(f"TI recommendations: {exc}", exc_info=True)
        return jsonify({"status": "error", "message": str(exc)}), 500


@threat_intel_api_bp.route("/clean", methods=["POST"])
@login_required
def api_clean_intel():
    try:
        result = threat_intelligence.clean_processed_state(
            user_email=getattr(current_user, "email", None),
            user_id=getattr(current_user, "id", None),
        )
        code = 200 if result.get("status") in ("success", "blocked") else 400
        try:
            from services.performance_cache import invalidate
            invalidate()
        except Exception:
            pass
        return jsonify(result), code
    except Exception as exc:
        logger.error(f"TI clean: {exc}", exc_info=True)
        return jsonify({"status": "error", "message": str(exc)}), 500


@threat_intel_api_bp.route("/adaptive-defense", methods=["GET"])
@login_required
def api_adaptive_defense():
    try:
        from services.adaptive_defense_engine import adaptive_defense
        panel = adaptive_defense.get_adaptive_defense_panel(
            user_email=getattr(current_user, "email", None),
        )
        return jsonify({"status": "success", "adaptive_defense": panel})
    except Exception as exc:
        logger.error(f"TI adaptive defense: {exc}", exc_info=True)
        return jsonify({"status": "error", "message": str(exc)}), 500


@threat_intel_api_bp.route("/sector-protection", methods=["GET"])
@login_required
def api_sector_protection_intel():
    try:
        from services.adaptive_sector_protection_engine import aspe
        panel = aspe.get_sector_protection_panel(
            user_email=getattr(current_user, "email", None),
        )
        return jsonify({"status": "success", "sector_protection": panel})
    except Exception as exc:
        logger.error(f"TI sector protection: {exc}", exc_info=True)
        return jsonify({"status": "error", "message": str(exc)}), 500
