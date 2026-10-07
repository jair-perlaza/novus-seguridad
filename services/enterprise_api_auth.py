"""
Autenticación unificada para APIs enterprise (TIE, ASM, SOC, etc.).

Flask-Login usa `_user_id` en sesión; las APIs legacy comprobaban solo
`user_id` / `user_email` / `email`, provocando 401 → middleware `recovering`.
"""
from __future__ import annotations

from flask import session


def enterprise_api_authenticated() -> bool:
    try:
        from flask_login import current_user

        if current_user.is_authenticated:
            return True
    except Exception:
        pass
    # Flask-Login persiste el id en _user_id; APIs legacy usaban user_id/email.
    return bool(
        session.get("_user_id")
        or session.get("user_id")
        or session.get("user_email")
        or session.get("email")
    )


def enterprise_auth_required_response():
    from flask import jsonify

    return jsonify({"ok": False, "error": "auth_required", "status": "auth_required"}), 401
