# WSAE — limitaciones

## MFA TOTP
IMPLEMENTADO (pyotp real + recovery codes + forense).

## OAuth/OIDC SSO
Framework de estado/credenciales. Proveedores NO afirmados sin CLIENT_ID/SECRET + prueba live.

## HSTS siempre
NO — solo condicional (proxy/NOVUS_FORCE_HSTS).

## JWT de negocio
NO — Flask-Login + refresh de sesión WSAE.
