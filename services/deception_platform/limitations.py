#!/usr/bin/env python3
"""Limitaciones DPE — Deception Platform Enterprise."""
LIMITATIONS = [
    "Espacio logico independiente: nunca reutiliza usuarios/credenciales/archivos/servidores reales.",
    "No inicia automaticamente servicios inseguros (SSH/FTP/SMB/RDP/etc.).",
    "Honeypots ACTIVO solo si hay listener verificado; si no, NO CONFIGURADO / CONFIGURADO.",
    "No genera eventos de ataque ni telemetria simulada.",
    "Integracion con IMCM/TIE/SOPE/SDL/UEBA/IAPA solo ante interaccion REAL con recurso senuelo.",
    "Kernel IA solo analiza; executes_actions=false.",
    "Swarm solo inteligencia anonimizada (sin PII ni credenciales).",
    "Sin evidencia de interaccion -> eventos vacios / NO DISPONIBLE.",
]
POLICY = {
    "auto_start_listeners": False,
    "reuse_real_assets": False,
    "simulate_attacks": False,
    "invent_events": False,
    "modify_engines": False,
    "kernel_executes": False,
    "swarm_pii": False,
    "mix_real_decoy": False,
}
NA = "NO DISPONIBLE"
NI = "NO IMPLEMENTADO"
NC = "NO CONFIGURADO"
CFG = "CONFIGURADO"
ACT = "ACTIVO"

HONEYPOT_PROTOCOLS = [
    "ssh", "ftp", "smb", "http", "https", "ldap", "sql", "smtp", "dns", "rdp",
]
DECOY_SERVER_TYPES = ["web", "dns", "ldap", "smtp", "sql", "ssh", "rdp"]
HONEYSHARE_TYPES = ["smb", "nas", "ftp", "webdav"]
HONEYFILE_TYPES = ["pdf", "docx", "xlsx", "txt", "csv", "backup", "database"]
HONEYTOKEN_TYPES = [
    "api_key", "jwt", "oauth_token", "cookie", "secret", "password", "usuario",
]
NAMESPACE = "dpe.decoy"
USERNAME_PREFIX = "dpe.honey."
