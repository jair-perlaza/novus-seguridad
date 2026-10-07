#!/usr/bin/env python3
"""
Script de migración para actualizar la base de datos NOVUS
Agrega columnas faltantes a tablas existentes
"""

import sqlite3
import os

def migrate_database():
    """Ejecuta migraciones necesarias en la base de datos"""
    db_path = "./novus_vault_v2.db"
    
    if not os.path.exists(db_path):
        print("Base de datos no encontrada, se creará nueva.")
        return
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Verificar si la tabla alertas existe
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='alertas'")
        alertas_exists = cursor.fetchone()
        
        if alertas_exists:
            # Verificar columnas existentes en alertas
            cursor.execute("PRAGMA table_info(alertas)")
            columns = [row[1] for row in cursor.fetchall()]
            
            # Agregar columnas faltantes si no existen
            if 'ip_afectada' not in columns:
                cursor.execute("ALTER TABLE alertas ADD COLUMN ip_afectada TEXT")
                print("Columna ip_afectada agregada a alertas")
            
            if 'recomendacion' not in columns:
                cursor.execute("ALTER TABLE alertas ADD COLUMN recomendacion TEXT")
                print("Columna recomendacion agregada a alertas")

            alerta_extra = {
                'motor': 'TEXT',
                'fuente': 'TEXT',
                'confianza': 'TEXT',
                'estado': "TEXT DEFAULT 'activo'",
                'estado_remediacion': 'TEXT',
                'evidencia_json': 'TEXT',
                'acciones_json': 'TEXT',
                'activa': 'INTEGER DEFAULT 1',
            }
            for col, col_type in alerta_extra.items():
                if col not in columns:
                    cursor.execute(f"ALTER TABLE alertas ADD COLUMN {col} {col_type}")
                    print(f"Columna {col} agregada a alertas")

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='network_device_inventory'")
        inv_exists = cursor.fetchone()
        if inv_exists:
            cursor.execute("PRAGMA table_info(network_device_inventory)")
            inv_cols = [row[1] for row in cursor.fetchall()]
            inv_extra = {
                'os_estimate': 'TEXT',
                'services_json': 'TEXT',
                'network_segment': 'TEXT',
                'asset_status': "TEXT DEFAULT 'pendiente_aprobacion'",
                'trust_score': 'INTEGER DEFAULT 45',
                'learning_json': 'TEXT',
                'classification_reason': 'TEXT',
                'admin_action': 'TEXT',
                'admin_action_by': 'TEXT',
                'admin_action_at': 'TEXT',
                'admin_tag': 'TEXT',
                'admin_notes': 'TEXT',
            }
            for col, col_type in inv_extra.items():
                if col not in inv_cols:
                    cursor.execute(f"ALTER TABLE network_device_inventory ADD COLUMN {col} {col_type}")
                    print(f"Columna {col} agregada a network_device_inventory")
        
        # Verificar tabla vulnerabilidades
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='vulnerabilidades'")
        vulns_exists = cursor.fetchone()
        
        if vulns_exists:
            # Verificar columnas existentes en vulnerabilidades
            cursor.execute("PRAGMA table_info(vulnerabilidades)")
            columns = [row[1] for row in cursor.fetchall()]
            
            # Agregar columnas faltantes
            if 'titulo' not in columns and 'nombre' in columns:
                # Renombrar nombre a titulo si existe
                cursor.execute("ALTER TABLE vulnerabilidades RENAME COLUMN nombre TO titulo")
                print("Columna nombre renombrada a titulo en vulnerabilidades")
            
            if 'descripcion' not in columns:
                cursor.execute("ALTER TABLE vulnerabilidades ADD COLUMN descripcion TEXT")
                print("Columna descripcion agregada a vulnerabilidades")
            
            if 'nivel' not in columns:
                cursor.execute("ALTER TABLE vulnerabilidades ADD COLUMN nivel TEXT DEFAULT 'medium'")
                print("Columna nivel agregada a vulnerabilidades")
            
            if 'componente' not in columns:
                cursor.execute("ALTER TABLE vulnerabilidades ADD COLUMN componente TEXT")
                print("Columna componente agregada a vulnerabilidades")

        _migrate_ips_bloqueadas(cursor)
        _ensure_device_connection_events(cursor)
        _ensure_platform_evidences(cursor)
        _migrate_usuario_roles(cursor)
        _ensure_tenant_monitoring_scope(cursor)
        _migrate_tenant_id_columns(cursor)
        _migrate_login_session_tenant_id(cursor)
        _ensure_registration_requests(cursor)
        
        conn.commit()
        conn.close()
        
        print("Migración completada exitosamente")
        
        try:
            from services.tenant_scope_service import (
                ensure_tenant_monitoring_seeded,
                backfill_tenant_ids_on_legacy_rows,
            )
            seed_stats = ensure_tenant_monitoring_seeded()
            backfilled = backfill_tenant_ids_on_legacy_rows()
            print(f"Tenant scope seed: {seed_stats}, backfill rows: {backfilled}")
        except Exception as seed_exc:
            print(f"Tenant seed post-migrate: {seed_exc}")
        
    except Exception as e:
        print(f"Error en migración: {e}")

def _migrate_ips_bloqueadas(cursor):
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='ips_bloqueadas'")
    if not cursor.fetchone():
        return
    cursor.execute("PRAGMA table_info(ips_bloqueadas)")
    cols = [row[1] for row in cursor.fetchall()]
    extra = {
        'blocked_at': 'TEXT',
        'blocked_until': 'TEXT',
        'failed_attempts': 'INTEGER DEFAULT 0',
        'target_email': 'TEXT',
        'user_agent': 'TEXT',
        'os_name': 'TEXT',
        'block_reason': 'TEXT',
        'evidence_json': 'TEXT',
        'recurrence_count': 'INTEGER DEFAULT 0',
        'requires_admin_review': 'INTEGER DEFAULT 0',
        'status': "TEXT DEFAULT 'active'",
    }
    for col, col_type in extra.items():
        if col not in cols:
            cursor.execute(f"ALTER TABLE ips_bloqueadas ADD COLUMN {col} {col_type}")
            print(f"Columna {col} agregada a ips_bloqueadas")


def _ensure_device_connection_events(cursor):
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='device_connection_events'")
    if cursor.fetchone():
        return
    cursor.execute("""
        CREATE TABLE device_connection_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT,
            timestamp TEXT,
            ip_address TEXT,
            mac_address TEXT,
            hostname TEXT,
            vendor TEXT,
            device_type TEXT,
            asset_status TEXT,
            trust_score INTEGER,
            risk_level TEXT,
            duration_seconds INTEGER,
            evidence_json TEXT
        )
    """)
    print("Tabla device_connection_events creada")


def _ensure_platform_evidences(cursor):
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='platform_evidences'")
    if cursor.fetchone():
        return
    cursor.execute("""
        CREATE TABLE platform_evidences (
            id TEXT PRIMARY KEY,
            fecha TEXT,
            hora TEXT,
            timestamp TEXT,
            motor TEXT,
            categoria TEXT,
            descripcion TEXT,
            nivel_riesgo TEXT,
            nivel_confianza TEXT,
            estado TEXT DEFAULT 'registrado',
            accion_ejecutada TEXT,
            resultado TEXT,
            source_event_id TEXT,
            evidence_json TEXT,
            created_at TEXT
        )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_platform_evidences_motor ON platform_evidences(motor)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_platform_evidences_categoria ON platform_evidences(categoria)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_platform_evidences_timestamp ON platform_evidences(timestamp)")
    print("Tabla platform_evidences creada")


def _migrate_usuario_roles(cursor):
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='usuarios'")
    if not cursor.fetchone():
        return
    cursor.execute("PRAGMA table_info(usuarios)")
    cols = [row[1] for row in cursor.fetchall()]
    if "role" not in cols:
        cursor.execute("ALTER TABLE usuarios ADD COLUMN role TEXT DEFAULT 'analyst'")
        print("Columna role agregada a usuarios")
    cursor.execute(
        "UPDATE usuarios SET role = 'super_admin' WHERE email = 'novus.qa.jul2026@example.com'"
    )
    for email in (
        "operaciones@novapay-fintech.co",
        "operaciones@translogistica-novus.co",
        "operaciones@appmovil-novus.co",
        "operaciones@corp-otros-novus.co",
    ):
        cursor.execute(
            "UPDATE usuarios SET role = 'client' WHERE email = ? AND (role IS NULL OR role = 'analyst')",
            (email,),
        )
    print("Roles RBAC aplicados en usuarios")


def _ensure_tenant_monitoring_scope(cursor):
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='tenant_monitoring_scope'"
    )
    if cursor.fetchone():
        return
    cursor.execute("""
        CREATE TABLE tenant_monitoring_scope (
            tenant_id TEXT PRIMARY KEY,
            monitoring_enabled INTEGER DEFAULT 0,
            node_id TEXT,
            monitoring_mode TEXT DEFAULT 'none',
            configured_at TEXT,
            updated_at TEXT
        )
    """)
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_tenant_monitoring_enabled "
        "ON tenant_monitoring_scope(monitoring_enabled)"
    )
    print("Tabla tenant_monitoring_scope creada")


def _migrate_tenant_id_columns(cursor):
    tenant_tables = (
        "alertas",
        "vulnerabilidades",
        "network_device_inventory",
        "platform_evidences",
        "device_connection_events",
    )
    for table in tenant_tables:
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
            (table,),
        )
        if not cursor.fetchone():
            continue
        cursor.execute(f"PRAGMA table_info({table})")
        cols = [row[1] for row in cursor.fetchall()]
        if "tenant_id" not in cols:
            cursor.execute(f"ALTER TABLE {table} ADD COLUMN tenant_id TEXT")
            cursor.execute(
                f"CREATE INDEX IF NOT EXISTS idx_{table}_tenant_id ON {table}(tenant_id)"
            )
            print(f"Columna tenant_id agregada a {table}")


def _migrate_login_session_tenant_id(cursor):
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='login_session_audits'"
    )
    if not cursor.fetchone():
        return
    cursor.execute("PRAGMA table_info(login_session_audits)")
    cols = [row[1] for row in cursor.fetchall()]
    if "tenant_id" not in cols:
        cursor.execute("ALTER TABLE login_session_audits ADD COLUMN tenant_id TEXT")
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_login_session_audits_tenant_id "
            "ON login_session_audits(tenant_id)"
        )
        print("Columna tenant_id agregada a login_session_audits")
    # Backfill solo donde usuario resuelve tenant legítimo — no inventar
    cursor.execute("""
        UPDATE login_session_audits
        SET tenant_id = (
            SELECT NULLIF(TRIM(u.nit_pyme), '')
            FROM usuarios u
            WHERE u.id = login_session_audits.user_id
               OR LOWER(u.email) = LOWER(login_session_audits.user_email)
            LIMIT 1
        )
        WHERE tenant_id IS NULL
    """)
    print("Backfill tenant_id login_session_audits (solo join usuarios verificable)")


def _ensure_registration_requests(cursor):
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='registration_requests'"
    )
    if cursor.fetchone():
        return
    cursor.execute("""
        CREATE TABLE registration_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            company_name TEXT,
            nit TEXT,
            sector TEXT,
            servicio TEXT,
            empleados TEXT,
            infra_json TEXT,
            status TEXT DEFAULT 'pending',
            setup_token TEXT,
            token_expires_at TEXT,
            approved_by TEXT,
            approved_at TEXT,
            rejected_by TEXT,
            rejected_at TEXT,
            rejection_reason TEXT,
            request_ip TEXT,
            created_at TEXT
        )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_registration_requests_status ON registration_requests(status)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_registration_requests_email ON registration_requests(email)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_registration_requests_token ON registration_requests(setup_token)")
    print("Tabla registration_requests creada")


if __name__ == "__main__":
    migrate_database()
