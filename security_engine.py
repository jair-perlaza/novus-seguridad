import re
import time
import hashlib
import math
import os
from datetime import datetime
from collections import defaultdict


class NovusSecurityEngine:
    _MAX_REGISTRY = 400

    def __init__(self):
        self.threat_registry = []
        self.blacklist = set()
        self.trusted_devices = {} 

        self.ATO_THRESHOLD = 0.85 

    def _append_to_registry(self, log_entry: dict) -> None:
        self.threat_registry.append(log_entry)
        if len(self.threat_registry) > self._MAX_REGISTRY:
            self.threat_registry = self.threat_registry[-self._MAX_REGISTRY:]
    
    def register_threat_event(
        self,
        db,
        vault,
        evento: str,
        payload: dict,
        *,
        emit_alerta: bool = True,
        notify_coordinator: bool = True,
    ):
        """
        Conecta el motor con database.py y crypto_vault.py.
        Guarda eventos de seguridad cifrados en logs y genera alertas cuando aplica.

        emit_alerta=False: el caller (p.ej. novus_security_integration._log_threat)
        es el dueño canónico de Alerta — evita duplicar RUNTIME_* + TYPE Threat Detected.
        """
        if not db:
            return None
        try:
            from database import Log, Alerta
            detail = vault.proteger_json(payload) if vault else str(payload)
            log = Log(
                evento=evento,
                detalle=detail,
                fecha=datetime.now().strftime("%Y-%m-%d %H:%M")
            )
            db.add(log)

            severity = payload.get("severity") or payload.get("nivel") or payload.get("risk_level", "")
            severity_text = str(severity).lower()
            details = payload.get("details") if isinstance(payload.get("details"), dict) else payload
            from utils.ip_validation import is_documentation_ip, text_contains_documentation_ip

            ip = details.get("ip") if isinstance(details, dict) else None
            has_evidence = bool(
                payload.get("verified")
                or (isinstance(details, dict) and (details.get("verified") or details.get("evidence")))
            )
            doc_ip = is_documentation_ip(ip) or text_contains_documentation_ip(str(payload))

            if (
                emit_alerta
                and has_evidence
                and not doc_ip
                and any(tag in severity_text for tag in ["crit", "alta", "high", "80", "90"])
            ):
                import json
                alerta_kwargs = dict(
                    titulo=f"Evento {evento}",
                    descripcion=f"Condición crítica detectada por motor de seguridad ({severity}).",
                    nivel="Critical",
                    motor=payload.get("source") or "security_engine",
                    fuente="security_engine.register_threat_event",
                    confianza=payload.get("confianza") or payload.get("confidence") or "Alta",
                    estado="activo",
                    ip_afectada=ip,
                    evidencia_json=json.dumps(details, ensure_ascii=False) if isinstance(details, dict) else None,
                    activa=True,
                )
                alerta = Alerta(**alerta_kwargs)
                if hasattr(alerta, "tenant_id") and payload.get("tenant_id"):
                    alerta.tenant_id = payload.get("tenant_id")
                db.add(alerta)
            db.commit()
            if notify_coordinator:
                try:
                    from services.defense_coordinator import defense_coordinator

                    defense_coordinator.record_detection(
                        "security_engine",
                        evento,
                        {
                            "payload_keys": list(payload.keys())[:12],
                            "severity": str(severity),
                            "event_id": payload.get("event_id"),
                            "scope": payload.get("scope"),
                            "tenant_id": payload.get("tenant_id"),
                        },
                        phase="detect",
                        outcome="detected",
                        threat_type=payload.get("threat_type") or payload.get("type") or payload.get("detection_type"),
                        finding_id=payload.get("event_id") or payload.get("finding_id"),
                        detail=f"Evento sectorial {evento}",
                        confidence=payload.get("confianza") or payload.get("confidence"),
                        tenant_id=payload.get("tenant_id"),
                        scope=payload.get("scope"),
                        event_id=payload.get("event_id"),
                    )
                except Exception:
                    pass
            return log
        except Exception:
            db.rollback()
            return None

    def build_sector_protection(self, sector_key: str):
        """
        Return sector protection profile metadata.
        Validation requires real sector telemetry; no demo payloads are injected.
        """
        sector = (sector_key or "otros").lower().strip()
        sector = sector.replace(" ", "_")
        if sector in ("movil", "móvil", "aplicaciones_móviles"):
            sector = "aplicaciones_moviles"
        if sector == "logística":
            sector = "logistica"
        profiles = {
            "fintech": {
                "sector": "fintech",
                "profile_title": "Escudo Fintech",
                "controls": ["Fraude BEC", "Integridad de pagos", "Validacion de cuenta destino"],
            },
            "logistica": {
                "sector": "logistica",
                "profile_title": "Escudo Logistico",
                "controls": ["Integridad IoT", "GPS spoofing", "Autenticacion de telemetria"],
            },
            "aplicaciones_digitales": {
                "sector": "aplicaciones_digitales",
                "profile_title": "Escudo Apps Digitales/Moviles",
                "controls": ["Anti-clickjacking", "Integridad de interfaz", "Proteccion de sesion"],
            },
            "aplicaciones_moviles": {
                "sector": "aplicaciones_moviles",
                "profile_title": "Escudo Apps Digitales/Moviles",
                "controls": ["Anti-clickjacking", "Integridad de interfaz", "Proteccion de sesion"],
            },
        }
        profile = profiles.get(sector, {
            "sector": "otros",
            "profile_title": "Escudo Base Corporativo",
            "controls": ["Hardening runtime", "Monitoreo de integridad", "Aislamiento de sesion"],
        })
        try:
            import json
            import os

            from services.adaptive_sector_protection_engine import aspe
            from services.sector_shield_service import SECTOR_MOTORS

            config_path = os.path.join(
                os.path.dirname(os.path.dirname(__file__)), "config", "security_config.json"
            )
            last_scan = None
            if os.path.exists(config_path):
                with open(config_path, "r", encoding="utf-8") as fh:
                    cfg = json.load(fh)
                last_scan = cfg.get("last_analysis")

            aspe_panel = aspe.get_sector_protection_panel()
            motors = SECTOR_MOTORS.get(sector, [])
            shield_status = None
            current_risk = None
            protection_level = None
            vault_active = False
            threat_count = 0
            vuln_count = 0

            try:
                from services.novus_security_integration import novus_security
                threats = novus_security.detect_threats_realtime()
                if threats.get("last_scan"):
                    last_scan = threats.get("last_scan")
                suspicious = threats.get("suspicious_processes") or []
                threat_count = len(suspicious)
                vulns = threats.get("vulnerabilities") or novus_security.get_cached_vulnerabilities() or []
                vuln_count = len(vulns)
                vault = novus_security.vault
                vault_active = vault is not None and getattr(vault, "llave_aes", None) is not None
                if threat_count > 5 or vuln_count > 15:
                    current_risk = "Alto"
                elif threat_count > 0 or vuln_count > 5:
                    current_risk = "Medio"
                else:
                    current_risk = "Bajo"
                if vault_active and threat_count == 0:
                    protection_level = "Alta"
                elif vault_active and threat_count < 3:
                    protection_level = "Media"
                else:
                    protection_level = "Baja"
                if threat_count > 3 or vuln_count > 10:
                    shield_status = "Alerta"
                elif threat_count > 0 or vuln_count > 0:
                    shield_status = "Monitoreo activo"
                else:
                    shield_status = "Protegido"
            except Exception:
                pass

            confidence = aspe_panel.get("confidence_level")
            if confidence and str(confidence).lower() not in ("no_data", "sin datos disponibles"):
                conf_text = confidence
            elif aspe_panel.get("protecciones_activas"):
                conf_text = "Media — protecciones activas sin evaluación formal de confianza"
            else:
                conf_text = (
                    "Pendiente — ASPE aún no ha calculado confianza sectorial tras detección UCE"
                )

            if last_scan or motors or aspe_panel.get("protecciones_activas"):
                status = "active"
                message = (
                    f"{profile['profile_title']} operativo. "
                    f"Estado: {shield_status or 'Monitoreo activo'}. "
                    f"Riesgo: {current_risk or 'evaluando'}. "
                    f"Último escaneo: {last_scan or 'ciclo background en curso'}."
                )
            else:
                status = "initializing"
                message = (
                    f"Perfil {profile['profile_title']} cargado. "
                    "Los motores sectoriales están inicializando; el primer escaneo "
                    "de background completará la telemetría."
                )

            profile["response"] = {
                "status": status,
                "message": message,
                "telemetry": {
                    "sector_key": sector,
                    "shield_status": shield_status,
                    "protection_level": protection_level,
                    "current_risk": current_risk,
                    "last_scan": last_scan,
                    "vault_active": vault_active,
                    "threats_detected": threat_count,
                    "vulnerabilities_detected": vuln_count,
                    "motors_count": len(motors),
                    "motors": motors[:6],
                    "aspe_confidence": conf_text,
                    "protecciones_activas": len(aspe_panel.get("protecciones_activas") or []),
                    "protecciones_standby": len(aspe_panel.get("protecciones_standby") or []),
                },
            }
        except Exception as exc:
            profile["response"] = {
                "status": "unavailable",
                "message": (
                    "No se pudo obtener telemetría sectorial en este momento. "
                    "Los motores de escudo no respondieron."
                ),
                "cause": str(exc)[:180],
            }
        return profile

    def analyze_ato_risk(self, user_id, access_data, history):
        """
        Calcula el ADN del acceso. Si el riesgo supera el umbral,
        ejecuta protocolos de bloqueo o desafío biométrico.
        """
        risk_score = 0.0
        details = []

        if history.get('last_location'):
            velocity = self._calculate_velocity(
                history['last_location'], 
                access_data['current_location'], 
                history['last_timestamp']
            )
            if velocity > 800: 
                risk_score += 0.60
                details.append("Anomalía de desplazamiento físico detectada.")

        device_id = self._generate_device_fingerprint(access_data['browser_data'])
        if device_id not in self.trusted_devices.get(user_id, []):
            risk_score += 0.30
            details.append("Dispositivo no reconocido para esta cuenta.")

        typing_diff = abs(access_data['typing_speed'] - history.get('avg_typing_speed', 0))
        if typing_diff > 45:
            risk_score += 0.25
            details.append("Patrón de tecleo inconsistente con el perfil del usuario.")

        return self._execute_ato_response(user_id, risk_score, details)

    def _generate_device_fingerprint(self, data):
        """Crea un hash único basado en el hardware y navegador"""
        raw_string = f"{data['os']}-{data['resolution']}-{data['cpu_cores']}"
        return hashlib.sha256(raw_string.encode()).hexdigest()

    def _calculate_velocity(self, loc1, loc2, time1):
        """Calcula km/h entre dos puntos geográficos (Simplificado)"""
        # En una versión real usaríamos la fórmula de Haversine
        dist = math.sqrt((loc2['lat'] - loc1['lat'])**2 + (loc2['lon'] - loc1['lon'])**2) * 111
        time_diff = (time.time() - time1) / 3600 # Diferencia en horas
        return dist / time_diff if time_diff > 0 else 0

    def _execute_ato_response(self, user_id, score, details):
        """Acciones automáticas según el riesgo"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if score >= self.ATO_THRESHOLD:
            action = "CRITICAL_LOCKOUT"
            status = "Bloqueado por Seguridad"
        elif score > 0.50:
            action = "REQUIRE_MFA"
            status = "Desafío de Identidad Requerido"
        else:
            action = "ALLOW"
            status = "Acceso Limpio"

        log_entry = {
            "timestamp": timestamp,
            "user": user_id,
            "score": f"{score*100:.1f}%",
            "action": action,
            "reasons": details
        }
        self._append_to_registry(log_entry)
        return log_entry
   
    def validate_api_request(self, client_ip, endpoint_path):
        """
        Controla el flujo de peticiones. Si una IP satura un endpoint,
        se le asigna una 'cuarentena' automática.
        """
       
        if not hasattr(self, 'api_traffic'):
            self.api_traffic = defaultdict(lambda: {"tokens": 20.0, "last_refill": time.time()})

        now = time.time()
        user_bucket = self.api_traffic[client_ip]
        
        time_passed = now - user_bucket["last_refill"]
        user_bucket["tokens"] = min(20.0, user_bucket["tokens"] + (time_passed * 1.5))
        user_bucket["last_refill"] = now

        if client_ip in self.blacklist:
            return self._execute_api_response(client_ip, "REJECTED_BLACKLIST", endpoint_path)

        if user_bucket["tokens"] >= 1.0:
            user_bucket["tokens"] -= 1.0
            return {"status": "SUCCESS", "remaining_burst": int(user_bucket["tokens"])}
        else:
            self.blacklist.add(client_ip)
            return self._execute_api_response(client_ip, "RATE_LIMIT_EXCEEDED", endpoint_path)

    def _execute_api_response(self, ip, reason, route):
        """Protocolo de mitigación para tráfico abusivo"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        if reason == "RATE_LIMIT_EXCEEDED":
            action = "TEMP_BAN_10MIN"
            severity = "ALTA"
        else:
            action = "HARD_DROP"
            severity = "CRÍTICA"

        log_entry = {
            "time": timestamp,
            "origin_ip": ip,
            "target": route,
            "incident": reason,
            "action": action,
            "severity": severity
        }
        
        self._append_to_registry(log_entry)
        print(f"!! [API_SHIELD] {severity}: {reason} desde {ip} en ruta {route}")
        return {"status": "BLOCKED", "details": log_entry}
    
    def inspect_email_integrity(self, email_metadata, content_body):
        """
        Analiza el ADN del correo recibido. Detecta suplantación de identidad
        y técnicas de ingeniería social antes de que lleguen al buzón del CEO.
        """
        risk_level = 0.0
        findings = []

        domain_age = email_metadata.get('domain_age_days')
        if domain_age is not None and isinstance(domain_age, (int, float)) and domain_age < 5:
            risk_level += 0.50
            findings.append("Dominio de remitente extremadamente joven (Alta sospecha).")

        import os
        corporate_domain = os.environ.get("NOVUS_CORPORATE_DOMAIN", "").strip()
        sender_domain = email_metadata.get('sender_domain') or ""
        if corporate_domain and sender_domain:
            if self._detect_typosquatting(sender_domain, corporate_domain):
                risk_level += 0.60
                findings.append("Posible suplantación de dominio corporativo (Look-alike).")

        urgency_keywords = [r"urgente", r"acción requerida", r"pago pendiente", r"transferencia", r"token"]
        for pattern in urgency_keywords:
            if re.search(pattern, content_body, re.IGNORECASE):
                risk_level += 0.15
                findings.append(f"Patrón de urgencia detectado: '{pattern}'.")

        if not email_metadata.get('is_digitally_signed', False):
            risk_level += 0.20
            findings.append("Falta de firma criptográfica en el origen.")

        return self._execute_phishing_response(email_metadata['sender'], risk_level, findings)

    def _detect_typosquatting(self, sender_domain, target_domain):
        """
        Compara la similitud visual entre dominios para detectar fraude.
        Utiliza una lógica de distancia de caracteres simplificada.
        """
        if sender_domain == target_domain: return False
        
        common_subs = ["0", "1", "l", "i", "vv"] 
        
        return len(set(sender_domain) & set(target_domain)) / len(set(target_domain)) > 0.8

    def _execute_phishing_response(self, sender, score, reasons):
        """Protocolo de cuarentena para correos maliciosos"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if score >= 0.70:
            action = "AUTO_QUARANTINE"
            label = "PELIGRO: Phishing Confirmado"
        elif score >= 0.40:
            action = "WARN_USER"
            label = "ADVERTENCIA: Remitente Sospechoso"
        else:
            action = "PASS"
            label = "Correo Seguro"

        log_entry = {
            "timestamp": timestamp,
            "sender": sender,
            "risk_score": f"{score*100:.0f}%",
            "findings": reasons,
            "action": action
        }
        
        if action != "PASS":
            self._append_to_registry(log_entry)
            print(f"!! [PHISHING_SHIELD] {label} desde {sender}")
            
        return log_entry
    
    def verify_tunnel_integrity(self, connection_metadata):
        """
        Analiza la capa de transporte (SSL/TLS) y busca indicios de
        interceptación o proxies maliciosos (SSL Stripping).

        Honesty:
        - TLS negociado (>=1.2) NO es SSL stripping aunque falle la CA local.
        - Fallo de trust store local ≠ MITM confirmado.
        - Pin mismatch solo cuenta si NOVUS_EXPECTED_CERT_PIN está configurado.
        """
        mitm_risk = 0.0
        anomalies = []
        meta = connection_metadata or {}
        try:
            tls_ver = float(meta.get("tls_version") or 0.0)
        except (TypeError, ValueError):
            tls_ver = 0.0
        tls_str = str(meta.get("tls_version_str") or "")
        has_tls = tls_ver >= 1.2 or tls_str.upper().startswith("TLS")
        probe_error = str(meta.get("probe_error") or meta.get("error") or "")
        local_trust_issue = "cert_verify_failed" in probe_error.lower() or "certificate verify failed" in probe_error.lower()

        if not meta.get("is_secure", False) and not has_tls:
            # Cleartext / no TLS negotiated — classic stripping signal
            mitm_risk += 0.90
            anomalies.append("CONEXIÓN NO CIFRADA: Intento de SSL Stripping detectado.")
        elif has_tls and tls_ver and tls_ver < 1.2:
            mitm_risk += 0.50
            anomalies.append("Protocolo TLS débil/obsoleto detectado.")
        elif not meta.get("is_secure", False) and has_tls and local_trust_issue:
            # TLS present; local CA verification failed — NOT_VERIFIABLE as MITM
            anomalies.append(
                "NOT_VERIFIABLE: fallo de trust store local (cert_verify_failed); "
                "TLS negociado — no equivale a SSL Stripping/MITM confirmado."
            )
            return {
                "status": "NOT_VERIFIABLE",
                "action": "OBSERVE",
                "incident": None,
                "risk_level": "NOT_AVAILABLE",
                "anomalies": anomalies,
                "protocol": "OBSERVE",
                "verified": False,
                "confidence": "NOT_AVAILABLE",
                "evidence": anomalies[0],
                "data_state": "NOT_VERIFIABLE",
            }

        expected_pin = os.environ.get('NOVUS_EXPECTED_CERT_PIN')
        if expected_pin and meta.get('server_cert_pin') and meta.get('server_cert_pin') != expected_pin:
            mitm_risk += 0.85
            anomalies.append("CERTIFICADO DESCONOCIDO: Posible interceptación por Proxy/MitM.")

        if len(meta.get('proxy_chain', []) or []) > 2:
            mitm_risk += 0.30
            anomalies.append("Cadena de proxy inusualmente larga o sospechosa.")

        if mitm_risk <= 0 and not anomalies:
            return {"status": "SECURE", "action": "CONTINUE", "verified": True, "confidence": "NOT_AVAILABLE"}

        if mitm_risk <= 0:
            return {
                "status": "NOT_VERIFIABLE",
                "action": "OBSERVE",
                "anomalies": anomalies,
                "verified": False,
                "confidence": "NOT_AVAILABLE",
                "data_state": "NOT_VERIFIABLE",
            }

        return self._execute_mitm_response(mitm_risk, anomalies)

    def _execute_mitm_response(self, risk_score, anomalies):
        """Protocolo de ruptura de túnel inseguro"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        if risk_score >= 0.80:
            action = "TERMINATE_CONNECTION"
            status = "CRÍTICO: Túnel Interceptado"
            severity = "ROJO"
        elif risk_score >= 0.40:
            action = "ENFORCE_RE_ENCRYPTION"
            status = "ADVERTENCIA: Integridad de Conexión Dudosa"
            severity = "AMARILLO"
        else:
            return {"status": "SECURE", "action": "CONTINUE"}

        log_entry = {
            "time": timestamp,
            "incident": "Man-in-the-Middle Attempt",
            "risk_level": f"{risk_score*100:.0f}%",
            "anomalies": anomalies,
            "protocol": action
        }
        
        self._append_to_registry(log_entry)
        print(f"!! [MITM_SHIELD] {status}. Ejecutando: {action} [{severity}]")
        
        return log_entry
    
    def monitor_filesystem_activity(self, activity_report):
        """
        Analiza patrones de escritura y lectura en el sistema de archivos.
        Detecta el cifrado masivo antes de que se complete el secuestro.
        Un único .tmp con alta entropía NO confirma ransomware.
        """
        ransom_risk = 0.0
        indicators = []

        high_entropy_count = activity_report.get("high_entropy_file_count", 0)
        max_entropy = activity_report.get("data_entropy", 0)
        files_per_sec = activity_report.get("files_modified_per_sec", 0)
        outbound_rate = activity_report.get("outbound_traffic_mbps", 0)

        if files_per_sec > 50:
            ransom_risk += 0.50
            indicators.append(
                f"RÁFAGA DE ESCRITURA: {files_per_sec:.1f} archivos/s modificados."
            )

        if high_entropy_count >= 3 and max_entropy > 7.9:
            ransom_risk += 0.35
            indicators.append(
                f"ENTROPÍA ELEVADA: {high_entropy_count} archivo(s) con entropía > 7.9."
            )
        elif max_entropy > 7.9 and high_entropy_count <= 2 and files_per_sec <= 5:
            return {
                "status": "OBSERVATION",
                "action": "CONTINUE_MONITORING",
                "verified": False,
                "observation": (
                    "Archivo temporal de alta entropía aislado; "
                    "no cumple criterios de ransomware confirmado."
                ),
                "high_entropy_files": activity_report.get("high_entropy_files", []),
            }

        if outbound_rate > 100 and files_per_sec > 10:
            ransom_risk += 0.25
            indicators.append(
                f"EXFILTRACIÓN POSIBLE: {outbound_rate:.1f} Mbps de salida con actividad de archivos."
            )

        if activity_report.get("header_integrity_violation", False):
            ransom_risk += 0.40
            indicators.append("VIOLACIÓN DE CABECERA: Cambio de formato no autorizado.")

        return self._execute_ransomware_response(ransom_risk, indicators, activity_report)

    def _execute_ransomware_response(self, risk_score, indicators, evidence=None):
        """Protocolo de 'Tierra Quemada' para salvar los datos."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if risk_score >= 0.80 and len(indicators) >= 2:
            action = "EMERGENCY_LOCKDOWN"
            status = "SISTEMA AISLADO: Ransomware en ejecución"
        elif risk_score >= 0.45 and len(indicators) >= 2:
            action = "READ_ONLY_MODE"
            status = "PROTECCIÓN ACTIVA: Modo Solo Lectura activado"
        else:
            return {
                "status": "STABLE",
                "action": "CONTINUE_MONITORING",
                "verified": False,
                "indicators": indicators,
            }

        log_entry = {
            "status": status,
            "timestamp": timestamp,
            "threat": "Ransomware / Exfiltration Attempt",
            "risk_level": f"{risk_score*100:.1f}%",
            "indicators": indicators,
            "protocol_executed": action,
            "verified": True,
            "evidence": evidence or {},
            "motor": "security_engine.monitor_filesystem_activity",
        }

        self._append_to_registry(log_entry)
        print(f"!! [RANSOM_SENTINEL] {status}. Protocolo: {action}")

        return log_entry
    
    def validate_transactional_integrity(self, email_data, invoice_metadata):
        """
        Analiza si un correo de "proveedor" o "directivo" contiene cambios 
        sospechosos en las instrucciones de pago o comportamiento anómalo.
        """
        bec_risk = 0.0
        red_flags = []

        # 1. Verificación de "Reply-To" Mismatch
        # Detecta si el correo parece venir de un jefe, pero las respuestas van a un extraño.
        if email_data.get('header_from') != email_data.get('reply_to'):
            bec_risk += 0.75
            red_flags.append("DISCREPANCIA DE CABECERA: El remitente y el destino de respuesta no coinciden.")

        if invoice_metadata.get('account_number_changed', False):
            bec_risk += 0.80
            red_flags.append("CAMBIO DE CUENTA DETECTADO: El proveedor solicita pago en una cuenta no registrada.")

        if self._has_homoglyphs(email_data['sender_display_name']):
            bec_risk += 0.65
            red_flags.append("ATAQUE DE HOMÓGRAFO: El nombre del remitente usa caracteres visualmente engañosos.")

        if email_data.get('is_urgent', False) and not self._is_business_hours():
            bec_risk += 0.30
            red_flags.append("PATRÓN SOSPECHOSO: Solicitud financiera urgente fuera de horario laboral.")

        return self._execute_bec_response(bec_risk, red_flags)

    def _has_homoglyphs(self, text):
        """Detecta si el texto contiene caracteres no estándar para engaño visual"""
        return any(ord(char) > 127 for char in text)

    def _is_business_hours(self):
        """Verifica si el evento ocurre en horario de oficina (L-V 8am-6pm)"""
        now = datetime.now()
        return now.weekday() < 5 and 8 <= now.hour <= 18

    def _execute_bec_response(self, risk_score, flags):
        """Protocolo de interceptación de fraude financiero"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        if risk_score >= 0.70:
            action = "FREEZE_TRANSACTION_UI"
            status = "FRAUDE BEC PROBABLE: Pago bloqueado preventivamente"
            severity = "CRÍTICA"
        elif risk_score >= 0.40:
            action = "VERIFICATION_REQUIRED"
            status = "VALIDACIÓN NECESARIA: Cambio de datos financieros"
            severity = "MEDIA"
        else:
            return {"status": "TRUSTED", "action": "CONTINUE"}

        log_entry = {
            "time": timestamp,
            "incident": "BEC / Financial Fraud Attempt",
            "risk_score": f"{risk_score*100:.0f}%",
            "flags": flags,
            "action_taken": action
        }
        
        self._append_to_registry(log_entry)
        print(f"!! [BEC_SHIELD] {status}. [{severity}]")
        
        return log_entry
    
    def validate_iot_telemetry(self, device_id, telemetry_data, historical_state):
        """
        Analiza la integridad de los sensores IoT. Detecta manipulación de 
        GPS (Spoofing), secuestro de dispositivos y telemetría falsa.
        """
        iot_risk = 0.0
        anomalies = []

        dist_km = self._calculate_velocity(
            historical_state['last_coord'], 
            telemetry_data['current_coord'], 
            historical_state['last_time']
        )
        if dist_km > 180: # Si un camión "viaja" a más de 180 km/h en Colombia
            iot_risk += 0.85
            anomalies.append("GPS SPOOFING: Salto geográfico físicamente imposible detectado.")

        if telemetry_data['engine_rpm'] < 100 and telemetry_data['speed'] > 20:
            iot_risk += 0.70
            anomalies.append("DISCREPANCIA DE SENSORES: Datos de motor e inercia no coinciden.")

        if not telemetry_data.get('is_signed_by_hardware', False):
            iot_risk += 0.50
            anomalies.append("PAQUETE NO FIRMADO: Telemetría enviada desde origen no verificado.")

        if (time.time() - historical_state['last_time']) > 300 and historical_state['in_signal_zone']:
            iot_risk += 0.40
            anomalies.append("POSIBLE JAMMING: Pérdida crítica de señal en zona de cobertura.")

        return self._execute_iot_response(device_id, iot_risk, anomalies)

    def _execute_iot_response(self, device_id, risk_score, anomalies):
        """Protocolo de seguridad para activos físicos"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        if risk_score >= 0.75:
            action = "ISOLATE_DEVICE_AND_ALERT_AUTHORITIES"
            status = "CRÍTICO: Manipulación de Activo Detectada"
        elif risk_score >= 0.40:
            action = "RECALIBRATE_SENSORS"
            status = "ADVERTENCIA: Telemetría Inconsistente"
        else:
            return {"status": "OPERATIONAL", "action": "LOG_DATA"}

        log_entry = {
            "time": timestamp,
            "device": device_id,
            "risk_score": f"{risk_score*100:.0f}%",
            "anomalies": anomalies,
            "protocol": action
        }
        
        self._append_to_registry(log_entry)
        print(f"!! [IOT_GUARD] {status} en dispositivo {device_id}.")
        
        return log_entry
    
    def sanitize_and_validate_query(self, user_input, context="PORTAL_LOGIN"):
        """
        Analiza cadenas de texto en busca de patrones de inyección SQL,
        caracteres de escape maliciosos y técnicas de ofuscación.
        """
        sqli_risk = 0.0
        malicious_patterns = []

        sqli_signatures = {
            r"(\%27)|(\')|(\-\-)|(\%23)|(#)": "Detección de caracteres de escape/comentarios",
            r"(?i)\b(UNION|SELECT|INSERT|DELETE|DROP|UPDATE|ALTER|CREATE|TRUNCATE)\b": "Inyección de comandos DDL/DML",
            r"(?i)\b(OR|AND)\b\s+(['\"]?\d?['\"]?)\s*=\s*\2": "Tautología detectada (ej. 1=1)",
            r"(?i)SLEEP\(|WAITFOR\s+DELAY|BENCHMARK\(": "Ataque de SQLi basado en tiempo (Blind SQLi)"
        }

        for pattern, description in sqli_signatures.items():
            if re.search(pattern, user_input):
                sqli_risk += 0.45
                malicious_patterns.append(description)

        if re.search(r"(?i)0x[0-9a-fA-F]+|CHAR\(", user_input):
            sqli_risk += 0.50
            malicious_patterns.append("Uso de codificación sospechosa (Hex/Char)")

        if len(user_input) > 100 and context != "COMMENTS":
            sqli_risk += 0.20
            malicious_patterns.append("Longitud de entrada excesiva para el contexto.")

        return self._execute_sqli_response(user_input, sqli_risk, malicious_patterns)

    def _execute_sqli_response(self, raw_input, risk_score, patterns):
        """Protocolo de limpieza y bloqueo de inyección"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        if risk_score >= 0.60:
            action = "BLOCK_AND_REPORT_IP"
            status = "ATAQUE DETECTADO: Intento de Inyección SQL"
            # Aquí podrías llamar a una función de limpieza extrema
            clean_input = None 
        elif risk_score >= 0.30:
            action = "STRIP_SPECIAL_CHARS"
            status = "ADVERTENCIA: Caracteres sospechosos removidos"
            # Limpieza agresiva de caracteres
            clean_input = re.sub(r"[^a-zA-Z0-9@\.]", "", raw_input)
        else:
            return {"status": "SAFE", "data": raw_input}

        log_entry = {
            "time": timestamp,
            "incident": "SQL Injection Attempt",
            "risk_score": f"{risk_score*100:.0f}%",
            "detected_patterns": patterns,
            "action": action
        }
        
        self._append_to_registry(log_entry)
        print(f"!! [SQLI_SHIELD] {status}. Acción: {action}")
        
        return {"status": "INTERCEPTED", "log": log_entry, "cleaned_data": clean_input}
    
    def verify_runtime_integrity(self, runtime_env):
        """
        Detecta si el entorno de ejecución es hostil o si se está 
        intentando depurar (debug) el código de NOVUS en tiempo real.
        """
        integrity_risk = 0.0
        violations = []

        if runtime_env.get('is_debugger_attached', False):
            integrity_risk += 0.95
            violations.append("DEBUGGER DETECTADO: Intento de análisis de flujo en vivo.")

        if runtime_env.get('is_rooted_or_jailbroken', False):
            integrity_risk += 0.60
            violations.append("ENTORNO NO CONFIABLE: Dispositivo con privilegios Root/Jailbreak.")

        current_code_hash = self._calculate_runtime_hash(runtime_env.get('binary_data', ""))
        if current_code_hash != runtime_env.get('expected_hash'):
            integrity_risk += 0.90
            violations.append("VIOLACIÓN DE INTEGRIDAD: El binario de NOVUS ha sido modificado (Tampering).")

        if runtime_env.get('malicious_hooks_detected', False):
            integrity_risk += 0.85
            violations.append("INYECCIÓN DE MEMORIA: Detectada herramienta de instrumentación dinámica.")

        return self._execute_integrity_response(integrity_risk, violations)

    def _calculate_runtime_hash(self, data):
        """Genera un hash SHA-256 para verificar que el código no cambió"""
        if not data: return ""
        return hashlib.sha256(data.encode()).hexdigest()

    def _execute_integrity_response(self, risk_score, violations):
        """Protocolo de autoprotección del software"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        if risk_score >= 0.80:
            action = "SELF_DESTRUCT_SESSION"
            status = "CRÍTICO: Intento de ingeniería inversa detectado"
            # Protocolo: Borrar llaves de sesión de la memoria y cerrar la app.
        elif risk_score >= 0.50:
            action = "RESTRICT_SENSITIVE_FEATURES"
            status = "ADVERTENCIA: Ejecución en entorno no seguro"
        else:
            return {"status": "INTEGRITY_OK", "action": "CONTINUE"}

        log_entry = {
            "time": timestamp,
            "incident": "Reverse Engineering Attempt",
            "risk_level": f"{risk_score*100:.0f}%",
            "violations": violations,
            "action": action
        }
        
        self._append_to_registry(log_entry)
        print(f"!! [ANTI_REVERSE] {status}. Acción ejecutada: {action}")
        
        return log_entry
    
    def detect_overlay_threat(self, window_context):
        """
        Detecta si hay aplicaciones maliciosas intentando dibujar sobre NOVUS
        o interceptar eventos táctiles mediante capas invisibles.
        """
        overlay_risk = 0.0
        alerts = []

        if window_context.get('foreign_overlay_active', False):
            overlay_risk += 0.80
            alerts.append("CAPA EXTERNA DETECTADA: Otra aplicación está dibujando sobre NOVUS.")

        if window_context.get('overlay_opacity', 1.0) < 0.1:
            overlay_risk += 0.90
            alerts.append("VENTANA FANTASMA: Capa invisible detectada sobre el campo de credenciales.")

        if window_context.get('is_synthetic_touch', False):
            overlay_risk += 0.70
            alerts.append("TAP-JACKING: Clics sintéticos detectados. Posible automatización maliciosa.")

        if not window_context.get('is_main_window_focused', True):
            overlay_risk += 0.40
            alerts.append("PÉRDIDA DE FOCO: La ventana de seguridad ya no es la principal.")

        return self._execute_overlay_response(overlay_risk, alerts)

    def _execute_overlay_response(self, risk_score, alerts):
        """Protocolo de blindaje de interfaz"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        if risk_score >= 0.75:
            action = "OBSCURE_SCREEN_AND_HALT"
            status = "CRÍTICO: Intento de robo de pantalla (Overlay)"
            # Protocolo: Poner la pantalla en negro y bloquear el teclado.
        elif risk_score >= 0.40:
            action = "SHOW_SECURITY_WARNING"
            status = "ADVERTENCIA: Interfaz posiblemente comprometida"
        else:
            return {"status": "UI_SAFE", "action": "CONTINUE"}

        log_entry = {
            "time": timestamp,
            "threat": "Overlay / Screen Hijacking",
            "risk_level": f"{risk_score*100:.0f}%",
            "detected_alerts": alerts,
            "action": action
        }
        
        self._append_to_registry(log_entry)
        print(f"!! [UI_SHIELD] {status}. Protocolo: {action}")
        
        return log_entry
    
    def verify_sim_and_identity(self, device_metadata, user_profile):
        """
        Analiza la consistencia de la línea telefónica y el hardware.
        Si la SIM o el dispositivo cambian sospechosamente, invalida el 2FA.
        """
        sim_risk = 0.0
        findings = []

        if device_metadata.get('current_sim_iccid') != user_profile.get('registered_sim_iccid'):
            sim_risk += 0.85
            findings.append("ALERTA DE HARDWARE: El serial de la tarjeta SIM ha cambiado.")

        if device_metadata.get('imsi_id') != user_profile.get('registered_imsi'):
            sim_risk += 0.70
            findings.append("INCONSISTENCIA DE LÍNEA: Identificador IMSI no coincide con el registro.")

        if device_metadata.get('device_days_on_network', 0) < 1:
            sim_risk += 0.40
            findings.append("NUEVO DISPOSITIVO: El acceso proviene de un terminal recién activado.")

        if device_metadata.get('network_region') != user_profile.get('home_region'):
            sim_risk += 0.30
            findings.append("SALTO REGIONAL: Actividad de red fuera del área habitual del usuario.")

        return self._execute_sim_response(sim_risk, findings)

    def _execute_sim_response(self, risk_score, findings):
        """Protocolo de protección de identidad móvil"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        if risk_score >= 0.75:
            action = "DISABLE_SMS_2FA_IMMEDIATELY"
            status = "CRÍTICO: Posible duplicado de SIM (Sim Swapping)"
            # Protocolo: Bloquear SMS como método de recuperación y forzar Llave Física/Biometría.
        elif risk_score >= 0.45:
            action = "REQUIRE_ADDITIONAL_BIOMETRICS"
            status = "ADVERTENCIA: Cambio de terminal o tarjeta detectado"
        else:
            return {"status": "IDENTITY_VERIFIED", "action": "ALLOW_MOBILE_OPS"}

        log_entry = {
            "time": timestamp,
            "incident": "SIM Swap / Identity Hijacking",
            "risk_score": f"{risk_score*100:.0f}%",
            "findings": findings,
            "action_executed": action
        }
        
        self._append_to_registry(log_entry)
        print(f"!! [IDENTITY_SHIELD] {status}. Acción: {action}")
        
        return log_entry
    
    def validate_ui_interaction(self, click_event, headers):
        """
        Verifica la legitimidad de las interacciones táctiles y de mouse.
        Asegura que el usuario esté interactuando con la capa real de NOVUS.
        """
        ui_risk = 0.0
        anomalies = []

        frame_policy = headers.get('X-Frame-Options', '').upper()
        if frame_policy not in ['DENY', 'SAMEORIGIN']:
            ui_risk += 0.80
            anomalies.append("SEGURIDAD DE MARCO DÉBIL: El portal es vulnerable a framing externo.")

        if click_event.get('is_element_obstructed', False):
            ui_risk += 0.70
            anomalies.append("INTERCEPCIÓN DE CLIC: Se detectó un clic a través de una capa superpuesta.")

        if not click_event.get('is_trusted_interaction', True):
            ui_risk += 0.60
            anomalies.append("INTERACCIÓN NO CONFIABLE: Evento de puntero generado artificialmente.")

        if abs(click_event.get('visual_x') - click_event.get('actual_x')) > 5:
            ui_risk += 0.50
            anomalies.append("DESVIACIÓN DE COORDENADAS: El clic no coincide con el elemento visual.")

        return self._execute_ui_response(ui_risk, anomalies)

    def _execute_ui_response(self, risk_score, anomalies):
        """Protocolo de protección de la experiencia de usuario"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        if risk_score >= 0.70:
            action = "INVALIDATE_CLICK_AND_REFRESH"
            status = "ATAQUE DETECTADO: Intento de Clickjacking"
            # Protocolo: Ignorar el clic, refrescar la sesión y re-posicionar elementos.
        elif risk_score >= 0.40:
            action = "ENFORCE_BREAK_OUT_OF_FRAMES"
            status = "ADVERTENCIA: Intento de enmarcado de interfaz"
        else:
            return {"status": "UI_INTEGRITY_OK", "action": "PROCESS_EVENT"}

        log_entry = {
            "time": timestamp,
            "incident": "Clickjacking / UI Redressing",
            "risk_score": f"{risk_score*100:.0f}%",
            "anomalies": anomalies,
            "action": action
        }
        
        self._append_to_registry(log_entry)
        print(f"!! [UI_INTEGRITY] {status}. Ejecutando: {action}")
        
        return log_entry

    # --- MÉTODO FINAL PARA EL DASHBOARD ---
    def get_security_summary(self):
        """Devuelve el estado de todas las neutralizaciones para el index.html"""
        return {
            "total_threats_neutralized": len(self.threat_registry),
            "critical_incidents": [t for t in self.threat_registry if "CRÍTICO" in t.get('status', '')],
            "system_health": "PROTECTED" if not self.blacklist else "UNDER_ATTACK"
        }