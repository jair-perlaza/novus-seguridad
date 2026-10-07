"""
Detector de Amenazas en Tiempo Real para NOVUS
Monitorea intentos de acceso, escaneos de puertos y actividad sospechosa
"""

import socket
import threading
import time
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Set
from collections import defaultdict, deque
import ipaddress
from database import SessionLocal, IntentoAcceso, Alerta, IPBloqueada

logger = logging.getLogger(__name__)

class ThreatDetector:
    def __init__(self):
        self.suspicious_ips = defaultdict(list)
        self.failed_attempts = defaultdict(int)
        self.port_scan_attempts = defaultdict(set)
        self.active_threats = []
        self.monitoring = False
        self.lock = threading.Lock()
        
        # Umbrales de detección
        self.max_failed_attempts = 3
        self.max_port_scans = 10
        self.time_window_minutes = 5
        
        # Patrones de ataque conocidos
        self.attack_patterns = {
            'brute_force': self.detect_brute_force,
            'port_scan': self.detect_port_scan,
            'sql_injection': self.detect_sql_injection,
            'xss_attempt': self.detect_xss_attempt,
            'directory_traversal': self.detect_directory_traversal
        }
    
    def detect_brute_force(self, ip: str, email: str, timestamp: datetime) -> Optional[Dict]:
        """Detecta ataques de fuerza bruta"""
        with self.lock:
            # Limpiar intentos antiguos
            cutoff_time = timestamp - timedelta(minutes=self.time_window_minutes)
            self.failed_attempts[ip] = [
                (email, ts) for email, ts in self.failed_attempts[ip] 
                if ts > cutoff_time
            ]
            
            # Agregar intento actual
            self.failed_attempts[ip].append((email, timestamp))
            
            # Verificar umbral
            if len(self.failed_attempts[ip]) >= self.max_failed_attempts:
                threat = {
                    "type": "brute_force",
                    "severity": "high",
                    "ip": ip,
                    "timestamp": timestamp.isoformat(),
                    "description": f"Ataque de fuerza bruta detectado desde {ip}",
                    "details": {
                        "attempts": len(self.failed_attempts[ip]),
                        "emails": list(set(email for email, _ in self.failed_attempts[ip])),
                        "time_window": f"{self.time_window_minutes} minutos"
                    },
                    "recommendation": "Bloquear IP temporalmente y notificar administrador"
                }
                
                logger.warning(f"Ataque de fuerza bruta detectado: {ip}")
                return threat
        
        return None
    
    def detect_port_scan(self, ip: str, port: int, timestamp: datetime) -> Optional[Dict]:
        """Detecta escaneos de puertos"""
        with self.lock:
            # Agregar puerto escaneado
            self.port_scan_attempts[ip].add(port)
            
            # Verificar umbral
            if len(self.port_scan_attempts[ip]) >= self.max_port_scans:
                threat = {
                    "type": "port_scan",
                    "severity": "medium",
                    "ip": ip,
                    "timestamp": timestamp.isoformat(),
                    "description": f"Escaneo de puertos detectado desde {ip}",
                    "details": {
                        "ports_scanned": list(self.port_scan_attempts[ip]),
                        "total_ports": len(self.port_scan_attempts[ip])
                    },
                    "recommendation": "Monitorear actividad y considerar bloqueo de IP"
                }
                
                logger.warning(f"Escaneo de puertos detectado: {ip}")
                return threat
        
        return None
    
    def detect_sql_injection(self, data: str, ip: str, timestamp: datetime) -> Optional[Dict]:
        """Detecta intentos de inyección SQL"""
        sql_patterns = [
            "OR '1'='1", "UNION SELECT", "DROP TABLE", "INSERT INTO",
            "DELETE FROM", "UPDATE SET", "--", "/*", "*/", "xp_",
            "sp_executesql", "WAITFOR DELAY", "BENCHMARK"
        ]
        
        data_upper = data.upper()
        for pattern in sql_patterns:
            if pattern in data_upper:
                threat = {
                    "type": "sql_injection",
                    "severity": "critical",
                    "ip": ip,
                    "timestamp": timestamp.isoformat(),
                    "description": f"Intento de inyección SQL detectado desde {ip}",
                    "details": {
                        "pattern_detected": pattern,
                        "payload": data[:100] + "..." if len(data) > 100 else data
                    },
                    "recommendation": "Bloquear IP inmediatamente y analizar logs"
                }
                
                logger.critical(f"Intento de inyección SQL: {ip}")
                return threat
        
        return None
    
    def detect_xss_attempt(self, data: str, ip: str, timestamp: datetime) -> Optional[Dict]:
        """Detecta intentos de XSS"""
        xss_patterns = [
            "<script>", "javascript:", "onerror=", "onload=", "onmouseover=",
            "alert(", "document.cookie", "window.location", "eval(",
            "innerHTML", "document.write"
        ]
        
        data_lower = data.lower()
        for pattern in xss_patterns:
            if pattern in data_lower:
                threat = {
                    "type": "xss_attempt",
                    "severity": "high",
                    "ip": ip,
                    "timestamp": timestamp.isoformat(),
                    "description": f"Intento de XSS detectado desde {ip}",
                    "details": {
                        "pattern_detected": pattern,
                        "payload": data[:100] + "..." if len(data) > 100 else data
                    },
                    "recommendation": "Sanitizar input y monitorear actividad"
                }
                
                logger.warning(f"Intento de XSS: {ip}")
                return threat
        
        return None
    
    def detect_directory_traversal(self, data: str, ip: str, timestamp: datetime) -> Optional[Dict]:
        """Detecta intentos de directory traversal"""
        traversal_patterns = [
            "../", "..\\", "%2e%2e%2f", "%2e%2e\\", "..%2f", "..%5c",
            "/etc/passwd", "/etc/shadow", "windows/system32", "boot.ini"
        ]
        
        data_lower = data.lower()
        for pattern in traversal_patterns:
            if pattern in data_lower:
                threat = {
                    "type": "directory_traversal",
                    "severity": "high",
                    "ip": ip,
                    "timestamp": timestamp.isoformat(),
                    "description": f"Intento de directory traversal desde {ip}",
                    "details": {
                        "pattern_detected": pattern,
                        "payload": data[:100] + "..." if len(data) > 100 else data
                    },
                    "recommendation": "Validar paths y bloquear IP si es repetitivo"
                }
                
                logger.warning(f"Intento de directory traversal: {ip}")
                return threat
        
        return None
    
    def analyze_request(self, ip: str, endpoint: str, data: str = "", email: str = "") -> List[Dict]:
        """Analiza una solicitud en busca de amenazas"""
        threats = []
        timestamp = datetime.now()
        
        # Detectar fuerza bruta (solo en endpoints de login)
        if 'login' in endpoint.lower() and email:
            threat = self.detect_brute_force(ip, email, timestamp)
            if threat:
                threats.append(threat)
        
        # Detectar otros patrones
        for attack_type, detector in self.attack_patterns.items():
            if attack_type == 'brute_force':
                continue  # Ya manejado arriba
            
            if attack_type == 'port_scan':
                # Esto se maneja por separado
                continue
            
            threat = detector(data, ip, timestamp)
            if threat:
                threats.append(threat)
        
        return threats
    
    def monitor_network_activity(self):
        """Monitorea actividad de red en tiempo real"""
        while self.monitoring:
            try:
                # Analizar intentos de acceso recientes
                db = SessionLocal()
                try:
                    # Obtener intentos de los últimos 5 minutos
                    cutoff_time = datetime.now() - timedelta(minutes=5)
                    recent_attempts = db.query(IntentoAcceso).filter(
                        IntentoAcceso.fecha >= cutoff_time.strftime("%Y-%m-%d %H:%M:%S")
                    ).all()
                    
                    for attempt in recent_attempts:
                        # Analizar cada intento
                        threats = self.analyze_request(
                            ip=attempt.ip_address,
                            endpoint=f"/sector-auth",
                            data=f"sector={attempt.sector_intentado}&email={attempt.email}",
                            email=attempt.email
                        )
                        
                        # Procesar amenazas detectadas
                        for threat in threats:
                            self.handle_threat(threat)
                
                finally:
                    db.close()
                
                time.sleep(10)  # Verificar cada 10 segundos
                
            except Exception as e:
                logger.error(f"Error en monitoreo de red: {e}")
                time.sleep(30)
    
    def handle_threat(self, threat: Dict):
        """Maneja una amenaza detectada"""
        with self.lock:
            # Agregar a amenazas activas
            self.active_threats.append(threat)
            
            # Limitar a las últimas 100 amenazas
            if len(self.active_threats) > 100:
                self.active_threats = self.active_threats[-100:]
        
        # Crear alerta en la base de datos
        self.create_security_alert(threat)
        
        # Notificar en tiempo real
        self.notify_threat(threat)
        
        # Auto-bloquear IP si es crítico
        if threat.get("severity") == "critical":
            self.auto_block_ip(threat["ip"])
    
    def create_security_alert(self, threat: Dict):
        """Crea una alerta de seguridad en la base de datos"""
        try:
            from utils.ip_validation import is_documentation_ip

            if is_documentation_ip(threat.get("ip")):
                logger.info("Alerta threat_detector omitida: IP RFC 5737")
                return
            db = SessionLocal()
            try:
                import json
                alerta = Alerta(
                    titulo=f"🚨 {threat['type'].replace('_', ' ').title()} Detectado",
                    descripcion=threat["description"],
                    nivel=threat["severity"].upper(),
                    fecha=threat["timestamp"],
                    ip_afectada=threat["ip"],
                    recomendacion=threat.get("recommendation", ""),
                    motor="threat_detector",
                    fuente="threat_detector",
                    confianza=threat.get("confidence", "Alta"),
                    estado="activo",
                    evidencia_json=json.dumps(threat, ensure_ascii=False),
                    activa=True,
                )
                
                db.add(alerta)
                db.commit()
                
            finally:
                db.close()
                
        except Exception as e:
            logger.error(f"Error creando alerta: {e}")
    
    def notify_threat(self, threat: Dict):
        """Notifica amenaza en tiempo real"""
        try:
            # Importación local para evitar circularidad
            from realtime_engine import realtime_engine
            
            if realtime_engine.active_connections:
                threat_data = {
                    "type": "threat_detected",
                    "threat": threat,
                    "timestamp": datetime.now().isoformat()
                }
                
                import asyncio
                asyncio.create_task(realtime_engine.broadcast(threat_data))
                
        except Exception as e:
            logger.error(f"Error notificando amenaza: {e}")
    
    def auto_block_ip(self, ip: str):
        """Bloquea automáticamente una IP peligrosa"""
        try:
            db = SessionLocal()
            try:
                # Verificar si ya está bloqueada
                existing_block = db.query(IPBloqueada).filter(IPBloqueada.ip == ip).first()
                
                if not existing_block:
                    blocked_ip = IPBloqueada(
                        ip=ip,
                        razon="Bloqueo automático por amenaza crítica",
                        fecha=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    )
                    
                    db.add(blocked_ip)
                    db.commit()
                    
                    logger.critical(f"IP bloqueada automáticamente: {ip}")
                    
            finally:
                db.close()
                
        except Exception as e:
            logger.error(f"Error bloqueando IP: {e}")
    
    def get_active_threats(self) -> List[Dict]:
        """Obtiene amenazas activas"""
        with self.lock:
            return self.active_threats.copy()
    
    def get_threat_statistics(self) -> Dict:
        """Obtiene estadísticas de amenazas"""
        with self.lock:
            stats = {
                "total_threats": len(self.active_threats),
                "by_type": defaultdict(int),
                "by_severity": defaultdict(int),
                "recent_threats": []
            }
            
            # Agrupar por tipo y severidad
            for threat in self.active_threats:
                stats["by_type"][threat["type"]] += 1
                stats["by_severity"][threat["severity"]] += 1
            
            # Amenazas recientes (última hora)
            one_hour_ago = datetime.now() - timedelta(hours=1)
            recent = [
                threat for threat in self.active_threats
                if datetime.fromisoformat(threat["timestamp"]) > one_hour_ago
            ]
            stats["recent_threats"] = recent
            
            return dict(stats)
    
    def start_monitoring(self):
        """Inicia el monitoreo de amenazas"""
        if not self.monitoring:
            self.monitoring = True
            monitor_thread = threading.Thread(target=self.monitor_network_activity, daemon=True)
            monitor_thread.start()
            logger.info("Monitor de amenazas iniciado")
    
    def stop_monitoring(self):
        """Detiene el monitoreo"""
        self.monitoring = False
        logger.info("Monitor de amenazas detenido")

# Instancia global del detector de amenazas
threat_detector = ThreatDetector()
