"""
Motor de Tiempo Real para NOVUS
Implementa WebSockets y Background Tasks para actualizaciones automáticas
"""

import asyncio
import json
import time
from datetime import datetime
from typing import Dict, List, Set
from fastapi import WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session
from database import SessionLocal, IntentoAcceso, Alerta, SectorAcceso, IPBloqueada
from network_scanner import network_scanner
from threat_detector import threat_detector
from vulnerability_scanner import vulnerability_scanner
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RealtimeEngine:
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
        self.background_tasks_running = False
        self.traffic_stats = {
            "total_requests": 0,
            "successful_logins": 0,
            "failed_attempts": 0,
            "blocked_ips": 0,
            "active_sessions": 0,
            "sector_access": {
                "fintech": {"attempts": 0, "success": 0, "blocked": 0},
                "logistica_movil": {"attempts": 0, "success": 0, "blocked": 0}
            },
            "recent_activity": []
        }
    
    async def connect(self, websocket: WebSocket):
        """Conecta un nuevo cliente WebSocket"""
        await websocket.accept()
        self.active_connections.add(websocket)
        logger.info(f"Cliente conectado. Total conexiones: {len(self.active_connections)}")
        
        # Enviar estado actual inmediatamente
        await self.send_update(websocket, self.get_current_stats())
    
    def disconnect(self, websocket: WebSocket):
        """Desconecta un cliente WebSocket"""
        self.active_connections.discard(websocket)
        logger.info(f"Cliente desconectado. Total conexiones: {len(self.active_connections)}")
    
    async def send_update(self, websocket: WebSocket, data: Dict):
        """Envía actualización a un cliente específico"""
        try:
            await websocket.send_text(json.dumps(data))
        except Exception as e:
            logger.error(f"Error enviando actualización: {e}")
            self.disconnect(websocket)
    
    async def broadcast(self, data: Dict):
        """Envía actualización a todos los clientes conectados"""
        if not self.active_connections:
            return
        
        disconnected = set()
        for connection in self.active_connections:
            try:
                await connection.send_text(json.dumps(data))
            except Exception as e:
                logger.error(f"Error en broadcast: {e}")
                disconnected.add(connection)
        
        # Limpiar conexiones rotas
        for connection in disconnected:
            self.disconnect(connection)
    
    def get_current_stats(self) -> Dict:
        """Obtiene estadísticas actuales de la base de datos"""
        db = SessionLocal()
        try:
            # Estadísticas de intentos de acceso
            total_intentos = db.query(IntentoAcceso).count()
            
            # Intentos por sector
            fintech_intentos = db.query(IntentoAcceso).filter(IntentoAcceso.sector_intentado == "fintech").count()
            logistica_intentos = db.query(IntentoAcceso).filter(IntentoAcceso.sector_intentado == "logistica_movil").count()
            
            # Accesos exitosos
            accesos_fintech = db.query(SectorAcceso).filter(SectorAcceso.sector == "fintech", SectorAcceso.is_active == True).count()
            accesos_logistica = db.query(SectorAcceso).filter(SectorAcceso.sector == "logistica_movil", SectorAcceso.is_active == True).count()
            
            # IPs bloqueadas
            ips_bloqueadas = db.query(IPBloqueada).count()
            
            # Alertas recientes (última hora)
            from datetime import datetime, timedelta
            hora_antes = datetime.now() - timedelta(hours=1)
            alertas_recientes = db.query(Alerta).filter(Alerta.fecha >= hora_antes.strftime("%Y-%m-%d %H:%M")).count()
            
            # Actividad reciente (últimos 10 intentos)
            intentos_recientes = db.query(IntentoAcceso).order_by(IntentoAcceso.fecha.desc()).limit(10).all()
            actividad_reciente = [
                {
                    "email": intento.email,
                    "sector": intento.sector_intentado,
                    "ip": intento.ip_address,
                    "fecha": intento.fecha,
                    "razon": intento.razon_bloqueo,
                    "tipo": "bloqueo" if intento.razon_bloqueo else "intento"
                }
                for intento in intentos_recientes
            ]
            
            return {
                "timestamp": datetime.now().isoformat(),
                "stats": {
                    "total_requests": total_intentos + accesos_fintech + accesos_logistica,
                    "successful_logins": accesos_fintech + accesos_logistica,
                    "failed_attempts": total_intentos,
                    "blocked_ips": ips_bloqueadas,
                    "active_sessions": len(self.active_connections),
                    "recent_alerts": alertas_recientes,
                    "sector_access": {
                        "fintech": {
                            "attempts": fintech_intentos,
                            "success": accesos_fintech,
                            "blocked": fintech_intentos - accesos_fintech
                        },
                        "logistica_movil": {
                            "attempts": logistica_intentos,
                            "success": accesos_logistica,
                            "blocked": logistica_intentos - accesos_logistica
                        }
                    },
                    "recent_activity": actividad_reciente
                }
            }
        except Exception as e:
            logger.error(f"Error obteniendo estadísticas: {e}")
            return {"error": str(e)}
        finally:
            db.close()
    
    async def update_traffic_stats(self):
        """Actualiza estadísticas de tráfico en tiempo real"""
        while True:
            try:
                stats = self.get_current_stats()
                await self.broadcast(stats)
                await asyncio.sleep(2)  # Actualizar cada 2 segundos
            except Exception as e:
                logger.error(f"Error en update_traffic_stats: {e}")
                await asyncio.sleep(5)
    
    async def monitor_security_events(self):
        """Monitorea eventos de seguridad en tiempo real"""
        while True:
            try:
                db = SessionLocal()
                
                # Buscar nuevos intentos de acceso
                from datetime import datetime, timedelta
                hace_10_segundos = datetime.now() - timedelta(seconds=10)
                
                nuevos_intentos = db.query(IntentoAcceso).filter(
                    IntentoAcceso.fecha >= hace_10_segundos.strftime("%Y-%m-%d %H:%M:%S")
                ).all()
                
                # Buscar nuevas alertas
                nuevas_alertas = db.query(Alerta).filter(
                    Alerta.fecha >= hace_10_segundos.strftime("%Y-%m-%d %H:%M:%S")
                ).all()
                
                if nuevos_intentos or nuevas_alertas:
                    event_data = {
                        "type": "security_event",
                        "timestamp": datetime.now().isoformat(),
                        "new_attempts": [
                            {
                                "email": intento.email,
                                "sector": intento.sector_intentado,
                                "ip": intento.ip_address,
                                "razon": intento.razon_bloqueo,
                                "fecha": intento.fecha
                            }
                            for intento in nuevos_intentos
                        ],
                        "new_alerts": [
                            {
                                "titulo": alerta.titulo,
                                "descripcion": alerta.descripcion,
                                "nivel": alerta.nivel,
                                "fecha": alerta.fecha
                            }
                            for alerta in nuevas_alertas
                        ]
                    }
                    
                    await self.broadcast(event_data)
                
                db.close()
                await asyncio.sleep(5)  # Verificar cada 5 segundos
                
            except Exception as e:
                logger.error(f"Error en monitor_security_events: {e}")
                await asyncio.sleep(10)
    
    async def start_background_tasks(self):
        """Inicia las tareas en segundo plano"""
        if self.background_tasks_running:
            return
        
        self.background_tasks_running = True
        logger.info("Iniciando tareas en segundo plano...")
        
        # Iniciar tareas concurrentes
        asyncio.create_task(self.update_traffic_stats())
        asyncio.create_task(self.monitor_security_events())
        asyncio.create_task(self.monitor_network_activity())
        asyncio.create_task(self.monitor_threats())
        asyncio.create_task(self.run_vulnerability_scan())
    
    def register_access_attempt(self, email: str, sector: str, success: bool, ip_address: str, reason: str = None):
        """Registra un intento de acceso y notifica en tiempo real"""
        try:
            # Actualizar estadísticas locales
            self.traffic_stats["total_requests"] += 1
            
            if success:
                self.traffic_stats["successful_logins"] += 1
                if sector in self.traffic_stats["sector_access"]:
                    self.traffic_stats["sector_access"][sector]["success"] += 1
            else:
                self.traffic_stats["failed_attempts"] += 1
                if sector in self.traffic_stats["sector_access"]:
                    self.traffic_stats["sector_access"][sector]["blocked"] += 1
            
            # Agregar a actividad reciente
            activity = {
                "email": email,
                "sector": sector,
                "ip": ip_address,
                "timestamp": datetime.now().isoformat(),
                "success": success,
                "reason": reason
            }
            
            self.traffic_stats["recent_activity"].insert(0, activity)
            if len(self.traffic_stats["recent_activity"]) > 20:
                self.traffic_stats["recent_activity"].pop()
            
            # Notificar a clientes (esto se manejará en el hilo principal)
            logger.info(f"Intento de acceso registrado: {email} -> {sector} ({'Exitoso' if success else 'Fallido'})")
            
        except Exception as e:
            logger.error(f"Error registrando intento: {e}")
    
    async def monitor_network_activity(self):
        """Monitorea actividad de red en tiempo real"""
        while True:
            try:
                # Obtener datos de red usando método seguro
                network_data = network_scanner.get_network_data()
                
                # Enviar datos de red a clientes
                network_update = {
                    "type": "network_update",
                    "timestamp": datetime.now().isoformat(),
                    "devices": network_data.get("devices", []),
                    "connections": network_data.get("connections", []),
                    "ngrok_connections": network_data.get("ngrok_connections", []),
                    "local_ip": network_data.get("local_ip", "unknown"),
                    "network_range": network_data.get("network_range", "unknown")
                }
                
                await self.broadcast(network_update)
                await asyncio.sleep(60)  # Escanear cada minuto
                
            except Exception as e:
                logger.error(f"Error en monitor_network_activity: {e}")
                await asyncio.sleep(30)
    
    async def monitor_threats(self):
        """Monitorea amenazas de seguridad en tiempo real"""
        # Iniciar el detector de amenazas
        threat_detector.start_monitoring()
        
        while True:
            try:
                # Obtener amenazas activas
                active_threats = threat_detector.get_active_threats()
                threat_stats = threat_detector.get_threat_statistics()
                
                # Enviar actualización de amenazas
                threat_update = {
                    "type": "threat_update",
                    "timestamp": datetime.now().isoformat(),
                    "active_threats": active_threats,
                    "statistics": threat_stats
                }
                
                await self.broadcast(threat_update)
                await asyncio.sleep(15)  # Actualizar cada 15 segundos
                
            except Exception as e:
                logger.error(f"Error en monitor_threats: {e}")
                await asyncio.sleep(30)
    
    async def run_vulnerability_scan(self):
        """Ejecuta escaneo de vulnerabilidades periódicamente"""
        # Esperar 30 segundos antes del primer escaneo
        await asyncio.sleep(30)
        
        while True:
            try:
                logger.info("Iniciando escaneo de vulnerabilidades...")
                vuln_report = vulnerability_scanner.scan_all_vulnerabilities()
                
                # Enviar reporte de vulnerabilidades
                vuln_update = {
                    "type": "vulnerability_update",
                    "timestamp": datetime.now().isoformat(),
                    "report": vuln_report
                }
                
                await self.broadcast(vuln_update)
                
                # Escanear cada 10 minutos
                await asyncio.sleep(600)
                
            except Exception as e:
                logger.error(f"Error en run_vulnerability_scan: {e}")
                await asyncio.sleep(300)

    async def handle_kernel_ws_message(self, data: dict) -> dict:
        """Procesa petición Kernel IA vía WebSocket — delega a ws_kernel_bridge."""
        from services.ai_kernel_core.ws_kernel_bridge import process_kernel_ws_message

        return process_kernel_ws_message(data)

    async def kernel_websocket_loop(self, websocket: WebSocket):
        """Loop /ws/kernel — extensión del realtime engine (proceso FastAPI separado)."""
        await self.connect(websocket)
        try:
            while True:
                raw = await websocket.receive_text()
                try:
                    request = json.loads(raw)
                except json.JSONDecodeError:
                    await websocket.send_json({
                        "status": "ERROR",
                        "message": "JSON inválido",
                        "executes_actions": False,
                    })
                    continue
                await websocket.send_json({"status": "PROCESSING", "action": request.get("action")})
                result = await self.handle_kernel_ws_message(request)
                await websocket.send_json(result)
        except WebSocketDisconnect:
            self.disconnect(websocket)


# Instancia global del motor de tiempo real
realtime_engine = RealtimeEngine()
