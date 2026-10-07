import hashlib
import hmac
import secrets
import uuid
import platform
import socket
from datetime import datetime
from typing import Dict, Optional, Tuple
from database import SessionLocal, SectorAcceso, DispositivoConfiado, IntentoAcceso, Alerta, Usuario
from werkzeug.security import check_password_hash
from realtime_engine import realtime_engine

class SectorAuthSystem:
    def __init__(self):
        self.sectores_permitidos = {
            "fintech": {
                "usuarios_permitidos": ["ciso@novus.local", "cto@novus.local"],
                "descripcion": "Sector Fintech - Acceso exclusivo CISO y CTO"
            },
            "logistica_movil": {
                "usuarios_permitidos": ["cpo@novus.local", "cso@novus.local"],
                "descripcion": "Sector Logística/Movilidad - Acceso exclusivo CPO y CSO"
            }
        }
    
    def generar_device_fingerprint(self, request_data: Dict) -> str:
        """Genera un fingerprint único del dispositivo"""
        fingerprint_data = f"{request_data.get('user_agent', '')}-{request_data.get('ip_address', '')}-{platform.node()}"
        return hashlib.sha256(fingerprint_data.encode()).hexdigest()
    
    def generar_device_id(self) -> str:
        """Genera un ID único para el dispositivo"""
        return str(uuid.uuid4())
    
    def validar_acceso_sector(self, email: str, password: str, sector: str, request_data: Dict) -> Tuple[bool, str, Optional[str]]:
        """
        Valida el acceso al sector específico
        Returns: (acceso_permitido, mensaje, device_id)
        """
        db = SessionLocal()
        
        try:
            # Verificar si el sector existe
            if sector not in self.sectores_permitidos:
                self.registrar_intento_no_autorizado(email, sector, request_data, "Sector no existe")
                return False, "Sector no válido", None
            
            # Verificar si el usuario está permitido en el sector
            sector_config = self.sectores_permitidos[sector]
            if email not in sector_config["usuarios_permitidos"]:
                self.registrar_intento_no_autorizado(email, sector, request_data, "Usuario no autorizado para este sector")
                return False, "Usuario no autorizado para este sector", None
            
            # Verificar contraseña contra base de datos SQLite (sin credenciales hardcodeadas)
            usuario = db.query(Usuario).filter(Usuario.email == email, Usuario.is_active == True).first()
            if not usuario or not usuario.hashed_password:
                self.registrar_intento_no_autorizado(email, sector, request_data, "Usuario no registrado en base de datos")
                return False, "Sin credenciales configuradas en base de datos", None
            if not check_password_hash(usuario.hashed_password, password):
                self.registrar_intento_no_autorizado(email, sector, request_data, "Contraseña incorrecta")
                return False, "Credenciales incorrectas", None
            if usuario.sector and usuario.sector.replace(" ", "_").lower() != sector.replace(" ", "_").lower():
                self.registrar_intento_no_autorizado(email, sector, request_data, "Sector no coincide con perfil")
                return False, "Usuario no autorizado para este sector", None
            
            # Generar fingerprint del dispositivo
            device_fingerprint = self.generar_device_fingerprint(request_data)
            
            # Verificar si el dispositivo ya está registrado para este usuario y sector
            acceso_existente = db.query(SectorAcceso).filter(
                SectorAcceso.email == email,
                SectorAcceso.sector == sector,
                SectorAcceso.dispositivo_fingerprint == device_fingerprint,
                SectorAcceso.is_active == True
            ).first()
            
            if acceso_existente:
                # Actualizar último acceso
                acceso_existente.ultimo_acceso = datetime.now().strftime("%Y-%m-%d %H:%M")
                db.commit()
                # Registrar evento en tiempo real
                realtime_engine.register_access_attempt(email, sector, True, request_data.get('ip_address', ''))
                
                return True, "Acceso concedido - dispositivo reconocido", acceso_existente.dispositivo_id
            
            # Si es un nuevo dispositivo, registrarlo
            device_id = self.generar_device_id()
            nuevo_acceso = SectorAcceso(
                email=email,
                sector=sector,
                dispositivo_id=device_id,
                dispositivo_fingerprint=device_fingerprint
            )
            
            # También registrar en dispositivos confiados
            dispositivo_confiado = DispositivoConfiado(
                usuario_email=email,
                dispositivo_id=device_id,
                fingerprint=device_fingerprint,
                user_agent=request_data.get('user_agent', ''),
                ip_address=request_data.get('ip_address', '')
            )
            
            db.add(nuevo_acceso)
            db.add(dispositivo_confiado)
            db.commit()
            
            # Registrar evento en tiempo real
            realtime_engine.register_access_attempt(email, sector, True, request_data.get('ip_address', ''))
            
            return True, "Acceso concedido - nuevo dispositivo registrado", device_id
            
        except Exception as e:
            db.rollback()
            return False, f"Error en validación: {str(e)}", None
        finally:
            db.close()
    
    def registrar_intento_no_autorizado(self, email: str, sector: str, request_data: Dict, razon: str):
        """Registra un intento de acceso no autorizado y genera alerta"""
        db = SessionLocal()
        
        try:
            # Registrar intento
            intento = IntentoAcceso(
                email=email,
                sector_intentado=sector,
                dispositivo_id=request_data.get('device_id', 'desconocido'),
                ip_address=request_data.get('ip_address', 'desconocida'),
                user_agent=request_data.get('user_agent', 'desconocido'),
                razon_bloqueo=razon
            )
            
            db.add(intento)
            
            # Generar alerta de seguridad
            alerta = Alerta(
                titulo=f"ALERTA DE SEGURIDAD: Intento de acceso no autorizado",
                descripcion=f"""
                DETALLES DEL INCIDENTE:
                • Email: {email}
                • Sector intentado: {sector}
                • IP: {request_data.get('ip_address', 'desconocida')}
                • Dispositivo: {request_data.get('device_id', 'desconocido')}
                • User Agent: {request_data.get('user_agent', 'desconocido')}
                • Fecha: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
                • Razón del bloqueo: {razon}
                
                SECTOR AFECTADO: {sector.upper()}
                NIVEL DE RIESGO: CRÍTICO
                
    ACCIONES RECOMENDADAS:
    1. Verificar la identidad del usuario
    2. Monitorear actividad adicional desde esta IP
    3. Considerar bloqueo de IP si hay intentos múltiples
                """,
                nivel="Critical"
            )
            
            db.add(alerta)
            db.commit()
            
            # Registrar evento en tiempo real
            realtime_engine.register_access_attempt(email, sector, False, request_data.get('ip_address', ''), razon)
            
        except Exception as e:
            db.rollback()
            print(f"Error al registrar intento no autorizado: {e}")
        finally:
            db.close()
    
    def verificar_dispositivo_confiado(self, email: str, device_id: str, sector: str) -> bool:
        """Verifica si el dispositivo está confiado para el usuario y sector"""
        db = SessionLocal()
        
        try:
            dispositivo = db.query(SectorAcceso).filter(
                SectorAcceso.email == email,
                SectorAcceso.dispositivo_id == device_id,
                SectorAcceso.sector == sector,
                SectorAcceso.is_active == True
            ).first()
            
            return dispositivo is not None
            
        except Exception:
            return False
        finally:
            db.close()
    
    def obtener_info_sector(self, sector: str) -> Optional[Dict]:
        """Obtiene información del sector"""
        return self.sectores_permitidos.get(sector)
    
    def listar_accesos_usuario(self, email: str) -> list:
        """Lista todos los accesos registrados para un usuario"""
        db = SessionLocal()
        
        try:
            accesos = db.query(SectorAcceso).filter(
                SectorAcceso.email == email
            ).all()
            
            return [{
                'sector': acceso.sector,
                'dispositivo_id': acceso.dispositivo_id,
                'fecha_registro': acceso.fecha_registro,
                'ultimo_acceso': acceso.ultimo_acceso,
                'is_active': acceso.is_active
            } for acceso in accesos]
            
        except Exception:
            return []
        finally:
            db.close()

# Instancia global del sistema de autenticación sectorial
sector_auth = SectorAuthSystem()
