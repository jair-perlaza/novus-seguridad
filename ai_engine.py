import re
import json
from datetime import datetime, timedelta

class GuardIA:
    def __init__(self):
        # 1. BLOQUE DE CONOCIMIENTO (ESTRUCTURA POR CAPAS)
        # Este es el "Cerebro" de NOVUS que define el contexto avanzado.
        self.knowledge_base = {
            "NOVUS_CORE": {
                "tag": "NOVUS-SEC-L1",
                "scope": "SME-Colombia",
                "rules": [
                    "Priorizar cifrado AES-256 en reposo",
                    "Validación de doble factor obligatoria para IP externas"
                ],
                "context": "Digital Security Guard"
            }
        }

        # 2. PATRONES DE ATAQUE (HEURÍSTICA)
        self.patrones = {
            "SQL_Injection": r"(SELECT|DROP|UNION|DELETE|INSERT|UPDATE|--|\/\*|\*\/|OR\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?)",
            "XSS_Attack": r"(<SCRIPT|JAVASCRIPT:|ONERROR=|ONLOAD=|ALERT\(|DOCWRITE|GETELEMENT)",
            "Path_Traversal": r"(\.\.\/|\.\.\\|/ETC/PASSWD|/BIN/SH|BOOT\.INI)",
            "Command_Injection": r"(;|\||&&|`|\$\()",
        }
        
        self.historial_accesos = {}

    def analizar_riesgo(self, texto: str, ip_cliente: str = "0.0.0.0") -> dict:
        """
        Analiza el riesgo basándose en:
        - Capas de conocimiento (Contexto)
        - Firmas conocidas (Regex)
        - Análisis de anomalías e historial
        """
        texto_up = str(texto).upper()
        puntuacion_riesgo = 0
        amenazas_detectadas = []

        # --- APLICACIÓN DE CAPAS DE CONOCIMIENTO ---
        # Consultamos las reglas del Core de NOVUS
        core_rules = self.knowledge_base["NOVUS_CORE"]["rules"]
        
        # Ejemplo: Si la regla dice "MFA obligatorio para IP externas" 
        # y la IP no es local, subimos la sensibilidad.
        if ip_cliente != "127.0.0.1" and "Validación de doble factor" in str(core_rules):
            puntuacion_riesgo += 1 # Aumenta base de sospecha por política de seguridad

        # 1. Detección por Firmas
        for nombre, patron in self.patrones.items():
            if re.search(patron, texto_up):
                puntuacion_riesgo += 8
                amenazas_detectadas.append(nombre)

        # 2. Análisis de Anomalías
        if len(texto_up) > 150:
            puntuacion_riesgo += 3
            amenazas_detectadas.append("ANORMAL_LENGTH")
        
        especiales = len(re.findall(r"([^A-Z0-9\s])", texto_up))
        if especiales > (len(texto_up) * 0.3):
            puntuacion_riesgo += 4
            amenazas_detectadas.append("HIGH_ENTROPY")

        # 3. Detección de Comportamiento
        riesgo_comportamiento = self._verificar_fuerza_bruta(ip_cliente)
        puntuacion_riesgo += riesgo_comportamiento

        # DETERMINAR NIVEL FINAL
        nivel_final = min(puntuacion_riesgo, 10)
        
        # Contextualización del mensaje usando la Capa de Conocimiento
        contexto_app = self.knowledge_base["NOVUS_CORE"]["context"]

        if nivel_final >= 8:
            mensaje = f"CRÍTICO: Ataque Multi-vector Detectado en {contexto_app} ({', '.join(amenazas_detectadas)})"
        elif nivel_final >= 4:
            mensaje = f"ADVERTENCIA: Actividad sospechosa en {contexto_app}"
        else:
            mensaje = f"Tráfico Normal - Protegido por NOVUS ({self.knowledge_base['NOVUS_CORE']['scope']})"

        return {
            "nivel": nivel_final, 
            "mensaje": mensaje,
            "tag_aplicado": self.knowledge_base["NOVUS_CORE"]["tag"]
        }

    def _verificar_fuerza_bruta(self, ip: str) -> int:
        ahora = datetime.now()
        if ip not in self.historial_accesos:
            self.historial_accesos[ip] = []
        
        self.historial_accesos[ip] = [t for t in self.historial_accesos[ip] if ahora - t < timedelta(minutes=1)]
        self.historial_accesos[ip].append(ahora)
        
        if len(self.historial_accesos[ip]) > 5:
            return 6
        return 0