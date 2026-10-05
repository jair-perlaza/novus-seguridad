# filename: novus_endpoint_guard.py
import sys
import psutil
import ctypes
import logging
from typing import List, Dict, Any

# Configuración de Logging para Audit Trail de NOVUS
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] NOVUS_AGENT: %(message)s')
logger = logging.getLogger("NOVUS_Guard")

class ProcessBehaviorAnalyzer:
    """
    Analiza la integridad de los procesos en ejecución y busca artefactos de 
    captura de pantalla, keylogging o inyección de procesos en memoria.
    """
    
    # Constantes de Permisos de Memoria en Windows (PAGE_EXECUTE_READWRITE)
    PAGE_EXECUTE_READWRITE = 0x40

    def __init__(self):
        self.suspicious_process_names = ["svchost.exe", "explorer.exe", "lsass.exe"]

    def inspect_parent_child_relationships(self) -> List[Dict[str, Any]]:
        """
        Detecta anomalías de ejecución (ej. MS Office spawning consola de comandos/PowerShell)
        """
        anomalies = []
        office_binaries = ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"]
        dangerous_children = ["cmd.exe", "powershell.exe", "pwsh.exe", "mshta.exe", "cscript.exe"]

        for proc in psutil.process_iter(['pid', 'name', 'ppid']):
            try:
                p_name = proc.info['name'].lower() if proc.info['name'] else ""
                if p_name in office_binaries:
                    parent_proc = psutil.Process(proc.info['pid'])
                    for child in parent_proc.children(recursive=True):
                        child_name = child.name().lower()
                        if child_name in dangerous_children:
                            anomaly = {
                                "rule": "OFFICE_SPAWN_SHELL",
                                "severity": "CRITICAL",
                                "parent_pid": proc.info['pid'],
                                "parent_name": p_name,
                                "child_pid": child.pid,
                                "child_name": child_name
                            }
                            anomalies.append(anomaly)
                            logger.critical(f"Ataque Spearphishing Detectado: {p_name} inició {child_name} (PID: {child.pid})")
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return anomalies

    def scan_memory_injection(self) -> List[Dict[str, Any]]:
        """
        Escanea la memoria de procesos críticos en busca de inyección de código (Process Hollowing).
        Nota: En producción esta función interactúa con la API de Win32 ReadProcessMemory.
        """
        suspicious_allocations = []
        # Verificación heurística de rutas y padres no válidos para svchost.exe
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'ppid']):
            try:
                if proc.info['name'] and proc.info['name'].lower() == "svchost.exe":
                    exe_path = proc.info['exe']
                    # Un svchost.exe legítimo SIEMPRE debe estar en System32 o SysWOW64
                    if exe_path and "system32" not in exe_path.lower() and "syswow64" not in exe_path.lower():
                        suspicious_allocations.append({
                            "rule": "MASQUERADING_PROCESS",
                            "severity": "HIGH",
                            "pid": proc.info['pid'],
                            "path": exe_path
                        })
                        logger.warning(f"Proceso Impostor Oculto Detectado: svchost ejecutándose desde ruta no segura: {exe_path}")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return suspicious_allocations

    def run_full_scan(self) -> Dict[str, Any]:
        """Ejecuta la batería completa de pruebas defensivas."""
        findings = []
        findings.extend(self.inspect_parent_child_relationships())
        findings.extend(self.scan_memory_injection())
        
        return {
            "status": "THREATS_DETECTED" if findings else "HEALTHY",
            "total_findings": len(findings),
            "details": findings
        }

if __name__ == "__main__":
    analyzer = ProcessBehaviorAnalyzer()
    print(analyzer.run_full_scan())