"""
Advanced Detector Service for NOVUS
Provides advanced threat detection capabilities including:
- File entropy analysis for ransomware detection
- Process scanning for suspicious activity
- Port scanning for vulnerable services
- Real-time threat monitoring
- Windows-specific threat detection
"""
import os
import math
import psutil
import socket
import hashlib
import requests
import tempfile
import platform
from typing import Optional
from utils.logger import logger
from utils.host_data import get_local_ip, get_disk_usage

EICAR_SIGNATURE = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)


class AdvancedDetector:
    """Advanced threat detection service"""
    
    def __init__(self):
        self.vt_api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
    
    def calculate_entropy(self, file_path):
        """
        Calculate Shannon entropy of a file.
        Ransomware and obfuscated trojans have high entropy (close to 8.0).
        Ideal for detecting malicious attachments or modified binaries.
        """
        if not os.path.exists(file_path):
            return 0
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            if not data:
                return 0
            entropy = 0
            for i in range(256):
                p_i = float(data.count(i)) / len(data)
                if p_i > 0:
                    entropy += -p_i * math.log(p_i, 2)
            return round(entropy, 2)
        except PermissionError:
            return 0
        except Exception as e:
            logger.debug(f"Error calculating entropy: {e}")
            return 0
    
    def scan_file_reputation(self, file_path):
        """
        Calculate SHA256 hash and verify global reputation in real-time.
        """
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            file_hash = sha256_hash.hexdigest()
        except Exception as e:
            logger.error(f"Error reading file for hash: {e}")
            return {"error": "No se pudo leer el archivo"}
        
        # Query global reputation in real-time
        if not self.vt_api_key:
            return {"hash": file_hash, "resultado": "API_KEY_NO_CONFIGURADA"}
        
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": self.vt_api_key}
        
        try:
            response = requests.get(url, headers=headers, timeout=5)
            if response.status_code == 200:
                stats = response.json()['data']['attributes']['last_analysis_stats']
                return {
                    "hash": file_hash,
                    "malicioso": stats['malicious'],
                    "sospechoso": stats['suspicious'],
                    "resultado": "PELIGRO" if stats['malicious'] > 0 else "SEGURO"
                }
            return {"hash": file_hash, "resultado": "DESCONOCIDO (Archivo nuevo u oculto)"}
        except requests.exceptions.RequestException as e:
            logger.error(f"VirusTotal API error: {e}")
            return {"hash": file_hash, "resultado": "Error de conexión con el motor global"}
    
    def scan_running_processes(self):
        """
        Analyze active processes for critical anomalies in Fintech/Logistics:
        - Hidden processes or without valid executables on disk
        - Scripts attempting to mine cryptocurrency or hijack resources (Ransomware)
        - Windows-specific threats (PowerShell encoded commands, persistence, etc.)
        """
        suspicious_processes = []
        
        for proc in psutil.process_iter(['pid', 'name', 'username', 'exe', 'cmdline']):
            try:
                proc_info = proc.info
                name = (proc_info.get('name') or '').lower()
                cmdline = " ".join(proc_info['cmdline']) if proc_info.get('cmdline') else ""
                cmdline_lower = cmdline.lower()

                # Only explicit attack patterns — never flag normal Windows/system tools.
                indicators = [
                    "nc -e", "bash -i", "sh -i", "/dev/tcp/", "reverse_shell",
                    "xmrig", "minerd", "mimikatz", "invoke-mimikatz", "hydra",
                    "powershell -enc", "powershell -encodedcommand", "powershell -e ",
                    "iex (new-object net.webclient)", "downloadstring(",
                ]

                is_malicious = any(
                    indicator in cmdline_lower or indicator in name
                    for indicator in indicators
                )

                if is_malicious:
                    suspicious_processes.append({
                        "pid": proc_info['pid'],
                        "name": proc_info['name'],
                        "user": proc_info.get('username'),
                        "path": proc_info.get('exe'),
                        "command_line": cmdline,
                        "description": "Patrón malicioso confirmado en línea de comandos",
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        try:
            from services.malware_behavior_engine import analyze_process
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
                try:
                    pi = proc.info
                    cmd = pi.get('cmdline') or []
                    for f in analyze_process({
                        "pid": pi.get("pid"),
                        "name": pi.get("name"),
                        "path": pi.get("exe"),
                        "command_line": " ".join(cmd) if cmd else "",
                    }):
                        suspicious_processes.append({
                            "pid": pi.get("pid"),
                            "name": pi.get("name"),
                            "path": pi.get("exe"),
                            "command_line": " ".join(cmd) if cmd else "",
                            "description": f.get("reason"),
                            "technique": f.get("technique"),
                            "risk": f.get("risk"),
                            "motor": "malware_behavior_engine",
                        })
                except Exception:
                    continue
        except Exception as exc:
            logger.debug("malware_behavior_engine merge: %s", exc)
        
        return suspicious_processes

    def evaluate_cmdline_threat(self, name: str = "", cmdline: str = "") -> Optional[dict]:
        """Evalúa patrones maliciosos en cmdline sin requerir proceso activo (lab seguro)."""
        name_l = (name or "").lower()
        cmdline_l = (cmdline or "").lower()
        indicators = [
            "nc -e", "bash -i", "sh -i", "/dev/tcp/", "reverse_shell",
            "xmrig", "minerd", "mimikatz", "invoke-mimikatz", "hydra",
            "powershell -enc", "powershell -encodedcommand", "powershell -e ",
            "iex (new-object net.webclient)", "downloadstring(",
        ]
        for indicator in indicators:
            if indicator in cmdline_l or indicator in name_l:
                return {
                    "name": name or "lab-process",
                    "command_line": cmdline,
                    "indicator": indicator,
                    "description": "Patrón malicioso confirmado en línea de comandos",
                }
        try:
            from services.malware_behavior_engine import analyze_process
            hits = analyze_process({"name": name, "command_line": cmdline})
            if hits:
                h = hits[0]
                return {
                    "name": name or "lab-process",
                    "command_line": cmdline,
                    "indicator": h.get("technique"),
                    "description": h.get("reason"),
                    "motor": h.get("motor"),
                    "risk": h.get("risk"),
                }
        except Exception:
            pass
        return None

    def detect_eicar_file(self, file_path: str) -> dict:
        """Detecta firma EICAR estándar — prueba antivirus segura, sin malware real."""
        if not os.path.exists(file_path):
            return {"detected": False, "reason": "file_not_found"}
        try:
            with open(file_path, "rb") as fh:
                data = fh.read(128)
            detected = EICAR_SIGNATURE in data
            entropy = self.calculate_entropy(file_path) if detected else 0
            return {
                "detected": detected,
                "signature": "EICAR-STANDARD-ANTIVIRUS-TEST-FILE",
                "entropy": entropy,
                "path": file_path,
            }
        except Exception as exc:
            return {"detected": False, "reason": str(exc)}
    
    def scan_open_ports(self, target_ip=None):
        """
        Scan for open ports on a target IP using real socket checks.
        Returns only ports confirmed open on the host.
        """
        if not target_ip:
            target_ip = get_local_ip()
        if not target_ip:
            return []

        known_services = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            53: "DNS",
            80: "HTTP",
            135: "Windows RPC",
            139: "NetBIOS",
            443: "HTTPS",
            445: "SMB",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            8080: "HTTP-ALT",
            8443: "HTTPS-ALT",
        }

        open_ports = []

        for port, service in known_services.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target_ip, port))
                if result == 0:
                    open_ports.append({
                        "port": port,
                        "status": "OPEN",
                        "service": service,
                        "target_ip": target_ip,
                        "description": f"Puerto {port} abierto ({service})"
                    })
                sock.close()
            except Exception as e:
                logger.error(f"Error scanning port {port}: {e}")

        return open_ports

    def scan_system_health(self):
        """
        Return raw system metrics and real scan findings only.
        """
        try:
            cpu = psutil.cpu_percent(interval=1.0)
            memory = psutil.virtual_memory()
            disk = get_disk_usage()

            suspicious_processes = self.scan_running_processes()
            open_ports = self.scan_open_ports()

            return {
                "cpu": round(cpu, 1),
                "memory": round(memory.percent, 1),
                "disk": round(disk.percent, 1),
                "suspicious_processes": suspicious_processes,
                "open_ports": open_ports,
                "suspicious_process_count": len(suspicious_processes),
                "open_port_count": len(open_ports),
            }
        except Exception as e:
            logger.error(f"Error in system health scan: {e}")
            return {
                "status": "error",
                "message": str(e)
            }
    
    def detect_antivirus_status(self):
        """
        Detect if antivirus is enabled (Windows only).
        """
        if platform.system() != "Windows":
            return {"status": "NOT_WINDOWS", "message": "Antivirus check only available on Windows"}
        
        try:
            import subprocess
            result = subprocess.run(
                ['powershell', '-Command', 'Get-MpComputerStatus'],
                capture_output=True,
                text=True,
                timeout=10
            )
            if "AntivirusEnabled" not in result.stdout or "False" in result.stdout:
                return {"status": "DISABLED", "message": "Windows Defender not active"}
            return {"status": "ENABLED", "message": "Antivirus active"}
        except Exception as e:
            logger.error(f"Error checking antivirus: {e}")
            return {"status": "UNKNOWN", "message": "Could not determine antivirus status"}
    
    def detect_windows_persistence(self):
        """
        Detect Windows persistence mechanisms:
        - Scheduled tasks
        - Registry run keys
        - Startup folders
        """
        if platform.system() != "Windows":
            return {"status": "NOT_WINDOWS", "message": "Windows persistence check only available on Windows"}

        defer_subprocess = False
        try:
            from services.resource_backpressure_service import (
                CAT_HEAVY_AGG,
                get_backpressure_level,
                should_run_background,
            )
            defer_subprocess = not should_run_background(CAT_HEAVY_AGG)
            if defer_subprocess:
                logger.debug(
                    "detect_windows_persistence deferred — backpressure %s",
                    get_backpressure_level(),
                )
        except Exception:
            defer_subprocess = False

        suspicious_persistence = []

        if not defer_subprocess:
            try:
                import subprocess
                # Check scheduled tasks
                result = subprocess.run(
                    ['schtasks', '/query', '/fo', 'csv'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.stdout:
                    suspicious_persistence.append({
                        "type": "scheduled_tasks",
                        "count": len([line for line in result.stdout.split('\n') if line]),
                        "status": "DETECTED"
                    })
            except Exception as e:
                logger.error(f"Error checking scheduled tasks: {e}")
        
        if not defer_subprocess:
            try:
                import subprocess
                # Check registry run keys
                result = subprocess.run(
                    ['reg', 'query', 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.stdout and len(result.stdout) > 100:
                    suspicious_persistence.append({
                        "type": "registry_run",
                        "status": "DETECTED",
                        "data": result.stdout[:200]
                    })
            except Exception as e:
                logger.error(f"Error checking registry: {e}")
        
        return suspicious_persistence


# Singleton instance
advanced_detector = AdvancedDetector()
