"""
System Monitor Service for NOVUS
Provides real-time system metrics with thread-safe caching
"""
import threading
import time
import psutil
from datetime import datetime
from typing import Optional
from utils.host_data import get_disk_usage
from utils.logger import logger
from core.config import Config


class SystemMonitor:
    """
    Thread-safe system monitor with caching
    Provides real-time system metrics without excessive resource usage
    """
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self._initialized = True
        self._cache = {}
        self._cache_lock = threading.Lock()
        self._last_update = 0
        self._cache_ttl = 5  # Cache TTL in seconds
        self._traffic_lock = threading.Lock()
        self._traffic_prev = None  # {ts, bytes_recv, bytes_sent, packets_recv, packets_sent, ifaces}
        self._traffic_last = None
        self._start_background_refresh()
    
    def _start_background_refresh(self) -> None:
        """Precalienta métricas sin bloquear requests HTTP."""
        def _loop():
            import time as _time
            while True:
                try:
                    self.get_system_status(force_refresh=True)
                    self.sample_traffic_rates()
                except Exception as exc:
                    logger.debug("system_monitor refresh: %s", exc)
                _time.sleep(max(self._cache_ttl, 3))

        threading.Thread(target=_loop, daemon=True, name="SystemMonitorRefresh").start()

    @staticmethod
    def _is_loopback_iface(name: str) -> bool:
        n = (name or "").strip().lower()
        return (
            n.startswith("lo")
            or "loopback" in n
            or n.startswith("isatap")
            or n.startswith("teredo")
        )

    def _read_host_io_counters(self):
        """Agrega contadores de interfaces reales (excluye loopback/virtuales obvios)."""
        try:
            pernic = psutil.net_io_counters(pernic=True) or {}
        except Exception as exc:
            logger.debug("net_io_counters(pernic): %s", exc)
            pernic = {}

        if pernic:
            recv = sent = pk_r = pk_s = 0
            used = []
            skipped = []
            for name, st in pernic.items():
                if self._is_loopback_iface(name):
                    skipped.append(name)
                    continue
                # Interfaz sin actividad nunca vista — aún cuenta si está up en el agregado OS
                recv += int(getattr(st, "bytes_recv", 0) or 0)
                sent += int(getattr(st, "bytes_sent", 0) or 0)
                pk_r += int(getattr(st, "packets_recv", 0) or 0)
                pk_s += int(getattr(st, "packets_sent", 0) or 0)
                used.append(name)
            if used:
                return {
                    "bytes_recv": recv,
                    "bytes_sent": sent,
                    "packets_recv": pk_r,
                    "packets_sent": pk_s,
                    "interfaces": used,
                    "skipped_interfaces": skipped,
                    "aggregation": "non_loopback",
                }

        # Fallback: contador agregado del SO (incluye loopback)
        net = psutil.net_io_counters()
        if not net:
            return None
        return {
            "bytes_recv": int(net.bytes_recv or 0),
            "bytes_sent": int(net.bytes_sent or 0),
            "packets_recv": int(net.packets_recv or 0),
            "packets_sent": int(net.packets_sent or 0),
            "interfaces": ["(aggregate)"],
            "skipped_interfaces": [],
            "aggregation": "psutil_aggregate",
        }

    def sample_traffic_rates(self) -> dict:
        """
        Muestrea deltas reales de psutil.net_io_counters sin sleep en hot path.
        Primer tick → PENDING; siguientes → MB transferidos en la ventana + Mbps.
        """
        now = time.time()
        try:
            counters = self._read_host_io_counters()
        except Exception as exc:
            logger.debug("sample_traffic_rates read: %s", exc)
            counters = None

        if not counters:
            result = {
                "measured": False,
                "pending": False,
                "data_state": "NOT_AVAILABLE",
                "display": "Tráfico no disponible",
                "source": "psutil.net_io_counters",
                "traffic_recv_mb": None,
                "traffic_sent_mb": None,
                "recv_mbps": None,
                "sent_mbps": None,
                "packets_recv_delta": None,
                "packets_sent_delta": None,
            }
            with self._traffic_lock:
                self._traffic_last = result
            return result

        with self._traffic_lock:
            prev = self._traffic_prev
            if prev is not None and (now - float(prev["ts"])) < 1.0 and self._traffic_last:
                return dict(self._traffic_last)

            self._traffic_prev = {
                "ts": now,
                "bytes_recv": counters["bytes_recv"],
                "bytes_sent": counters["bytes_sent"],
                "packets_recv": counters["packets_recv"],
                "packets_sent": counters["packets_sent"],
            }

            if prev is None:
                result = {
                    "measured": False,
                    "pending": True,
                    "data_state": "PENDING",
                    "display": "Tráfico pendiente (calibrando)",
                    "source": "psutil.net_io_counters",
                    "unit": "MB/s",
                    "interfaces": counters.get("interfaces") or [],
                    "aggregation": counters.get("aggregation"),
                    "cumulative_recv_bytes": counters["bytes_recv"],
                    "cumulative_sent_bytes": counters["bytes_sent"],
                    "traffic_recv_mb": None,
                    "traffic_sent_mb": None,
                    "recv_mbps": None,
                    "sent_mbps": None,
                }
                self._traffic_last = result
                return result

            elapsed = max(now - float(prev["ts"]), 0.1)
            recv_delta = max(int(counters["bytes_recv"]) - int(prev["bytes_recv"]), 0)
            sent_delta = max(int(counters["bytes_sent"]) - int(prev["bytes_sent"]), 0)
            pk_r_delta = max(int(counters["packets_recv"]) - int(prev["packets_recv"]), 0)
            pk_s_delta = max(int(counters["packets_sent"]) - int(prev["packets_sent"]), 0)

            recv_mb = round(recv_delta / (elapsed * (1024 ** 2)), 4)  # MB/s
            sent_mb = round(sent_delta / (elapsed * (1024 ** 2)), 4)  # MB/s
            recv_mbps = round((recv_delta * 8) / (elapsed * 1_000_000), 4)
            sent_mbps = round((sent_delta * 8) / (elapsed * 1_000_000), 4)

            result = {
                "measured": True,
                "pending": False,
                "data_state": "LIVE",
                "display": None,
                "source": "psutil.net_io_counters delta",
                "unit": "MB/s",
                "window_sec": round(elapsed, 2),
                "interfaces": counters.get("interfaces") or [],
                "skipped_interfaces": counters.get("skipped_interfaces") or [],
                "aggregation": counters.get("aggregation"),
                "cumulative_recv_bytes": counters["bytes_recv"],
                "cumulative_sent_bytes": counters["bytes_sent"],
                "traffic_recv_mb": recv_mb,
                "traffic_sent_mb": sent_mb,
                "recv_mbps": recv_mbps,
                "sent_mbps": sent_mbps,
                "packets_recv_delta": pk_r_delta,
                "packets_sent_delta": pk_s_delta,
            }
            self._traffic_last = result
            return result

    def get_last_traffic_sample(self) -> Optional[dict]:
        with self._traffic_lock:
            return dict(self._traffic_last) if self._traffic_last else None

    def get_system_status(self, force_refresh=False):
        """
        Get current system status with caching
        Args:
            force_refresh: Force refresh even if cache is valid
        Returns:
            Dictionary with system metrics
        """
        current_time = time.time()
        
        # Check if cache is valid
        if not force_refresh and (current_time - self._last_update) < self._cache_ttl:
            return self._cache
        
        # Nunca bloquear requests HTTP esperando recolección psutil en otro hilo
        acquired = self._cache_lock.acquire(blocking=False)
        if not acquired:
            return self._cache if self._cache else self._get_fallback_metrics()
        
        try:
            # Double-check after acquiring lock
            if not force_refresh and (current_time - self._last_update) < self._cache_ttl:
                return self._cache
            
            try:
                metrics = self._collect_metrics()
                self._cache = metrics
                self._last_update = current_time
                return metrics
            except Exception as e:
                logger.error(f"Error collecting system metrics: {e}", exc_info=True)
                return self._cache if self._cache else self._get_fallback_metrics()
        finally:
            self._cache_lock.release()
    
    def _collect_metrics(self):
        """
        Collect system metrics
        Returns:
            Dictionary with system metrics
        """
        try:
            cpu_percent = psutil.cpu_percent(interval=0)
            memory = psutil.virtual_memory()
            
            # Try disk usage with fallback for psutil compatibility issues
            try:
                disk = get_disk_usage()
            except (SystemError, OSError, ValueError, TypeError):
                # Fallback values if disk_usage fails
                disk = type('obj', (object,), {
                    'percent': 0,
                    'total': 0,
                    'used': 0,
                    'free': 0
                })()
            
            network = psutil.net_io_counters()
            boot_time = psutil.boot_time()
            
            try:
                procesos_activos = len(psutil.pids())
            except Exception:
                procesos_activos = self._cache.get("procesos_activos")
            users = len(psutil.users())
            uptime = time.time() - boot_time

            try:
                from services.performance_cache import peek_cached

                conn_val = peek_cached("proc_conn_count")
                if conn_val is None:
                    conexiones_activas = self._cache.get("conexiones_activas")
                else:
                    conexiones_activas = conn_val
            except Exception:
                conexiones_activas = self._cache.get("conexiones_activas", 0)
            
            metrics = {
                "cpu": cpu_percent,
                "ram": memory.percent,
                "disk": disk.percent,
                "ram_total": f"{memory.total / (1024**3):.1f} GB",
                "ram_usada": f"{memory.used / (1024**3):.1f} GB",
                "ram_disponible": f"{memory.available / (1024**3):.1f} GB",
                "disk_total": f"{disk.total / (1024**3):.1f} GB",
                "disk_usado": f"{disk.used / (1024**3):.1f} GB",
                "disk_free": f"{disk.free / (1024**3):.1f} GB",
                "network_bytes_sent": f"{network.bytes_sent / (1024**2):.1f} MB",
                "network_bytes_recv": f"{network.bytes_recv / (1024**2):.1f} MB",
                "procesos_activos": procesos_activos,
                "conexiones_activas": conexiones_activas,
                "usuarios_conectados": users,
                "uptime_horas": f"{uptime / 3600:.1f}h",
                "uptime_dias": f"{uptime / 86400:.1f}d",
                "cpu_cores": psutil.cpu_count(),
                "frecuencia_cpu": f"{psutil.cpu_freq().current / 1000:.1f} GHz" if psutil.cpu_freq() else "N/A",
                "boot_time": datetime.fromtimestamp(boot_time).strftime("%Y-%m-%d %H:%M:%S"),
                "timestamp_actual": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            
            return metrics
            
        except Exception as e:
            logger.error(f"Error in _collect_metrics: {e}", exc_info=True)
            return self._get_fallback_metrics()
    
    def _get_fallback_metrics(self):
        """Get fallback metrics when collection fails"""
        return {
            "cpu": None,
            "ram": None,
            "disk": None,
            "ram_total": "Sin datos disponibles",
            "ram_usada": "Sin datos disponibles",
            "ram_disponible": "Sin datos disponibles",
            "disk_total": "Sin datos disponibles",
            "disk_usado": "Sin datos disponibles",
            "disk_free": "Sin datos disponibles",
            "network_bytes_sent": "Sin datos disponibles",
            "network_bytes_recv": "Sin datos disponibles",
            "procesos_activos": None,
            "usuarios_conectados": None,
            "uptime_horas": "Sin datos disponibles",
            "uptime_dias": "Sin datos disponibles",
            "cpu_cores": None,
            "frecuencia_cpu": "Sin datos disponibles",
            "boot_time": "Sin datos disponibles",
            "timestamp_actual": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "metrics_unavailable": True,
        }
    
    def get_network_stats(self):
        """Get network statistics — fast path; conexiones desde cache peek."""
        try:
            from services.performance_cache import peek_cached

            net_stats = psutil.net_io_counters()
            conn_value = peek_cached("proc_conn_count")
            conn_meta = {"available": conn_value is not None, "pending": conn_value is None}

            return {
                "bytes_sent": net_stats.bytes_sent,
                "bytes_recv": net_stats.bytes_recv,
                "packets_sent": net_stats.packets_sent,
                "packets_recv": net_stats.packets_recv,
                "connections": conn_value,
                "connections_meta": conn_meta,
            }
        except Exception as e:
            logger.error(f"Error getting network stats: {e}", exc_info=True)
            return {
                "bytes_sent": None,
                "bytes_recv": None,
                "packets_sent": None,
                "packets_recv": None,
                "connections": None,
                "connections_meta": {"available": False},
                "metrics_unavailable": True,
            }
    
    def get_process_list(self, limit=50):
        """Get list of processes with resource usage"""
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    processes.append({
                        'pid': proc.info['pid'],
                        'name': proc.info['name'],
                        'cpu_percent': proc.info.get('cpu_percent', 0),
                        'memory_percent': proc.info.get('memory_percent', 0)
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Sort by CPU usage and return top N
            processes.sort(key=lambda x: x['cpu_percent'], reverse=True)
            return processes[:limit]
            
        except Exception as e:
            logger.error(f"Error getting process list: {e}", exc_info=True)
            return []


# Global monitor instance
system_monitor = SystemMonitor()
