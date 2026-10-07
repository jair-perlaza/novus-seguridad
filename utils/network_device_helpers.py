"""
Helpers to enrich real network devices discovered by ARP scan.
"""
import platform
import re
import subprocess
import time

from utils.logger import logger


def measure_response_time_ms(ip):
    """Measure ICMP response time in milliseconds for a discovered host."""
    if not ip:
        return None
    try:
        if platform.system() == "Windows":
            cmd = ["ping", "-n", "1", "-w", "1000", ip]
        else:
            cmd = ["ping", "-c", "1", "-W", "1", ip]

        started = time.time()
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=3,
        )
        if result.returncode != 0:
            return None

        output = result.stdout.lower()
        match = re.search(r"(?:time[=<]|tiempo[=<])\s*([0-9]+)\s*ms", output)
        if match:
            return int(match.group(1))
        return int((time.time() - started) * 1000)
    except Exception as exc:
        logger.debug(f"Ping failed for {ip}: {exc}")
        return None


def lookup_mac_vendor(mac):
    """Resolve MAC vendor using Scapy manufacturer database when available."""
    if not mac:
        return "Sin datos disponibles"
    try:
        from scapy.config import conf

        if conf.manuf_db is None:
            conf.manuf_db = conf.load_manuf()
        vendor = conf.manuf_db._get_manuf(mac)
        return vendor or "Sin datos disponibles"
    except Exception as exc:
        logger.debug(f"Vendor lookup failed for {mac}: {exc}")
        return "Sin datos disponibles"
