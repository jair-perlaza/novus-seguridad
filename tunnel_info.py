#!/usr/bin/env python3
"""
Script simple para mostrar información de túnel y acceso
"""

import socket
import sys

def get_local_ip():
    """Obtiene la IP local de la máquina"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

def main():
    print("=" * 60)
    print("NOVUS PLATFORM - INFORMACION DE ACCESO")
    print("=" * 60)
    
    local_ip = get_local_ip()
    
    print(f"\nIP LOCAL: {local_ip}")
    print(f"URL LOCAL: http://localhost:8000")
    print(f"URL RED LOCAL: http://{local_ip}:8000")
    
    print("\n" + "CREDENCIALES" * 10)
    print("CREDENCIALES PARA SOCIOS:")
    print("CREDENCIALES" * 10)
    
    print("\nSECTOR FINTECH:")
    print("  CISO: ciso@novus.local / CISO!FINTECH#2026")
    print("  CTO: cto@novus.local / CTO!FINTECH#2026")
    
    print("\nSECTOR LOGISTICA/MOVILIDAD:")
    print("  CPO: cpo@novus.local / CPO!LOGISTICA#2026")
    print("  CSO: cso@novus.local / CSO!LOGISTICA#2026")
    
    print("\n" + "TUNELES" * 10)
    print("OPCIONES PARA ACCESO EXTERNO:")
    print("TUNELES" * 10)
    
    print("\n1. NGROK (Requiere registro gratis):")
    print("   - Descarga: https://ngrok.com/download")
    print("   - Registro: https://ngrok.com/signup")
    print("   - Comando: ngrok http 8000")
    
    print("\n2. LOCALXPOSE (Gratis sin registro):")
    print("   - Descarga: https://localxpose.io/")
    print("   - Comando: loclx tunnel 8000")
    
    print("\n3. CLOUDFLARED (Requiere registro):")
    print("   - Descarga: https://github.com/cloudflare/cloudflared")
    print("   - Comando: cloudflared tunnel --url http://localhost:8000")
    
    print("\n4. SERVEO (Gratis con SSH):")
    print("   - Comando: ssh -R 80:localhost:8000 serveo.net")
    
    print("\n" + "ENLACES" * 10)
    print("ENLACES DEL SISTEMA:")
    print("ENLACES" * 10)
    print(f"Principal: http://localhost:8000/")
    print(f"Login Sectorial: http://localhost:8000/sector-login")
    print(f"Panel Pruebas: http://localhost:8000/test-sector-auth")
    
    print("\nPresiona Enter para salir...")
    input()

if __name__ == "__main__":
    main()
