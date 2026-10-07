#!/usr/bin/env python3
"""
Script para crear túnel público usando localhost.run
Alternativa simple que no requiere SSH complejo
"""

import time
import sys

def print_banner():
    print("=" * 60)
    print("NOVUS PLATFORM - TUNEL LOCALHOST.RUN")
    print("=" * 60)
    print("Creando tunel publico gratuito...")

def create_localhost_tunnel():
    """Intenta crear túnel usando localhost.run"""
    print_banner()
    
    print("\nOPCION 1: Usar localhost.run manualmente")
    print("Abre otra terminal y ejecuta:")
    print("ssh -R 80:localhost:8000 localhost.run")
    
    print("\nOPCION 2: Usar ngrok (recomendado)")
    print("1. Ve a https://ngrok.com/signup")
    print("2. Registrate gratis")
    print("3. Descarga ngrok para Windows")
    print("4. Configura tu authtoken")
    print("5. Ejecuta: ngrok http 8000")
    
    print("\nOPCION 3: Usar cloudflared")
    print("1. Descarga: https://github.com/cloudflare/cloudflared/releases")
    print("2. Ejecuta: cloudflared tunnel --url http://localhost:8000")
    
    print("\n" + "INFO" * 20)
    print("INFORMACION ACTUAL:")
    print("INFO" * 20)
    
    print(f"URL Local: http://localhost:8000")
    print(f"URL Red: http://10.177.141.166:8000")
    
    print("\nCREDENCIALES:")
    print("FINTECH - CISO: ciso@novus.local / CISO!FINTECH#2026")
    print("FINTECH - CTO: cto@novus.local / CTO!FINTECH#2026")
    print("LOGISTICA - CPO: cpo@novus.local / CPO!LOGISTICA#2026")
    print("LOGISTICA - CSO: cso@novus.local / CSO!LOGISTICA#2026")
    
    print("\nENLACES:")
    print("Principal: http://localhost:8000/")
    print("Login: http://localhost:8000/sector-login")
    print("Pruebas: http://localhost:8000/test-sector-auth")
    
    print("\n" + "RECOMENDACION" * 10)
    print("LA SOLUCION MAS RAPIDA:")
    print("RECOMENDACION" * 10)
    print("1. Descarga ngrok desde https://ngrok.com/download")
    print("2. Registrate en https://ngrok.com/signup")
    print("3. Obtén tu authtoken del dashboard")
    print("4. Ejecuta: ngrok http 8000")
    print("5. Copia la URL publica y compartela")

def main():
    create_localhost_tunnel()
    
    print("\nPresiona Enter para salir...")
    try:
        input()
    except:
        pass

if __name__ == "__main__":
    main()
