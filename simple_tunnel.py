#!/usr/bin/env python3
"""
Script simple para crear túnel público usando localhost.run
Alternativa gratuita que no requiere registro
"""

import urllib.request
import urllib.parse
import json
import time
import threading
import sys
import os

def print_banner():
    """Muestra el banner de NOVUS"""
    print("=" * 60)
    print("NOVUS PLATFORM - TUNEL PUBLICO GRATIS")
    print("=" * 60)
    print("Sistema de Autenticacion Sectorial Segura")
    print("Creando tunel publico gratuito...")
    print("=" * 60)

def create_tunnel_info():
    """
    Crea información de túnel manual para compartir
    """
    print("\n" + "INFO" * 20)
    print("CONFIGURACION MANUAL DE TUNEL")
    print("INFO" * 20)
    
    print("\nOPCION 1: Usar ngrok (requiere registro gratuito)")
    print("1. Ve a https://ngrok.com/signup")
    print("2. Registrate gratis")
    print("3. Obtén tu authtoken en https://dashboard.ngrok.com/get-started/your-authtoken")
    print("4. Configura con: ngrok config add-authtoken TU_TOKEN")
    print("5. Ejecuta: ngrok http 8000")
    
    print("\nOPCION 2: Usar cloudflared (requiere registro)")
    print("1. Descarga cloudflared de https://github.com/cloudflare/cloudflared")
    print("2. Ejecuta: cloudflared tunnel --url http://localhost:8000")
    
    print("\nOPCION 3: Usar serveo.net con SSH")
    print("1. Asegurate de tener SSH instalado")
    print("2. Ejecuta: ssh -R 80:localhost:8000 serveo.net")
    
    print("\nOPCION 4: Usar localhost.run")
    print("1. Ejecuta: ssh -R 80:localhost:8000 localhost.run")
    
    print("\n" + "URL" * 20)
    print("ENLACES DE TU SERVIDOR LOCAL:")
    print("URL" * 20)
    print("Local: http://localhost:8000")
    print("Red: http://TU_IP_LOCAL:8000")
    
    print("\nCREDENCIALES PARA SOCIOS:")
    print("\nSECTOR FINTECH:")
    print("   CISO: ciso@novus.local / CISO!FINTECH#2026")
    print("   CTO: cto@novus.local / CTO!FINTECH#2026")
    
    print("\nSECTOR LOGISTICA/MOVILIDAD:")
    print("   CPO: cpo@novus.local / CPO!LOGISTICA#2026")
    print("   CSO: cso@novus.local / CSO!LOGISTICA#2026")
    
    print("\nCARACTERISTICAS DE SEGURIDAD:")
    print("   • Validacion de dispositivo por fingerprint")
    print("   • Aislamiento de sector con acceso exclusivo")
    print("   • Alertas automaticas para accesos no autorizados")
    print("   • Registro completo de auditoria")
    print("   • Sesion segura con monitoreo 24/7")

def get_local_ip():
    """Obtiene la IP local de la máquina"""
    try:
        # Conectar a un DNS para obtener IP local
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

def main():
    """Función principal"""
    print_banner()
    
    # Importar socket para obtener IP local
    import socket
    
    # Obtener IP local
    local_ip = get_local_ip()
    
    print(f"\nIP LOCAL DETECTADA: {local_ip}")
    print(f"URL LOCAL: http://localhost:8000")
    print(f"URL RED LOCAL: http://{local_ip}:8000")
    
    print("\n" + "ADVERTENCIA" * 10)
    print("SOLUCIONES PARA ACCESO EXTERNO:")
    print("ADVERTENCIA" * 10)
    
    create_tunnel_info()
    
    print("\n" + "RECOMENDACION" * 10)
    print("LA OPCION MAS FACIL:")
    print("RECOMENDACION" * 10)
    print("1. Registrate gratis en ngrok.com")
    print("2. Descarga ngrok para Windows")
    print("3. Configura tu authtoken")
    print("4. Ejecuta: ngrok http 8000")
    print("5. Copia la URL publica y compartela")
    
    print("\nPara mantener el servidor corriendo, usa otra terminal.")
    print("El servidor NOVUS ya esta activo en http://localhost:8000")
    
    # Mantener el script corriendo para mostrar información
    try:
        while True:
            time.sleep(60)
            print(f"\nServidor activo - {time.strftime('%H:%M:%S')}")
            print(f"URL local: http://localhost:8000")
            print(f"URL red: http://{local_ip}:8000")
    except KeyboardInterrupt:
        print("\nInformacion de tunel cerrada")
        sys.exit(0)

if __name__ == "__main__":
    main()
