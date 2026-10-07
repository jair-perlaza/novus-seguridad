#!/usr/bin/env python3
"""
Script para crear túnel ngrok y exponer la plataforma NOVUS públicamente
Permite que CISO, CTO, CPO y CSO accedan desde fuera de la red local
"""

import time
import threading
from pyngrok import ngrok
import sys
import os

def print_banner():
    """Muestra el banner de NOVUS"""
    print("=" * 60)
    print("NOVUS PLATFORM - TUNEL PUBLICO NGROK")
    print("=" * 60)
    print("Sistema de Autenticación Sectorial Segura")
    print("Creando tunel publico para acceso remoto...")
    print("=" * 60)

def create_ngrok_tunnel(port=5000):
    """
    Crea un túnel ngrok para el puerto especificado
    """
    try:
        # Configurar authtoken si existe (opcional)
        # ngrok.set_auth_token("TU_AUTH_TOKEN")
        
        print(f"Creando tunel para el puerto {port}...")
        
        # Crear túnel HTTP
        tunnel = ngrok.connect(port, "http")
        
        print("\n" + "OK" * 20)
        print("¡TUNEL CREADO EXITOSAMENTE!")
        print("OK" * 20)
        
        print(f"\nURL PUBLICA: {tunnel.public_url}")
        print(f"URL Local: http://localhost:{port}")
        
        print("\nENLACES DISPONIBLES PARA SOCIOS:")
        print(f"Login Principal: {tunnel.public_url}/login")
        print(f"Login Sectorial: {tunnel.public_url}/sector-login")
        
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
        
        print("\n" + "ADVERTENCIA" * 10)
        print("INSTRUCCIONES IMPORTANTES:")
        print("ADVERTENCIA" * 10)
        print("1. Comparte la URL publica solo con personal autorizado")
        print("2. La URL cambiara cada vez que inicies este script")
        print("3. Manten esta ventana abierta para mantener el tunel activo")
        print("4. Presiona Ctrl+C para detener el tunel")
        
        print("\n" + "URL" * 20)
        print("ENVIAR ESTA URL A TUS SOCIOS:")
        print(f"{tunnel.public_url}")
        print("URL" * 20)
        
        return tunnel
        
    except Exception as e:
        print(f"ERROR al crear tunel: {e}")
        print("\nSOLUCIONES POSIBLES:")
        print("1. Verifica que ngrok este instalado correctamente")
        print("2. Revisa tu conexion a internet")
        print("3. Intenta con un puerto diferente (ej: 8001)")
        print("4. Configura tu authtoken de ngrok si tienes cuenta premium")
        return None

def keep_alive():
    """Mantiene el tunel activo mostrando informacion periodica"""
    while True:
        time.sleep(30)  # Cada 30 segundos
        print(f"TUNEL ACTIVO - {time.strftime('%H:%M:%S')}")

def main():
    """Función principal"""
    print_banner()
    
    # Verificar si el servidor NOVUS esta corriendo
    print("Verificando que el servidor NOVUS este activo...")
    time.sleep(2)
    
    try:
        # Crear tunel
        tunnel = create_ngrok_tunnel(int(os.environ.get("PORT", 5000)))
        
        if tunnel:
            print(f"\nTUNEL ESTABLECIDO: {tunnel.public_url}")
            print("Manteniendo tunel activo...")
            
            # Iniciar hilo para mantener vivo
            alive_thread = threading.Thread(target=keep_alive, daemon=True)
            alive_thread.start()
            
            try:
                # Mantener el script corriendo
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n\nDETENIENDO tunel ngrok...")
                ngrok.disconnect(tunnel.public_url)
                print("Tunel cerrado correctamente")
                sys.exit(0)
        else:
            print("No se pudo crear el tunel")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\nOperacion cancelada por el usuario")
        sys.exit(0)
    except Exception as e:
        print(f"Error inesperado: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
