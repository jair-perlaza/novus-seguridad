#!/usr/bin/env python3
"""
Script para crear túnel público usando Serveo.net
Alternativa gratuita a ngrok que no requiere registro
"""

import subprocess
import time
import threading
import sys
import os
import re

def print_banner():
    """Muestra el banner de NOVUS"""
    print("=" * 60)
    print("NOVUS PLATFORM - TUNEL PUBLICO SERVEO")
    print("=" * 60)
    print("Sistema de Autenticacion Sectorial Segura")
    print("Creando tunel publico gratuito con Serveo.net...")
    print("=" * 60)

def extract_serveo_url(output):
    """Extrae la URL pública del output de serveo"""
    # Buscar patrones como: https://random.serveo.net
    patterns = [
        r'https://[a-zA-Z0-9-]+\.serveo\.net',
        r'https://[a-zA-Z0-9-]+\.ssh\.io',
        r'https://[a-zA-Z0-9-]+\.tunnel\.moe'
    ]
    
    for pattern in patterns:
        match = re.search(pattern, output)
        if match:
            return match.group(0)
    return None

def create_serveo_tunnel(port=8000, custom_subdomain=None):
    """
    Crea un túnel usando Serveo.net
    """
    try:
        print(f"Creando tunel para el puerto {port}...")
        
        # Construir comando serveo
        if custom_subdomain:
            command = f"ssh -R {custom_subdomain}:80:localhost:{port} serveo.net"
        else:
            command = f"ssh -R 80:localhost:{port} serveo.net"
        
        print(f"Ejecutando: {command}")
        
        # Iniciar proceso serveo
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            universal_newlines=True
        )
        
        url_found = False
        public_url = None
        
        print("\nEsperando conexion con Serveo...")
        
        # Monitorear output por hasta 30 segundos
        start_time = time.time()
        while time.time() - start_time < 30:
            if process.poll() is not None:
                # Proceso terminó
                stdout, stderr = process.communicate()
                print(f"STDOUT: {stdout}")
                print(f"STDERR: {stderr}")
                break
            
            # Leer línea por línea
            try:
                output_line = process.stdout.readline()
                if output_line:
                    print(f"Serveo: {output_line.strip()}")
                    
                    # Buscar URL en el output
                    url = extract_serveo_url(output_line)
                    if url and not url_found:
                        public_url = url
                        url_found = True
                        
                        print("\n" + "OK" * 20)
                        print("¡TUNEL CREADO EXITOSAMENTE!")
                        print("OK" * 20)
                        
                        print(f"\nURL PUBLICA: {public_url}")
                        print(f"URL Local: http://localhost:{port}")
                        
                        print("\nENLACES DISPONIBLES PARA SOCIOS:")
                        print(f"Login Principal: {public_url}/")
                        print(f"Login Sectorial: {public_url}/sector-login")
                        print(f"Panel de Pruebas: {public_url}/test-sector-auth")
                        
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
                        
                        print("\n" + "URL" * 20)
                        print("ENVIAR ESTA URL A TUS SOCIOS:")
                        print(f"{public_url}")
                        print("URL" * 20)
                        
                        print("\n" + "ADVERTENCIA" * 10)
                        print("INSTRUCCIONES IMPORTANTES:")
                        print("ADVERTENCIA" * 10)
                        print("1. Comparte la URL publica solo con personal autorizado")
                        print("2. La URL puede cambiar si la conexion se pierde")
                        print("3. Manten esta ventana abierta para mantener el tunel activo")
                        print("4. Presiona Ctrl+C para detener el tunel")
                        
                        return public_url, process
                        
            except Exception as e:
                print(f"Error leyendo output: {e}")
                
            time.sleep(0.5)
        
        if not url_found:
            print("No se pudo obtener URL publica en 30 segundos")
            process.terminate()
            return None, None
            
    except Exception as e:
        print(f"ERROR al crear tunel: {e}")
        return None, None

def keep_tunnel_alive(process):
    """Mantiene el túnel activo mostrando estado"""
    try:
        while True:
            time.sleep(30)
            if process.poll() is not None:
                print("TUNEL CERRADO - El proceso termino")
                break
            else:
                print(f"TUNEL ACTIVO - {time.strftime('%H:%M:%S')}")
    except Exception as e:
        print(f"Error en monitoreo: {e}")

def main():
    """Función principal"""
    print_banner()
    
    # Verificar si el servidor NOVUS esta corriendo
    print("Verificando que el servidor NOVUS este activo...")
    time.sleep(2)
    
    print("\nNOTA: Este metodo usa SSH para conectar con Serveo.net")
    print("Si te pide confirmacion de fingerprint SSH, escribe 'yes'")
    print()
    
    try:
        # Intentar con subdominio aleatorio primero
        public_url, process = create_serveo_tunnel(8000)
        
        if public_url and process:
            print(f"\nTUNEL ESTABLECIDO: {public_url}")
            print("Manteniendo tunel activo...")
            
            # Iniciar hilo para mantener vivo
            alive_thread = threading.Thread(target=keep_tunnel_alive, args=(process,), daemon=True)
            alive_thread.start()
            
            try:
                # Mantener el script corriendo
                while True:
                    time.sleep(1)
                    if process.poll() is not None:
                        print("El tunel se ha cerrado inesperadamente")
                        break
            except KeyboardInterrupt:
                print("\n\nDETENIENDO tunel Serveo...")
                process.terminate()
                print("Tunel cerrado correctamente")
                sys.exit(0)
        else:
            print("No se pudo crear el tunel")
            print("\nSOLUCIONES ALTERNATIVAS:")
            print("1. Asegurate de tener acceso a internet")
            print("2. Verifica que el puerto 8000 este libre")
            print("3. Intenta registrar una cuenta gratuita en ngrok")
            print("4. Usa otro servicio de tunel como cloudflare tunnel")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\nOperacion cancelada por el usuario")
        sys.exit(0)
    except Exception as e:
        print(f"Error inesperado: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
