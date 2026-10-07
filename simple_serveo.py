#!/usr/bin/env python3
"""
Script simple para crear túnel público con serveo.net
"""

import subprocess
import time
import sys
import re

def main():
    print("=" * 60)
    print("NOVUS PLATFORM - TUNEL SERVEO")
    print("=" * 60)
    print("Creando tunel publico con serveo.net...")
    
    # Comando SSH para serveo
    command = "ssh -R 80:localhost:8000 serveo.net"
    
    print(f"Ejecutando: {command}")
    print("\nSi te pide confirmacion de fingerprint SSH, escribe 'yes'")
    print("\nEsperando URL publica...")
    
    try:
        # Ejecutar comando SSH
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            universal_newlines=True
        )
        
        url_found = False
        
        # Monitorear salida
        for line in process.stdout:
            print(line.strip())
            
            # Buscar URL en la salida
            if "https://" in line and "serveo.net" in line:
                url_match = re.search(r'https://[a-zA-Z0-9-]+\.serveo\.net', line)
                if url_match and not url_found:
                    public_url = url_match.group(0)
                    url_found = True
                    
                    print("\n" + "EXITO" * 20)
                    print("TUNEL CREADO!")
                    print("EXITO" * 20)
                    
                    print(f"\nURL PUBLICA: {public_url}")
                    print(f"URL Local: http://localhost:8000")
                    
                    print("\nENLACES PARA SOCIOS:")
                    print(f"Principal: {public_url}/")
                    print(f"Login: {public_url}/sector-login")
                    print(f"Pruebas: {public_url}/test-sector-auth")
                    
                    print("\nCREDENCIALES:")
                    print("FINTECH - CISO: ciso@novus.local / CISO!FINTECH#2026")
                    print("FINTECH - CTO: cto@novus.local / CTO!FINTECH#2026")
                    print("LOGISTICA - CPO: cpo@novus.local / CPO!LOGISTICA#2026")
                    print("LOGISTICA - CSO: cso@novus.local / CSO!LOGISTICA#2026")
                    
                    print(f"\nCOMPARTIR ESTA URL: {public_url}")
                    print("Mantener esta ventana abierta para mantener el tunel activo.")
                    
                    # Guardar URL en archivo
                    with open("serveo_url.txt", "w") as f:
                        f.write(f"URL PUBLICA: {public_url}\n")
                        f.write(f"Login: {public_url}/sector-login\n")
                        f.write(f"Pruebas: {public_url}/test-sector-auth\n")
                    
                    print("\nURL guardada en serveo_url.txt")
                    
                    # Mantener proceso corriendo
                    try:
                        process.wait()
                    except KeyboardInterrupt:
                        print("\nDeteniendo tunel...")
                        process.terminate()
                        sys.exit(0)
        
        # Si no se encontró URL
        if not url_found:
            print("\nNo se pudo obtener URL publica.")
            print("Revisa si tienes SSH instalado y conexion a internet.")
            
    except KeyboardInterrupt:
        print("\nOperacion cancelada")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
