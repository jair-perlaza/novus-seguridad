#!/usr/bin/env python3
import sys
sys.path.append('.')
from main import scan_network_real

print('=== VERIFICACIÓN DE ESCANEO REAL ===')
try:
    resultados = scan_network_real()
    print(f'Dispositivos encontrados: {len(resultados)}')
    for disp in resultados:
        print(f'IP: {disp["ip"]} | MAC: {disp["mac"]} | Nombre: {disp["name"]}')
    print('=== FIN VERIFICACIÓN ===')
except Exception as e:
    print(f'ERROR: {e}')
    import traceback
    traceback.print_exc()
