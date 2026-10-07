#!/usr/bin/env python3
import requests
import json

def test_api(url, name):
    try:
        response = requests.get(f'http://localhost:5000{url}')
        print(f'\n=== {name} - {url} ===')
        print('Status Code:', response.status_code)
        print('Content-Type:', response.headers.get('Content-Type', 'N/A'))
        
        if 'application/json' in response.headers.get('Content-Type', ''):
            try:
                json_data = response.json()
                print('JSON:', json.dumps(json_data, indent=2))
            except:
                print('ERROR: JSON inválido')
        else:
            print('Raw Response (first 200 chars):')
            print(response.text[:200])
            
    except Exception as e:
        print(f'ERROR en {name}: {e}')

# Probar todas las APIs principales
test_api('/api/network/nodes', 'Network API')
test_api('/dashboard', 'Dashboard')
test_api('/xdr', 'Amenazas/XDR')
test_api('/vulnerabilidades', 'Vulnerabilidades')
test_api('/endpoints', 'Endpoints')
test_api('/automatizacion', 'Automatización')
test_api('/reportes', 'Reportes')

print('\n=== FIN VERIFICACIÓN DE APIs ===')
