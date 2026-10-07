#!/usr/bin/env python3
import requests
import json

try:
    response = requests.get('http://localhost:5000/api/network/nodes')
    print('=== JSON REAL DEVUELTO POR /api/network/nodes ===')
    print('Status Code:', response.status_code)
    print('Headers:', dict(response.headers))
    print('Raw Response (first 500 chars):')
    print(response.text[:500])
    print('---')
    try:
        json_data = response.json()
        print('JSON Parsed:', json.dumps(json_data, indent=2))
    except:
        print('ERROR: No es JSON válido')
    print('=== FIN JSON REAL ===')
except Exception as e:
    print('ERROR:', e)
