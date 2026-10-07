#!/usr/bin/env python3
import requests
import json

try:
    response = requests.get('http://localhost:5000/api/network/nodes')
    print('=== JSON REAL DEVUELTO POR /api/network/nodes ===')
    print('Status Code:', response.status_code)
    print('Headers:', dict(response.headers))
    print('Body:', json.dumps(response.json(), indent=2))
    print('=== FIN JSON REAL ===')
except Exception as e:
    print('ERROR:', e)
