import requests
s = requests.Session()
b = "http://127.0.0.1:5000"
s.post(b + "/login", data={"email": "novus.qa.jul2026@example.com", "password": "NovusQA2026!"}, allow_redirects=True)
t = s.get(b + "/api/network/topology").json()
print("twin", bool(t.get("digital_twin")))
print("connections", len(t.get("connections", [])))
if t.get("nodes"):
    ip = t["nodes"][0]["ip"]
    d = s.get(b + f"/api/network/topology/device/{ip}").json()
    print("panel_fields", len(d.get("panel", {})))
    print("funcion_red", bool(d.get("panel", {}).get("funcion_red")))
print("API OK")
