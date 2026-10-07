"""Verify topology HTML fix — no CSS leak, body renders."""
import re
import requests

BASE = "http://127.0.0.1:5000"
EMAIL = "novus.qa.jul2026@example.com"
PASSWORD = "NovusQA2026!"


def main():
    s = requests.Session()
    s.post(f"{BASE}/login", data={"email": EMAIL, "password": PASSWORD}, allow_redirects=True, timeout=30)
    html = s.get(f"{BASE}/topology", timeout=30).text

    checks = [
        ("style tag closed", "</style>" in html),
        ("body present", "<body" in html),
        ("topology-map div", "topology-map" in html),
        ("side-panel", "side-panel" in html),
        ("renderMap function", "renderMap" in html),
        ("head before body", html.find("</head>") < html.find("<body")),
        ("twin-chip styles", "twin-chip" in html),
        ("action-btn secondary", "action-btn.secondary" in html),
    ]
    styles = re.findall(r"<style[^>]*>(.*?)</style>", html, re.DOTALL | re.IGNORECASE)
    leak = any(re.search(r"<\s*(body|header|div|main)\b", b, re.I) for b in styles)
    checks.append(("no HTML inside style blocks", not leak))

    ok = 0
    for name, passed in checks:
        status = "OK" if passed else "FAIL"
        print(f"[{status}] {name}")
        ok += int(passed)

    body = html[html.find("<body"):]
    print(f"[INFO] body length: {len(body)} chars")
    print(f"\n{ok}/{len(checks)} checks passed")
    return 0 if ok == len(checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
