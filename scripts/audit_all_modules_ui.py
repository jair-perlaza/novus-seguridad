"""Auditoría UI completa — estructura HTML, style tags, contenido visible."""
import re
import requests

BASE = "http://127.0.0.1:5000"
EMAIL = "novus.qa.jul2026@example.com"
PASSWORD = "NovusQA2026!"

MODULES = [
    ("Dashboard", "/dashboard"),
    ("Centro Inteligencia", "/inteligencia"),
    ("Network", "/network"),
    ("Topology", "/topology"),
    ("Vulnerabilidades", "/vulnerabilidades"),
    ("Incidentes", "/incidentes"),
    ("XDR", "/xdr"),
    ("Endpoints", "/endpoints"),
    ("Playbooks", "/automatizacion"),
    ("Reportes", "/reportes"),
    ("Configuracion", "/configuracion"),
    ("Casos Estudio", "/casos-estudio"),
    ("SIEM", "/siem"),
]


def check_html(name, html):
    issues = []
    style_open = html.count("<style")
    style_close = html.count("</style>")
    if style_open != style_close:
        issues.append(f"style tags unbalanced ({style_open}/{style_close})")

    head_end = html.lower().find("</head>")
    body_start = html.lower().find("<body")
    if head_end < 0:
        issues.append("missing </head>")
    if body_start < 0:
        issues.append("missing <body>")

    # Body content swallowed into CSS: </head> immediately after unclosed style
    if head_end > 0 and body_start > head_end:
        between = html[head_end:body_start]
        if "<div" in between or "<header" in between or "<main" in between:
            issues.append("HTML between </head> and <body> (possible CSS leak)")

    # Black screen indicator: body tag inside style block
    style_blocks = re.findall(r"<style[^>]*>(.*?)</style>", html, re.DOTALL | re.IGNORECASE)
    for i, block in enumerate(style_blocks):
        if re.search(r"<\s*(body|div|header|main|section)\b", block, re.I):
            issues.append(f"style block #{i+1} contains HTML tags")

    # Unclosed style before head end
    pre_head = html[:head_end] if head_end > 0 else html
    if "<style" in pre_head.lower() and "</style>" not in pre_head.lower():
        issues.append("unclosed <style> before </head>")

    # Minimal content check
    body = html[body_start:] if body_start > 0 else html
    visible_markers = [
        "novus-shell", "sidebar", "dashboard", "topology-map", "card",
        "novus-nav", "main", "header", "panel", "table",
    ]
    has_content = any(m in body.lower() for m in visible_markers)
    if not has_content and len(body) < 500:
        issues.append("body appears empty or minimal")

    return issues


def main():
    s = requests.Session()
    r = s.post(f"{BASE}/login", data={"email": EMAIL, "password": PASSWORD}, allow_redirects=True, timeout=30)
    if "login" in r.url.lower():
        print("[FAIL] Login failed")
        return 1
    print("[OK] Login\n")

    passed = 0
    failed = []
    for name, path in MODULES:
        try:
            resp = s.get(f"{BASE}{path}", timeout=60)
            status = resp.status_code
            html = resp.text
            issues = check_html(name, html)
            if status != 200:
                issues.insert(0, f"HTTP {status}")
            if issues:
                failed.append((name, path, issues))
                print(f"[FAIL] {name} ({path})")
                for iss in issues:
                    print(f"       - {iss}")
            else:
                passed += 1
                # Topology-specific
                extra = ""
                if path == "/topology":
                    extra = f" | </style>={'</style>' in html} | topo-map={'topology-map' in html}"
                print(f"[OK] {name} ({path}){extra}")
        except Exception as e:
            failed.append((name, path, [str(e)]))
            print(f"[FAIL] {name} ({path}) - {e}")

    print(f"\n=== UI AUDIT: {passed}/{len(MODULES)} modules OK ===")
    if failed:
        print(f"Failed: {', '.join(n for n, _, _ in failed)}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
