#!/usr/bin/env python3
"""Retry inconclusive HTTP isolation probes."""
import json, re, time, requests
BASE = "http://127.0.0.1:5000"
QA = ("novus.qa.jul2026@example.com", "NovusQA2026!")
CL = ("operaciones@novapay-fintech.co", "NovaPay#Fintech2026")


def login(email, pw):
    s = requests.Session()
    r = s.get(BASE + "/login", timeout=30)
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', r.text)
    s.post(BASE + "/login", data={"email": email, "password": pw, "csrf_token": csrf.group(1) if csrf else ""}, timeout=30)
    return s


def probe(sess, path, who):
    t0 = time.perf_counter()
    try:
        r = sess.get(BASE + path, timeout=60)
        body = r.json() if "json" in r.headers.get("content-type", "") else {}
    except Exception as e:
        return {"who": who, "path": path, "error": str(e)[:80], "ms": round((time.perf_counter() - t0) * 1000, 1)}
    rec = body.get("status") == "recovering" or body.get("_novusRecovery")
    leaked = False
    if "login-sessions" in path and body.get("status") == "success":
        sid = path.split("id=")[-1]
        leaked = (body.get("session") or {}).get("id") == sid and "foreign" in who
    if "/api/reports/" in path and body.get("status") == "success":
        rid = path.rsplit("/", 1)[-1]
        leaked = (body.get("report") or {}).get("id") == rid and "foreign" in who
    own = None
    if "reports/list" in path:
        blob = json.dumps(body)
        if who == "B_list":
            leaked = "A-HTTP-ISOL-REPORT-001" in blob
            own = "B-HTTP-ISOL-REPORT-001" in blob
        if who == "A_list":
            leaked = "B-HTTP-ISOL-REPORT-001" in blob
            own = "A-HTTP-ISOL-REPORT-001" in blob
    blocked = (not leaked) and (body.get("status") in ("error", None) or r.status_code in (403, 404) or (body.get("status") == "success" and "foreign" in who and not leaked))
    if "own" in who and body.get("status") == "success":
        blocked = False
    verdict = "VERIFIED" if not rec and not leaked and (("foreign" in who and blocked) or ("own" in who and body.get("status") == "success")) else ("INCONCLUSIVE" if rec or "timeout" in str(body) else "FAIL")
    return {"who": who, "path": path, "http": r.status_code, "recovering": rec, "leaked": leaked, "own": own, "ms": round((time.perf_counter() - t0) * 1000, 1), "status": body.get("status"), "verdict": verdict}


if __name__ == "__main__":
    time.sleep(5)
    qa = login(*QA)
    cl = login(*CL)
    cases = [
        (qa, "A_foreign_session", "/api/system/login-sessions?id=B-HTTP-ISOL-SESSION-001"),
        (qa, "A_foreign_report", "/api/reports/B-HTTP-ISOL-REPORT-001"),
        (cl, "B_foreign_session", "/api/system/login-sessions?id=A-HTTP-ISOL-SESSION-001"),
        (cl, "B_reports_list", "/api/reports/list"),
        (cl, "B_own_report", "/api/reports/B-HTTP-ISOL-REPORT-001"),
        (cl, "B_foreign_report", "/api/reports/A-HTTP-ISOL-REPORT-001"),
    ]
    out = []
    for s, who, p in cases:
        time.sleep(3)
        out.append(probe(s, p, who))
    print(json.dumps(out, ensure_ascii=False, indent=2))
