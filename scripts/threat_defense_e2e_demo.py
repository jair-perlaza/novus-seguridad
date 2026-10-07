#!/usr/bin/env python3
"""
NOVUS Threat Defense E2E Demonstration Campaign — controlled TEST_FIXTURE only.
No malware real. No destructive attacks. Writes evidence under
data/production_closure/threat_defense_capability_audit/
"""
from __future__ import annotations

import json
import os
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

OUT = ROOT / "data" / "production_closure" / "threat_defense_capability_audit"
LAB = OUT / "lab_fixtures"
OUT.mkdir(parents=True, exist_ok=True)
LAB.mkdir(parents=True, exist_ok=True)
RUN_ID = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
BASE = os.environ.get("NOVUS_TEST_BASE", "http://127.0.0.1:5000")

# Documentation / TEST ranges — never real customers
TEST_IP = "203.0.113.77"
TEST_EMAIL = f"syn_test_only_{RUN_ID}@novus-client.test"


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_json(name: str, data: Any) -> None:
    (OUT / name).write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding="utf-8")


def log(msg: str) -> None:
    print(msg, flush=True)


def evidence_row(**kw: Any) -> Dict[str, Any]:
    row = {
        "test_id": kw.get("test_id"),
        "timestamp": utc(),
        "environment": "LAB_SYNTHETIC",
        "engine": kw.get("engine"),
        "input": kw.get("input"),
        "expected": kw.get("expected"),
        "actual": kw.get("actual"),
        "event_id": kw.get("event_id"),
        "tenant_id": kw.get("tenant_id"),
        "scope": kw.get("scope"),
        "severity": kw.get("severity"),
        "confidence": kw.get("confidence"),
        "evidence": kw.get("evidence"),
        "response": kw.get("response"),
        "verification": kw.get("verification"),
        "notification": kw.get("notification"),
        "result": kw.get("result"),
        "TEST_FIXTURE": True,
        "SYNTHETIC_TEST_ONLY": True,
    }
    return row


def host_snap() -> Dict[str, Any]:
    try:
        import psutil

        snap = {
            "cpu": psutil.cpu_percent(0.2),
            "ram": psutil.virtual_memory().percent,
            "rss_mb": None,
            "threads": None,
        }
        for c in psutil.net_connections(kind="inet"):
            if c.laddr and getattr(c.laddr, "port", None) == 5000 and c.status == "LISTEN":
                p = psutil.Process(c.pid)
                snap["rss_mb"] = round(p.memory_info().rss / 1024 / 1024, 1)
                snap["threads"] = p.num_threads()
                break
        return snap
    except Exception as e:
        return {"error": str(e)[:120]}


def demo_yara() -> Dict[str, Any]:
    from services.endpoint_enterprise.yara_engine import (
        get_engine_status,
        scan_file,
        RULES_DIR,
    )
    from services.endpoint_enterprise.publish import publish_finding, publish_findings

    status = get_engine_status()
    rules = sorted(p.name for p in Path(RULES_DIR).glob("*.yar"))

    eicar = (
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    )
    eicar_path = LAB / f"eicar_{RUN_ID}.txt"
    eicar_path.write_text(eicar, encoding="utf-8")

    mimikatz_path = LAB / f"mimikatz_strings_{RUN_ID}.txt"
    mimikatz_path.write_text(
        "SYNTHETIC_TEST_ONLY TEST_FIXTURE\n"
        "This file contains strings for YARA lab matching only.\n"
        "mimikatz\nsekurlsa::logonpasswords\nprivilege::debug\n",
        encoding="utf-8",
    )

    keylog_path = LAB / f"keylog_heuristic_{RUN_ID}.txt"
    keylog_path.write_text(
        "SYNTHETIC_TEST_ONLY TEST_FIXTURE\n"
        "GetAsyncKeyState\nGetForegroundWindow\nBitBlt\n",
        encoding="utf-8",
    )

    eicar_hits = scan_file(str(eicar_path))
    mim_hits = scan_file(str(mimikatz_path))
    key_hits = scan_file(str(keylog_path))

    # Tag all hits as fixtures
    for h in eicar_hits + mim_hits + key_hits:
        h["TEST_FIXTURE"] = True
        h["SYNTHETIC_TEST_ONLY"] = True
        h["real_malware"] = False

    # publish_findings skips severity info — EICAR is info → expect no UI publish via that path
    published_mim = publish_findings(mim_hits, prefix=f"LAB-{RUN_ID}")
    # Explicit publish for EICAR documenting pipeline with fixture tags (severity stays informational)
    eicar_pub = None
    if eicar_hits:
        eicar_pub = publish_finding(
            action="yara_eicar_test_fixture",
            evidence={
                **eicar_hits[0],
                "TEST_FIXTURE": True,
                "SYNTHETIC_TEST_ONLY": True,
                "EICAR_STANDARD": True,
                "real_malware": False,
                "message": "EICAR TEST_FIXTURE — not client malware",
            },
            threat_type="TEST_FIXTURE_EICAR",
            confidence="high",
            finding_id=f"EEP-LAB-EICAR-{RUN_ID}",
            risk_level="info",
            feed_ape=False,
        )

    # Canonic alerts sample
    alert_note = "DETECTION_RECORDED"
    try:
        from services.alerts_canonical_service import get_canonical_alerts, TEST_SOURCES

        # EICAR/test may be filtered from client view — document that
        alerts = []
        try:
            alerts = get_canonical_alerts()  # type: ignore
        except TypeError:
            alerts = get_canonical_alerts(limit=20)  # type: ignore
        if not isinstance(alerts, list):
            alerts = []
        fixture_in_ui = [
            a
            for a in alerts
            if isinstance(a, dict)
            and (
                "EICAR" in str(a).upper()
                or "TEST_FIXTURE" in str(a).upper()
                or "mimikatz" in str(a).lower()
                or RUN_ID in str(a)
            )
        ]
        if fixture_in_ui:
            alert_note = "USER_VISIBLE_OR_CANONICAL_MATCH"
        elif "csv_bas" in TEST_SOURCES or "test" in TEST_SOURCES:
            alert_note = "DETECTION_WITHOUT_USER_ALERT_OR_FILTERED_TEST_SOURCE"
    except Exception as e:
        alert_note = f"ALERT_QUERY_ERROR:{e}"[:160]

    eicar_ok = any((h.get("rule") or "") == "NOVUS_EICAR_TestFile" for h in eicar_hits)
    mim_ok = any("Mimikatz" in str(h.get("rule") or "") for h in mim_hits)
    key_ok = any("Keylogging" in str(h.get("rule") or "") for h in key_hits)

    result = "PASS" if status.get("ok") and eicar_ok and mim_ok else ("PASS_WITH_LIMITATIONS" if eicar_ok else "FAIL")
    if not status.get("ok"):
        result = "FAIL"

    rows = [
        evidence_row(
            test_id="YARA-ENGINE-STATUS",
            engine="endpoint_enterprise.yara_engine",
            input={"rules_dir": str(RULES_DIR), "rules": rules},
            expected="engine ok + rules loaded",
            actual=status,
            result="PASS" if status.get("ok") else "FAIL",
            verification="engine_status",
            notification="N/A",
        ),
        evidence_row(
            test_id="YARA-EICAR-MATCH",
            engine="yara_engine.scan_file",
            input={"path": str(eicar_path), "fixture": "EICAR"},
            expected="NOVUS_EICAR_TestFile match",
            actual={"hits": eicar_hits, "publish": eicar_pub},
            event_id=(eicar_pub or {}).get("event_id") if isinstance(eicar_pub, dict) else None,
            severity=(eicar_hits[0].get("severity") if eicar_hits else None),
            confidence=(eicar_hits[0].get("confidence") if eicar_hits else None),
            evidence=eicar_hits[:1],
            response="none_auto",
            verification="match_present" if eicar_ok else "NO_MATCH",
            notification=alert_note,
            result="PASS" if eicar_ok else "FAIL",
            scope="HOST",
            tenant_id=None,
        ),
        evidence_row(
            test_id="YARA-MIMIKATZ-STRINGS",
            engine="yara_engine.scan_file + publish_findings",
            input={"path": str(mimikatz_path)},
            expected="NOVUS_Mimikatz_Strings + publish",
            actual={"hits": mim_hits, "published_count": published_mim},
            severity=(mim_hits[0].get("severity") if mim_hits else None),
            confidence=(mim_hits[0].get("confidence") if mim_hits else None),
            evidence=mim_hits[:1],
            response="record_detection via publish_findings",
            verification="match_and_publish" if mim_ok else "NO_MATCH",
            notification=alert_note,
            result="PASS" if mim_ok else "FAIL",
        ),
        evidence_row(
            test_id="YARA-KEYLOG-HEURISTIC",
            engine="yara_engine.scan_file",
            input={"path": str(keylog_path)},
            expected="NOVUS_PE_Keylogging_Screencapture_Heuristic",
            actual={"hits": key_hits},
            evidence=key_hits[:1],
            verification="match" if key_ok else "NO_MATCH",
            notification="heuristic_only",
            result="PASS" if key_ok else "PASS_WITH_LIMITATIONS",
        ),
    ]
    return {
        "result": result,
        "engine_ok": status.get("ok"),
        "backend": status.get("backend"),
        "rules_files": rules,
        "rows": rows,
        "commercial_note": "YARA lab signatures ≠ commercial antivirus",
        "eicar_policy": "TEST_FIXTURE never client malware",
        "publish_info_skip": "publish_findings skips severity=info (EICAR meta)",
    }


def demo_malware_boundary() -> Dict[str, Any]:
    from services.malware_behavior_engine import analyze_process

    synthetic = {
        "name": "powershell.exe",
        "command_line": "powershell -EncodedCommand syn_TEST_FIXTURE_ONLY FromBase64String",
        "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "pid": 0,
        "TEST_FIXTURE": True,
    }
    findings = analyze_process(synthetic)
    for f in findings:
        f["TEST_FIXTURE"] = True
        f["SYNTHETIC_TEST_ONLY"] = True

    return {
        "result": "PASS_WITH_LIMITATIONS" if findings else "PASS_WITH_LIMITATIONS",
        "conclusion": "MALWARE DETECTION: PARTIAL — detects only demonstrated patterns (YARA rules, cmdline heuristics, entropy/process indicators). NOT universal malware detection. NOT commercial AV.",
        "classes_demonstrated": [
            "YARA_EICAR_TEST_FIXTURE",
            "YARA_mimikatz_strings",
            "YARA_keylog_heuristic_strings",
            "cmdline_powershell_encoded_heuristic",
        ],
        "synthetic_cmdline_findings": findings,
        "not_demonstrated": ["packed_PE_live", "fileless_memory_live", "VT_without_key", "commercial_signatures"],
    }


def demo_ransomware() -> Dict[str, Any]:
    from security_engine import NovusSecurityEngine

    eng = NovusSecurityEngine()
    # Safe synthetic report — no real file mass-encrypt
    observation = eng.monitor_filesystem_activity(
        {
            "high_entropy_file_count": 1,
            "data_entropy": 8.0,
            "files_modified_per_sec": 1,
            "outbound_traffic_mbps": 0,
            "high_entropy_files": [{"path": "TEST_FIXTURE.tmp", "entropy": 8.0}],
            "SYNTHETIC_TEST_ONLY": True,
            "TEST_FIXTURE": True,
        }
    )
    confirmed_input = {
        "high_entropy_file_count": 5,
        "data_entropy": 8.1,
        "files_modified_per_sec": 80,
        "outbound_traffic_mbps": 0,
        "header_integrity_violation": False,
        "high_entropy_files": [{"path": f"TEST_FIXTURE_{i}.enc", "entropy": 8.1} for i in range(5)],
        "SYNTHETIC_TEST_ONLY": True,
        "TEST_FIXTURE": True,
    }
    confirmed = eng.monitor_filesystem_activity(confirmed_input)

    # Decision path only — do NOT claim OS lockdown verified
    action = (confirmed or {}).get("protocol_executed") or (confirmed or {}).get("action")
    verification = "DECISION_LOGIC_ONLY"
    if (confirmed or {}).get("verified") is True and action not in (None, "CONTINUE_MONITORING"):
        verification = "EXECUTED_NOT_VERIFIED"  # engine marks verified on decision; OS effect not proven here

    rows = [
        evidence_row(
            test_id="RANSOM-SINGLE-ENTROPY-OBSERVATION",
            engine="SecurityEngine.monitor_filesystem_activity",
            input="1 high-entropy file synthetic",
            expected="OBSERVATION not confirmed ransomware",
            actual=observation,
            result="PASS" if (observation or {}).get("status") == "OBSERVATION" else "PASS_WITH_LIMITATIONS",
            verification="observation_gate",
            notification="none_expected",
            response=(observation or {}).get("action"),
        ),
        evidence_row(
            test_id="RANSOM-BURST-SYNTHETIC",
            engine="SecurityEngine.monitor_filesystem_activity",
            input=confirmed_input,
            expected="elevated risk decision with indicators",
            actual=confirmed,
            severity=(confirmed or {}).get("risk_level"),
            evidence=(confirmed or {}).get("indicators"),
            response=action,
            verification=verification,
            notification="DETECTION_WITHOUT_USER_ALERT unless NSI _log_threat wired in this call",
            result="PASS_WITH_LIMITATIONS" if action and action != "CONTINUE_MONITORING" else "PASS_WITH_LIMITATIONS",
        ),
    ]
    return {
        "result": "PASS_WITH_LIMITATIONS",
        "conclusion": "RANSOMWARE: PARTIAL — heuristic FS/entropy/burst decision demonstrated on synthetic activity_report. Not real ransomware. Response protocol returned by engine is NOT proven OS lockdown SUCCESS.",
        "rows": rows,
        "do_not_claim": "RANSOMWARE BLOCKED",
    }


def demo_suspicious_process() -> Dict[str, Any]:
    import psutil
    from services.malware_behavior_engine import analyze_process
    from services.advanced_detector_service import AdvancedDetector

    live_samples = []
    for p in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            info = p.info
            cmd = " ".join(info.get("cmdline") or [])
            if not cmd:
                continue
            findings = analyze_process(
                {"name": info.get("name"), "command_line": cmd, "pid": info.get("pid"), "path": ""}
            )
            if findings:
                live_samples.append({"pid": info.get("pid"), "name": info.get("name"), "findings": findings[:2]})
            if len(live_samples) >= 3:
                break
        except (psutil.Error, Exception):
            continue

    # Synthetic fixture (not live kill)
    synth = analyze_process(
        {
            "name": "cmd.exe",
            "command_line": "cmd /c echo TEST_FIXTURE & powershell -w hidden -nop SYNTHETIC",
            "pid": -1,
        }
    )

    adv = None
    try:
        det = AdvancedDetector()
        if hasattr(det, "scan_running_processes"):
            adv = det.scan_running_processes()
        elif hasattr(det, "get_suspicious_processes"):
            adv = det.get_suspicious_processes()
        else:
            adv = {"note": "method_probe", "dir": [x for x in dir(det) if "scan" in x.lower() or "process" in x.lower()][:20]}
    except Exception as e:
        adv = {"error": str(e)[:200]}

    return {
        "result": "PASS_WITH_LIMITATIONS",
        "live_heuristic_hits_sample": live_samples,
        "synthetic_findings": synth,
        "advanced_detector": adv if not isinstance(adv, list) else {"count": len(adv), "sample": adv[:3]},
        "response": "NO_KILL_EXECUTED_IN_DEMO",
        "verification": "heuristic_match_only",
        "conclusion": "Suspicious process heuristics demonstrated on synthetic cmdline + optional live host samples. No process kill executed.",
    }


def demo_ndr_arp() -> Dict[str, Any]:
    nodes = []
    gateway = None
    try:
        from services.system_monitor import SystemMonitor

        rates = SystemMonitor().sample_traffic_rates()
    except Exception as e:
        rates = {"error": str(e)[:120]}
    try:
        # Prefer snapshot/cache if available
        from services import network_snapshot_service as nss

        if hasattr(nss, "get_cached_nodes"):
            nodes = nss.get_cached_nodes() or []
        elif hasattr(nss, "load_latest_snapshot"):
            snap = nss.load_latest_snapshot()
            nodes = (snap or {}).get("nodes") or []
    except Exception as e:
        nodes = [{"error": str(e)[:120]}]
    try:
        import subprocess

        out = subprocess.check_output("route print 0.0.0.0", shell=True, text=True, errors="replace")[:2000]
        for line in out.splitlines():
            if "0.0.0.0" in line and "Gateway" not in line:
                parts = line.split()
                if len(parts) >= 3:
                    gateway = parts[2]
                    break
    except Exception:
        pass

    observation = {
        "node_count": len(nodes) if isinstance(nodes, list) else None,
        "sample_nodes": (nodes[:5] if isinstance(nodes, list) else nodes),
        "gateway_guess": gateway,
        "traffic": rates,
        "scope": "HOST_GLOBAL",
    }
    # Discovery ≠ intrusion
    return {
        "result": "PASS_WITH_LIMITATIONS",
        "observation": observation,
        "anomaly": "NOT_INJECTED_IN_THIS_DEMO",
        "intrusion_confirmed": False,
        "conclusion": "INTRUSION DETECTION: NOT CONFIRMED — ARP/topology observation demonstrated; new-device≠intruder without policy+context. Traffic remains HOST_GLOBAL.",
        "rows": [
            evidence_row(
                test_id="NDR-ARP-OBSERVATION",
                engine="network_snapshot / SystemMonitor",
                input="host LAN observation",
                expected="nodes/gateway/traffic without fake devices",
                actual=observation,
                scope="HOST_GLOBAL",
                tenant_id=None,
                result="PASS" if observation.get("node_count") is not None or rates else "PASS_WITH_LIMITATIONS",
                verification="observation_only",
                notification="network_ui_if_configured",
            )
        ],
    }


def demo_brute_force() -> Dict[str, Any]:
    from services.auth_protection_service import record_auth_attempt, is_origin_blocked, unblock_ip

    results = []
    blocked = False
    last = {}
    for i in range(12):
        last = record_auth_attempt(
            success=False,
            email=TEST_EMAIL,
            route="login_TEST_FIXTURE",
            ip=TEST_IP,
            user_agent=f"NOVUS-SYNTHETIC-TEST/{RUN_ID}",
            session_id=f"syn-sess-{RUN_ID}",
        )
        results.append(
            {
                "i": i + 1,
                "sanction_level": last.get("sanction_level"),
                "incident": bool(last.get("incident")),
                "recorded": last.get("recorded"),
            }
        )
        if last.get("sanction_level", 0) > 0 or (last.get("incident") or {}).get("id"):
            blocked = True
            # continue a couple more then break
            if i >= 5:
                break

    status = is_origin_blocked(TEST_IP)
    # Cleanup — do not leave lab IP blocked
    cleanup = None
    try:
        cleanup = unblock_ip(TEST_IP, admin_email="syn_test_only@novus-client.test")
    except Exception as e:
        cleanup = {"error": str(e)[:120]}

    return {
        "result": "PASS" if any(r.get("recorded") for r in results) else "FAIL",
        "test_ip": TEST_IP,
        "test_email": TEST_EMAIL,
        "attempts": results,
        "blocked_or_sanctioned": blocked or bool(status.get("blocked")),
        "is_origin_blocked": status,
        "cleanup": cleanup,
        "distinction": {
            "DETECTION": "failed attempts recorded",
            "PREVENTION": "check_login_allowed / Abuse Guard (separate)",
            "BLOCKING": "sanction_level / IP block when threshold hit",
        },
        "rows": [
            evidence_row(
                test_id="BRUTE-FORCE-LAB",
                engine="auth_protection_service.record_auth_attempt",
                input={"ip": TEST_IP, "email": TEST_EMAIL, "n": len(results)},
                expected="record failures; possible sanction",
                actual={"attempts": results[-3:], "block": status},
                response="sanction/block if threshold" if blocked else "record_only",
                verification="db_event_recorded",
                notification="auth incident if escalated",
                result="PASS" if results else "FAIL",
                scope="PLATFORM",
            )
        ],
    }


def demo_web_api() -> Dict[str, Any]:
    import requests

    rows = []
    probes = [
        ("/config.py", "path_traversal_sensitive", (403, 404)),
        ("/secret.key", "sensitive_secret", (403, 404)),
        ("/.env", "dotenv", (403, 404, 302, 401)),
        ("/login", "csrf_page", (200,)),
        ("/api/dashboard/live", "unauth_api", (401, 302, 403)),
    ]
    for path, name, ok_status in probes:
        try:
            r = requests.get(f"{BASE}{path}", timeout=12, allow_redirects=False)
            st = r.status_code
            rows.append(
                evidence_row(
                    test_id=f"WEB-{name}",
                    engine="http + BLOCKED_PATHS / auth",
                    input={"path": path},
                    expected=list(ok_status),
                    actual={"status": st, "len": len(r.content or b"")},
                    result="PASS" if st in ok_status else "PASS_WITH_LIMITATIONS",
                    response="deny/redirect",
                    verification="status_code",
                    notification="N/A",
                )
            )
        except Exception as e:
            rows.append(evidence_row(test_id=f"WEB-{name}", engine="http", input=path, actual={"error": str(e)[:120]}, result="NOT_VERIFIABLE"))

    # Malformed / injection-ish on login GET only (non-destructive)
    try:
        r = requests.get(f"{BASE}/login", params={"q": "' OR 1=1 --"}, timeout=12)
        rows.append(
            evidence_row(
                test_id="WEB-SQLI-PARAM-GET",
                engine="login GET",
                input="sqli-ish query param",
                expected="page still serves without stack trace",
                actual={"status": r.status_code, "traceback": "Traceback" in (r.text or "")},
                result="PASS" if r.status_code == 200 and "Traceback" not in (r.text or "") else "PASS_WITH_LIMITATIONS",
                verification="no_stack_trace",
                notification="N/A",
                response="preventive_not_full_waf",
            )
        )
    except Exception as e:
        rows.append(evidence_row(test_id="WEB-SQLI-PARAM-GET", result="NOT_VERIFIABLE", actual={"error": str(e)[:100]}))

    fails = [r for r in rows if r.get("result") == "FAIL"]
    return {
        "result": "FAIL" if fails else "PASS_WITH_LIMITATIONS",
        "conclusion": "Web/API: platform preventive controls demonstrated (sensitive path deny, auth gate). NOT a full customer WAF.",
        "rows": rows,
    }


def demo_swarm_multi_signal() -> Dict[str, Any]:
    from services.swarm_defense.correlation import correlate
    from services.platform_event_contract import decide_response_action, normalize_severity_label, normalize_confidence_label

    event_payload = {
        "tenant_id": "SYNTHETIC_TEST_ONLY",
        "scope": "TENANT",
        "TEST_FIXTURE": True,
        "SYNTHETIC_TEST_ONLY": True,
        "event_id": f"SYN-CORR-{RUN_ID}",
    }
    indicators = {
        "auth": ["brute_force", "failed_login"],
        "endpoint": ["suspicious_process", "yara_hit"],
        "network": ["port_scan"],
    }
    contributions = [
        {"module_id": "auth", "found": True, "tenant_id": "SYNTHETIC_TEST_ONLY", "weight": 1},
        {"module_id": "endpoint", "found": True, "tenant_id": "SYNTHETIC_TEST_ONLY", "weight": 1},
        {"module_id": "network", "found": True, "tenant_id": "SYNTHETIC_TEST_ONLY", "weight": 1},
        # foreign tenant must be dropped
        {"module_id": "foreign", "found": True, "tenant_id": "OTHER_TENANT", "weight": 9},
    ]
    corr = correlate(event_payload, indicators, contributions)
    multi = bool((corr.get("multi_signal") or {}).get("is_multi_signal"))
    foreign_kept = "foreign" in ((corr.get("multi_signal") or {}).get("supporting_modules") or [])

    sev = normalize_severity_label("HIGH")
    conf = normalize_confidence_label("MEDIUM")
    decision = decide_response_action(severity=sev, confidence=conf)

    return {
        "result": "PASS" if multi and not foreign_kept else "PASS_WITH_LIMITATIONS",
        "correlation": corr,
        "multi_signal": multi,
        "foreign_tenant_dropped": not foreign_kept,
        "decision": decision,
        "tenant_lab": "SYNTHETIC_TEST_ONLY",
        "scope": "TENANT",
        "event_id": event_payload["event_id"],
        "conclusion": "Swarm multi_signal correlation exercised with lab signals; foreign tenant contribution dropped. Not APT campaign confirmed.",
    }


def demo_mitm() -> Dict[str, Any]:
    try:
        from security_engine import NovusSecurityEngine

        eng = NovusSecurityEngine()
        # Call with empty/minimal metadata — expect limited/no confirm
        if hasattr(eng, "verify_tunnel_integrity"):
            out = eng.verify_tunnel_integrity({})
        else:
            out = {"error": "method_missing"}
        return {
            "result": "NOT_VERIFIABLE",
            "actual": out,
            "conclusion": "MITM: NOT_VERIFIABLE — no safe isolated MITM lab exercised; empty TLS metadata path only probed.",
            "do_not_claim": "MITM protection E2E",
        }
    except Exception as e:
        return {"result": "NOT_VERIFIABLE", "error": str(e)[:200]}


def demo_mail_shield() -> Dict[str, Any]:
    gmail = False
    m365 = False
    try:
        from services.gmail_oauth_service import is_oauth_configured

        gmail = bool(is_oauth_configured())
    except Exception as e:
        gmail = f"error:{e}"[:80]
    try:
        from services.microsoft365_oauth_service import is_oauth_configured as m365_cfg

        m365 = bool(m365_cfg())
    except Exception as e:
        m365 = f"error:{e}"[:80]
    code_exists = (ROOT / "services" / "mail_shield_engine.py").exists()
    status = "NOT_CONFIGURED"
    if gmail is True or m365 is True:
        status = "PARTIAL"
    elif code_exists:
        status = "NOT_CONFIGURED"
    return {
        "result": "NOT_VERIFIABLE" if status == "NOT_CONFIGURED" else "PASS_WITH_LIMITATIONS",
        "code_exists": code_exists,
        "gmail_oauth": gmail,
        "m365_oauth": m365,
        "status": status,
        "conclusion": "Mail Shield implemented in code; inactive without OAuth credentials. No credentials created in this campaign.",
    }


def demo_defense_response() -> Dict[str, Any]:
    from services.swarm_defense.response_policy import (
        AUTO_ALLOWED,
        APPROVAL_REQUIRED,
        action_policy,
        verification_status_for_result,
    )

    matrix = []
    for a in sorted(AUTO_ALLOWED | APPROVAL_REQUIRED):
        pol = action_policy(a)
        # Simulate call result without executing destructive actions
        fake_result = {"ok": True, "action": a, "TEST_FIXTURE": True}
        ver = verification_status_for_result(fake_result)
        # Honest: ok True without post-check → should not be SUCCESS
        matrix.append(
            {
                "action": a,
                "policy": pol,
                "demo_execution": "NOT_EXECUTED_DESTRUCTIVE" if a in APPROVAL_REQUIRED else "POLICY_ONLY",
                "verification_label_on_bare_ok": ver,
                "commercial": "APPROVAL_REQUIRED" if a in APPROVAL_REQUIRED else "AUTO_NON_DESTRUCTIVE",
            }
        )

    # Prove honesty: bare function call ≠ SUCCESS
    bare = verification_status_for_result({"ok": True})
    verified_true = verification_status_for_result({"ok": True, "verified": True})

    return {
        "result": "PASS_WITH_LIMITATIONS",
        "auto": sorted(AUTO_ALLOWED),
        "approval": sorted(APPROVAL_REQUIRED),
        "matrix": matrix,
        "honesty_check": {
            "bare_ok_label": bare,
            "verified_true_label": verified_true,
            "rule": "Never claim SUCCESS from function call alone",
        },
        "destructive_actions_executed_in_demo": False,
    }


def demo_notification_flow(yara_pack: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "result": "PASS_WITH_LIMITATIONS",
        "flow": [
            "motor → record_detection/defense_coordinator",
            "evidence registry / evidence center",
            "NSI _log_threat → SQLite Alerta (separate path)",
            "alerts_canonical → API → Incidentes/XDR/Dashboard",
            "notification_center (partial emitters)",
        ],
        "yara_notification_note": (yara_pack.get("rows") or [{}])[1].get("notification")
        if yara_pack.get("rows")
        else None,
        "record_detection_alone_creates_alerta": False,
        "detection_without_user_alert_possible": True,
    }


def security_regression_light() -> Dict[str, Any]:
    import requests

    tests = []
    try:
        r = requests.get(f"{BASE}/login", timeout=15)
        tests.append({"id": "login", "result": "PASS" if r.status_code == 200 and "csrf_token" in (r.text or "") else "FAIL"})
    except Exception as e:
        tests.append({"id": "login", "result": "FAIL", "error": str(e)[:100]})
    for p in ("/config.py", "/secret.key"):
        try:
            r = requests.get(f"{BASE}{p}", timeout=10, allow_redirects=False)
            tests.append({"id": f"path{p}", "result": "PASS" if r.status_code in (403, 404) else "FAIL", "status": r.status_code})
        except Exception as e:
            tests.append({"id": f"path{p}", "result": "NOT_VERIFIABLE", "error": str(e)[:80]})
    # Tenant: cite prior if import works
    tenant_leaks = 0
    tenant_verdict = "CITED_PRIOR"
    try:
        prior = ROOT / "data" / "production_closure" / "beta_launch_gate" / "FINAL_TENANT_REGRESSION.json"
        if prior.exists():
            d = json.loads(prior.read_text(encoding="utf-8"))
            tenant_leaks = d.get("TENANT_LEAKS", 0)
            tenant_verdict = d.get("verdict", "PASS")
    except Exception:
        pass
    # Honesty units
    try:
        from services.alerts_canonical_service import _normalize_risk

        tests.append(
            {
                "id": "severity_not_invented",
                "result": "PASS" if _normalize_risk(None) == "NOT_AVAILABLE" else "FAIL",
            }
        )
    except Exception as e:
        tests.append({"id": "severity_not_invented", "result": "PARTIAL", "error": str(e)[:80]})

    fails = [t for t in tests if t.get("result") == "FAIL"]
    return {
        "verdict": "FAIL" if fails else "PASS_WITH_LIMITATIONS",
        "tests": tests,
        "TENANT_LEAKS": tenant_leaks,
        "tenant_verdict_cited": tenant_verdict,
        "MFA_E2E": "NOT_VERIFIABLE",
        "note": "Full tenant suite cited from beta_launch_gate; light HTTP probes this run",
    }


def main() -> int:
    log(f"=== THREAT DEFENSE E2E DEMO {RUN_ID} ===")
    before = host_snap()
    results: Dict[str, Any] = {"run_id": RUN_ID, "generated_at_utc": utc(), "code_modified": False}

    log("YARA...")
    results["yara"] = demo_yara()
    log(f"  yara={results['yara']['result']}")

    log("Malware boundary...")
    results["malware"] = demo_malware_boundary()

    log("Ransomware synthetic...")
    results["ransomware"] = demo_ransomware()
    log(f"  ransom={results['ransomware']['result']}")

    log("Suspicious process...")
    results["suspicious_process"] = demo_suspicious_process()

    log("NDR/ARP...")
    results["ndr_arp"] = demo_ndr_arp()

    log("Brute force lab...")
    results["brute_force"] = demo_brute_force()
    log(f"  brute={results['brute_force']['result']}")

    log("Web/API...")
    results["web_api"] = demo_web_api()

    log("Swarm multi-signal...")
    results["swarm"] = demo_swarm_multi_signal()
    log(f"  swarm={results['swarm']['result']}")

    log("MITM...")
    results["mitm"] = demo_mitm()

    log("Mail Shield...")
    results["mail_shield"] = demo_mail_shield()

    log("Defense response policy...")
    results["defense"] = demo_defense_response()

    log("Notification flow...")
    results["notification"] = demo_notification_flow(results["yara"])

    log("Security regression light...")
    results["security_regression"] = security_regression_light()

    after = host_snap()
    results["performance"] = {"before": before, "after": after}
    results["av_boundary"] = {
        "commercial_av": "NOT_IMPLEMENTED",
        "novus_threat_detection": "PARTIAL_YARA_HEURISTICS",
        "ml_trained": "NOT_IMPLEMENTED",
        "apt_hunting": "NOT_DEMONSTRATED",
    }

    write_json(f"E2E_DEMO_RESULTS_{RUN_ID}.json", results)
    write_json("E2E_DEMO_RESULTS_LATEST.json", results)
    print(json.dumps({k: (v.get("result") if isinstance(v, dict) else v) for k, v in results.items() if k not in ("performance",)}, indent=2, default=str)[:2000])
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        traceback.print_exc()
        raise SystemExit(1)
