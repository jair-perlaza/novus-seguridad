"""
Prueba del Kernel IA SOC/XDR — ≥30 consultas distintas.
Verifica: ejecución de motores, informes SOC, no respuestas genéricas.
"""
import sys
import uuid

sys.path.insert(0, ".")

from services.kernel_operator import classify_request, kernel_operator

# (pregunta, tipo_esperado, perfil_o_none, debe_tener_motores, no_generico)
SOC_QUERIES = [
    ("¿Cómo está mi red?", "action", "network", True, True),
    ("¿Cuántas vulnerabilidades tiene mi equipo?", "query", None, True, True),
    ("Escanea mi portátil", "action", "full", True, True),
    ("Analiza mi red", "action", "network", True, True),
    ("Busca malware", "action", "malware", True, True),
    ("Revisa si alguien está conectado a mi WiFi", "action", "network", True, True),
    ("Mi computador está lento", "action", "processes", True, True),
    ("No puedo entrar al banco", "action", "connections", True, True),
    ("Creo que tengo un virus", "action", "malware", True, True),
    ("¿Cómo está la seguridad de mi empresa?", "action", "full", True, True),
    ("Limpia las amenazas", "clean_threats", None, True, True),
    ("Analiza este correo", "action", "gmail", True, True),
    ("¿Cuántos dispositivos hay en mi red?", "action", "network", True, True),
    ("Analiza conexiones", "action", "connections", True, True),
    ("Revisa procesos sospechosos", "action", "processes", True, True),
    ("Busca rootkits", "action", "rootkit", True, True),
    ("Analiza memoria", "action", "memory", True, True),
    ("Revisa mi firewall", "action", "connections", True, True),
    ("Genera un informe", "action", "report", True, True),
    ("Deep Scan", "action", "full", True, True),
    ("¿Hay procesos sospechosos?", "query", None, True, True),
    ("¿Cuál es el tráfico de red?", "query", None, True, True),
    ("¿Cuántas amenazas hay?", "query", None, True, True),
    ("Estado del firewall", "query", None, True, True),
    ("Dispositivos conectados", "action", "network", True, True),
    ("Analiza servicios de Windows", "action", "services", True, True),
    ("Busca aplicaciones sospechosas", "action", "processes", True, True),
    ("Analiza tareas programadas", "action", "scheduled", True, True),
    ("Escanea mi equipo", "action", "full", True, True),
    ("¿Qué puertos están abiertos?", "query", None, True, True),
    ("Revisa el registro de Windows", "action", "registry", True, True),
    ("Analiza programas instalados", "action", "installed", True, True),
    ("Busca anomalías", "action", "full", True, True),
    ("¿Hay incidentes críticos?", "query", None, True, True),
    ("Analiza mis correos", "action", "gmail", True, True),
]

GENERIC_MARKERS = [
    "CPU:",
    "RAM:",
    "Dashboard",
    "RESPUESTA DIRECTA:",
    "Sin datos disponibles en caché",
    "Estado general — CPU",
]

SOC_MARKERS = [
    "RESUMEN EJECUTIVO",
    "INFORME SOC",
    "MOTORES EJECUTADOS",
    "TAREA SOC INICIADA",
    "═══",
    "Motores:",
    "Motores cargados",
    "Motores ejecutados",
]


def _is_soc_report(reply: str) -> bool:
    if not reply or len(reply) < 80:
        return False
    return any(m in reply for m in SOC_MARKERS)


def _is_generic_only(reply: str) -> bool:
    """Respuesta demasiado corta o solo métricas dashboard."""
    if len(reply) < 60:
        return True
    has_soc = _is_soc_report(reply)
    if has_soc:
        return False
    # Solo CPU/RAM sin informe
    if reply.count("\n") < 3 and any(g in reply for g in GENERIC_MARKERS[:3]):
        return True
    return False


def test_classification():
    ok = 0
    print("\n-- Clasificacion de intenciones --")
    for msg, exp_type, exp_profile, _, _ in SOC_QUERIES:
        c = classify_request(msg)
        got_type = c["request_type"]
        got_profile = None
        if c.get("action"):
            got_profile = c["action"].get("action_id") or c["action"].get("profile")
        type_ok = got_type == exp_type
        profile_ok = exp_profile is None or got_profile == exp_profile
        passed = type_ok and profile_ok
        if passed:
            ok += 1
        status = "OK" if passed else "FAIL"
        print(f"  [{status}] {msg[:45]!r} → {got_type}/{got_profile} (esp: {exp_type}/{exp_profile})")
    print(f"Clasificación: {ok}/{len(SOC_QUERIES)}")
    return ok, len(SOC_QUERIES)


def test_execution_and_reports(max_live: int = 35):
    """Ejecuta consultas reales y verifica motores + informe SOC."""
    ok = 0
    engines_seen = set()
    session = f"soc-test-{uuid.uuid4().hex[:8]}"
    print("\n-- Ejecucion de motores e informes SOC --")

    for i, (msg, exp_type, _, need_engines, no_generic) in enumerate(SOC_QUERIES):
        if i >= max_live:
            break
        try:
            r = kernel_operator.process(session, msg, user_id=None)
            reply = r.get("reply", "")
            engines = r.get("engines_executed") or r.get("engines_executed", [])
            if not engines:
                intent = r.get("intent") or {}
                engines = intent.get("capabilities") or []

            has_engines = bool(engines) or bool(r.get("scan_id")) or r.get("soc_workflow")
            soc_ok = _is_soc_report(reply) or r.get("defer_full_reply") or r.get("confirm_required")
            generic_bad = _is_generic_only(reply) if no_generic else False

            passed = soc_ok and not generic_bad
            if need_engines and not has_engines and exp_type != "clean_threats":
                passed = False

            for e in (engines if isinstance(engines, list) else []):
                engines_seen.add(str(e))

            if passed:
                ok += 1
            status = "OK" if passed else "FAIL"
            eng_preview = (engines[:2] if isinstance(engines, list) else [r.get("profile")]) or ["—"]
            print(
                f"  [{status}] {msg[:40]!r} "
                f"type={r.get('request_type')} soc={soc_ok} engines={eng_preview}"
            )
            if not passed and reply:
                print(f"         preview: {reply[:100].replace(chr(10), ' ')}...")
        except Exception as exc:
            print(f"  [FAIL] {msg[:40]!r} ERROR: {exc}")

    print(f"\nEjecución/informes: {ok}/{min(max_live, len(SOC_QUERIES))}")
    print(f"Motores distintos observados: {len(engines_seen)}")
    for e in sorted(engines_seen)[:15]:
        print(f"    • {e}")
    return ok, min(max_live, len(SOC_QUERIES)), engines_seen


def test_diverse_engines(min_distinct: int = 5):
    _, _, engines = test_execution_and_reports(max_live=20)
    # Re-run a few more for diversity
    session = f"soc-div-{uuid.uuid4().hex[:8]}"
    extra = ["Escanea mi portátil", "Analiza mi red", "Busca malware"]
    for msg in extra:
        try:
            r = kernel_operator.process(session, msg, user_id=None)
            for e in r.get("engines_executed") or []:
                engines.add(str(e))
            if r.get("profile"):
                engines.add(f"profile:{r.get('profile')}")
        except Exception:
            pass
    passed = len(engines) >= min_distinct
    print(f"\n-- Diversidad de motores: {len(engines)} (min {min_distinct}) {'OK' if passed else 'FAIL'} --")
    return passed


if __name__ == "__main__":
    print("=" * 60)
    print("  TEST KERNEL IA SOC/XDR — NOVUS")
    print("=" * 60)

    c_ok, c_total = test_classification()
    e_ok, e_total, _ = test_execution_and_reports(max_live=35)
    d_ok = test_diverse_engines(min_distinct=5)

    total_pass = c_ok >= int(c_total * 0.95) and e_ok >= int(e_total * 0.85) and d_ok
    print("\n" + "=" * 60)
    print(f"  CLASIFICACION: {c_ok}/{c_total}")
    print(f"  EJECUCION/INFORMES: {e_ok}/{e_total}")
    print(f"  DIVERSIDAD MOTORES: {'PASS' if d_ok else 'FAIL'}")
    print(f"  RESULTADO GLOBAL: {'PASS' if total_pass else 'NEEDS FIX'}")
    print("=" * 60)
    sys.exit(0 if total_pass else 1)
