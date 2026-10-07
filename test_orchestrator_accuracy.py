"""
Test de precision del clasificador de intenciones del Kernel IA.
Objetivo: >95% aciertos en seleccion de intent y modulos.
"""
from services.ai_orchestrator import kernel_orchestrator, SOC_INTENTS

# (pregunta, intent_esperado, modulos_obligatorios, modulos_prohibidos)
TEST_CASES = [
    # Vulnerabilidades (15)
    ("Cuántas vulnerabilidades tiene mi equipo?", "vulnerabilities", ["vulnerabilities"], ["network"]),
    ("¿Cuántas vulnerabilidades tengo?", "vulnerabilities", ["vulnerabilities"], ["network"]),
    ("Cuantas vulns detectaste", "vulnerabilities", ["vulnerabilities"], ["network"]),
    ("Hay vulnerabilidades en mi PC?", "vulnerabilities", ["vulnerabilities"], ["network"]),
    ("Lista de vulnerabilidades del equipo", "vulnerabilities", ["vulnerabilities"], ["network"]),
    ("Buscar vulnerabilidades", "vulnerabilities", ["vulnerabilities"], []),
    ("Escanea vulnerabilidades del sistema", "vulnerabilities", ["vulnerabilities"], []),
    ("Tengo CVEs abiertos?", "vulnerabilities", ["vulnerabilities"], ["network"]),
    ("Cuántos hallazgos de seguridad hay", "vulnerabilities", ["vulnerabilities"], []),
    ("Estado de pentesting", "vulnerabilities", ["vulnerabilities"], ["network"]),
    ("Mi equipo tiene exploits?", "vulnerabilities", ["vulnerabilities"], ["network"]),
    ("Necesito saber las vulnerabilidades", "vulnerabilities", ["vulnerabilities"], ["network"]),
    ("Que vulnerabilidades tiene mi computador", "vulnerabilities", ["vulnerabilities"], ["network"]),
    ("Informe de vulnerabilidades del host", "vulnerabilities", ["vulnerabilities"], []),
    ("Parchear vulnerabilidades detectadas", "vulnerabilities", ["vulnerabilities"], []),
    # Red (12)
    ("Como esta mi red?", "network_status", ["network"], []),
    ("Estado de la red", "network_status", ["network"], []),
    ("Cuantos dispositivos conectados hay?", "network_status", ["network"], []),
    ("Quien esta conectado a la red?", "network_status", ["network"], []),
    ("Gateway y segmento de red", "network_status", ["network"], []),
    ("Como esta el wifi?", "network_status", ["network"], []),
    ("Dispositivos en la red local", "network_status", ["network"], []),
    ("Escaneo ARP de la red", "network_status", ["network"], []),
    ("Estado del router", "network_status", ["network"], []),
    ("Nodos detectados en network", "network_status", ["network"], []),
    ("Informacion de la red corporativa", "network_status", ["network"], []),
    ("Cuántos equipos hay en la red?", "network_status", ["network"], []),
    # Trafico (5)
    ("Como esta el trafico de la red?", "network_status", ["network", "traffic"], []),
    ("Consumo de ancho de banda", "traffic", ["traffic"], []),
    ("Cuanto trafico hay?", "traffic", ["traffic"], []),
    ("Bytes recibidos y enviados", "traffic", ["traffic"], []),
    ("Trafico de red actual", "network_status", ["traffic", "network"], []),
    # Procesos (6)
    ("Hay procesos sospechosos?", "processes", ["processes"], []),
    ("Quien consume mas CPU?", "processes", ["processes"], []),
    ("Lista de procesos activos", "processes", ["processes"], []),
    ("Procesos con alto consumo de memoria", "processes", ["processes"], []),
    ("Analiza los procesos del sistema", "processes", ["processes"], []),
    ("PID sospechosos", "processes", ["processes"], []),
    # Malware (4)
    ("Busca malware", "malware", ["security"], []),
    ("Hay ransomware?", "malware", ["security"], []),
    ("Detecta rootkits", "malware", ["security"], []),
    ("Escanea virus en el equipo", "malware", ["security"], []),
    # Firewall (4)
    ("Revisa el firewall", "firewall", ["firewall"], []),
    ("Puertos abiertos", "firewall", ["firewall"], []),
    ("Estado del cortafuegos", "firewall", ["firewall"], []),
    ("Analiza puertos expuestos", "firewall", ["firewall"], []),
    # Conexiones (3)
    ("Conexiones activas", "connections", ["connections"], []),
    ("Analiza conexiones de red", "connections", ["connections"], []),
    ("Sockets establecidos", "connections", ["connections"], []),
    # Gmail (3)
    ("Analiza mis correos", "gmail", ["gmail"], []),
    ("Seguridad del correo gmail", "gmail", ["gmail"], []),
    ("Hay phishing en mi email?", "gmail", ["gmail"], []),
    # Incidentes (3)
    ("Incidentes recientes", "incidents", ["incidents"], []),
    ("Hay algo raro?", "incidents", ["incidents"], []),
    ("Alertas criticas", "incidents", ["incidents"], []),
    # Reportes (3)
    ("Generar reporte de seguridad", "reports", ["reports"], []),
    ("Exportar informe PDF", "reports", ["reports"], []),
    ("Historial de reportes", "reports", ["reports"], []),
    # Sistema (4)
    ("Como esta la memoria RAM?", "system_health", ["system"], []),
    ("Uso de CPU", "system_health", ["system"], []),
    ("Estado del disco", "system_health", ["system"], []),
    ("Revisame el computador", "system_health", ["system"], []),
    # General (3)
    ("Como estamos?", "general_status", ["dashboard"], []),
    ("Que tal el estado general?", "general_status", ["dashboard"], []),
    ("Panorama de seguridad", "general_status", ["security"], []),
    # Deep Scan (8)
    ("Escanea mi portátil", "deep_scan", ["deep_scan"], []),
    ("Analiza mi computador", "deep_scan", ["deep_scan"], []),
    ("Haz un análisis completo", "deep_scan", ["deep_scan"], []),
    ("Busca anomalías", "deep_scan", ["deep_scan"], []),
    ("Analiza todos los archivos", "deep_scan", ["deep_scan"], []),
    ("Deep Scan", "deep_scan", ["deep_scan"], []),
    ("Revisa todo", "deep_scan", ["deep_scan"], []),
    ("Escaneo integral del equipo", "deep_scan", ["deep_scan"], []),
    # Analisis completo legacy (3)
    ("Analiza completamente mi computador", "full_computer_analysis", ["system", "vulnerabilities"], []),
    ("Escanea todo el sistema", "full_computer_analysis", ["vulnerabilities", "system"], []),
    ("Auditoria completa del equipo", "full_computer_analysis", ["vulnerabilities"], []),
]


def validate_case(question, expected_intent, required_modules, forbidden_modules):
    intent = kernel_orchestrator.classify_intent(question)
    primary = intent.get("primary_intent")
    modules = intent.get("active_modules", [])
    errors = []

    if primary != expected_intent:
        # Permitir intents relacionados para trafico/red
        related = {
            "network_status": {"traffic"},
            "traffic": {"network_status"},
            "vulnerabilities": set(),
            "general_status": {"full_computer_analysis"},
            "deep_scan": {"full_computer_analysis"},
            "full_computer_analysis": {"deep_scan"},
        }
        allowed_alt = related.get(expected_intent, set())
        if primary not in allowed_alt and expected_intent not in allowed_alt:
            errors.append(f"intent: esperado={expected_intent} got={primary}")

    for mod in required_modules:
        if mod not in modules:
            errors.append(f"falta modulo: {mod}")

    for mod in forbidden_modules:
        if mod in modules:
            errors.append(f"modulo prohibido presente: {mod}")

    return len(errors) == 0, errors, primary, modules


def run_tests():
    passed = 0
    failed = []
    for q, exp_int, req_mod, forbid_mod in TEST_CASES:
        ok, errs, primary, modules = validate_case(q, exp_int, req_mod, forbid_mod)
        if ok:
            passed += 1
        else:
            failed.append({"question": q, "expected": exp_int, "got": primary, "modules": modules, "errors": errs})

    total = len(TEST_CASES)
    pct = (passed / total) * 100
    print(f"RESULTADOS: {passed}/{total} ({pct:.1f}%)")
    if failed:
        print("\nFALLIDOS:")
        for f in failed:
            print(f"  Q: {f['question']}")
            print(f"     {f['errors']}")
    return pct, failed


if __name__ == "__main__":
    pct, failed = run_tests()
    if pct < 95:
        raise SystemExit(1)
