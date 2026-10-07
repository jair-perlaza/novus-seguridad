"""Verifica conexiones de componentes existentes."""
import sys
import uuid

sys.path.insert(0, ".")


def test_vault_wired():
    from services.novus_security_integration import novus_security
    v = novus_security.vault
    ok = v is not None and v.llave_aes is not None
    print(f"  [{'OK' if ok else 'FAIL'}] CryptoVault conectado a novus_security")
    return ok


def test_sector_shield_api():
    from services.novus_security_integration import novus_security
    profile = novus_security.security_engine.build_sector_protection("fintech")
    ok = profile.get("profile_title") == "Escudo Fintech"
    print(f"  [{'OK' if ok else 'FAIL'}] build_sector_protection fintech")
    return ok


def test_vulnerability_scanner_wired():
    from services.novus_security_integration import novus_security
    vulns = novus_security.scan_vulnerabilities()
    sources = {v.get("fuente") for v in vulns}
    ok = isinstance(vulns, list)
    print(f"  [{'OK' if ok else 'FAIL'}] scan_vulnerabilities ({len(vulns)} items, fuentes: {sources})")
    return ok


def test_capability_registry_new():
    from services.ai_capability_registry import capability_registry
    for cap in ("security.sector_shield", "security.vault", "vulnerability.scanner", "remediation.engine"):
        assert cap in capability_registry.CAPABILITY_CATALOG
    data = capability_registry.execute(["security.vault"])
    ok = "security.vault" in data.get("capabilities_executed", [])
    print(f"  [{'OK' if ok else 'FAIL'}] capability_registry nuevas capacidades")
    return ok


def test_register_threat_event():
    from services.novus_security_integration import novus_security
    novus_security._register_runtime_threat("TEST", "integration", "LOW", {"test": True})
    ok = any(t.get("threat_type") == "TEST" for t in novus_security.security_engine.threat_registry)
    print(f"  [{'OK' if ok else 'FAIL'}] register_threat_event + threat_registry")
    return ok


def test_kernel_capabilities():
    from services.kernel_operator import kernel_operator
    r = kernel_operator.process(f"test-{uuid.uuid4().hex[:6]}", "¿Cuántas vulnerabilidades tengo?", user_id=None)
    ok = r.get("request_type") == "query" and bool(r.get("engines_executed"))
    print(f"  [{'OK' if ok else 'FAIL'}] Kernel IA consulta motores: {r.get('engines_executed', [])[:2]}")
    return ok


if __name__ == "__main__":
    print("=== test_integration_wiring ===\n")
    tests = [
        test_vault_wired,
        test_sector_shield_api,
        test_vulnerability_scanner_wired,
        test_capability_registry_new,
        test_register_threat_event,
        test_kernel_capabilities,
    ]
    results = [t() for t in tests]
    print(f"\n=== {sum(results)}/{len(results)} PASS ===")
    sys.exit(0 if all(results) else 1)
