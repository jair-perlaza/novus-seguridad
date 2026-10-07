"""
Pruebas del operador autónomo KernelOperator — arquitectura agente async.
"""
import sys
import time
import uuid

sys.path.insert(0, ".")

from services.kernel_operator import classify_request, resolve_action, kernel_operator
from services.kernel_coordinator import kernel_coordinator


def _wait_result(operation_id: str, timeout: float = 120.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        st = kernel_coordinator.get_status(operation_id)
        if st and st.get("status") in ("completed", "error"):
            return kernel_coordinator.get_result(operation_id) or st
        time.sleep(1.0)
    return None


def test_classification():
    cases = [
        ("¿Cómo está mi red?", "action"),
        ("¿Cuántas vulnerabilidades tengo?", "query"),
        ("Escanea mi portátil", "action"),
        ("Limpia las amenazas", "clean_threats"),
        ("Hola", "query"),
    ]
    ok = 0
    for msg, expected in cases:
        got = classify_request(msg)["request_type"]
        if got == expected or (expected == "query" and got in ("query", "greeting")):
            ok += 1
            print(f"  [OK] {msg!r} -> {got}")
        else:
            print(f"  [FAIL] {msg!r} -> {got} (esp {expected})")
    print(f"Clasificacion: {ok}/{len(cases)}")
    return ok == len(cases)


def test_greeting_immediate():
    session = f"test-{uuid.uuid4().hex[:8]}"
    r = kernel_operator.process(session, "Hola", user_id=None)
    ok = r.get("request_type") == "greeting" and r.get("reply") and not r.get("working")
    print(f"  [{'OK' if ok else 'FAIL'}] Hola -> reply inmediato, working={r.get('working')}")
    return ok


def test_query_async_work():
    session = f"test-{uuid.uuid4().hex[:8]}"
    r = kernel_operator.process(session, "¿Hay procesos sospechosos?", user_id=None)
    ok = r.get("working") and r.get("operation_id") and r.get("reply") is None
    print(f"  [{'OK' if ok else 'FAIL'}] query async working={r.get('working')} op={r.get('operation_id')}")
    if ok:
        final = _wait_result(r["operation_id"], 90)
        ok = final and final.get("reply") and len(final.get("reply", "")) > 200
        print(f"  [{'OK' if ok else 'FAIL'}] resultado final len={len(final.get('reply','')) if final else 0}")
    return ok


def test_action_starts_work():
    session = f"test-{uuid.uuid4().hex[:8]}"
    r = kernel_operator.process(session, "Genera un informe", user_id=None)
    ok = r.get("working") or r.get("operation_id")
    print(f"  [{'OK' if ok else 'FAIL'}] Genera informe -> working={r.get('working')}")
    return ok


if __name__ == "__main__":
    print("=== test_kernel_operator (agente async) ===\n")
    results = [
        test_classification(),
        test_greeting_immediate(),
        test_query_async_work(),
        test_action_starts_work(),
    ]
    passed = sum(results)
    print(f"\n=== TOTAL: {passed}/{len(results)} PASS ===")
    sys.exit(0 if passed == len(results) else 1)
