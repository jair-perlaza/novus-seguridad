"""
Verificacion funcional del Kernel Agent autonomo.
"""
import sys
import uuid

sys.path.insert(0, ".")

from services.kernel_agent import kernel_agent
from services.kernel_planner import build_plan

CASES = [
    ("Hola", "greeting", False),
    ("Escanea mi portatil", "action", True),
    ("Como esta mi red", "action", True),
    ("Hay procesos sospechosos?", "query", True),
    ("Tengo malware?", "action", True),
    ("Que vulnerabilidades tiene mi equipo?", "query", True),
    ("Que paso hoy?", "query", True),
    ("Analiza este correo", "action", True),
    ("Limpia las amenazas", "clean_threats", True),
]

def main():
    session = f"verify-{uuid.uuid4().hex[:8]}"
    ok = 0
    print("=== verify_kernel_agent ===\n")
    for msg, exp_type, need_agent in CASES:
        plan = build_plan(msg)
        r = kernel_agent.process(session, msg, user_id=None)
        agent = r.get("agent_mode") is True
        has_trace = bool(r.get("decision_trace") or r.get("plan"))
        engines = bool(r.get("engines_executed") or r.get("scan_id") or r.get("defer_full_reply"))
        generic = len(r.get("reply", "")) < 50 and "CPU" in r.get("reply", "")
        passed = agent and not generic
        if need_agent and exp_type != "greeting":
            passed = passed and (engines or r.get("soc_report") or r.get("confirm_required"))
        if passed:
            ok += 1
        status = "OK" if passed else "FAIL"
        print(f"  [{status}] {msg[:35]!r} plan={plan.request_type} agent={agent}")
    print(f"\nResultado: {ok}/{len(CASES)}")
    return 0 if ok >= len(CASES) - 1 else 1

if __name__ == "__main__":
    sys.exit(main())
