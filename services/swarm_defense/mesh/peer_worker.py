#!/usr/bin/env python3
"""
Nodo Mesh peer mínimo (segunda instancia NOVUS) para pruebas multi-nodo reales.
Uso: NOVUS_MESH_NODE_ID=peer-b py -3 -m services.swarm_defense.mesh.peer_worker --port 5055
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)


def main() -> int:
    parser = argparse.ArgumentParser(description="NOVUS Swarm Mesh peer worker")
    parser.add_argument("--port", type=int, default=5055)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()

    if not os.environ.get("NOVUS_MESH_NODE_ID"):
        os.environ["NOVUS_MESH_NODE_ID"] = f"peer-worker-{args.port}"

    from flask import Flask
    from api.swarm_mesh import swarm_mesh_api_bp
    from services.swarm_defense.mesh import node_identity

    node_identity.ensure_node_identity()
    app = Flask("novus_mesh_peer")
    app.register_blueprint(swarm_mesh_api_bp)

    print(
        f"[mesh-peer] node_id={node_identity.resolve_node_id()} "
        f"listening http://{args.host}:{args.port}"
    )
    app.run(host=args.host, port=args.port, threaded=True, use_reloader=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
