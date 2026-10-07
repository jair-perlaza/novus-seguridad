#!/usr/bin/env python3
"""Diagnóstico ligero de cadena forense (solo lectura)."""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from services.forensic_evidence_integrity_service import (  # noqa: E402
    _compute_chain_hash,
    _payload_for_hash,
    _verify_signature,
)


def main() -> int:
    rec = ROOT / "data" / "forensic_ledger" / "records.jsonl"
    prev = "0" * 64
    stats: Counter = Counter()
    samples = []
    n = 0
    with open(rec, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            n += 1
            r = json.loads(line)
            link = r.get("prev_chain_hash") == prev
            expected = _payload_for_hash(
                source_id=r.get("source_id") or "",
                motor=r.get("motor") or "",
                evidence_type=r.get("evidence_type") or "",
                payload=r.get("payload") if isinstance(r.get("payload"), dict) else {},
                user_email=r.get("user_email"),
                tenant_id=r.get("tenant_id"),
                equipment=r.get("equipment"),
            )
            ch_ok = r.get("content_hash_sha256") == expected
            core = {
                k: r.get(k)
                for k in (
                    "forensic_id",
                    "source_id",
                    "source_type",
                    "version",
                    "supersedes",
                    "update_reason",
                    "event_date",
                    "event_time",
                    "timestamp",
                    "user_email",
                    "tenant_id",
                    "equipment",
                    "motor",
                    "evidence_type",
                    "payload",
                    "content_hash_sha256",
                    "prev_chain_hash",
                    "hash_algorithm",
                    "sign_algorithm",
                    "migrated_from_legacy",
                )
            }
            if not isinstance(core.get("payload"), dict):
                core["payload"] = {}
            chain_ok = r.get("chain_hash") == _compute_chain_hash(core)
            msg = "|".join(
                [
                    str(r.get("content_hash_sha256") or ""),
                    str(r.get("chain_hash") or ""),
                    str(r.get("prev_chain_hash") or ""),
                    str(r.get("forensic_id") or ""),
                ]
            ).encode()
            sig_ok = bool(r.get("signature_hex")) and _verify_signature(
                msg, r.get("signature_hex") or ""
            )
            if not link:
                stats["chain_break"] += 1
            if not ch_ok:
                stats["content_fail"] += 1
            if not chain_ok:
                stats["chain_hash_fail"] += 1
            if not sig_ok:
                stats["sig_fail"] += 1
            if link and ch_ok and chain_ok and sig_ok:
                stats["ok"] += 1
            else:
                stats["bad"] += 1
                if len(samples) < 8:
                    samples.append(
                        {
                            "fid": r.get("forensic_id"),
                            "link": link,
                            "ch": ch_ok,
                            "chain": chain_ok,
                            "sig": sig_ok,
                            "motor": r.get("motor"),
                            "type": r.get("evidence_type"),
                        }
                    )
            prev = r.get("chain_hash") or prev
    head = json.loads(
        (ROOT / "data" / "forensic_ledger" / "chain_head.json").read_text(encoding="utf-8")
    )
    print(
        json.dumps(
            {
                "total": n,
                "stats": dict(stats),
                "samples": samples,
                "head_match": head.get("chain_hash") == prev,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
