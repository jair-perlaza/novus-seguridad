#!/usr/bin/env python3
"""Probar qué clave verifica firmas del ledger."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

KEY_DIR = ROOT / "data" / "forensic_keys"


def try_verify(pub: Ed25519PublicKey, msg: bytes, sig_hex: str) -> bool:
    try:
        pub.verify(bytes.fromhex(sig_hex), msg)
        return True
    except Exception:
        return False


def main() -> int:
    rec_path = ROOT / "data" / "forensic_ledger" / "records.jsonl"
    samples = []
    with open(rec_path, encoding="utf-8") as fh:
        for i, line in enumerate(fh):
            if i >= 3 and i < 6460:
                continue
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            msg = "|".join(
                [
                    str(r.get("content_hash_sha256") or ""),
                    str(r.get("chain_hash") or ""),
                    str(r.get("prev_chain_hash") or ""),
                    str(r.get("forensic_id") or ""),
                ]
            ).encode()
            samples.append((r.get("forensic_id"), r.get("signature_key_id"), msg, r.get("signature_hex") or ""))

    candidates = {}
    # current public
    pub_pem = (KEY_DIR / "ed25519_public.pem").read_bytes()
    candidates["current_pub"] = serialization.load_pem_public_key(pub_pem)

    # plaintext private if present
    priv_path = KEY_DIR / "ed25519_private.pem"
    if priv_path.is_file():
        priv = serialization.load_pem_private_key(priv_path.read_bytes(), password=None)
        candidates["plaintext_priv_pub"] = priv.public_key()

    legacy = KEY_DIR / "legacy" / "ed25519_private.pem.migrated"
    if legacy.is_file():
        priv = serialization.load_pem_private_key(legacy.read_bytes(), password=None)
        candidates["legacy_migrated_pub"] = priv.public_key()

    # wrapped
    try:
        from services.key_protection_service import read_wrapped_file

        wrap = KEY_DIR / "ed25519_private.pem.wrap"
        if wrap.is_file():
            pem = read_wrapped_file(str(wrap))
            priv = serialization.load_pem_private_key(pem, password=None)
            candidates["wrap_pub"] = priv.public_key()
    except Exception as exc:
        candidates["wrap_error"] = str(exc)  # type: ignore

    report = {"sample_count": len(samples), "keys": list(candidates.keys()), "results": []}
    for name, pub in list(candidates.items()):
        if not hasattr(pub, "verify"):
            continue
        ok_n = 0
        for fid, kid, msg, sig in samples:
            if try_verify(pub, msg, sig):
                ok_n += 1
        report["results"].append({"key": name, "verified_samples": ok_n, "of": len(samples)})

    # also check key ids in first/last records
    report["sample_kids"] = [(s[0], s[1]) for s in samples]
    print(json.dumps(report, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
