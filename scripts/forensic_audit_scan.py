#!/usr/bin/env python3
"""Auditoría forense automatizada — métricas verificables del repositorio NOVUS."""
import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKIP_DIRS = {'.git', '__pycache__', 'build', 'node_modules', '.venv', 'venv', 'dist'}
EXTENSIONS = {'.py', '.html', '.js', '.css', '.jinja', '.jinja2', '.json', '.sql', '.md'}
PATTERNS = [
    (r'\bmock\b', 'mock'),
    (r'\bfake\b', 'fake'),
    (r'\bdummy\b', 'dummy'),
    (r'\bdemo\b', 'demo'),
    (r'\bsample\b', 'sample'),
    (r'\bhardcod', 'hardcoded'),
    (r'\bplaceholder\b', 'placeholder'),
    (r'Math\.random', 'Math.random'),
    (r'\bfaker\b', 'faker'),
    (r'\bfixture\b', 'fixture'),
    (r'"Online"', 'Online string'),
    (r"'Online'", 'Online string'),
    (r'Cali', 'Cali reference'),
    (r'domain_age_days.*365', 'domain_age_days 365'),
    (r'known_vulns', 'known_vulns static'),
    (r'novus-security\.com', 'fixed corporate domain'),
]

def iter_files():
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            p = Path(dirpath) / fn
            if p.suffix.lower() in EXTENSIONS or fn.endswith('.jinja'):
                yield p

def main():
    files = list(iter_files())
    total_lines = 0
    findings = []
    for fp in files:
        try:
            text = fp.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            continue
        lines = text.splitlines()
        total_lines += len(lines)
        rel = fp.relative_to(ROOT).as_posix()
        for i, line in enumerate(lines, 1):
            for pat, label in PATTERNS:
                if re.search(pat, line, re.I):
                    # skip benign: HTML placeholder attrs, audit registry docs, comments about no demo
                    if label == 'placeholder' and 'placeholder=' in line:
                        continue
                    if label == 'demo' and 'no demo' in line.lower():
                        continue
                    if label == 'sample' and 'sample' in line and 'ai_capability' in rel:
                        continue
                    if rel.startswith('build/'):
                        continue
                    if rel == 'scripts/forensic_audit_scan.py':
                        continue
                    findings.append({
                        'file': rel,
                        'line': i,
                        'label': label,
                        'snippet': line.strip()[:120],
                    })

    print(f"FILES_ANALYZED={len(files)}")
    print(f"LINES_REVIEWED={total_lines}")
    print(f"PATTERN_HITS={len(findings)}")
    for f in findings[:80]:
        print(f"  [{f['label']}] {f['file']}:{f['line']} — {f['snippet']}")
    if len(findings) > 80:
        print(f"  ... y {len(findings)-80} más")

if __name__ == '__main__':
    main()
