#!/usr/bin/env python3
import time
from pathlib import Path

import psutil

ROOT = str(Path(r"C:\NOVUS"))


def main():
    pids = []
    for p in psutil.process_iter(["pid", "cmdline", "memory_info"]):
        try:
            cmd = " ".join(p.info.get("cmdline") or [])
            if "main.py" in cmd and ROOT.replace("\\", "/") in cmd.replace("\\", "/"):
                pids.append(p.info["pid"])
                print("FOUND", p.info["pid"], round(p.info["memory_info"].rss / 1024 / 1024, 1))
        except Exception:
            pass
    for pid in pids:
        try:
            psutil.Process(pid).terminate()
        except Exception as e:
            print("term fail", pid, e)
    time.sleep(3)
    for pid in pids:
        try:
            if psutil.pid_exists(pid):
                psutil.Process(pid).kill()
                print("killed", pid)
        except Exception:
            pass
    # also port 5000
    for c in psutil.net_connections(kind="inet"):
        if c.laddr and getattr(c.laddr, "port", None) == 5000 and c.pid:
            try:
                psutil.Process(c.pid).kill()
                print("port5000 kill", c.pid)
            except Exception:
                pass
    print("done killed", pids)


if __name__ == "__main__":
    main()
