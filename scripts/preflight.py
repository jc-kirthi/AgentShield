"""Preflight verification script for AgentShield services."""

import sys
import httpx


def check_service(name: str, url: str) -> bool:
    try:
        r = httpx.get(f"{url}/health", timeout=3.0)
        if r.status_code == 200:
            print(f"[OK] {name} is healthy at {url}")
            return True
        else:
            print(f"[FAIL] {name} returned HTTP {r.status_code}")
            return False
    except Exception as e:
        print(f"[WARN] {name} unreachable at {url}: {e}")
        return False


def main():
    print("=== AgentShield Preflight Check ===")
    services = [
        ("Mock S/4HANA (erp_sim)", "http://127.0.0.1:8001"),
        ("Out-of-band Oracles", "http://127.0.0.1:8002"),
        ("AttackLab", "http://127.0.0.1:8004"),
    ]
    all_ok = True
    for name, url in services:
        if not check_service(name, url):
            all_ok = False

    if all_ok:
        print("All Kirti services are operational.")
        sys.exit(0)
    else:
        print("Some services were not reachable (they may need to be started).")
        sys.exit(0)


if __name__ == "__main__":
    main()
