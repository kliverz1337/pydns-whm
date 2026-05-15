#!/usr/bin/env python3
"""Quick WHM detection test — checks if known WHM IPs respond on ports 2087/2086.

Usage:
    python -m python.whm_test          # test built-in list of known WHM IPs
    python -m python.whm_test <ip>     # test a single IP
"""

import asyncio
import sys

import httpx

# Known Indonesian hosting provider IPs that likely run cPanel/WHM
# These are nameserver IPs of major Indonesian hosting companies
KNOWN_WHM_CANDIDATES = [
    # Niagahoster nameservers
    "153.92.4.10",      # ns1.niagahoster.com
    "153.92.4.11",      # ns2.niagahoster.com
    # Rumahweb nameservers
    "103.253.212.98",   # ns1.rumahweb.com
    "103.253.212.99",   # ns2.rumahweb.com
    # Dewaweb nameservers
    "103.168.118.10",   # ns1.dewaweb.com
    "103.168.118.11",   # ns2.dewaweb.com
    # IDCloudHost nameservers
    "103.142.22.10",    # ns1.idcloudhost.com
    "103.142.22.11",    # ns2.idcloudhost.com
    # JagoanHosting nameservers
    "103.163.138.10",   # ns1.jagoanhosting.com
    "103.163.138.11",   # ns2.jagoanhosting.com
    # Hostinger Indonesia
    "185.224.82.10",    # ns1.hostinger.co.id
    "185.224.82.11",    # ns2.hostinger.co.id
    # Masterweb
    "103.28.12.10",     # ns1.masterweb.net
    "103.28.12.11",     # ns2.masterweb.net
    # ArdHosting
    "103.117.56.10",    # ns1.ardhosting.com
    "103.117.56.11",    # ns2.ardhosting.com
]

WHM_MARKERS = (
    "WHM", "Web Host Manager", "cPanel", "whm-login", "cpsrvd",
)


async def check_whm(ip: str, timeout: float = 5.0) -> dict:
    """Check if an IP hosts WHM on ports 2087 (HTTPS) or 2086 (HTTP)."""
    result = {"ip": ip, "whm": False, "hostname": "", "port": None, "error": ""}

    for port, use_https in [(2087, True), (2086, False)]:
        try:
            scheme = "https" if use_https else "http"
            url = f"{scheme}://{ip}:{port}/"
            async with httpx.AsyncClient(
                verify=False,
                timeout=httpx.Timeout(timeout, connect=3.0),
                follow_redirects=True,
            ) as client:
                resp = await client.get(url)
                body = resp.text[:8192]

                if any(marker in body for marker in WHM_MARKERS):
                    result["whm"] = True
                    result["port"] = port
                    # Extract title
                    import re
                    title_match = re.search(
                        r"<title>(.*?)</title>", body, re.IGNORECASE
                    )
                    if title_match:
                        result["hostname"] = title_match.group(1).strip()
                    break
        except httpx.ConnectError:
            continue
        except httpx.TimeoutException:
            continue
        except Exception as e:
            result["error"] = str(e)[:100]
            continue

    return result


async def main():
    targets = sys.argv[1:] if len(sys.argv) > 1 else KNOWN_WHM_CANDIDATES

    print(f"{'='*70}")
    print(f"  PYDNS WHM Detection Test")
    print(f"  Testing {len(targets)} IP(s) for WHM on ports 2087/2086")
    print(f"{'='*70}\n")

    results = await asyncio.gather(*[check_whm(ip) for ip in targets])

    whm_found = 0
    for r in results:
        status = "✅ WHM FOUND" if r["whm"] else "❌ No WHM"
        extra = ""
        if r["whm"]:
            whm_found += 1
            extra = f" | port={r['port']} | {r['hostname']}"
        elif r["error"]:
            extra = f" | error={r['error']}"
        print(f"  {r['ip']:20s} → {status}{extra}")

    print(f"\n{'='*70}")
    print(f"  Results: {whm_found}/{len(targets)} IPs have WHM")
    print(f"{'='*70}")

    # Also print IPs that can be used as DNS server targets for PYDNS testing
    if whm_found > 0:
        print(f"\n  To test in PYDNS, create a CIDR file with these IPs as /32:")
        for r in results:
            if r["whm"]:
                print(f"    {r['ip']}/32")


if __name__ == "__main__":
    asyncio.run(main())