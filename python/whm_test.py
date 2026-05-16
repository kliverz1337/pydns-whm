#!/usr/bin/env python3
"""Quick WHM detection test — checks if candidate IPs respond on WHM/cPanel ports.

Usage:
    python -m python.whm_test          # test built-in list of known WHM candidates
    python -m python.whm_test <ip>     # test one or more IPs
"""

import asyncio
import re
import sys

import httpx

# Known Indonesian hosting provider IPs that may run or front cPanel/WHM.
# These are nameserver IPs of major Indonesian hosting companies; many providers
# separate nameserver hosts from actual WHM nodes, so this list is diagnostic,
# not a guarantee that every entry should be WHM-positive.
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
    "whm",
    "web host manager",
    "cpanel",
    "whm-login",
    "cpsrvd",
    "cpsession",
    "cpsess",
    "login_theme",
    "security token",
    "server login",
    "powered by cpanel",
    "copyright cpanel",
)
WHM_PATHS = ("/", "/login", "/whm", "/cpanel")
WHM_PORTS = ((2087, True), (2086, False))


async def tcp_port_open(ip: str, port: int, timeout: float = 3.0) -> bool:
    """Return True if a TCP connection to ip:port succeeds."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        try:
            reader.feed_eof()
        except Exception:
            pass
        return True
    except Exception:
        return False


def extract_title(body: str) -> str:
    """Extract a compact HTML title from a response body."""
    title_match = re.search(r"<title>\s*(.*?)\s*</title>", body, re.IGNORECASE | re.DOTALL)
    if not title_match:
        return ""
    return " ".join(title_match.group(1).split())[:120]


async def check_whm(ip: str, timeout: float = 8.0) -> dict:
    """Check if an IP hosts WHM on ports 2087 (HTTPS) or 2086 (HTTP)."""
    result = {
        "ip": ip,
        "whm": False,
        "possible": False,
        "hostname": "",
        "target": ip,
        "port": None,
        "path": "",
        "open_ports": [],
        "error": "",
    }

    try:
        async with httpx.AsyncClient(
            verify=False,
            timeout=httpx.Timeout(timeout, connect=5.0),
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 PYDNS-WHM-Detector/1.0"},
        ) as client:
            for port, use_https in WHM_PORTS:
                if not await tcp_port_open(ip, port):
                    continue

                result["open_ports"].append(f"{ip}:{port}")
                scheme = "https" if use_https else "http"

                for path in WHM_PATHS:
                    try:
                        url = f"{scheme}://{ip}:{port}{path}"
                        resp = await client.get(url)
                        body = resp.text[:16384]
                        body_lc = body.lower()
                        final_url = str(resp.url).lower()

                        marker_found = any(marker in body_lc for marker in WHM_MARKERS)
                        url_hint = any(token in final_url for token in ("cpsess", "whm", "cpanel"))
                        status_hint = resp.status_code in (401, 403) and port in (2086, 2087)

                        if marker_found or url_hint:
                            result.update({
                                "whm": True,
                                "possible": True,
                                "hostname": extract_title(body) or "WHM Login",
                                "port": port,
                                "path": path,
                            })
                            return result

                        if status_hint:
                            result["possible"] = True
                    except (httpx.TimeoutException, httpx.ConnectError, httpx.ProtocolError):
                        continue
                    except Exception as e:
                        result["error"] = str(e)[:120]
                        continue
    except Exception as e:
        result["error"] = str(e)[:120]

    return result


async def main():
    targets = sys.argv[1:] if len(sys.argv) > 1 else KNOWN_WHM_CANDIDATES

    print(f"{'='*80}")
    print("  PYDNS WHM Detection Test")
    print("  TCP pre-check + ports 2087/2086 + paths /, /login, /whm, /cpanel")
    print(f"  Testing {len(targets)} IP(s)")
    print(f"{'='*80}\n")

    results = await asyncio.gather(*[check_whm(ip) for ip in targets])

    whm_found = 0
    possible_found = 0
    for r in results:
        if r["whm"]:
            whm_found += 1
            status = "✅ WHM FOUND"
            extra = f" | port={r['port']} | path={r['path']} | {r['hostname']}"
        elif r["possible"]:
            possible_found += 1
            status = "⚠️  WHM POSSIBLE"
            extra = f" | open={','.join(r['open_ports'])}"
        else:
            status = "❌ No WHM"
            extra = f" | open={','.join(r['open_ports'])}" if r["open_ports"] else ""
            if r["error"]:
                extra += f" | error={r['error']}"
        print(f"  {r['ip']:20s} → {status}{extra}")

    print(f"\n{'='*80}")
    print(f"  Results: {whm_found}/{len(targets)} confirmed WHM, {possible_found} possible/protected")
    print(f"{'='*80}")

    if whm_found > 0:
        print("\n  Confirmed WHM IPs as /32 CIDRs:")
        for r in results:
            if r["whm"]:
                print(f"    {r['ip']}/32")


if __name__ == "__main__":
    asyncio.run(main())
