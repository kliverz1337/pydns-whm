#!/usr/bin/env python3
"""Headless WHM/cPanel scanner — CIDR → TCP pre-check → HTTP probe → results.

Usage:
    python -m python.whm_scan --cidr iran-ipv4.cidrs
    python -m python.whm_scan --cidr targets.cidrs --concurrency 200 --timeout 10
    python -m python.whm_scan --cidr targets.cidrs --output results.txt
    python -m python.whm_scan --cidr targets.cidrs --json whm_results.json

Arguments:
    --cidr PATH          CIDR file to scan (required)
    --concurrency N      Max simultaneous HTTP probes (default: 100)
    --timeout SECONDS    HTTP request timeout (default: 8.0)
    --tcp-timeout SECONDS TCP pre-check timeout (default: 3.0)
    --output PATH        Save WHM-positive IPs to TXT as ip:port plus optional hostname comment
    --json PATH          Save full results as JSON
    --max-ips N          Stop after scanning N IPs (default: unlimited)
    --quiet              Suppress per-IP progress output
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import logging
import mmap
import os
import random
import signal
import struct
import socket
import sys
import time
from pathlib import Path
from typing import Optional

# Allow running as `python -m python.whm_scan` from repo root
_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

from scanner.whm_worker import WhmScanner, WhmResult

logger = logging.getLogger("whm_scan")


# ── IP streaming (standalone, no TUI dependency) ────────────────────────────

def _load_subnets(cidr_path: str) -> list[ipaddress.IPv4Network]:
    """Load CIDR subnets from file using mmap with fallback."""
    subnets: list[ipaddress.IPv4Network] = []
    try:
        with open(cidr_path, "r+b") as f:
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                for raw in iter(mm.readline, b""):
                    line = raw.decode("utf-8", errors="ignore").strip()
                    if line and not line.startswith("#"):
                        try:
                            subnets.append(ipaddress.IPv4Network(line, strict=False))
                        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
                            pass
    except (OSError, mmap.error):
        try:
            with open(cidr_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        try:
                            subnets.append(ipaddress.IPv4Network(line, strict=False))
                        except ValueError:
                            pass
        except (OSError, IOError) as e:
            logger.error(f"Failed to read CIDR file: {e}")
            raise
    return subnets


def _count_total_ips(subnets: list[ipaddress.IPv4Network]) -> int:
    """Count total host addresses across all subnets."""
    total = 0
    for net in subnets:
        total += max(1, net.num_addresses - (2 if net.prefixlen < 31 else 0))
    return total


async def _stream_ips(
    subnets: list[ipaddress.IPv4Network],
    concurrency: int,
    max_ips: int = 0,
    shutdown_event: Optional[asyncio.Event] = None,
) -> "AsyncGenerator[list[str], None]":
    """Stream IPs in randomised batches using Redis-style pincer strategy."""
    chunk_size = max(4, min(16, concurrency // 4 if concurrency > 0 else 8))
    rng = random.Random()

    # Split into /24 blocks
    all_blocks: list[ipaddress.IPv4Network] = []
    for net in subnets:
        if net.prefixlen >= 24:
            all_blocks.append(net)
        else:
            all_blocks.extend(net.subnets(new_prefix=24))

    if not all_blocks:
        return

    rng.shuffle(all_blocks)
    num_lanes = min(max(1, concurrency), len(all_blocks))

    # Distribute blocks across lanes
    lanes: list[list[ipaddress.IPv4Network]] = [[] for _ in range(num_lanes)]
    for idx, blk in enumerate(all_blocks):
        lanes[idx % num_lanes].append(blk)

    # Reverse every other lane for pincer effect
    for lane_idx in range(1, len(lanes), 2):
        lanes[lane_idx].reverse()

    positions = [0] * len(lanes)
    batch: list[str] = []
    total_yielded = 0
    _pack = struct.pack
    _ntoa = socket.inet_ntoa
    _sample = random.sample

    while True:
        if shutdown_event and shutdown_event.is_set():
            break

        any_remaining = False
        for lane_idx, lane_blocks in enumerate(lanes):
            pos = positions[lane_idx]
            if pos >= len(lane_blocks):
                continue

            any_remaining = True
            subnet_chunk = lane_blocks[pos]
            positions[lane_idx] = pos + 1

            net_int = int(subnet_chunk.network_address)
            num_addr = subnet_chunk.num_addresses

            if num_addr == 1:
                batch.append(_ntoa(_pack(">I", net_int)))
                total_yielded += 1
            elif subnet_chunk.prefixlen >= 31:
                indices = list(range(num_addr))
                rng.shuffle(indices)
                for idx in indices:
                    batch.append(_ntoa(_pack(">I", net_int + idx)))
                    total_yielded += 1
                    if max_ips > 0 and total_yielded >= max_ips:
                        break
            else:
                host_count = num_addr - 2
                start_int = net_int + 1
                for idx in _sample(range(host_count), host_count):
                    batch.append(_ntoa(_pack(">I", start_int + idx)))
                    total_yielded += 1
                    if max_ips > 0 and total_yielded >= max_ips:
                        break

            if len(batch) >= chunk_size:
                yield batch
                batch = []
                await asyncio.sleep(0)

            if max_ips > 0 and total_yielded >= max_ips:
                if batch:
                    yield batch
                return

        if not any_remaining:
            break

    if batch:
        yield batch


# ── Main scan loop ──────────────────────────────────────────────────────────

async def run_scan(
    cidr_path: str,
    concurrency: int = 100,
    http_timeout: float = 8.0,
    tcp_timeout: float = 3.0,
    max_ips: int = 0,
    quiet: bool = False,
    shutdown_event: Optional[asyncio.Event] = None,
) -> dict[str, WhmResult]:
    """Run a full WHM scan over a CIDR file and return all results.

    Returns a dict mapping IP → WhmResult for every probed IP.
    """
    # Load subnets
    print(f"Loading CIDR file: {cidr_path}")
    subnets = _load_subnets(cidr_path)
    total_ips = _count_total_ips(subnets)
    print(f"  Subnets loaded: {len(subnets)}")
    print(f"  Estimated IPs:   {total_ips:,}")
    if max_ips > 0:
        print(f"  Max IPs limit:   {max_ips:,}")
    print(f"  Concurrency:     {concurrency}")
    print(f"  HTTP timeout:    {http_timeout}s")
    print(f"  TCP timeout:     {tcp_timeout}s")
    print(f"{'=' * 70}")

    # Create scanner
    scanner = WhmScanner(
        concurrency=concurrency,
        http_timeout=http_timeout,
        tcp_timeout=tcp_timeout,
        pause_event=None,
        progress_callback=None,
    )
    await scanner.start()

    all_results: dict[str, WhmResult] = {}
    whm_found = 0
    possible_found = 0
    scanned = 0
    start_time = time.monotonic()

    try:
        async for ip_batch in _stream_ips(subnets, concurrency, max_ips, shutdown_event):
            if shutdown_event and shutdown_event.is_set():
                break

            results = await scanner.scan_batch(ip_batch)
            for ip, result in results.items():
                all_results[ip] = result
                scanned += 1

                if result.get("whm"):
                    whm_found += 1
                    if not quiet:
                        hostname = result.get("hostname", "")
                        print(
                            f"  ✓ WHM FOUND  {ip}:{result.get('port')}"
                            f"{f' — {hostname}' if hostname else ''}"
                        )
                elif result.get("possible"):
                    possible_found += 1
                    if not quiet:
                        print(f"  ⚠ POSSIBLE   {ip}:{result.get('port')}")

            # Progress line
            elapsed = time.monotonic() - start_time
            rate = scanned / elapsed if elapsed > 0 else 0
            if not quiet:
                print(
                    f"  [{scanned:,}/{total_ips:,} | {rate:.0f} IP/s | "
                    f"✓{whm_found} ⚠{possible_found}]",
                    end="\r",
                )
    finally:
        await scanner.stop()

    elapsed = time.monotonic() - start_time
    rate = scanned / elapsed if elapsed > 0 else 0
    print(f"\n{'=' * 70}")
    print(f"  Scan complete in {elapsed:.1f}s")
    print(f"  IPs scanned:    {scanned:,}")
    print(f"  Rate:           {rate:.0f} IP/s")
    print(f"  WHM confirmed:  {whm_found}")
    print(f"  WHM possible:   {possible_found}")
    print(f"{'=' * 70}")

    return all_results


# ── Output helpers ──────────────────────────────────────────────────────────

def save_whm_txt(results: dict[str, WhmResult], output_path: str) -> None:
    """Save WHM-positive IPs to a plain-text file (ip:port, optional hostname comment)."""
    whm_ips = sorted(ip for ip, r in results.items() if r.get("whm"))
    with open(output_path, "w", encoding="utf-8") as f:
        for ip in whm_ips:
            r = results[ip]
            port = r.get("port", "")
            hostname = str(r.get("hostname", "") or "").strip()
            line = f"{ip}:{port}"
            if hostname:
                line += f"  # {hostname}"
            f.write(line + "\n")
    print(f"\n  WHM results saved to: {output_path} ({len(whm_ips)} servers)")


def save_json(results: dict[str, WhmResult], json_path: str) -> None:
    """Save full scan results as JSON."""
    # Convert to serialisable format
    serialisable = {}
    for ip, r in results.items():
        serialisable[ip] = {
            "whm": r.get("whm", False),
            "possible": r.get("possible", False),
            "hostname": r.get("hostname", ""),
            "target": r.get("target", ip),
            "port": r.get("port"),
            "path": r.get("path", ""),
            "open_ports": r.get("open_ports", []),
        }
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(serialisable, f, indent=2, ensure_ascii=False)
    print(f"  JSON results saved to: {json_path}")


# ── CLI entry point ─────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Headless WHM/cPanel scanner — CIDR → TCP pre-check → HTTP probe",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m python.whm_scan --cidr iran-ipv4.cidrs
  python -m python.whm_scan --cidr targets.cidrs --concurrency 200 --timeout 10
  python -m python.whm_scan --cidr targets.cidrs --output whm_servers.txt
  python -m python.whm_scan --cidr targets.cidrs --json results.json --quiet
        """,
    )
    parser.add_argument(
        "--cidr", required=True, metavar="PATH",
        help="CIDR file to scan (one subnet per line)",
    )
    parser.add_argument(
        "--concurrency", type=int, default=100, metavar="N",
        help="Max simultaneous HTTP probes (default: 100)",
    )
    parser.add_argument(
        "--timeout", type=float, default=8.0, metavar="SECONDS",
        help="HTTP request timeout (default: 8.0)",
    )
    parser.add_argument(
        "--tcp-timeout", type=float, default=3.0, metavar="SECONDS",
        help="TCP pre-check timeout (default: 3.0)",
    )
    parser.add_argument(
        "--output", metavar="PATH",
        help="Save WHM-positive IPs to TXT as 'ip:port' or 'ip:port  # hostname'",
    )
    parser.add_argument(
        "--json", metavar="PATH", dest="json_path",
        help="Save full results as JSON",
    )
    parser.add_argument(
        "--max-ips", type=int, default=0, metavar="N",
        help="Stop after scanning N IPs (default: unlimited)",
    )
    parser.add_argument(
        "--quiet", action="store_true",
        help="Suppress per-IP progress output",
    )

    args = parser.parse_args()

    if not os.path.isfile(args.cidr):
        print(f"Error: CIDR file not found: {args.cidr}", file=sys.stderr)
        sys.exit(1)

    # Handle Ctrl+C gracefully
    shutdown_event = asyncio.Event()
    loop = asyncio.new_event_loop()

    def _sig_handler():
        print("\n  Interrupted — shutting down...")
        shutdown_event.set()

    try:
        loop.add_signal_handler(signal.SIGINT, _sig_handler)
    except NotImplementedError:
        # Windows doesn't support add_signal_handler
        signal.signal(signal.SIGINT, lambda s, f: shutdown_event.set())

    try:
        results = loop.run_until_complete(
            run_scan(
                cidr_path=args.cidr,
                concurrency=args.concurrency,
                http_timeout=args.timeout,
                tcp_timeout=args.tcp_timeout,
                max_ips=args.max_ips,
                quiet=args.quiet,
                shutdown_event=shutdown_event,
            )
        )
    except KeyboardInterrupt:
        print("\n  Interrupted by user.")
        results = {}
    finally:
        loop.close()

    # Save outputs
    if args.output and results:
        save_whm_txt(results, args.output)

    if args.json_path and results:
        save_json(results, args.json_path)

    # Print summary of WHM-positive servers
    whm_ips = sorted(ip for ip, r in results.items() if r.get("whm"))
    if whm_ips:
        print(f"\n  Confirmed WHM servers ({len(whm_ips)}):")
        for ip in whm_ips:
            r = results[ip]
            hostname = r.get("hostname", "")
            print(f"    {ip}:{r.get('port')}{f' — {hostname}' if hostname else ''}")


if __name__ == "__main__":
    main()